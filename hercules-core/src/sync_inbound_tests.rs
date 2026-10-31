//! What one message from a connected peer can make the node do
//! (`handle_peer_message`, the monitor loop's dispatcher): limits on
//! `getheaders`, `getdata`, `inv`, `addr`/`addrv2`, and the small
//! protocol replies. Peers are scripted `MemStream`s (p2p tests), so no
//! socket is involved; the node is a regtest `HeaderSync` in a temp dir
//! with a short fixture chain stored.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use proptest::prelude::*;
use tempfile::TempDir;

use super::*;
use crate::p2p::tests::{arb_message, decode_all, mem_peer};
use crate::p2p::Peer;
use crate::testkit::{lmdb_slot, FixtureChain, LmdbSlot};

/// A node with `chain`'s headers stored and its last `served` blocks in
/// the block store (what NODE_NETWORK_LIMITED serves).
struct Fixture {
    hs: HeaderSync,
    chain: FixtureChain,
    pool: PeerPool,
    _dir: TempDir,
    _slot: LmdbSlot,
}

fn fixture(height: u32, served: u32) -> Fixture {
    let slot = lmdb_slot();
    let dir = TempDir::new().unwrap();
    let hs = HeaderSync::with_config(SyncConfig {
        db_path: dir.path().join("headers.sqlite3").to_str().unwrap().to_string(),
        tor: None,
        params: ChainParams::regtest(),
        peers: PeerSource::Static(vec![]),
    })
    .unwrap();
    let mut chain = FixtureChain::new();
    chain.mine(height);
    let headers: Vec<Header> = (1..=height).map(|h| chain.block(h).header).collect();
    hs.store.store_headers(&headers, 1).unwrap();
    for h in height.saturating_sub(served) + 1..=height {
        hs.block_store.store_block(chain.block(h), h).unwrap();
    }
    Fixture {
        hs,
        chain,
        pool: PeerPool::new_for_test_with(ChainParams::regtest()),
        _dir: dir,
        _slot: slot,
    }
}

const ADDR: &str = "203.0.113.9:8333";

impl Fixture {
    /// Deliver `msg` from a fresh peer; returns the handler's verdict and
    /// every message the node sent back.
    fn handle(&self, msg: NetworkMessage) -> (Result<(), String>, Vec<NetworkMessage>) {
        let (mut peer, written) = mem_peer(vec![], Magic::REGTEST);
        self.handle_on(&mut peer, msg, &written)
    }

    fn handle_on(
        &self,
        peer: &mut Peer,
        msg: NetworkMessage,
        written: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    ) -> (Result<(), String>, Vec<NetworkMessage>) {
        let before = written.lock().unwrap().len();
        let r = self.hs.handle_peer_message(ADDR, msg, peer, &self.pool);
        let sent = decode_all(&written.lock().unwrap()[before..]);
        (r, sent)
    }

    fn pending_gossip(&self) -> Vec<String> {
        std::mem::take(&mut *self.hs.pending_gossip_addrs.lock().unwrap())
    }
}

fn getheaders(locator: Vec<BlockHash>, stop: BlockHash) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage { version: 70016, locator_hashes: locator, stop_hash: stop })
}

fn junk_hash(i: u32) -> BlockHash {
    let mut b = [0xee; 32];
    b[..4].copy_from_slice(&i.to_le_bytes());
    BlockHash::from_byte_array(b)
}

// ── getheaders ───────────────────────────────────────────────────────

#[test]
fn getheaders_answers_after_the_first_locator_entry_we_know() {
    let f = fixture(20, 0);
    let locator = vec![junk_hash(1), f.chain.hash_at(5), f.chain.hash_at(0)];
    let (r, sent) = f.handle(getheaders(locator, BlockHash::all_zeros()));
    r.unwrap();
    match &sent[..] {
        [NetworkMessage::Headers(h)] => {
            assert_eq!(h.len(), 15);
            assert_eq!(h[0].block_hash(), f.chain.hash_at(6));
            assert_eq!(h[14].block_hash(), f.chain.hash_at(20));
        }
        other => panic!("{:?}", other.iter().map(msg_name).collect::<Vec<_>>()),
    }
    assert_eq!(f.hs.stats.lock().unwrap().headers_served, 15);
}

#[test]
fn getheaders_honors_stop_hash_and_answers_empty_at_our_tip() {
    let f = fixture(20, 0);
    let (_, sent) = f.handle(getheaders(vec![f.chain.hash_at(2)], f.chain.hash_at(4)));
    assert!(matches!(&sent[..], [NetworkMessage::Headers(h)] if h.len() == 2));
    // Already at our tip: an empty batch, not silence (the peer waits).
    let (_, sent) = f.handle(getheaders(vec![f.chain.hash_at(20)], BlockHash::all_zeros()));
    assert!(matches!(&sent[..], [NetworkMessage::Headers(h)] if h.is_empty()));
    // A stop hash we don't know doesn't truncate anything.
    let (_, sent) = f.handle(getheaders(vec![f.chain.hash_at(10)], junk_hash(9)));
    assert!(matches!(&sent[..], [NetworkMessage::Headers(h)] if h.len() == 10));
}

#[test]
fn getheaders_batches_are_capped_at_2000() {
    let f = fixture(2100, 0);
    let (_, sent) = f.handle(getheaders(vec![f.chain.hash_at(0)], BlockHash::all_zeros()));
    match &sent[..] {
        [NetworkMessage::Headers(h)] => {
            assert_eq!(h.len(), 2000);
            assert_eq!(h[0].block_hash(), f.chain.hash_at(1));
        }
        other => panic!("{:?}", other.iter().map(msg_name).collect::<Vec<_>>()),
    }
}

/// Reviewer finding: the locator is walked hash by hash (one SQLite
/// lookup each) with no size limit, so one 4 MB `getheaders` costs ~125k
/// lookups on the sync thread. Core refuses locators over
/// MAX_LOCATOR_SZ = 101 and disconnects.
#[test]
#[ignore = "BUG: getheaders locator size is unbounded (Core caps at 101); one message costs up to ~125k DB lookups"]
fn getheaders_with_an_oversized_locator_is_refused() {
    let f = fixture(20, 0);
    let locator: Vec<BlockHash> = (0..100_000).map(junk_hash).collect();
    let start = Instant::now();
    let (r, sent) = f.handle(getheaders(locator, BlockHash::all_zeros()));
    let took = start.elapsed();
    assert!(r.is_err(), "100k-hash locator served ({} replies) after {:?}", sent.len(), took);
}

// ── getdata ──────────────────────────────────────────────────────────

#[test]
fn getdata_serves_stored_blocks_and_notfound_for_everything_else() {
    let f = fixture(10, 3);
    let items = vec![
        Inventory::WitnessBlock(f.chain.hash_at(10)),
        Inventory::Block(f.chain.hash_at(9)),
        Inventory::WitnessBlock(f.chain.hash_at(2)), // pruned
        Inventory::WitnessBlock(junk_hash(1)),       // unknown
        Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([3; 32])),
        Inventory::CompactBlock(f.chain.hash_at(10)),
        Inventory::Error,
    ];
    let (r, sent) = f.handle(NetworkMessage::GetData(items));
    r.unwrap();
    let names: Vec<&str> = sent.iter().map(msg_name).collect();
    assert_eq!(names, ["block", "block", "notfound"]);
    assert!(matches!(&sent[0], NetworkMessage::Block(b) if b.block_hash() == f.chain.hash_at(10)));
    assert!(matches!(&sent[2], NetworkMessage::NotFound(nf) if nf.len() == 5));
    assert_eq!(f.hs.stats.lock().unwrap().blocks_served, 2);
}

#[test]
fn getdata_and_inv_over_50000_entries_are_refused_and_at_50000_handled() {
    let f = fixture(1, 0);
    let items = |n: u32| (0..n).map(|i| Inventory::WitnessBlock(junk_hash(i))).collect::<Vec<_>>();
    let (r, sent) = f.handle(NetworkMessage::GetData(items(50_001)));
    assert!(r.is_err() && sent.is_empty());
    let (r, sent) = f.handle(NetworkMessage::GetData(items(50_000)));
    r.unwrap();
    assert!(matches!(&sent[..], [NetworkMessage::NotFound(nf)] if nf.len() == 50_000));

    let (r, sent) = f.handle(NetworkMessage::Inv(items(50_001)));
    assert!(r.is_err() && sent.is_empty());
}

// ── inv ──────────────────────────────────────────────────────────────

#[test]
fn inv_of_an_unknown_block_wakes_the_monitor_loop_and_a_known_one_does_not() {
    let f = fixture(5, 0);
    f.hs.new_block_announced.store(false, Ordering::Relaxed);
    f.handle(NetworkMessage::Inv(vec![Inventory::Block(f.chain.hash_at(5))])).0.unwrap();
    assert!(!f.hs.new_block_announced.load(Ordering::Relaxed));
    let (r, sent) = f.handle(NetworkMessage::Inv(vec![Inventory::Block(junk_hash(3))]));
    r.unwrap();
    assert!(f.hs.new_block_announced.load(Ordering::Relaxed));
    // Blocks are fetched by the sync loop via headers, never by getdata
    // straight off an inv.
    assert!(sent.is_empty());
}

#[test]
fn inv_of_transactions_requests_only_unknown_ones_with_witness() {
    let f = fixture(1, 0);
    let txids: Vec<bitcoin::Txid> = (0..3u8).map(|i| bitcoin::Txid::from_byte_array([i + 1; 32])).collect();
    let (r, sent) = f.handle(NetworkMessage::Inv(vec![
        Inventory::Transaction(txids[0]),
        Inventory::WitnessTransaction(txids[1]),
        Inventory::WTx(bitcoin::Wtxid::from_byte_array([9; 32])),
        Inventory::Unknown { inv_type: 77, hash: [5; 32] },
    ]));
    r.unwrap();
    match &sent[..] {
        [NetworkMessage::GetData(req)] => {
            assert_eq!(req.len(), 2);
            assert!(req.iter().all(|i| matches!(i, Inventory::WitnessTransaction(_))));
        }
        other => panic!("{:?}", other.iter().map(msg_name).collect::<Vec<_>>()),
    }
    // The announcer is remembered as knowing them (never announced back).
    let state = f.hs.relay_state.lock().unwrap();
    assert!(state[ADDR].known_txids.contains(&txids[0]) && state[ADDR].known_txids.contains(&txids[1]));
}

#[test]
fn inv_floods_keep_per_peer_txid_memory_bounded() {
    let f = fixture(1, 0);
    for round in 0..3u32 {
        let inv: Vec<Inventory> = (0..20_000u32)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&(round * 20_000 + i).to_le_bytes());
                Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(b))
            })
            .collect();
        f.handle(NetworkMessage::Inv(inv)).0.unwrap();
        let n = f.hs.relay_state.lock().unwrap()[ADDR].known_txids.len();
        assert!(n <= MAX_KNOWN_TXIDS_PER_PEER, "{} known txids after round {}", n, round);
    }
}

// ── addr / addrv2 ────────────────────────────────────────────────────

fn v1(ip: [u8; 4], port: u16) -> (u32, Address) {
    (1_700_000_000, Address::new(&SocketAddr::from((Ipv4Addr::from(ip), port)), ServiceFlags::NETWORK))
}

fn v2(addr: AddrV2, port: u16) -> AddrV2Message {
    AddrV2Message { time: 1_700_000_000, services: ServiceFlags::NETWORK, addr, port }
}

#[test]
fn addr_queues_at_most_1000_routable_entries_per_message() {
    let f = fixture(1, 0);
    let flood: Vec<(u32, Address)> =
        (0..5000u32).map(|i| v1([45, (i >> 16) as u8, (i >> 8) as u8, i as u8], 8333)).collect();
    f.handle(NetworkMessage::Addr(flood)).0.unwrap();
    assert_eq!(f.pending_gossip().len(), MAX_GOSSIP_ADDRS_PER_MSG);

    let mixed = vec![
        v1([8, 8, 8, 8], 8333),
        v1([127, 0, 0, 1], 8333),   // loopback
        v1([0, 0, 0, 0], 8333),     // unspecified
        v1([224, 0, 0, 1], 8333),   // multicast
        v1([169, 254, 1, 1], 8333), // link-local
        v1([255, 255, 255, 255], 8333),
        v1([9, 9, 9, 9], 0), // port 0
    ];
    f.handle(NetworkMessage::Addr(mixed)).0.unwrap();
    assert_eq!(f.pending_gossip(), vec!["8.8.8.8:8333".to_string()]);
}

#[test]
fn addrv2_keeps_ip_and_torv3_and_drops_what_we_cannot_dial() {
    let f = fixture(1, 0);
    let onion_key = [0x42u8; 32];
    let msgs = vec![
        v2(AddrV2::Ipv4(Ipv4Addr::new(8, 8, 4, 4)), 8333),
        v2(AddrV2::Ipv6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888)), 8333),
        v2(AddrV2::TorV3(onion_key), 8333),
        v2(AddrV2::TorV2([1; 10]), 8333),
        v2(AddrV2::I2p([2; 32]), 0),
        v2(AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), 8333),
        v2(AddrV2::Unknown(99, vec![1, 2, 3]), 8333),
        v2(AddrV2::Ipv6(Ipv6Addr::LOCALHOST), 8333),
        v2(AddrV2::TorV3(onion_key), 0),
    ];
    f.handle(NetworkMessage::AddrV2(msgs)).0.unwrap();
    let got = f.pending_gossip();
    assert!(got.contains(&"8.8.4.4:8333".to_string()), "{:?}", got);
    assert!(got.iter().any(|a| a.starts_with("[2001:4860")), "{:?}", got);
    let onion = format!("{}:8333", crate::tor_v3::pubkey_to_hostname(&onion_key));
    assert!(got.contains(&onion), "{:?}", got);
    assert_eq!(got.len(), 3, "{:?}", got);
}

#[test]
fn addrv2_flood_is_capped_per_message_too() {
    let f = fixture(1, 0);
    let flood: Vec<AddrV2Message> = (0..3000u32)
        .map(|i| {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            v2(AddrV2::TorV3(key), 8333)
        })
        .collect();
    f.handle(NetworkMessage::AddrV2(flood)).0.unwrap();
    assert_eq!(f.pending_gossip().len(), MAX_GOSSIP_ADDRS_PER_MSG);
}

// ── Small protocol replies ───────────────────────────────────────────

#[test]
fn ping_pong_feefilter_sendheaders_and_unknown_messages() {
    let f = fixture(1, 0);
    let (_, sent) = f.handle(NetworkMessage::Ping(u64::MAX));
    assert!(matches!(sent[..], [NetworkMessage::Pong(u64::MAX)]));

    for (rate, stored) in [(i64::MIN, 0), (-1, 0), (0, 0), (1000, 1000), (i64::MAX, i64::MAX as u64)] {
        f.handle(NetworkMessage::FeeFilter(rate)).0.unwrap();
        assert_eq!(f.hs.relay_state.lock().unwrap()[ADDR].feefilter_rate, stored, "{}", rate);
    }

    f.handle(NetworkMessage::SendHeaders).0.unwrap();
    assert!(f.hs.relay_state.lock().unwrap()[ADDR].wants_sendheaders);

    for msg in [
        NetworkMessage::Verack,
        NetworkMessage::WtxidRelay,
        NetworkMessage::SendAddrV2,
        NetworkMessage::Unknown {
            command: bitcoin::p2p::message::CommandString::try_from("hercjunk").unwrap(),
            payload: vec![1, 2, 3],
        },
    ] {
        let (r, sent) = f.handle(msg);
        assert!(r.is_ok() && sent.is_empty());
    }
}

#[test]
fn getaddr_is_answered_once_per_connection() {
    let f = fixture(1, 0);
    let (mut peer, written) = mem_peer(vec![], Magic::REGTEST);
    let (_, first) = f.handle_on(&mut peer, NetworkMessage::GetAddr, &written);
    assert!(matches!(first[..], [NetworkMessage::Addr(_)]), "{:?}", first.iter().map(msg_name).collect::<Vec<_>>());
    let (_, second) = f.handle_on(&mut peer, NetworkMessage::GetAddr, &written);
    assert!(second.is_empty(), "scraper answered twice");
}

// ── Never panics ─────────────────────────────────────────────────────

#[test]
fn prop_handle_peer_message_never_panics() {
    // One node for every case (opening LMDB per case would dominate).
    let f = fixture(30, 5);
    let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(128),
        ..Default::default()
    });
    runner
        .run(&prop::collection::vec(arb_message(), 1..8), |msgs| {
            let (mut peer, written) = mem_peer(vec![], Magic::REGTEST);
            for m in msgs {
                let _ = f.handle_on(&mut peer, m, &written);
            }
            Ok(())
        })
        .unwrap();
}
