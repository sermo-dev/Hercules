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
use crate::p2p::tests::{arb_message, decode_all, encode, mem_peer, Chunk};
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

    /// `handle`, on a given peer. Queued `getdata` is served to the end,
    /// as the monitor loop would over its next passes.
    fn handle_on(
        &self,
        peer: &mut Peer,
        msg: NetworkMessage,
        written: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    ) -> (Result<(), String>, Vec<NetworkMessage>) {
        let before = written.lock().unwrap().len();
        let mut r = self.hs.handle_peer_message(ADDR, msg, peer, &self.pool);
        while r.is_ok() && self.hs.has_queued_getdata(ADDR) {
            r = self.hs.serve_getdata_step(ADDR, peer).map(|_| ());
        }
        let sent = decode_all(&written.lock().unwrap()[before..]);
        (r, sent)
    }

    fn pending_gossip(&self) -> Vec<String> {
        let queued = std::mem::take(&mut *self.hs.pending_gossip_addrs.lock().unwrap());
        assert!(queued.iter().all(|(from, _)| from == ADDR), "gossip attributed to its sender");
        queued.into_iter().flat_map(|(_, batch)| batch).collect()
    }
}

/// A `MemStream` script delivering `msgs` with regtest magic.
fn script_of_magic(magic: Magic, msgs: Vec<NetworkMessage>) -> Vec<Chunk> {
    msgs.into_iter().map(|m| Chunk::Data(encode(magic, m))).collect()
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
    // Answered in full, a step (GETDATA_ITEMS_PER_STEP) at a time.
    let answered: Vec<usize> = sent
        .iter()
        .map(|m| match m {
            NetworkMessage::NotFound(nf) => nf.len(),
            other => panic!("{}", msg_name(other)),
        })
        .collect();
    assert_eq!(answered.iter().sum::<usize>(), 50_000);
    assert!(answered.iter().all(|&n| n <= GETDATA_ITEMS_PER_STEP), "{:?}", answered);

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

// ── What one request costs us (ticket 049) ───────────────────────────

#[test]
fn getheaders_locator_at_the_limit_is_served() {
    let f = fixture(20, 0);
    let mut locator: Vec<BlockHash> = (0..MAX_LOCATOR_SZ as u32 - 1).map(junk_hash).collect();
    locator.push(f.chain.hash_at(10));
    let (r, sent) = f.handle(getheaders(locator, BlockHash::all_zeros()));
    r.unwrap();
    assert!(matches!(&sent[..], [NetworkMessage::Headers(h)] if h.len() == 10));
}

#[test]
fn getdata_is_served_a_block_per_step_with_nothing_else_read_meanwhile() {
    let f = fixture(10, 3);
    let mut pool = PeerPool::new_for_test_with(ChainParams::regtest());
    let (mut peer, written) = mem_peer(
        script_of_magic(Magic::REGTEST, vec![NetworkMessage::Ping(5)]),
        Magic::REGTEST,
    );
    peer.set_addr_for_test(ADDR, true);
    let items: Vec<Inventory> = (8..=10).map(|h| Inventory::WitnessBlock(f.chain.hash_at(h))).collect();
    // The handler serves the first step at once.
    f.hs.handle_peer_message(ADDR, NetworkMessage::GetData(items), &mut peer, &f.pool).unwrap();
    assert_eq!(decode_all(&written.lock().unwrap()).len(), 1);
    assert!(f.hs.has_queued_getdata(ADDR));
    assert!(pool.add_inbound_peer(peer));

    // Each monitor pass serves one more block, and the peer's queued ping
    // waits until the getdata is done (back-pressure).
    let names = || decode_all(&written.lock().unwrap()).iter().map(msg_name).collect::<Vec<_>>();
    f.hs.service_peer_messages(&mut pool);
    assert_eq!(names(), ["block", "block"]);
    f.hs.service_peer_messages(&mut pool);
    assert_eq!(names(), ["block", "block", "block"]);
    assert!(!f.hs.has_queued_getdata(ADDR));
    f.hs.service_peer_messages(&mut pool);
    assert_eq!(names(), ["block", "block", "block", "pong"]);
    let blocks: Vec<BlockHash> = decode_all(&written.lock().unwrap())
        .iter()
        .filter_map(|m| match m {
            NetworkMessage::Block(b) => Some(b.block_hash()),
            _ => None,
        })
        .collect();
    assert_eq!(blocks, (8..=10).map(|h| f.chain.hash_at(h)).collect::<Vec<_>>(), "served in order");
}

#[test]
fn blocks_served_to_one_peer_are_capped_per_window() {
    let f = fixture(3, 1);
    let extra = 5;
    let items = vec![Inventory::WitnessBlock(f.chain.hash_at(3)); MAX_BLOCKS_SERVED_PER_PEER as usize + extra];
    let (r, sent) = f.handle(NetworkMessage::GetData(items));
    r.unwrap();
    let blocks = sent.iter().filter(|m| matches!(m, NetworkMessage::Block(_))).count();
    let refused: usize = sent
        .iter()
        .map(|m| match m {
            NetworkMessage::NotFound(nf) => nf.len(),
            _ => 0,
        })
        .sum();
    assert_eq!((blocks, refused), (MAX_BLOCKS_SERVED_PER_PEER as usize, extra));
    // Another peer has its own allowance.
    let (mut other, written) = mem_peer(vec![], Magic::REGTEST);
    let one = vec![Inventory::WitnessBlock(f.chain.hash_at(3))];
    f.hs.handle_peer_message("198.51.100.20:8333", NetworkMessage::GetData(one), &mut other, &f.pool).unwrap();
    assert!(matches!(&decode_all(&written.lock().unwrap())[..], [NetworkMessage::Block(_)]));
}

#[test]
fn metered_upload_cap_stops_block_serving_until_unmetered() {
    let mut f = fixture(3, 1);
    let block_size = f.chain.block(3).total_size() as u64;
    f.hs.upload_budget = crate::upload_budget::UploadBudget::new(2 * block_size);
    let tip = || NetworkMessage::GetData(vec![Inventory::WitnessBlock(f.chain.hash_at(3)); 3]);
    let count = |sent: &[NetworkMessage]| {
        (
            sent.iter().filter(|m| matches!(m, NetworkMessage::Block(_))).count(),
            sent.iter().filter(|m| matches!(m, NetworkMessage::NotFound(_))).count(),
        )
    };
    // Unmetered (the default): no cap.
    assert_eq!(count(&f.handle(tip()).1), (3, 0));
    f.hs.set_network_metered(true);
    assert_eq!(count(&f.handle(tip()).1), (2, 1), "past the metered cap");
    assert_eq!(count(&f.handle(tip()).1), (0, 1), "the cap holds across requests");
    f.hs.set_network_metered(false);
    assert_eq!(count(&f.handle(tip()).1), (3, 0), "unmetered again");
}

#[test]
fn inv_looks_up_a_bounded_number_of_blocks() {
    let f = fixture(10, 0);
    f.hs.new_block_announced.store(false, Ordering::Relaxed);
    // Known blocks fill the lookup budget; an unknown one after them is
    // never looked at.
    let mut inv: Vec<Inventory> =
        (1..=MAX_BLOCK_INV_LOOKUPS as u32).map(|h| Inventory::Block(f.chain.hash_at(h))).collect();
    inv.push(Inventory::Block(junk_hash(1)));
    f.handle(NetworkMessage::Inv(inv)).0.unwrap();
    assert!(!f.hs.new_block_announced.load(Ordering::Relaxed));
    assert!(f.hs.take_block_announcement().is_none());
}

#[test]
fn inv_of_a_known_block_raises_the_announcers_height() {
    // Core's UpdateBlockAvailability: an announced block we have is a
    // block the peer has shown it has.
    let f = fixture(10, 0);
    let (mut peer, _) = mem_peer(vec![], Magic::REGTEST);
    peer.set_addr_for_test(ADDR, false);
    f.pool.add_outbound_peer_for_test(peer);
    assert_eq!(f.pool.get_peer_height(ADDR), Some(0));
    f.handle(NetworkMessage::Inv(vec![Inventory::Block(f.chain.hash_at(7))])).0.unwrap();
    assert_eq!(f.pool.get_peer_height(ADDR), Some(7));
    f.handle(NetworkMessage::Inv(vec![Inventory::Block(f.chain.hash_at(3))])).0.unwrap();
    assert_eq!(f.pool.get_peer_height(ADDR), Some(7), "never lowered");
}

#[test]
fn unknown_block_announcements_name_the_first_outbound_announcer_and_throttle_inbound_ones() {
    let f = fixture(5, 0);
    f.hs.new_block_announced.store(false, Ordering::Relaxed);
    f.handle(NetworkMessage::Inv(vec![Inventory::Block(junk_hash(1))])).0.unwrap();
    f.hs.handle_peer_message("198.51.100.30:8333", NetworkMessage::Inv(vec![Inventory::Block(junk_hash(2))]), &mut mem_peer(vec![], Magic::REGTEST).0, &f.pool).unwrap();
    assert!(f.hs.new_block_announced.swap(false, Ordering::Relaxed));
    assert_eq!(f.hs.take_block_announcement(), Some((ADDR.to_string(), junk_hash(1))), "first outbound announcer");
    assert_eq!(f.hs.take_block_announcement(), None);

    // Inbound announcers are never asked, and wake the loop once per
    // INBOUND_ANNOUNCEMENT_INTERVAL between them all.
    let inbound = |id: &str, n: u32| {
        f.hs.note_block_announcement(id, junk_hash(n), true);
        f.hs.new_block_announced.swap(false, Ordering::Relaxed)
    };
    assert!(inbound("inbound#900001", 3));
    assert!(!inbound("inbound#900002", 4), "a second inbound wake within the interval");
    assert_eq!(f.hs.take_block_announcement(), None);
}

#[test]
fn transaction_inv_asks_for_at_most_max_getdata_sz() {
    let f = fixture(1, 0);
    let inv: Vec<Inventory> = (0..1500u32)
        .map(|i| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            Inventory::Transaction(bitcoin::Txid::from_byte_array(b))
        })
        .collect();
    let (r, sent) = f.handle(NetworkMessage::Inv(inv));
    r.unwrap();
    assert!(matches!(&sent[..], [NetworkMessage::GetData(req)] if req.len() == MAX_GETDATA_SZ));
    // All 1500 are remembered as known to the peer, asked for or not.
    assert_eq!(f.hs.relay_state.lock().unwrap()[ADDR].known_txids.len(), 1500);
}

#[test]
fn handler_errors_disconnect_the_peer() {
    // A request over a limit (here an oversized locator) or a failed send
    // drops the peer from the monitor loop, as Core disconnects.
    let f = fixture(5, 0);
    let mut pool = PeerPool::new_for_test_with(ChainParams::regtest());
    let locator: Vec<BlockHash> = (0..MAX_LOCATOR_SZ as u32 + 1).map(junk_hash).collect();
    let (mut peer, _) = mem_peer(
        script_of_magic(Magic::REGTEST, vec![getheaders(locator, BlockHash::all_zeros())]),
        Magic::REGTEST,
    );
    peer.set_addr_for_test(ADDR, true);
    assert!(pool.add_inbound_peer(peer));
    f.hs.service_peer_messages(&mut pool);
    assert_eq!(pool.count(), 0);
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
