//! Sync integration tests (ticket 027): the real `HeaderSync` against
//! loopback mock peers serving a regtest `FixtureChain`.
//!
//! Mounted as `sync::integration_tests` so scenarios can reach `HeaderSync`
//! internals (header store, UTXO set, anchor, minimum work). Each test gets
//! its own temp directory and its own mock-peer ports, so they run in
//! parallel.
//!
//! Tests that describe behavior the code doesn't have yet (tickets 024 and
//! 025) are `#[ignore]`d with the ticket named. Run them with
//! `cargo test --offline -- --ignored sync::integration_tests`.

use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, TxOut};
use tempfile::TempDir;

use super::*;
use crate::peer_store::PeerStore;
use crate::testkit::{Behavior, FixtureChain, Invalid, MockPeer};

/// Default SCORE_DEFAULT in peer_pool: a fresh peer's reputation.
const FRESH_SCORE: i32 = 100;

// ── Harness ──────────────────────────────────────────────────────────

/// A regtest `HeaderSync` in a temp directory, pointed at mock peers.
struct Node {
    dir: TempDir,
    hs: HeaderSync,
}

impl Node {
    fn new(peers: &[&MockPeer]) -> Node {
        let dir = TempDir::new().unwrap();
        let hs = HeaderSync::with_config(SyncConfig {
            db_path: dir.path().join("headers.sqlite3").to_str().unwrap().to_string(),
            tor: None,
            params: ChainParams::regtest(),
            peers: static_peers(peers),
        })
        .unwrap();
        Node { dir, hs }
    }

    /// Point later sync sessions at a different set of mock peers.
    fn use_peers(&mut self, peers: &[&MockPeer]) {
        self.hs.peer_source = static_peers(peers);
    }

    fn tip(&self) -> (u32, BlockHash) {
        let (h, hash, _) = self.hs.store.tip().unwrap().unwrap();
        (h, hash)
    }

    fn hash_at(&self, height: u32) -> Option<BlockHash> {
        self.hs.store.get_hash_at_height(height).unwrap()
    }

    fn validated(&self) -> u32 {
        self.hs.store.validated_height().unwrap()
    }

    fn has_utxo(&self, op: &OutPoint) -> bool {
        self.hs.utxo.get(&op.txid, op.vout).unwrap().is_some()
    }

    fn peer_store(&self) -> PeerStore {
        PeerStore::open(self.dir.path().join("peers.sqlite3").to_str().unwrap()).unwrap()
    }

    fn is_banned(&self, addr: &str) -> bool {
        self.peer_store().load_active_bans().unwrap().contains_key(addr)
    }

    fn score(&self, addr: &str) -> Option<i32> {
        self.peer_store().load_score(addr).unwrap()
    }

    /// The node's UTXO set is exactly the one `chain` implies.
    fn assert_utxos_match(&self, chain: &FixtureChain) {
        let expected = chain.expected_utxos();
        assert_eq!(self.hs.utxo.count().unwrap(), expected.len() as u64, "UTXO count");
        for (op, out) in &expected {
            let got = self
                .hs
                .utxo
                .get(&op.txid, op.vout)
                .unwrap()
                .unwrap_or_else(|| panic!("missing UTXO {}", op));
            assert_eq!(got.amount, out.value.to_sat(), "amount of {}", op);
            assert_eq!(got.script_pubkey, out.script_pubkey.to_bytes(), "script of {}", op);
        }
    }

    /// Run `sync()` on a background thread while `body` drives the test,
    /// then stop it. Returns `body`'s result and `sync()`'s return value.
    fn run_sync<R>(&self, body: impl FnOnce(&HeaderSync) -> R) -> (R, Result<(), SyncError>) {
        std::thread::scope(|s| {
            let handle = s.spawn(|| self.hs.sync(|_| {}));
            let r = body(&self.hs);
            // `sync()` clears the stop flag on entry, so keep asking until
            // it has actually returned.
            while !handle.is_finished() {
                self.hs.stop_sync();
                std::thread::sleep(Duration::from_millis(20));
            }
            (r, handle.join().expect("sync thread panicked"))
        })
    }

    /// Run `sync()` until `done` holds (true) or `timeout` passes (false).
    fn sync_until(
        &self,
        timeout: Duration,
        done: impl Fn(&HeaderSync) -> bool,
    ) -> (bool, Result<(), SyncError>) {
        self.run_sync(|hs| wait_until(hs, timeout, &done))
    }
}

fn static_peers(peers: &[&MockPeer]) -> PeerSource {
    PeerSource::Static(peers.iter().map(|p| p.addr()).collect())
}

/// Poll `done` until it holds or `timeout` passes.
fn wait_until(hs: &HeaderSync, timeout: Duration, done: &dyn Fn(&HeaderSync) -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if done(hs) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done(hs)
}

/// Header tip is `chain`'s tip and every block up to it is validated.
fn synced_to(chain: &FixtureChain) -> impl Fn(&HeaderSync) -> bool + '_ {
    move |hs| {
        let tip_ok = hs
            .store
            .tip()
            .ok()
            .flatten()
            .map(|(h, hash, _)| h == chain.tip_height() && hash == chain.tip_hash())
            .unwrap_or(false);
        tip_ok && hs.store.validated_height().unwrap_or(0) == chain.tip_height()
    }
}

const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

/// Sync `node` to `chain` from fresh mocks, then drop the mocks.
fn presync(node: &mut Node, chain: &FixtureChain) {
    let peer = MockPeer::spawn(chain, vec![]);
    node.use_peers(&[&peer]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(chain));
    assert!(ok, "presync to {} failed: {:?}", chain.tip_height(), res);
}

/// `n` blocks with real spends: coinbase 1 is split into P2TR + P2WPKH
/// outputs at 102, both are spent together at 103 (taproot key path +
/// segwit v0 in one tx), and 104 carries a parent/child pair.
fn chain_with_spends(n: u32) -> FixtureChain {
    assert!(n >= 110);
    let mut c = FixtureChain::new();
    c.mine(101);

    let cb = c.coinbase_outpoint(1);
    let value = c.block(1).txdata[0].output[0].value;
    let split = c.spend(
        &[cb],
        vec![
            TxOut { value: value / 2, script_pubkey: c.p2tr_script() },
            TxOut { value: value / 2 - Amount::from_sat(500), script_pubkey: c.p2wpkh_script() },
        ],
    );
    c.mine_block(vec![split.clone()]);

    let merge = c.spend(
        &[OutPoint::new(split.compute_txid(), 0), OutPoint::new(split.compute_txid(), 1)],
        vec![TxOut { value: value - Amount::from_sat(2_000), script_pubkey: c.p2tr_script() }],
    );
    c.mine_block(vec![merge]);

    let cb2 = c.coinbase_outpoint(2);
    let parent = c.spend(
        &[cb2],
        vec![TxOut { value: value - Amount::from_sat(1_000), script_pubkey: c.p2wpkh_script() }],
    );
    // The child spends an output created in the same block, so sign it
    // against a scratch chain that already contains the parent.
    let mut scratch = c.clone();
    scratch.mine_block(vec![parent.clone()]);
    let child = scratch.spend(
        &[OutPoint::new(parent.compute_txid(), 0)],
        vec![TxOut { value: value - Amount::from_sat(3_000), script_pubkey: c.p2tr_script() }],
    );
    c.mine_block(vec![parent, child]);

    c.mine(n - c.tip_height());
    c
}

// ── Baseline sync ────────────────────────────────────────────────────

#[test]
fn initial_sync_from_genesis_three_honest_peers() {
    let chain = chain_with_spends(300);
    let peers: Vec<MockPeer> = (0..3).map(|_| MockPeer::spawn(&chain, vec![])).collect();
    let refs: Vec<&MockPeer> = peers.iter().collect();
    let node = Node::new(&refs);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "did not sync: {:?}, tip {:?}", res, node.tip());
    assert!(res.is_ok(), "{:?}", res);

    node.assert_utxos_match(&chain);
    // The spent coinbase is gone; subsidy halved at regtest height 150.
    assert!(!node.has_utxo(&chain.coinbase_outpoint(1)));
    assert!(node.has_utxo(&chain.coinbase_outpoint(150)));
    // All three peers were connected (no /16 collapse on loopback).
    for p in &peers {
        assert!(p.connections() >= 1, "peer {} never connected", p.addr());
    }
    // Every block was fetched, once per height at least.
    let requested: HashSet<BlockHash> = peers.iter().flat_map(|p| p.block_requests()).collect();
    for h in 1..=chain.tip_height() {
        assert!(requested.contains(&chain.hash_at(h)), "block {} never requested", h);
    }
}

#[test]
fn faulty_peers_are_dropped_and_sync_completes() {
    let mut chain = FixtureChain::new();
    chain.mine(30);
    let garbage = MockPeer::spawn(&chain, vec![Behavior::SendGarbage]);
    let hangup = MockPeer::spawn(&chain, vec![Behavior::Disconnect]);
    let slow = MockPeer::spawn(&chain, vec![Behavior::DelayResponses(Duration::from_millis(20))]);
    let node = Node::new(&[&garbage, &hangup, &slow]);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "did not sync: {:?}", res);
    node.assert_utxos_match(&chain);
}

#[test]
fn withheld_block_is_fetched_from_another_peer() {
    let mut chain = FixtureChain::new();
    chain.mine(12);
    // Listed first, so `any_peer` asks the withholder before the honest one.
    let withholder = MockPeer::spawn(&chain, vec![Behavior::WithholdBlock(5)]);
    let honest = MockPeer::spawn(&chain, vec![]);
    let node = Node::new(&[&withholder, &honest]);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "did not sync: {:?}", res);
    assert!(withholder.block_requests().contains(&chain.hash_at(5)));
    assert!(honest.block_requests().contains(&chain.hash_at(5)));
}

// ── Ticket 022: wake path binds the block to the requested header ───

/// A node validated to 109 and a 110-block chain whose tip it hasn't seen,
/// plus an impostor block for height 110 (valid PoW, different hash).
fn wake_fixture() -> (Node, FixtureChain, bitcoin::Block) {
    let mut chain = FixtureChain::new();
    chain.mine(110);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(109));
    let mut impostor = chain.fork_at(109);
    let wrong = impostor.mine_block(vec![]);
    (node, chain, wrong)
}

#[test]
fn wake_path_wrong_block_leaves_validated_height_unchanged() {
    let (mut node, chain, wrong) = wake_fixture();
    let bad = MockPeer::spawn(&chain, vec![Behavior::WrongBlockAt(110, wrong.clone())]);
    node.use_peers(&[&bad]);

    let n = node.hs.validate_latest_block(25).unwrap();
    assert!(n.header_validated);
    assert!(!n.validated, "wrong block must not validate");
    assert_eq!(n.height, 110);
    assert_eq!(node.validated(), 109, "validated_height must not advance");
    assert_eq!(node.tip(), (110, chain.tip_hash()), "header is still stored");
    assert!(bad.block_requests().contains(&chain.hash_at(110)));
    // Neither the impostor's nor the real block's coinbase was applied.
    assert!(!node.has_utxo(&OutPoint::new(wrong.txdata[0].compute_txid(), 0)));
    assert!(!node.has_utxo(&chain.coinbase_outpoint(110)));
    let score = node.score(&bad.addr()).expect("score persisted");
    assert!(score < FRESH_SCORE, "peer not penalized: {}", score);
}

#[test]
fn wake_path_retries_another_peer_after_wrong_block() {
    let (mut node, chain, wrong) = wake_fixture();
    let bad = MockPeer::spawn(&chain, vec![Behavior::WrongBlockAt(110, wrong)]);
    let honest = MockPeer::spawn(&chain, vec![]);
    node.use_peers(&[&bad, &honest]);

    let n = node.hs.validate_latest_block(25).unwrap();
    assert!(n.validated, "{:?}", n.validation_error);
    assert_eq!(node.validated(), 110);
    assert!(node.has_utxo(&chain.coinbase_outpoint(110)));
}

#[test]
fn wake_path_skips_unsolicited_block() {
    let (mut node, chain, wrong) = wake_fixture();
    let racer = MockPeer::spawn(&chain, vec![Behavior::UnsolicitedBlockBefore(110, wrong.clone())]);
    node.use_peers(&[&racer]);

    let n = node.hs.validate_latest_block(25).unwrap();
    assert!(n.validated, "{:?}", n.validation_error);
    assert_eq!(node.validated(), 110);
    assert!(node.has_utxo(&chain.coinbase_outpoint(110)));
    assert!(!node.has_utxo(&OutPoint::new(wrong.txdata[0].compute_txid(), 0)));
}

// ── Ticket 023: chain anchoring end to end ───────────────────────────

#[test]
fn anchor_conflict_bans_peer_and_honest_chain_wins() {
    let mut honest_chain = FixtureChain::new();
    honest_chain.mine(30);
    // Longer, so the pool picks it as the best (active) peer first.
    let mut hostile_chain = honest_chain.fork_at(5);
    hostile_chain.mine(40);
    let honest = MockPeer::spawn(&honest_chain, vec![]);
    let hostile = MockPeer::spawn(&hostile_chain, vec![]);
    let mut node = Node::new(&[&honest, &hostile]);
    node.hs.anchor = SnapshotAnchor {
        height: 10,
        block_hash: honest_chain.hash_at(10).to_byte_array(),
        utxo_hash: [0u8; 32],
    };

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&honest_chain));
    assert!(ok, "did not sync honest chain: {:?}, tip {:?}", res, node.tip());
    assert!(node.is_banned(&hostile.addr()), "anchor-conflicting peer not banned");
    assert_eq!(node.hash_at(10), Some(honest_chain.hash_at(10)));
    node.assert_utxos_match(&honest_chain);
}

#[test]
fn pending_snapshot_activates_when_headers_reach_anchor() {
    const ANCHOR: u32 = 110;
    let chain = chain_with_spends(130);

    // Build the snapshot the way 032's pipeline would: from a node that
    // validated the chain up to the anchor.
    let mut donor = Node::new(&[]);
    presync(&mut donor, &chain.prefix(ANCHOR));
    let mut buf = Vec::new();
    let block_hash = chain.hash_at(ANCHOR).to_byte_array();
    let meta = donor.hs.utxo.write_snapshot(&mut buf, ANCHOR, &block_hash).unwrap();

    let peer_a = MockPeer::spawn(&chain, vec![]);
    let peer_b = MockPeer::spawn(&chain, vec![]);
    let mut node = Node::new(&[&peer_a, &peer_b]);
    let path = node.dir.path().join("snapshot.hutx");
    std::fs::write(&path, &buf).unwrap();
    node.hs.anchor = SnapshotAnchor { height: ANCHOR, block_hash, utxo_hash: meta.utxo_hash };

    // Loaded before any headers: pending, validated_height untouched.
    node.hs.load_snapshot(path.to_str().unwrap(), |_, _| {}).unwrap();
    assert_eq!(node.validated(), 0, "snapshot must stay pending without headers");

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "did not sync: {:?}, validated {}", res, node.validated());
    assert_eq!(node.hs.get_trust_info().unwrap().snapshot_height, ANCHOR);
    node.assert_utxos_match(&chain);
    // Blocks at or below the anchor were never downloaded.
    for p in [&peer_a, &peer_b] {
        for hash in p.block_requests() {
            let h = node.hs.store.find_height_of_hash(hash).unwrap().unwrap();
            assert!(h > ANCHOR, "fetched block {} at or below the snapshot", h);
        }
    }
}

#[test]
fn low_work_chain_from_colluding_peers_is_never_validated() {
    let mut chain = FixtureChain::new();
    chain.mine(20);
    let a = MockPeer::spawn(&chain, vec![]);
    let b = MockPeer::spawn(&chain, vec![]);
    let mut node = Node::new(&[&a, &b]);
    let headers: Vec<Header> = chain.blocks().iter().map(|b| b.header).collect();
    let mut one = [0u8; 32];
    one[0] = 1;
    // One unit more than the whole chain's work.
    node.hs.min_chain_work = u256_add(chainwork_for_headers(&headers), one);

    let (_, _res) = node.sync_until(Duration::from_secs(4), |_| false);
    assert_eq!(node.validated(), 0, "validated blocks on a below-min-work chain");
    assert!(a.block_requests().is_empty() && b.block_requests().is_empty());
}

// ── Header cross-check ───────────────────────────────────────────────

/// Two peers on disjoint chains and no third opinion: every batch is
/// rejected and both peers take `HEADER_DISAGREEMENT_PENALTY`. The active
/// peer is also rewarded +1 for answering `getheaders` before the
/// cross-check runs, so the witness reaches the ban threshold first. Once
/// it is gone the cross-check has no witness and (outside initial sync)
/// accepts the survivor's headers. This pins that current behavior: the
/// peer with the higher claimed height ends up unopposed.
#[test]
fn cross_check_two_peer_disagreement_rejects_until_witness_banned() {
    let mut a_chain = FixtureChain::new();
    a_chain.mine(10);
    // Taller, so it is the active peer and `a` the witness.
    let mut b_chain = FixtureChain::new().fork_at(0);
    b_chain.mine(11);
    let a = MockPeer::spawn(&a_chain, vec![]);
    let b = MockPeer::spawn(&b_chain, vec![]);
    let node = Node::new(&[&a, &b]);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&b_chain));
    assert!(ok, "{:?}, tip {:?}", res, node.tip());
    assert!(node.is_banned(&a.addr()), "witness not banned by repeated disagreement");
    let b_score = node.score(&b.addr());
    assert!(b_score.map_or(false, |s| s < FRESH_SCORE), "active peer not penalized: {:?}", b_score);
    // Several getheaders rounds were needed before the batch was accepted.
    let rounds = b
        .log()
        .iter()
        .filter(|m| matches!(m, NetworkMessage::GetHeaders(_)))
        .count();
    assert!(rounds >= 5, "only {} getheaders rounds", rounds);
}

/// A peer that claims a higher tip but answers `getheaders` with nothing
/// is always picked as the active peer (height-weighted), so the node
/// believes it is synced and never asks the honest peer. Only gaps above
/// 2016 blocks are treated as lying. Not yet tracked by a ticket; closest
/// to 024 (a single peer stalls sync).
#[test]
#[ignore = "untracked (found by 027; cf. 024): an empty-headers peer with a higher claimed height stalls header sync"]
fn empty_headers_from_taller_peer_do_not_stall_sync() {
    let mut chain = FixtureChain::new();
    chain.mine(10);
    let mut taller = chain.clone();
    taller.mine(5);
    let staller = MockPeer::spawn(&taller, vec![Behavior::WithholdHeaders]);
    let honest = MockPeer::spawn(&chain, vec![]);
    let node = Node::new(&[&staller, &honest]);

    let (ok, res) = node.sync_until(Duration::from_secs(15), synced_to(&chain));
    assert!(ok, "stalled: {:?}, tip {:?}", res, node.tip());
}

#[test]
fn cross_check_tiebreaker_rejects_minority_active_peer() {
    let mut a_chain = FixtureChain::new();
    a_chain.mine(10);
    // Taller, so the minority peer is the first active peer.
    let mut b_chain = FixtureChain::new().fork_at(0);
    b_chain.mine(12);
    let b = MockPeer::spawn(&b_chain, vec![]);
    let a1 = MockPeer::spawn(&a_chain, vec![]);
    let a2 = MockPeer::spawn(&a_chain, vec![]);
    let node = Node::new(&[&a1, &a2, &b]);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&a_chain));
    assert!(ok, "did not sync majority chain: {:?}, tip {:?}", res, node.tip());
    assert_eq!(node.hash_at(1), Some(a_chain.hash_at(1)));
    let score = node.score(&b.addr());
    assert!(
        node.is_banned(&b.addr()) || score.map_or(false, |s| s < FRESH_SCORE),
        "minority peer not penalized (score {:?})",
        score
    );
}

// ── catch_up_blocks ──────────────────────────────────────────────────

#[test]
fn catch_up_blocks_validates_backlog_within_budget() {
    let chain = chain_with_spends(120);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(110));
    let a = MockPeer::spawn(&chain, vec![]);
    let b = MockPeer::spawn(&chain, vec![]);
    node.use_peers(&[&a, &b]);

    let status = node.hs.catch_up_blocks(50, 10).unwrap();
    assert!(status.caught_up, "{:?}", status);
    assert_eq!(status.blocks_validated, 10);
    assert_eq!(status.current_height, 120);
    assert!(status.error.is_none() && !status.tip_disagreement, "{:?}", status);
    node.assert_utxos_match(&chain);
}

#[test]
fn catch_up_blocks_stops_at_max_blocks() {
    let mut chain = FixtureChain::new();
    chain.mine(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(10));
    let a = MockPeer::spawn(&chain, vec![]);
    let b = MockPeer::spawn(&chain, vec![]);
    node.use_peers(&[&a, &b]);

    let status = node.hs.catch_up_blocks(4, 10).unwrap();
    assert!(!status.caught_up);
    assert_eq!(status.blocks_validated, 4);
    assert_eq!(status.current_height, 14);
    assert_eq!(status.target_height, 20);
    assert_eq!(node.validated(), 14);
}

#[test]
fn catch_up_blocks_respects_time_budget_with_slow_peer() {
    let mut chain = FixtureChain::new();
    chain.mine(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(10));
    let slow = MockPeer::spawn(&chain, vec![Behavior::DelayResponses(Duration::from_millis(1200))]);
    node.use_peers(&[&slow]);

    let start = Instant::now();
    let status = node.hs.catch_up_blocks(10, 2).unwrap();
    let elapsed = start.elapsed();
    assert!(!status.caught_up, "{:?}", status);
    assert!(status.blocks_validated <= 1, "{:?}", status);
    assert!(status.error.is_none(), "{:?}", status);
    assert_eq!(node.validated(), 10 + status.blocks_validated);
    // Budget plus at most one in-flight request, with slack for CI.
    assert!(elapsed < Duration::from_secs(5), "overran budget: {:?}", elapsed);
}

// ── Reorgs ───────────────────────────────────────────────────────────

/// 105 blocks; block 105 spends coinbase 1. The fork replaces 105 with two
/// blocks that don't contain the spend.
fn reorg_fixture() -> (FixtureChain, FixtureChain) {
    let mut a = FixtureChain::new();
    a.mine(104);
    let cb = a.coinbase_outpoint(1);
    let value = a.block(1).txdata[0].output[0].value - Amount::from_sat(1_000);
    let tx = a.spend(&[cb], vec![TxOut { value, script_pubkey: a.p2tr_script() }]);
    a.mine_block(vec![tx]);
    let mut b = a.fork_at(104);
    b.mine(2);
    (a, b)
}

#[test]
fn one_block_reorg_to_more_work_fork_while_running() {
    let (a, b) = reorg_fixture();
    let p1 = MockPeer::spawn(&a, vec![]);
    let p2 = MockPeer::spawn(&a, vec![]);
    let node = Node::new(&[&p1, &p2]);

    let ((on_a, on_b), res) = node.run_sync(|hs| {
        let on_a = wait_until(hs, SYNC_TIMEOUT, &synced_to(&a));
        // Both peers switch to the heavier fork and announce it; the node
        // is in its monitor loop and must break out and reorg.
        p1.set_chain(&b);
        p2.set_chain(&b);
        p1.announce_tip();
        p2.announce_tip();
        let on_b = wait_until(hs, SYNC_TIMEOUT, &synced_to(&b));
        (on_a, on_b)
    });
    assert!(on_a, "never synced chain A: {:?}", res);
    assert!(on_b, "did not reorg to B: {:?}, tip {:?}", res, node.tip());
    node.assert_utxos_match(&b);
    // The reorged-out spend is undone.
    assert!(node.has_utxo(&a.coinbase_outpoint(1)));
    assert!(!node.has_utxo(&a.coinbase_outpoint(105)));
}

// ── Known bugs (documented, not yet fixed) ───────────────────────────

#[test]
#[ignore = "ticket 024: a consensus-invalid block from one peer halts sync instead of marking it failed"]
fn invalid_block_is_marked_failed_and_honest_chain_followed() {
    let mut honest_chain = FixtureChain::new();
    honest_chain.mine(30);
    let mut hostile_chain = honest_chain.fork_at(20);
    hostile_chain.mine_invalid(Invalid::CoinbaseOverpay);
    hostile_chain.mine(15);
    let hostile = MockPeer::spawn(&hostile_chain, vec![]);
    let honest = MockPeer::spawn(&honest_chain, vec![]);
    let node = Node::new(&[&hostile, &honest]);

    let (ok, res) = node.sync_until(Duration::from_secs(20), synced_to(&honest_chain));
    assert!(ok, "did not recover to the honest chain: {:?}, tip {:?}", res, node.tip());
}

#[test]
#[ignore = "ticket 024: a mutated (witness-stripped) delivery halts sync instead of penalize-and-refetch"]
fn mutated_block_penalizes_peer_and_refetches() {
    let chain = chain_with_spends(110);
    // Block 102 carries witness spends; listed first, so it serves first.
    let mutator = MockPeer::spawn(&chain, vec![Behavior::ServeMutated(102)]);
    let honest = MockPeer::spawn(&chain, vec![]);
    let node = Node::new(&[&mutator, &honest]);

    let (ok, res) = node.sync_until(Duration::from_secs(20), synced_to(&chain));
    assert!(ok, "did not sync past the mutated delivery: {:?}", res);
    let score = node.score(&mutator.addr());
    assert!(score.map_or(true, |s| s < FRESH_SCORE), "mutator not penalized");
}

#[test]
#[ignore = "ticket 024: invalid extending headers halt sync instead of penalizing the peer"]
fn invalid_extending_headers_penalize_peer_and_continue() {
    let mut honest_chain = FixtureChain::new();
    honest_chain.mine(30);
    let mut hostile_chain = honest_chain.fork_at(20);
    // Timestamp at or below median-time-past: valid PoW, invalid header.
    let genesis_time = honest_chain.block(0).header.time;
    hostile_chain.mine_custom(vec![], |b| b.header.time = genesis_time);
    hostile_chain.mine(15);
    let hostile = MockPeer::spawn(&hostile_chain, vec![]);
    let honest = MockPeer::spawn(&honest_chain, vec![]);
    let node = Node::new(&[&hostile, &honest]);

    let (ok, res) = node.sync_until(Duration::from_secs(20), synced_to(&honest_chain));
    assert!(ok, "sync halted on bad headers: {:?}", res);
}

#[test]
#[ignore = "ticket 025: reorg rolls back before the new branch's blocks are validated"]
fn withheld_reorg_blocks_leave_node_on_old_tip() {
    let (a, b) = reorg_fixture();
    let mut node = Node::new(&[]);
    presync(&mut node, &a);
    let withholder = MockPeer::spawn(&b, vec![]);
    withholder.set_behaviors(vec![Behavior::WithholdBlock(105), Behavior::WithholdBlock(106)]);
    node.use_peers(&[&withholder]);

    let _ = node.sync_until(Duration::from_secs(8), |_| false);
    assert_eq!(node.tip(), (a.tip_height(), a.tip_hash()), "abandoned A for an unvalidated branch");
    assert_eq!(node.validated(), a.tip_height());
    node.assert_utxos_match(&a);
}

#[test]
#[ignore = "ticket 025: the push-wake path can't follow a 1-block reorg (single-hash locator)"]
fn wake_path_follows_one_block_reorg() {
    let (a, b) = reorg_fixture();
    let mut node = Node::new(&[]);
    presync(&mut node, &a);
    let peer = MockPeer::spawn(&b, vec![]);
    node.use_peers(&[&peer]);

    let n = node.hs.validate_latest_block(25).expect("wake path errored on reorg");
    assert!(n.validated, "{:?}", n.validation_error);
    assert_eq!(node.tip(), (b.tip_height(), b.tip_hash()));
}
