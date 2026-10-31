//! Ticket 050: the one block-connect path, pruning on every path, and
//! safe resets and activation, against the real `HeaderSync` and mock
//! peers.
//!
//! Mounted as `sync::connect_path_tests`, beside `integration_tests`, whose
//! harness (`Node`, `presync`, `sync_until`) it reuses. Most tests shrink
//! the prune window (`SMALL`) so short fixture chains prune.

use std::time::Duration;

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, TxOut};

use super::integration_tests::{presync, synced_to, Node, SYNC_TIMEOUT};
use super::*;
use crate::own_tx_store::OwnTxStatus;
use crate::testkit::{FixtureChain, MockPeer};

/// Keep 6 heights, prune once 3 more pile up, at most 4 heights a call; a
/// prune lock holds at most 20 back.
const SMALL: PruneWindow = PruneWindow { keep: 6, slack: 3, step: 4, lock_max_hold: 20 };

/// `n` blocks in which every block from 101 on spends the coinbase from
/// 100 blocks earlier, so every such height has undo data.
fn spending_chain(n: u32) -> FixtureChain {
    let mut c = FixtureChain::new();
    c.mine(n.min(100));
    while c.tip_height() < n {
        let cb = c.coinbase_outpoint(c.tip_height() + 1 - 100);
        let value = c.output(&cb).value;
        let tx = c.spend(
            &[cb],
            vec![TxOut { value: value - Amount::from_sat(1_000), script_pubkey: c.p2wpkh_script() }],
        );
        c.mine_block(vec![tx]);
    }
    c
}

fn lowest_block(node: &Node) -> u32 {
    node.hs.block_store.lowest_height().unwrap().expect("no blocks stored")
}

fn lowest_undo(node: &Node) -> Option<u32> {
    node.hs.utxo.lowest_undo_height().unwrap()
}

/// Neither store holds more than `w` allows below the validated tip.
fn assert_pruned(node: &Node, w: PruneWindow) {
    let validated = node.validated();
    let floor = validated.saturating_sub(w.keep + w.slack);
    assert!(lowest_block(node) >= floor, "blocks from {} kept at {}", lowest_block(node), validated);
    assert!(node.hs.block_store.count().unwrap() <= w.keep + w.slack + 1);
    if let Some(u) = lowest_undo(node) {
        assert!(u >= floor, "undo from {} kept at {}", u, validated);
    }
    // One spend per block in `spending_chain`.
    assert!(node.hs.utxo.test_count_undo().unwrap() <= (w.keep + w.slack + 1) as u64);
}

fn honest_pair(chain: &FixtureChain) -> (MockPeer, MockPeer) {
    (MockPeer::spawn(chain, vec![]), MockPeer::spawn(chain, vec![]))
}

// ── Pruning on every path ────────────────────────────────────────────

/// Background wakes prune: a node that synced in the foreground without
/// pruning (no height reached the old every-1000 trigger) and is then kept
/// current by `catch_up_blocks` works its backlog off a bounded step per
/// block, and from then on stays inside the window.
#[test]
fn catch_up_blocks_prunes_across_several_windows() {
    let chain = spending_chain(150);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(110));
    assert_eq!(lowest_block(&node), 1, "default window: nothing pruned yet");
    node.hs.prune_window = SMALL;
    let (a, b) = honest_pair(&chain);
    node.use_peers(&[&a, &b]);

    let mut caught_up_with_backlog = false;
    while node.validated() < chain.tip_height() {
        let before = lowest_block(&node);
        let status = node.hs.catch_up_blocks(5, 30).unwrap();
        assert!(status.error.is_none(), "{:?}", status);
        assert!(status.blocks_validated > 0, "{:?}", status);
        // Bounded work per call: at most one step per connected block.
        let after = lowest_block(&node);
        assert!(after <= before + SMALL.step * status.blocks_validated, "{} -> {}", before, after);
        if caught_up_with_backlog {
            assert_pruned(&node, SMALL);
        } else {
            caught_up_with_backlog = after >= node.validated() - SMALL.keep - SMALL.slack;
        }
    }
    assert!(caught_up_with_backlog, "backlog never worked off");
    assert_pruned(&node, SMALL);
    assert!(node.hs.utxo.undo_pruned_below().unwrap() > 110);
    node.assert_utxos_match(&chain);
}

/// The same for push wakes: every `validate_latest_block` that connects
/// a block prunes.
#[test]
fn validate_latest_block_prunes_in_every_wake() {
    let chain = spending_chain(125);
    let mut node = Node::new(&[]);
    node.hs.prune_window = SMALL;
    presync(&mut node, &chain.prefix(110));
    assert_pruned(&node, SMALL);
    for h in 111..=chain.tip_height() {
        let peer = MockPeer::spawn(&chain.prefix(h), vec![]);
        node.use_peers(&[&peer]);
        let n = node.hs.validate_latest_block(25).unwrap();
        assert!(n.validated, "block {}: {:?}", h, n.validation_error);
        assert_pruned(&node, SMALL);
    }
    assert!(lowest_block(&node) > 110 - SMALL.keep, "wakes never pruned");
    node.assert_utxos_match(&chain);
}

/// A prune lock (035's wallet scanner) holds stored blocks back at its
/// height, but never further than `lock_max_hold` below the tip, and
/// leaves undo pruning alone.
#[test]
fn prune_floor_holds_blocks_back_within_its_bound() {
    let chain = spending_chain(140);
    let mut node = Node::new(&[]);
    node.hs.prune_window = SMALL;
    presync(&mut node, &chain.prefix(100));
    node.hs.set_prune_floor(Some(115));
    let (a, b) = honest_pair(&chain.prefix(130));
    node.use_peers(&[&a, &b]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain.prefix(130)));
    assert!(ok, "{:?}", res);
    assert!(lowest_block(&node) <= 115, "lock not honoured: blocks from {}", lowest_block(&node));
    assert!(node.hs.block_store.has_block(&chain.hash_at(115)).unwrap());
    assert!(lowest_undo(&node).unwrap() >= 130 - SMALL.keep - SMALL.slack, "lock held undo back");

    // A wallet stuck at 105 can't hold more than 20 blocks below the tip.
    // (The old mocks go first: they'd otherwise be preferred while they
    // stop advancing, the ignored adversarial_sync BUG.)
    drop((a, b));
    node.hs.set_prune_floor(Some(105));
    let (a, b) = honest_pair(&chain);
    node.use_peers(&[&a, &b]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "{:?}", res);
    let bound = 140 - SMALL.lock_max_hold;
    assert!(lowest_block(&node) >= bound - SMALL.slack, "blocks from {}", lowest_block(&node));
    assert!(node.hs.block_store.has_block(&chain.hash_at(bound)).unwrap());

    // Released: the held blocks are worked off a step per connect.
    drop((a, b));
    node.hs.set_prune_floor(None);
    let more = {
        let mut c = chain.clone();
        c.mine(10);
        c
    };
    let (a, b) = honest_pair(&more);
    node.use_peers(&[&a, &b]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&more));
    assert!(ok, "{:?}", res);
    assert_pruned(&node, SMALL);
}

/// `MAX_REORG_DEPTH` stays exact with pruning running at the real window:
/// right after a prune (undo kept from exactly `tip - 288`), a fork one
/// deeper is refused by the header rules and a fork exactly 288 deep is
/// followed, undo data and all.
#[test]
fn max_depth_reorg_right_after_a_prune_is_followed() {
    // Undo starts at 101, so the first undo prune is at 101 + 288 + 144 + 1.
    const TIP: u32 = 534;
    let a = spending_chain(TIP);
    let mut node = Node::new(&[]);
    presync(&mut node, &a);
    assert_eq!(node.hs.utxo.undo_pruned_below().unwrap(), TIP - MAX_REORG_DEPTH, "pruned at the tip");

    let mut too_deep = a.fork_at(TIP - MAX_REORG_DEPTH - 1);
    too_deep.mine(MAX_REORG_DEPTH + 10);
    let (p1, p2) = honest_pair(&too_deep);
    node.use_peers(&[&p1, &p2]);
    let (switched, _) = node.sync_window(Duration::from_secs(5), |hs| {
        hs.store.tip().ok().flatten().map(|t| t.1) != Some(a.tip_hash())
    });
    assert!(!switched, "followed a reorg deeper than MAX_REORG_DEPTH");
    assert_eq!(node.validated(), TIP);
    node.assert_utxos_match(&a);
    drop((p1, p2));

    let mut b = a.fork_at(TIP - MAX_REORG_DEPTH);
    b.mine(MAX_REORG_DEPTH + 1);
    let (p1, p2) = honest_pair(&b);
    node.use_peers(&[&p1, &p2]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&b));
    assert!(ok, "did not follow a {}-deep reorg: {:?}, tip {:?}", MAX_REORG_DEPTH, res, node.tip());
    node.assert_utxos_match(&b);
    for p in [&p1, &p2] {
        assert!(!node.is_banned(&p.addr()));
    }
}

/// A reorg the header rules allow but whose fork point is below the undo
/// horizon (here because the test window is smaller than
/// `MAX_REORG_DEPTH`) is refused as a local fault before anything is
/// rolled back: no block failed, nobody banned, the set untouched.
#[test]
fn reorg_below_the_undo_horizon_is_refused_cleanly() {
    let a = spending_chain(130);
    let mut node = Node::new(&[]);
    node.hs.prune_window = SMALL;
    presync(&mut node, &a);
    let horizon = node.hs.utxo.undo_pruned_below().unwrap();
    assert!(horizon > 110, "{}", horizon);
    let mut b = a.fork_at(110);
    b.mine(25);
    let (p1, p2) = honest_pair(&b);
    node.use_peers(&[&p1, &p2]);

    let res = node.sync_for(Duration::from_secs(10));
    let err = format!("{:?}", res.expect_err("sync must stop on a local fault"));
    assert!(err.contains("undo data below"), "{}", err);
    assert_eq!(node.validated(), 130);
    assert_eq!(node.tip(), (130, a.tip_hash()), "headers replaced");
    node.assert_utxos_match(&a);
    assert!(node.hs.store.failed_hashes().unwrap().is_empty());
    for p in [&p1, &p2] {
        assert!(!node.is_banned(&p.addr()));
    }
}

/// A pre-050 `blocks.sqlite3` (auto_vacuum NONE) is migrated only by a
/// processing-length wake, never a push-length one.
#[test]
fn block_store_vacuum_migration_waits_for_a_processing_wake() {
    let mut chain = FixtureChain::new();
    chain.mine(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(10));
    let (a, b) = honest_pair(&chain);
    let mut node = node.restart_after(&[&a, &b], |dir| {
        let conn = rusqlite::Connection::open(dir.join("blocks.sqlite3")).unwrap();
        conn.execute_batch("PRAGMA auto_vacuum = NONE; VACUUM;").unwrap();
    });
    node.use_peers(&[&a, &b]);
    assert!(node.hs.block_store.needs_auto_vacuum_migration().unwrap());

    let status = node.hs.catch_up_blocks(2, 25).unwrap();
    assert_eq!(status.blocks_validated, 2, "{:?}", status);
    assert!(node.hs.block_store.needs_auto_vacuum_migration().unwrap(), "migrated in a push wake");

    let status = node.hs.catch_up_blocks(2, 120).unwrap();
    assert_eq!(status.blocks_validated, 2, "{:?}", status);
    assert!(!node.hs.block_store.needs_auto_vacuum_migration().unwrap(), "not migrated");
    for h in 1..=14 {
        assert!(node.hs.block_store.has_block(&chain.hash_at(h)).unwrap(), "block {} lost", h);
    }
}

// ── Kill points on every path ────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Path {
    Sync,
    Wake,
    CatchUp,
}

/// Kill `path` right after `step` while it connects block 101 (which
/// confirms one of our own transactions), restart, and check the block is
/// finished exactly once: applied, stored, its hook run (the own tx
/// confirmed) and `validated_height` advanced. A push wake only validates
/// a new tip, so a wake killed mid-connect is finished by the next
/// catch-up, as the app's next wake would.
fn killed_connect_is_finished(path: Path, step: ConnectStep) {
    let chain = spending_chain(101);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(100));
    let own = chain.block(101).txdata[1].clone();
    node.hs.submit_own_tx(&serialize(&own)).unwrap();
    let peer = MockPeer::spawn(&chain, vec![]);
    node.use_peers(&[&peer]);

    *node.hs.connect_kill.lock().unwrap() = Some(step);
    let killed = match path {
        Path::Sync => format!("{:?}", node.sync_for(Duration::from_secs(20))),
        Path::Wake => {
            let n = node.hs.validate_latest_block(25).unwrap();
            assert!(!n.validated);
            format!("{:?}", n.validation_error)
        }
        Path::CatchUp => format!("{:?}", node.hs.catch_up_blocks(10, 30)),
    };
    assert!(killed.contains("test kill"), "{:?} {:?}: {}", path, step, killed);
    assert_eq!(node.validated(), 100);
    assert_eq!(
        node.hs.utxo.best_block().unwrap(),
        Some((101, chain.hash_at(101).to_byte_array())),
        "block not applied before the kill"
    );

    let node = node.restart(&[&peer]);
    match path {
        Path::Sync => {
            let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
            assert!(ok, "{:?} {:?}: {:?}", path, step, res);
        }
        Path::Wake | Path::CatchUp => {
            let status = node.hs.catch_up_blocks(10, 30).unwrap();
            assert!(status.caught_up, "{:?} {:?}: {:?}", path, step, status);
        }
    }
    assert_eq!(node.validated(), 101);
    node.assert_utxos_match(&chain);
    assert!(node.hs.block_store.has_block(&chain.hash_at(101)).unwrap(), "block not stored");
    let rec = node.hs.own_tx_status(&own.compute_txid()).unwrap().unwrap();
    assert_eq!(rec.status, OwnTxStatus::Confirmed { height: 101 }, "hook not run");
    assert!(node.hs.store.failed_hashes().unwrap().is_empty());
}

#[test]
fn sync_killed_after_apply_is_finished() {
    killed_connect_is_finished(Path::Sync, ConnectStep::Applied);
}

#[test]
fn sync_killed_after_store_is_finished() {
    killed_connect_is_finished(Path::Sync, ConnectStep::Stored);
}

#[test]
fn sync_killed_after_hook_is_finished() {
    killed_connect_is_finished(Path::Sync, ConnectStep::Hooked);
}

#[test]
fn wake_killed_after_apply_is_finished() {
    killed_connect_is_finished(Path::Wake, ConnectStep::Applied);
}

#[test]
fn wake_killed_after_store_is_finished() {
    killed_connect_is_finished(Path::Wake, ConnectStep::Stored);
}

#[test]
fn wake_killed_after_hook_is_finished() {
    killed_connect_is_finished(Path::Wake, ConnectStep::Hooked);
}

#[test]
fn catch_up_killed_after_apply_is_finished() {
    killed_connect_is_finished(Path::CatchUp, ConnectStep::Applied);
}

#[test]
fn catch_up_killed_after_store_is_finished() {
    killed_connect_is_finished(Path::CatchUp, ConnectStep::Stored);
}

#[test]
fn catch_up_killed_after_hook_is_finished() {
    killed_connect_is_finished(Path::CatchUp, ConnectStep::Hooked);
}

// ── Interrupted reset and snapshot activation ────────────────────────

/// Remove the header database (and its WAL sidecars), as a reset killed
/// after its first unlink used to leave things.
fn remove_headers(dir: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("headers.sqlite3{}", suffix)));
    }
}

/// A node that imported a snapshot at `anchor` and synced `chain` past
/// it with `SMALL` pruning, so its undo data is pruned above the floor.
fn snapshot_node_synced_past_floor(chain: &FixtureChain, anchor: u32) -> (Node, MockPeer, MockPeer) {
    let mut donor = Node::new(&[]);
    presync(&mut donor, &chain.prefix(anchor));
    let mut buf = Vec::new();
    let block_hash = chain.hash_at(anchor).to_byte_array();
    let meta = donor.hs.utxo.write_snapshot(&mut buf, anchor, &block_hash).unwrap();

    let (a, b) = honest_pair(chain);
    let mut node = Node::new(&[&a, &b]);
    node.hs.prune_window = SMALL;
    let path = node.dir.path().join("snapshot.hutx");
    std::fs::write(&path, &buf).unwrap();
    node.hs.anchor = SnapshotAnchor {
        height: anchor,
        block_hash,
        utxo_hash: meta.utxo_hash,
        utxo_count: meta.utxo_count,
    };
    node.hs.load_snapshot(path.to_str().unwrap(), |_, _| true).unwrap();
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(chain));
    assert!(ok, "{:?}", res);
    assert!(node.hs.utxo.undo_pruned_below().unwrap() > anchor + 1, "undo not pruned past the floor");
    (node, a, b)
}

/// The ticket's interrupted reset, where the network no longer follows
/// the set's chain: the header database is gone, and the snapshot-loaded
/// UTXO env survived, validated past its floor (undo pruned) on a chain
/// that forks from what our peers now serve above the floor. Activation
/// must not roll that set back to the floor (deleting outputs and
/// restoring nothing, then condemning the honest block above the floor):
/// it wipes the set and asks for a re-import.
#[test]
fn interrupted_reset_with_snapshot_set_off_our_chain_is_wiped() {
    let chain = spending_chain(140);
    let (node, a, b) = snapshot_node_synced_past_floor(&chain, 110);
    drop((a, b));
    let mut other = chain.fork_at(120);
    other.mine(30);
    let (c, d) = honest_pair(&other);
    let mut node = node.restart_after(&[&c, &d], remove_headers);
    node.hs.prune_window = SMALL;
    assert_eq!(node.validated(), 0);
    assert!(!node.hs.needs_snapshot().unwrap(), "set still there before activation");

    let res = node.sync_for(Duration::from_secs(20));
    let err = format!("{:?}", res.expect_err("activation must refuse the set"));
    assert!(err.contains("import the snapshot again"), "{}", err);
    assert!(node.hs.needs_snapshot().unwrap());
    assert_eq!(node.hs.utxo.count().unwrap(), 0);
    assert_eq!(node.hs.utxo.assume_valid_floor().unwrap(), 0);
    assert!(!node.hs.utxo.load_in_progress(), "wipe left its marker");
    assert!(node.hs.store.failed_hashes().unwrap().is_empty(), "honest block condemned");
    for p in [&c, &d] {
        assert!(!node.is_banned(&p.addr()));
    }
}

/// The same lost headers with the set on the chain our peers serve (an
/// interrupted reset, or a power loss that dropped the header store's
/// commits): once headers reach the set's block it is kept and activated
/// at its own height, with nothing re-downloaded.
#[test]
fn snapshot_set_ahead_on_our_chain_is_kept_when_headers_are_lost() {
    let chain = spending_chain(140);
    let (node, a, b) = snapshot_node_synced_past_floor(&chain, 110);
    drop((a, b));
    let (c, d) = honest_pair(&chain);
    let mut node = node.restart_after(&[&c, &d], remove_headers);
    node.hs.prune_window = SMALL;
    assert_eq!(node.validated(), 0);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "{:?}, validated {}", res, node.validated());
    node.assert_utxos_match(&chain);
    assert_eq!(node.hs.utxo.assume_valid_floor().unwrap(), 110, "set was replaced");
    for p in [&c, &d] {
        assert!(p.block_requests().is_empty(), "re-downloaded blocks: {:?}", p.block_requests());
    }
}

/// The same reset in genesis mode: the set is far above `validated_height`
/// at open, its block isn't in our (now empty) header chain and its undo
/// is pruned, so it is wiped there, and the node re-syncs from genesis.
#[test]
fn interrupted_reset_with_genesis_set_is_wiped_and_resynced() {
    let chain = spending_chain(130);
    let mut node = Node::new(&[]);
    node.hs.prune_window = SMALL;
    presync(&mut node, &chain);
    assert!(node.hs.utxo.undo_pruned_below().unwrap() > 0);
    let (a, b) = honest_pair(&chain);
    let mut node = node.restart_after(&[&a, &b], remove_headers);
    node.hs.prune_window = SMALL;
    assert!(node.hs.needs_snapshot().unwrap(), "set not wiped at open");
    assert_eq!(node.hs.utxo.count().unwrap(), 0);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "{:?}", res);
    node.assert_utxos_match(&chain);
    assert!(node.hs.store.failed_hashes().unwrap().is_empty());
}

/// Apply `blocks` (heights from `from`) to the UTXO set without advancing
/// `validated_height`: what survives a power loss that drops the header
/// store's commits but keeps LMDB's.
fn apply_only(node: &Node, chain: &FixtureChain, from: u32, to: u32) {
    for h in from..=to {
        node.hs.utxo.apply_block(chain.block(h), h).unwrap();
    }
}

/// Review (PR #32): a set several blocks above `validated_height` on our
/// own header chain is the truth, not a foreign set: `validated_height` is
/// raised to it at open, nothing is wiped, and sync carries on from there.
#[test]
fn set_ahead_on_our_chain_raises_validated_height_at_open() {
    let chain = spending_chain(120);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(110));
    let headers: Vec<Header> = (111..=115).map(|h| chain.block(h).header).collect();
    node.hs.store.store_headers(&headers, 111).unwrap();
    apply_only(&node, &chain, 111, 115);
    let (a, b) = honest_pair(&chain);
    let node = node.restart(&[&a, &b]);
    assert_eq!(node.validated(), 115, "validated_height not repaired");
    assert_eq!(node.hs.utxo.best_block().unwrap(), Some((115, chain.hash_at(115).to_byte_array())));

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "{:?}", res);
    node.assert_utxos_match(&chain);
    for p in [&a, &b] {
        for hash in p.block_requests() {
            let h = node.hs.store.find_height_of_hash(hash).unwrap().unwrap();
            assert!(h > 115, "re-fetched block {}", h);
        }
    }
}

/// A set several blocks ahead on a chain that isn't ours, with its undo
/// still there, is not wiped at open: the next connect rolls it back to
/// our chain and sync continues.
#[test]
fn set_ahead_on_another_chain_is_rolled_back_not_wiped() {
    let chain = spending_chain(120);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(110));
    let mut other = chain.prefix(110).fork_at(110);
    other.mine(5);
    apply_only(&node, &other, 111, 115);
    let count = node.hs.utxo.count().unwrap();
    let (a, b) = honest_pair(&chain);
    let node = node.restart(&[&a, &b]);
    assert_eq!(node.validated(), 110);
    assert_eq!(node.hs.utxo.count().unwrap(), count, "set wiped");
    assert_eq!(node.hs.utxo.best_block().unwrap().map(|b| b.0), Some(115));

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, synced_to(&chain));
    assert!(ok, "{:?}", res);
    node.assert_utxos_match(&chain);
    assert!(node.hs.store.failed_hashes().unwrap().is_empty());
}

/// A node holding a snapshot of `chain` at `anchor`, pending (no headers).
fn pending_snapshot_node(chain: &FixtureChain, anchor: u32) -> Node {
    let mut donor = Node::new(&[]);
    presync(&mut donor, &chain.prefix(anchor));
    let mut buf = Vec::new();
    let block_hash = chain.hash_at(anchor).to_byte_array();
    let meta = donor.hs.utxo.write_snapshot(&mut buf, anchor, &block_hash).unwrap();

    let mut node = Node::new(&[]);
    let path = node.dir.path().join("snapshot.hutx");
    std::fs::write(&path, &buf).unwrap();
    node.hs.anchor = SnapshotAnchor {
        height: anchor,
        block_hash,
        utxo_hash: meta.utxo_hash,
        utxo_count: meta.utxo_count,
    };
    node.hs.load_snapshot(path.to_str().unwrap(), |_, _| true).unwrap();
    assert!(!node.hs.activate_pending_snapshot().unwrap(), "pending without headers");
    node
}

fn store_chain_headers(node: &Node, chain: &FixtureChain) {
    let headers: Vec<Header> = (1..=chain.tip_height()).map(|h| chain.block(h).header).collect();
    node.hs.store.store_headers(&headers, 1).unwrap();
}

/// Activation of a pending snapshot whose set has moved off the floor:
/// it waits until headers reach the set's block, then activates at that
/// block when it is on our chain, activates at the floor (for the next
/// connect to roll it back) when it isn't but its undo reaches the floor,
/// and wipes it only when neither is possible.
#[test]
fn activation_of_a_set_off_the_floor_repairs_rolls_back_or_wipes() {
    const ANCHOR: u32 = 110;
    let chain = spending_chain(120);
    let mut other = chain.prefix(ANCHOR).fork_at(ANCHOR);
    other.mine(2);

    // On our chain.
    let node = pending_snapshot_node(&chain, ANCHOR);
    apply_only(&node, &chain, ANCHOR + 1, ANCHOR + 3);
    assert!(!node.hs.activate_pending_snapshot().unwrap(), "decided before headers reached the set");
    assert_eq!(node.hs.utxo.best_block().unwrap().map(|b| b.0), Some(ANCHOR + 3));
    store_chain_headers(&node, &chain);
    assert!(node.hs.activate_pending_snapshot().unwrap());
    assert_eq!(node.validated(), ANCHOR + 3);

    // Another chain, undo intact: activated at the floor, then rolled back.
    let mut node = pending_snapshot_node(&chain, ANCHOR);
    apply_only(&node, &other, ANCHOR + 1, ANCHOR + 2);
    store_chain_headers(&node, &chain);
    assert!(node.hs.activate_pending_snapshot().unwrap());
    assert_eq!(node.validated(), ANCHOR);
    let (a, b) = honest_pair(&chain);
    node.use_peers(&[&a, &b]);
    let status = node.hs.catch_up_blocks(20, 30).unwrap();
    assert!(status.caught_up, "{:?}", status);
    node.assert_utxos_match(&chain);

    // Another chain, undo pruned past the floor: wiped.
    let node = pending_snapshot_node(&chain, ANCHOR);
    apply_only(&node, &other, ANCHOR + 1, ANCHOR + 2);
    node.hs.utxo.prune_undo_below(ANCHOR + 2).unwrap();
    store_chain_headers(&node, &chain);
    let err = node.hs.activate_pending_snapshot().unwrap_err();
    assert!(format!("{}", err).contains("import the snapshot again"), "{}", err);
    assert_eq!(node.hs.utxo.count().unwrap(), 0);
    assert_eq!(node.validated(), 0);
    assert!(node.hs.needs_snapshot().unwrap());
}

/// A partial set behind the `.loading` marker (a load that failed without
/// cleaning up) is not a set: `needs_snapshot` says so, nothing validates
/// against it, and the next open wipes it.
#[test]
fn partial_set_behind_the_loading_marker_is_never_used() {
    let chain = spending_chain(115);
    let mut node = Node::new(&[]);
    presync(&mut node, &chain.prefix(110));
    let marker = node.dir.path().join("utxo-lmdb.loading");
    std::fs::write(&marker, b"snapshot load in progress\n").unwrap();
    assert!(node.hs.needs_snapshot().unwrap());
    assert!(!node.hs.activate_pending_snapshot().unwrap());

    let (a, b) = honest_pair(&chain);
    node.use_peers(&[&a, &b]);
    let (validated, _) = node.sync_window(Duration::from_secs(5), |hs| {
        hs.store.validated_height().unwrap_or(0) > 110
    });
    assert!(!validated, "validated blocks against a partial set");
    let catch_up = node.hs.catch_up_blocks(5, 10).unwrap();
    assert_eq!(catch_up.blocks_validated, 0, "{:?}", catch_up);

    let node = node.restart(&[&a, &b]);
    assert!(!marker.exists());
    assert_eq!(node.hs.utxo.count().unwrap(), 0);
    assert!(node.hs.needs_snapshot().unwrap());
}
