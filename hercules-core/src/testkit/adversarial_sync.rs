//! Adversarial peers against the real sync paths (tests/network-app):
//! peers that trickle, stop reading, inflate their height, dribble
//! headers or spam announcements, plus reorg-depth and first-seen
//! boundaries and the snapshot / clock / privacy edges reviewers raised.
//!
//! Mounted as `sync::adversarial_tests`, beside `integration_tests`, whose
//! harness (`Node`, `presync`, `sync_until`) it reuses. Liveness tests that
//! may hang run `HeaderSync` on a detached thread, so a confirmed bug fails
//! the test rather than hanging the run.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, TxOut};
use tempfile::TempDir;

use super::integration_tests::{presync, static_peers, Node, SYNC_TIMEOUT};
use super::*;
use crate::peer_store::PeerStore;
use crate::testkit::{lmdb_slot, Behavior, FixtureChain, MockPeer};

const FRESH_SCORE: i32 = 100;

/// `HeaderSync` shared with a detached thread (for tests where the thread
/// may never return), in its own temp dir, pointed at `peers`.
struct Detached {
    hs: Arc<HeaderSync>,
    _dir: TempDir,
}

fn detached(peers: &[&MockPeer], chain: &FixtureChain) -> Detached {
    // Presync with the harness, then reopen the same files as an Arc.
    let mut node = Node::new(&[]);
    presync(&mut node, chain);
    let Node { hs, dir, .. } = node;
    drop(hs);
    let hs = HeaderSync::with_config(SyncConfig {
        db_path: dir.path().join("headers.sqlite3").to_str().unwrap().to_string(),
        tor: None,
        params: ChainParams::regtest(),
        peers: static_peers(peers),
    })
    .unwrap();
    Detached { hs: Arc::new(hs), _dir: dir }
}

/// Start `sync()` on a detached thread; returns a "finished" probe.
fn spawn_sync(hs: &Arc<HeaderSync>) -> std::thread::JoinHandle<Result<(), SyncError>> {
    let hs = Arc::clone(hs);
    std::thread::spawn(move || hs.sync(|_| {}))
}

/// Ask `sync()` to stop and wait up to `limit` for it to return.
fn stop_within(hs: &HeaderSync, handle: &std::thread::JoinHandle<Result<(), SyncError>>, limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    while start.elapsed() < limit {
        hs.stop_sync();
        if handle.is_finished() {
            return Some(start.elapsed());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn chain(n: u32) -> FixtureChain {
    let mut c = FixtureChain::new();
    c.mine(n);
    c
}

// ── Peers that hold the sync thread ─────────────────────────────────

/// Reviewer finding: the main sync loop's `get_headers` has no overall
/// deadline, only the per-read timeout. A peer that claims a taller chain
/// (so it is picked to sync from) and answers with a 4 MB frame header and
/// then one byte at a time, each inside the timeout, holds the sync thread
/// indefinitely; `stop_sync` is never even checked.
#[test]
#[ignore = "BUG: main-loop get_headers has no overall deadline; a trickling peer holds the sync thread and stop_sync"]
fn trickling_header_reply_cannot_hold_the_sync_loop_past_stop() {
    let c = chain(20);
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    let staller = MockPeer::spawn(
        &c,
        vec![Behavior::InflatedHeight(5_000), Behavior::EndlessHeadersTrickle(Duration::from_millis(500))],
    );
    let node = detached(&[&staller, &a, &b], &c);
    let handle = spawn_sync(&node.hs);
    // Let it pick the staller and get stuck on its reply.
    let start = Instant::now();
    while !staller.log().iter().any(|m| matches!(m, NetworkMessage::GetHeaders(_))) {
        assert!(start.elapsed() < SYNC_TIMEOUT, "staller never asked for headers");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_secs(1));
    let stopped = stop_within(&node.hs, &handle, Duration::from_secs(10));
    assert!(stopped.is_some(), "sync still blocked on a trickling peer 10 s after stop_sync");
}

/// Reviewer finding: `handle_getdata` serves up to 50,000 items in one go
/// and sockets have no write timeout, so a peer that requests our tip
/// block 50,000 times and never reads blocks the monitor loop in `send`:
/// stop is never honored (and a wake can't get the session).
#[test]
#[ignore = "BUG: no write timeout and no getdata batching; a non-reading peer blocks the monitor loop and stop_sync"]
fn non_reading_peer_cannot_hold_the_sync_loop_past_stop() {
    let c = chain(30);
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    // Claims a low tip, so it is never the header peer (which would time
    // it out before the monitor loop serves its getdata).
    let flooder = MockPeer::spawn(
        &c,
        vec![Behavior::InflatedHeight(1), Behavior::FloodGetDataNeverRead { height: 30, count: 50_000 }],
    );
    let node = detached(&[&a, &b, &flooder], &c);
    let handle = spawn_sync(&node.hs);
    // Monitor mode services the flooder's getdata within a few polls.
    std::thread::sleep(Duration::from_secs(3));
    let stopped = stop_within(&node.hs, &handle, Duration::from_secs(10));
    assert!(stopped.is_some(), "sync still blocked writing to a non-reading peer 10 s after stop_sync");
}

/// The wake path, unlike the main loop, bounds every exchange by the
/// budget: the same trickling peer costs a wake its budget, not more.
#[test]
fn wake_catch_up_is_bounded_by_its_budget_against_a_trickling_peer() {
    let c = chain(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(10));
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    let staller = MockPeer::spawn(
        &c,
        vec![Behavior::InflatedHeight(5_000), Behavior::EndlessHeadersTrickle(Duration::from_millis(300))],
    );
    node.use_peers(&[&staller, &a, &b]);

    let start = Instant::now();
    let budget = WakeBudget::new(3_000);
    let status = node.hs.catch_up_blocks_in(50, &budget);
    let took = start.elapsed();
    // Budget, plus at most one connect attempt in flight, with CI slack.
    assert!(took < Duration::from_secs(8), "wake overran its 3 s budget: {:?}", took);
    if let Ok(s) = status {
        assert!(!s.caught_up, "caught up without checking headers: {:?}", s);
    }
    assert!(!node.is_banned(&staller.addr()), "a slow peer is not proof of anything");
}

// ── Peers that lie about their height ───────────────────────────────

/// Reviewer finding: a wake asks the best (tallest-claiming) peer for
/// headers once. A peer that claims a huge height and answers with nothing
/// makes the wake validate only the local backlog and report caught up,
/// though honest peers have more blocks. (The main loop caps such a peer's
/// height and asks others; the wake path has no second round.)
#[test]
#[ignore = "BUG: wake reports caught_up when the tallest-claiming peer withholds headers (no second peer asked)"]
fn inflated_height_peer_withholding_headers_does_not_make_a_wake_report_caught_up() {
    let c = chain(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(10));
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    let liar = MockPeer::spawn(&c, vec![Behavior::InflatedHeight(100_000), Behavior::WithholdHeaders]);
    node.use_peers(&[&liar, &a, &b]);

    let status = node.hs.catch_up_blocks(50, 15).unwrap();
    assert!(
        !status.caught_up || status.current_height == 20,
        "reported caught up at {} while honest peers are at 20: {:?}",
        status.current_height,
        status
    );
}

/// Reviewer finding: the main loop asks the best peer again after a short
/// batch, so a peer that claims the tallest chain and answers each
/// `getheaders` with a single header sets the pace: one round trip (and a
/// cross-check) per header, ~900k over Tor on mainnet. Core stops a
/// header chain with a peer on its first non-full batch.
#[test]
#[ignore = "BUG: a tallest-claiming peer serving one header per batch dominates header sync (one round trip per header)"]
fn one_header_per_batch_peer_does_not_dominate_header_sync() {
    let c = chain(400);
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    let dripper = MockPeer::spawn(&c, vec![Behavior::InflatedHeight(450), Behavior::OneHeaderPerBatch]);
    let node = Node::new(&[&dripper, &a, &b]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.tip().ok().flatten().map(|t| t.0) == Some(400));
    assert!(ok, "headers never synced: {:?}", res);
    let rounds = dripper.log().iter().filter(|m| matches!(m, NetworkMessage::GetHeaders(_))).count();
    assert!(rounds < 50, "{} getheaders rounds spent on a one-header-per-batch peer for 400 headers", rounds);
}

#[test]
fn inflated_height_peer_is_capped_and_sync_still_completes() {
    // The main loop's answer to the same liar: cap its claimed height at
    // our tip, take a small penalty, ask the others.
    let c = chain(25);
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    let liar = MockPeer::spawn(&c, vec![Behavior::InflatedHeight(1_000), Behavior::WithholdHeaders]);
    let node = Node::new(&[&liar, &a, &b]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.validated_height().unwrap_or(0) == 25);
    assert!(ok, "liar stalled sync: {:?}, tip {:?}", res, node.tip());
    // Claimed 1,000 with nothing past 25: within 2016 of our tip, so a
    // small penalty, never a ban.
    assert!(!node.is_banned(&liar.addr()));
}

#[test]
fn absurd_height_claim_with_no_headers_is_banned() {
    // More than 2016 blocks above our tip and nothing to show for it: no
    // honest peer looks like that.
    let c = chain(10);
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    let liar = MockPeer::spawn(&c, vec![Behavior::InflatedHeight(900_000), Behavior::WithholdHeaders]);
    let node = Node::new(&[&liar, &a, &b]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.validated_height().unwrap_or(0) == 10);
    assert!(ok, "{:?}", res);
    assert!(node.is_banned(&liar.addr()), "a 900k-block claim with no headers went unpunished");
}

#[test]
fn trickled_but_complete_replies_are_slow_not_misbehavior() {
    // Every reply arrives a byte per 2 ms (a ~1 kB block takes ~2 s), well
    // inside the per-read timeout: slow, but honest. Sync completes, and
    // the peer is not penalized.
    let c = chain(6);
    let slow = MockPeer::spawn(&c, vec![Behavior::TrickleResponses(Duration::from_millis(2))]);
    let fast = MockPeer::spawn(&c, vec![]);
    let node = Node::new(&[&slow, &fast]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.validated_height().unwrap_or(0) == 6);
    assert!(ok, "{:?}", res);
    assert!(!node.is_banned(&slow.addr()));
    assert!(node.score(&slow.addr()).map_or(true, |s| s >= FRESH_SCORE), "slow peer penalized");
}

// ── Our own faults are not the peer's ───────────────────────────────

/// Ticket 024's rule (honest peers are never punished for our local
/// faults) applied to the clock: a header more than 2 h past *our* clock
/// is refused, but a phone whose clock runs slow sees every honest peer's
/// new tip that way. Core doesn't punish time-too-new headers (they may
/// become valid); here each batch costs the sender INVALID_HEADERS_PENALTY,
/// so two such batches ban an honest peer.
#[test]
#[ignore = "BUG: a header >2 h ahead of our clock costs its (honest) sender 50 points; a slow phone clock bans every peer"]
fn header_from_our_future_does_not_cost_the_peer() {
    let mut c = chain(20);
    let ahead = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3 * 3600) as u32;
    c.mine_custom(vec![], |b| b.header.time = ahead);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(20));
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    node.use_peers(&[&a, &b]);

    let _ = node.sync_for(Duration::from_secs(5));
    assert_eq!(node.tip().0, 20, "a header 3 h in the future was stored");
    for p in [&a, &b] {
        assert!(!node.is_banned(&p.addr()), "{} banned over our clock", p.addr());
        let score = node.score(&p.addr());
        assert!(score.map_or(true, |s| s >= FRESH_SCORE), "{} penalized over our clock: {:?}", p.addr(), score);
    }
}

// ── Reorg depth and first-seen ──────────────────────────────────────

/// `MAX_REORG_DEPTH` is exact (see its doc): a more-work fork exactly 288
/// blocks deep is followed, undo data and all.
#[test]
fn reorg_exactly_max_depth_deep_is_followed() {
    let a = chain(300);
    let fork_at = a.tip_height() - MAX_REORG_DEPTH;
    let mut b = a.fork_at(fork_at);
    b.mine(MAX_REORG_DEPTH + 1);
    let mut node = Node::new(&[]);
    presync(&mut node, &a);
    let p1 = MockPeer::spawn(&b, vec![]);
    let p2 = MockPeer::spawn(&b, vec![]);
    node.use_peers(&[&p1, &p2]);

    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| {
        hs.store.tip().ok().flatten().map(|t| t.1) == Some(b.tip_hash())
            && hs.store.validated_height().unwrap_or(0) == b.tip_height()
    });
    assert!(ok, "did not follow a {}-deep reorg: {:?}, tip {:?}", MAX_REORG_DEPTH, res, node.tip());
    node.assert_utxos_match(&b);
    for p in [&p1, &p2] {
        assert!(!node.is_banned(&p.addr()));
    }
}

/// One block deeper than `MAX_REORG_DEPTH` is refused once we have
/// minimum work (regtest: always), however much work the fork has.
#[test]
fn reorg_one_past_max_depth_is_refused() {
    let a = chain(300);
    let fork_at = a.tip_height() - MAX_REORG_DEPTH - 1;
    let mut b = a.fork_at(fork_at);
    b.mine(MAX_REORG_DEPTH + 10);
    let mut node = Node::new(&[]);
    presync(&mut node, &a);
    let p1 = MockPeer::spawn(&b, vec![]);
    let p2 = MockPeer::spawn(&b, vec![]);
    node.use_peers(&[&p1, &p2]);

    let (switched, _) = node.sync_window(Duration::from_secs(5), |hs| {
        hs.store.tip().ok().flatten().map(|t| t.1) != Some(a.tip_hash())
    });
    assert!(!switched, "followed a reorg deeper than MAX_REORG_DEPTH");
    assert_eq!(node.validated(), a.tip_height());
    node.assert_utxos_match(&a);
}

/// First seen wins between equal-work tips: peers switching to a sibling
/// of our tip don't move us.
#[test]
fn equal_work_sibling_tip_is_not_followed() {
    let a = chain(12);
    let mut b = a.fork_at(11);
    b.mine(1);
    let mut node = Node::new(&[]);
    presync(&mut node, &a);
    let p1 = MockPeer::spawn(&b, vec![]);
    let p2 = MockPeer::spawn(&b, vec![]);
    node.use_peers(&[&p1, &p2]);
    let (switched, res) = node.sync_window(Duration::from_secs(4), |hs| {
        hs.store.tip().ok().flatten().map(|t| t.1) == Some(b.tip_hash())
    });
    assert!(!switched, "switched to an equal-work sibling: {:?}", res);
    assert_eq!(node.tip(), (12, a.tip_hash()));
    for p in [&p1, &p2] {
        assert!(!node.is_banned(&p.addr()), "peer banned for a competing tip");
    }
}

// ── Bans across restarts ────────────────────────────────────────────

#[test]
fn banned_peer_is_not_redialed_after_a_restart() {
    let mut c = chain(12);
    let mut taller = c.clone();
    taller.mine(3);
    let foreign = MockPeer::spawn(&taller, vec![Behavior::WrongMagic]);
    let honest = MockPeer::spawn(&c, vec![]);
    let node = Node::new(&[&foreign, &honest]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.validated_height().unwrap_or(0) == 12);
    assert!(ok, "{:?}", res);
    assert!(node.is_banned(&foreign.addr()));
    let dials = foreign.connections();

    // The old honest peer is gone (a well-scored peer that stopped
    // advancing would otherwise be preferred: see the next test).
    drop(honest);
    c.mine(2);
    let honest2 = MockPeer::spawn(&c, vec![]);
    let honest3 = MockPeer::spawn(&c, vec![]);
    let node = node.restart(&[&foreign, &honest2, &honest3]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.validated_height().unwrap_or(0) == 14);
    assert!(ok, "{:?}, tip {:?}", res, node.tip());
    assert_eq!(foreign.connections(), dials, "banned peer redialed after restart");
    assert!(node.is_banned(&foreign.addr()), "ban lost across restart");
}

/// Found while writing the test above: peer selection weights a peer's
/// claimed height by its reputation (`height × score / 100`), and nothing
/// raises a claim after the handshake. A peer that earned a score above
/// 100 and then stops advancing outweighs every fresh peer whose tip is
/// less than score/100 times taller (on mainnet: any honest tip a few
/// hundred blocks ahead). The node asks only it, gets no headers, decides
/// it is synced, and block announcements from the others just send it
/// back to the same peer: stuck behind until that peer disconnects.
#[test]
#[ignore = "BUG: a high-score peer that stops advancing hides taller honest peers; announcements re-ask the same peer"]
fn high_score_peer_that_stops_advancing_cannot_hide_the_chain() {
    let mut c = chain(12);
    let veteran = MockPeer::spawn(&c, vec![]);
    let witness = MockPeer::spawn(&c, vec![]);
    let node = Node::new(&[&veteran, &witness]);
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.validated_height().unwrap_or(0) == 12);
    assert!(ok, "{:?}", res);
    drop(witness);
    assert!(node.score(&veteran.addr()).unwrap_or(0) > FRESH_SCORE, "veteran earned no reputation");

    // The network moves on; the veteran doesn't.
    c.mine(2);
    let fresh1 = MockPeer::spawn(&c, vec![]);
    let fresh2 = MockPeer::spawn(&c, vec![]);
    let node = node.restart(&[&veteran, &fresh1, &fresh2]);
    let (ok, res) = node.run_sync(|hs| {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(20) {
            // Announce the new tip, as honest peers do for every block.
            fresh1.announce_tip();
            fresh2.announce_tip();
            if hs.store.validated_height().unwrap_or(0) == 14 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    });
    assert!(ok, "still at {:?} 20 s after taller peers announced 14: {:?}", node.tip(), res);
}

#[test]
fn expired_bans_are_dropped_and_the_peer_is_usable_again() {
    let c = chain(8);
    let peer = MockPeer::spawn(&c, vec![]);
    let witness = MockPeer::spawn(&c, vec![]);
    let node = Node::new(&[&peer, &witness]);
    // A ban that ran out while the app was closed.
    node.peer_store()
        .save_ban(&peer.addr(), Instant::now() + Duration::from_millis(1))
        .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let (ok, res) = node.sync_until(SYNC_TIMEOUT, |hs| hs.store.validated_height().unwrap_or(0) == 8);
    assert!(ok, "{:?}", res);
    assert!(peer.connections() >= 1, "expired ban still kept the peer out");
    assert!(!node.is_banned(&peer.addr()));
}

// ── Own transactions: starvation and privacy ────────────────────────

/// A node synced to a 110-block chain in Tor mode (own txs go out on
/// regular peers), and a spend of coinbase 1 paying a 10 kvB-ish fee.
fn own_tx_fixture() -> (Node, FixtureChain, bitcoin::Transaction) {
    let c = chain(110);
    let mut node = Node::new(&[]);
    presync(&mut node, &c);
    node.hs.regular_peers_over_tor = true;
    let value = c.block(1).txdata[0].output[0].value;
    let tx = c.spend(
        &[c.coinbase_outpoint(1)],
        vec![TxOut { value: value - Amount::from_sat(20_000), script_pubkey: c.p2wpkh_script() }],
    );
    (node, c, tx)
}

fn announced(peer: &MockPeer, txid: bitcoin::Txid) -> bool {
    peer.log().iter().any(|m| match m {
        NetworkMessage::Inv(items) => items.iter().any(|i| match i {
            Inventory::Transaction(t) | Inventory::WitnessTransaction(t) => *t == txid,
            _ => false,
        }),
        _ => false,
    })
}

/// Control for the spam test below: without spam the own tx is announced
/// on the next monitor-loop pass.
#[test]
fn own_tx_is_announced_to_outbound_peers_promptly() {
    let (mut node, c, tx) = own_tx_fixture();
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    node.use_peers(&[&a, &b]);
    let txid = tx.compute_txid();
    let ((), res) = node.run_sync(|hs| {
        std::thread::sleep(Duration::from_millis(500));
        hs.submit_own_tx(&serialize(&tx)).expect("own tx accepted");
        let start = Instant::now();
        while !(announced(&a, txid) || announced(&b, txid)) && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    assert!(res.is_ok(), "{:?}", res);
    assert!(announced(&a, txid) || announced(&b, txid), "own tx never announced");
}

/// Reviewer finding: every `inv` of an unknown block breaks the monitor
/// loop before `drain_relay_queue`, so a peer announcing a fresh fake block
/// every few tens of ms keeps the relay queue (own transactions included)
/// from ever draining.
#[test]
#[ignore = "BUG: block-inv spam breaks the monitor loop before drain_relay_queue, starving own-tx announcements"]
fn block_inv_spam_does_not_starve_own_tx_announcements() {
    let (mut node, c, tx) = own_tx_fixture();
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    let spammer = MockPeer::spawn(&c, vec![Behavior::SpamBlockInv(Duration::from_millis(20))]);
    node.use_peers(&[&a, &b, &spammer]);
    let txid = tx.compute_txid();
    let ((), res) = node.run_sync(|hs| {
        std::thread::sleep(Duration::from_millis(500));
        hs.submit_own_tx(&serialize(&tx)).expect("own tx accepted");
        let start = Instant::now();
        while !(announced(&a, txid) || announced(&b, txid)) && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    assert!(res.is_ok(), "{:?}", res);
    assert!(announced(&a, txid) || announced(&b, txid), "own tx starved by block-inv spam for 10 s");
}

/// Reviewer finding: in Tor mode our inbound peers reached us at our
/// stable .onion address, so an own tx announced to them first ties it to
/// that identity. `drain_relay_queue` announces own txs to every peer,
/// inbound included.
#[test]
#[ignore = "BUG: own txs are announced to inbound peers, who know our onion address (privacy leak in Tor mode)"]
fn own_tx_is_never_announced_to_inbound_peers() {
    use crate::p2p::tests::{decode_all, inbound, mem_peer, script_of, their_version};
    let (node, _c, tx) = own_tx_fixture();
    node.hs.submit_own_tx(&serialize(&tx)).expect("own tx accepted");
    let txid = tx.compute_txid();

    let pool = PeerPool::new_for_test_with(ChainParams::regtest());
    let (out_peer, out_written) = mem_peer(vec![], bitcoin::p2p::Magic::REGTEST);
    pool.add_outbound_peer_for_test(out_peer);
    let (in_peer, in_written) = inbound(script_of(vec![their_version(70016), NetworkMessage::Verack]));
    let in_peer = in_peer.unwrap();
    let in_before = in_written.lock().unwrap().len();
    assert!(pool.add_inbound_peer(in_peer));
    node.hs.drain_relay_queue(&pool);

    let has_inv = |bytes: &[u8]| {
        decode_all(bytes).iter().any(|m| matches!(m, NetworkMessage::Inv(i) if i.iter().any(|x| matches!(x, Inventory::Transaction(t) if *t == txid))))
    };
    assert!(has_inv(&out_written.lock().unwrap()), "control: outbound peer not told");
    assert!(!has_inv(&in_written.lock().unwrap()[in_before..]), "own tx announced to an inbound peer");
}

// ── Snapshot mode: the Rust contract the app relies on ──────────────

/// No snapshot loaded and headers past the anchor: Rust has no notion of
/// "AssumeUTXO chosen", so a catch-up validates from genesis and the node
/// stops reporting `needs_snapshot`. Pinned here because the app must gate
/// every wake on it (NotificationManager.nodeIsSetUp): a wake that skips
/// the gate turns an AssumeUTXO node into a genesis sync for good.
#[test]
fn catch_up_without_a_snapshot_validates_from_genesis_and_clears_needs_snapshot() {
    let c = chain(30);
    let mut node = Node::new(&[]);
    node.hs.anchor = SnapshotAnchor { height: 20, block_hash: c.hash_at(20).to_byte_array(), utxo_hash: [0; 32] };
    let headers: Vec<bitcoin::block::Header> = (1..=30).map(|h| c.block(h).header).collect();
    node.hs.store.store_headers(&headers, 1).unwrap();
    assert!(node.hs.needs_snapshot().unwrap());
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    node.use_peers(&[&a, &b]);

    let status = node.hs.catch_up_blocks(5, 15).unwrap();
    assert_eq!(status.blocks_validated, 5);
    assert_eq!(node.validated(), 5, "validated from genesis");
    assert!(!node.hs.needs_snapshot().unwrap(), "needs_snapshot still true after genesis validation");
}

/// Below the anchor (minimum work not met), the same catch-up validates
/// nothing.
#[test]
fn catch_up_below_minimum_work_validates_nothing() {
    let c = chain(30);
    let mut node = Node::new(&[]);
    node.hs.anchor = SnapshotAnchor { height: 40, block_hash: [9; 32], utxo_hash: [0; 32] };
    let headers: Vec<bitcoin::block::Header> = c.blocks().iter().map(|b| b.header).collect();
    let mut one = [0u8; 32];
    one[0] = 1;
    node.hs.min_chain_work = crate::validation::u256_add(crate::validation::chainwork_for_headers(&headers), one);
    let hs_headers: Vec<bitcoin::block::Header> = (1..=30).map(|h| c.block(h).header).collect();
    node.hs.store.store_headers(&hs_headers, 1).unwrap();
    let a = MockPeer::spawn(&c, vec![]);
    let b = MockPeer::spawn(&c, vec![]);
    node.use_peers(&[&a, &b]);

    let status = node.hs.catch_up_blocks(5, 15).unwrap();
    assert_eq!(status.blocks_validated, 0, "{:?}", status);
    assert!(!status.caught_up);
    assert_eq!(node.validated(), 0);
    assert!(a.block_requests().is_empty() && b.block_requests().is_empty());
}

// ── Ban persistence at the store level ──────────────────────────────

#[test]
fn bans_and_scores_survive_reopening_the_peer_store() {
    let _slot = lmdb_slot();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("peers.sqlite3");
    let path = path.to_str().unwrap();
    {
        let s = PeerStore::open(path).unwrap();
        s.save_ban("198.51.100.1:8333", Instant::now() + Duration::from_secs(3600)).unwrap();
        s.save_ban("198.51.100.2:8333", Instant::now() + Duration::from_millis(1)).unwrap();
        s.save_score("198.51.100.3:8333", 37).unwrap();
    }
    std::thread::sleep(Duration::from_millis(1100));
    let s = PeerStore::open(path).unwrap();
    let bans = s.load_active_bans().unwrap();
    assert!(bans.contains_key("198.51.100.1:8333"));
    assert!(!bans.contains_key("198.51.100.2:8333"), "expired ban loaded");
    assert_eq!(s.load_score("198.51.100.3:8333").unwrap(), Some(37));
}
