//! `HerculesNode` wake tests (ticket 028): one session at a time, deadline
//! from wake receipt, cancellation, and Tor-mode transport gating. Runs a
//! regtest node against the 027 mock peers.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::*;
use crate::chain_params::ChainParams;
use crate::peer_pool::PeerSource;
use crate::testkit::{lmdb_slot, Behavior, FixtureChain, LmdbSlot, MockPeer};

/// Fields drop in order: the node (and its stores) first, then the
/// directory, then the LMDB slot (`testkit::lmdb_gate`).
struct Node {
    node: HerculesNode,
    _dir: TempDir,
    _slot: LmdbSlot,
}

/// A clearnet regtest node pointed at `peers`. With `tor`, the node is in
/// Tor mode and uses that gate as its transport.
fn node_with(peers: &[&MockPeer], tor: Option<Arc<TorGate>>) -> Node {
    let slot = lmdb_slot();
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("headers.sqlite3").to_str().unwrap().to_string();
    let mut syncer = sync::HeaderSync::with_config(sync::SyncConfig {
        db_path: db_path.clone(),
        tor: None,
        params: ChainParams::regtest(),
        peers: PeerSource::Static(peers.iter().map(|p| p.addr()).collect()),
    })
    .unwrap();
    if tor.is_some() {
        syncer.require_tor();
    }
    let node = HerculesNode {
        syncer: Arc::new(syncer),
        tor,
        session: Mutex::new(()),
        sync_sessions: Mutex::new(Vec::new()),
        running_sync: Mutex::new(None),
        next_sync_id: AtomicU64::new(1),
        snapshot_loading: AtomicBool::new(false),
        closed: Arc::new(AtomicBool::new(false)),
        wakes: Mutex::new(Vec::new()),
        wallet_rpc: Mutex::new(None),
        wallet_auth_token: Mutex::new(None),
        data_dir: dir.path().to_str().unwrap().to_string(),
        claim: Arc::new(PathClaim::take(&db_path).unwrap()),
    };
    Node { node, _dir: dir, _slot: slot }
}

impl Node {
    fn validated(&self) -> u32 {
        self.node.syncer.rpc_validated_height().unwrap()
    }

    /// A sync loop holds the session.
    fn sync_running(&self) -> bool {
        lock(&self.node.running_sync).is_some()
    }

    fn sync_running_id(&self) -> Option<u64> {
        lock(&self.node.running_sync).as_ref().map(|s| s.id)
    }
}

/// Wait (up to 10 s) until `cond` holds.
fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(10), "timed out waiting for {}", what);
        thread::sleep(Duration::from_millis(10));
    }
}

struct NoProgress;
impl SyncCallback for NoProgress {
    fn on_progress(&self, _status: SyncStatus) {}
}

/// Mocks serving `chain`, two of them so the header cross-check passes.
fn honest_pair(chain: &FixtureChain) -> (MockPeer, MockPeer) {
    (MockPeer::spawn(chain, vec![]), MockPeer::spawn(chain, vec![]))
}

fn chain(n: u32) -> FixtureChain {
    let mut c = FixtureChain::new();
    c.mine(n);
    c
}

/// A Tor gate whose bootstrap never finishes within a test (it fails
/// after `after`).
fn stuck_gate(after: Duration) -> Arc<TorGate> {
    Arc::new(TorGate::new(move || {
        thread::sleep(after);
        Err("test: bootstrap never completes".into())
    }))
}

#[test]
fn wake_catch_up_validates_and_records_phases_in_order() {
    let c = chain(12);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);

    let budget = Arc::new(WakeBudget::new(20_000));
    let r = n.node.wake_catch_up(Arc::clone(&budget), 50, 1_000);
    assert_eq!(r.outcome, WakeOutcome::Completed, "{:?}", r);
    let s = r.status.expect("status");
    assert!(s.caught_up, "{:?}", s);
    assert_eq!(s.blocks_validated, 12);
    assert_eq!(n.validated(), 12);
    assert!(!r.preempted_sync);

    let t = r.timings;
    let order = [
        t.transport_ready_ms.expect("transport"),
        t.peers_ready_ms.expect("peers"),
        t.headers_checked_ms.expect("headers"),
        t.blocks_downloaded_ms.expect("download"),
        t.validated_ms.expect("validated"),
    ];
    assert!(order.windows(2).all(|w| w[0] <= w[1]), "{:?}", order);
    assert!(r.elapsed_ms >= order[4]);
}

#[test]
fn deadline_counts_time_spent_before_the_call() {
    // The wake arrived 9.5 s into a 10 s budget (e.g. a slow node open):
    // less than the 1 s floor is left, so nothing touches the network.
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    let budget = Arc::new(WakeBudget::starting_at(
        Instant::now() - Duration::from_millis(9_500),
        Duration::from_secs(10),
    ));
    let r = n.node.wake_catch_up(budget, 50, 1_000);
    assert_eq!(r.outcome, WakeOutcome::TransportSlow, "{:?}", r);
    assert!(r.status.is_none());
    assert_eq!(a.connections() + b.connections(), 0, "no peer contacted");
    assert_eq!(n.validated(), 0);
}

#[test]
fn cancelled_before_the_call_does_nothing() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    let budget = Arc::new(WakeBudget::new(20_000));
    budget.cancel();
    let r = n.node.wake_catch_up(budget, 50, 1_000);
    assert_eq!(r.outcome, WakeOutcome::Cancelled, "{:?}", r);
    assert_eq!(a.connections() + b.connections(), 0);
}

#[test]
fn cancel_mid_catch_up_returns_partial_progress_promptly() {
    let c = chain(30);
    let slow = Behavior::DelayResponses(Duration::from_millis(300));
    let a = MockPeer::spawn(&c, vec![slow.clone()]);
    let b = MockPeer::spawn(&c, vec![slow]);
    let n = node_with(&[&a, &b], None);

    let budget = Arc::new(WakeBudget::new(60_000));
    let canceller = {
        let budget = Arc::clone(&budget);
        thread::spawn(move || {
            // Let the headers land and a block or two validate.
            thread::sleep(Duration::from_millis(1_800));
            budget.cancel();
            Instant::now()
        })
    };
    let r = n.node.wake_catch_up(Arc::clone(&budget), 50, 1_000);
    let cancelled_at = canceller.join().unwrap();
    let lag = Instant::now().saturating_duration_since(cancelled_at);

    assert_eq!(r.outcome, WakeOutcome::Cancelled, "{:?}", r);
    let s = r.status.expect("partial status");
    assert!(!s.caught_up);
    assert!(s.blocks_validated > 0 && s.blocks_validated < 30, "{:?}", s);
    assert_eq!(n.validated(), s.current_height, "progress persisted");
    // At most one in-flight block request (300 ms) after the cancel.
    assert!(lag < Duration::from_secs(2), "returned {:?} after cancel", lag);
}

#[test]
fn wake_preempts_a_running_sync_loop() {
    let c = chain(10);
    let (a, b) = honest_pair(&c);
    let n = Arc::new(node_with(&[&a, &b], None));

    let sync_thread = {
        let n = Arc::clone(&n);
        thread::spawn(move || n.node.start_header_sync(Box::new(NoProgress)))
    };
    // Wait until the loop owns the session.
    let start = Instant::now();
    while !n.sync_running() {
        assert!(start.elapsed() < Duration::from_secs(10), "sync never started");
        thread::sleep(Duration::from_millis(10));
    }

    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(30_000)), 50, 1_000);
    assert!(r.preempted_sync, "{:?}", r);
    assert_eq!(r.outcome, WakeOutcome::Completed, "{:?}", r);
    assert!(sync_thread.join().unwrap().is_ok(), "sync loop stops cleanly");
    assert!(!n.sync_running());
    assert_eq!(n.validated(), 10);
}

#[test]
fn wake_never_runs_beside_another_session() {
    // Stand-in for a snapshot load: something holds the session and
    // doesn't respond to stop requests. The wake gives up at the floor.
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    let _held = n.node.lock_session();

    let start = Instant::now();
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(1_500)), 50, 1_000);
    let waited = start.elapsed();
    assert_eq!(r.outcome, WakeOutcome::Busy, "{:?}", r);
    assert!(!r.preempted_sync);
    assert!(waited >= Duration::from_millis(400), "{:?}", waited);
    assert!(waited < Duration::from_millis(1_200), "{:?}", waited);
    assert_eq!(a.connections() + b.connections(), 0);

    // The legacy budgeted calls refuse instead of running alongside.
    match n.node.catch_up_blocks(5, 5) {
        Err(HerculesError::SyncFailed { msg }) => assert!(msg.contains("busy"), "{}", msg),
        other => panic!("expected busy, got {:?}", other.map(|s| s.current_height)),
    }
    assert!(n.node.validate_latest_block(5).is_err());
}

#[test]
fn second_wake_waits_for_the_first_then_runs() {
    let c = chain(10);
    let slow = Behavior::DelayResponses(Duration::from_millis(100));
    let a = MockPeer::spawn(&c, vec![slow.clone()]);
    let b = MockPeer::spawn(&c, vec![slow]);
    let n = Arc::new(node_with(&[&a, &b], None));

    let first = {
        let n = Arc::clone(&n);
        thread::spawn(move || n.node.wake_catch_up(Arc::new(WakeBudget::new(30_000)), 50, 1_000))
    };
    thread::sleep(Duration::from_millis(50));
    let second = n.node.wake_catch_up(Arc::new(WakeBudget::new(30_000)), 50, 1_000);
    let first = first.join().unwrap();

    assert_eq!(first.outcome, WakeOutcome::Completed, "{:?}", first);
    assert_eq!(second.outcome, WakeOutcome::Completed, "{:?}", second);
    // Between them every block was applied exactly once.
    let total = first.status.unwrap().blocks_validated + second.status.unwrap().blocks_validated;
    assert_eq!(total, 10);
    assert_eq!(n.validated(), 10);
}

#[test]
fn tor_mode_waits_for_transport_and_never_falls_back_to_clearnet() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], Some(stuck_gate(Duration::from_secs(30))));

    // 2 s budget, 1 s floor: gives up after ~1 s, before any peer.
    let start = Instant::now();
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(2_000)), 50, 1_000);
    assert_eq!(r.outcome, WakeOutcome::TransportSlow, "{:?}", r);
    assert!(r.timings.transport_ready_ms.is_none());
    assert!(start.elapsed() < Duration::from_millis(1_500), "{:?}", start.elapsed());
    assert_eq!(a.connections() + b.connections(), 0, "no clearnet fallback");

    // The status reports Tor as still bootstrapping.
    let tor = n.node.get_tor_status().expect("tor mode");
    assert!(!tor.is_bootstrapped);
    assert!(!n.node.wait_for_transport(50).unwrap());
}

#[test]
fn tor_bootstrap_failure_is_reported_as_failed() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], Some(stuck_gate(Duration::ZERO)));
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(5_000)), 50, 1_000);
    assert_eq!(r.outcome, WakeOutcome::Failed, "{:?}", r);
    assert!(r.error.unwrap().contains("never completes"));
    assert_eq!(a.connections() + b.connections(), 0);
    assert!(matches!(n.node.wait_for_transport(1_000), Err(HerculesError::TorError { .. })));
}

#[test]
fn open_clearnet_node_is_ready_at_once() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("hercules-headers.sqlite3").to_string_lossy().into_owned();
    let node = HerculesNode::open(db, None).unwrap();
    assert!(node.get_tor_status().is_none());
    assert!(node.wait_for_transport(0).unwrap());
}

#[test]
fn block_download_is_clamped_to_the_budget() {
    // Both peers sit on the block. Unclamped, the request would wait out
    // the full download timeout (3 s in tests, 120 s / 300 s in the app).
    let c = chain(5);
    let a = MockPeer::spawn(&c, vec![Behavior::WithholdBlock(1)]);
    let b = MockPeer::spawn(&c, vec![Behavior::WithholdBlock(1)]);
    let n = node_with(&[&a, &b], None);

    let start = Instant::now();
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(1_200)), 50, 0);
    let took = start.elapsed();
    assert!(took < Duration::from_millis(2_400), "overran budget: {:?}", took);
    assert_eq!(r.outcome, WakeOutcome::Completed, "{:?}", r);
    let s = r.status.expect("status");
    assert_eq!(s.blocks_validated, 0);
    assert!(s.error.is_none(), "budget exhaustion is not a peer error: {:?}", s);
    assert_eq!(n.validated(), 0);
}

// ── Review follow-ups ────────────────────────────────────────────────

#[test]
fn budget_spent_before_headers_is_timed_out_not_caught_up() {
    // A fresh node is "at tip" locally (genesis, validated 0). Reporting
    // that as caught up would post "Block #0 Validated" for a wake that
    // never heard from a peer.
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    let spent = Arc::new(WakeBudget::starting_at(
        Instant::now() - Duration::from_secs(10),
        Duration::from_secs(10),
    ));
    let r = n.node.wake_catch_up(spent, 50, 0);
    assert_eq!(r.outcome, WakeOutcome::TimedOut, "{:?}", r);
    assert!(!r.status.expect("status").caught_up);
    assert!(r.timings.headers_checked_ms.is_none());
    assert_eq!(a.connections() + b.connections(), 0);

    // Same at the sync layer, for the legacy entry points.
    let spent = WakeBudget::starting_at(Instant::now() - Duration::from_secs(1), Duration::ZERO);
    let s = n.node.syncer.catch_up_blocks_in(50, &spent).unwrap();
    assert!(!s.caught_up, "{:?}", s);
}

#[test]
fn tor_required_without_tor_never_dials_clearnet() {
    // No gate at all: straight at the syncer, past any transport wait, so
    // only `open_pool`'s guard stands between us and a clearnet dial.
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let dir = TempDir::new().unwrap();
    let mut hs = sync::HeaderSync::with_config(sync::SyncConfig {
        db_path: dir.path().join("headers.sqlite3").to_str().unwrap().to_string(),
        tor: None,
        params: ChainParams::regtest(),
        peers: PeerSource::Static(vec![a.addr(), b.addr()]),
    })
    .unwrap();
    hs.require_tor();

    let err = hs.catch_up_blocks_in(50, &WakeBudget::new(5_000)).unwrap_err();
    assert!(format!("{}", err).contains("Tor transport not ready"), "{}", err);
    assert!(hs.validate_latest_block_in(&WakeBudget::new(5_000)).is_err());
    assert!(hs.run_sync(&AtomicBool::new(false), |_| {}).is_err());
    assert_eq!(a.connections() + b.connections(), 0, "no clearnet fallback");
}

#[test]
fn stop_while_waiting_for_the_session_is_not_lost() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = Arc::new(node_with(&[&a, &b], None));

    // A wake holds the session; foreground sync queues behind it.
    let held = n.node.lock_session();
    let sync_thread = {
        let n = Arc::clone(&n);
        thread::spawn(move || n.node.start_header_sync(Box::new(NoProgress)))
    };
    thread::sleep(Duration::from_millis(100));
    n.node.stop_sync(); // the user taps Stop while it waits
    drop(held);

    let start = Instant::now();
    let result = sync_thread.join().unwrap();
    assert!(result.is_ok(), "{:?}", result.err());
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(a.connections() + b.connections(), 0, "never started syncing");
}

#[test]
fn wake_behind_a_snapshot_load_is_busy_at_once() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    let _held = n.node.lock_session();
    let _loading = FlagGuard::set(&n.node.snapshot_loading);

    let start = Instant::now();
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(25_000)), 50, 8_000);
    assert_eq!(r.outcome, WakeOutcome::Busy, "{:?}", r);
    assert!(start.elapsed() < Duration::from_millis(300), "{:?}", start.elapsed());
}

#[test]
fn one_node_per_database_and_no_reset_under_a_live_node() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("hercules-headers.sqlite3").to_string_lossy().into_owned();
    let node = HerculesNode::open(db.clone(), None).unwrap();
    assert!(matches!(
        HerculesNode::open(db.clone(), None),
        Err(HerculesError::NodeOpen { .. })
    ));
    assert!(matches!(reset_database(db.clone()), Err(HerculesError::NodeOpen { .. })));
    assert!(dir.path().join("utxo-lmdb").exists(), "nothing deleted");

    // Closing isn't enough: the files are only released with the node.
    assert!(node.close(1_000));
    assert!(matches!(reset_database(db.clone()), Err(HerculesError::NodeOpen { .. })));
    drop(node);
    reset_database(db.clone()).unwrap();
    assert!(!dir.path().join("utxo-lmdb").exists());
    let _again = HerculesNode::open(db, None).unwrap();
}

#[test]
fn close_ends_sync_wakes_and_transport_waits() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = Arc::new(node_with(&[&a, &b], None));

    let sync_thread = {
        let n = Arc::clone(&n);
        thread::spawn(move || n.node.start_header_sync(Box::new(NoProgress)))
    };
    let start = Instant::now();
    while !n.sync_running() {
        assert!(start.elapsed() < Duration::from_secs(10), "sync never started");
        thread::sleep(Duration::from_millis(10));
    }
    assert!(n.node.close(10_000), "session freed");
    assert!(sync_thread.join().unwrap().is_ok());

    // Everything afterwards is refused without touching the network.
    let before = a.connections() + b.connections();
    assert!(matches!(
        n.node.start_header_sync(Box::new(NoProgress)),
        Err(HerculesError::NodeOpen { .. })
    ));
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(5_000)), 50, 0);
    assert_eq!(r.outcome, WakeOutcome::Cancelled, "{:?}", r);
    assert!(n.node.catch_up_blocks(5, 5).is_err());
    assert_eq!(a.connections() + b.connections(), before);
}

#[test]
fn close_interrupts_a_foreground_transport_wait() {
    // The reset race: foreground sync blocked on Tor bootstrap when the
    // user resets. close() must release it promptly.
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = Arc::new(node_with(&[&a, &b], Some(stuck_gate(Duration::from_secs(30)))));
    let waiter = {
        let n = Arc::clone(&n);
        thread::spawn(move || n.node.start_header_sync(Box::new(NoProgress)))
    };
    thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    assert!(n.node.close(5_000));
    let result = waiter.join().unwrap();
    assert!(matches!(result, Err(HerculesError::NodeOpen { .. })), "{:?}", result.err());
    assert!(start.elapsed() < Duration::from_secs(1), "{:?}", start.elapsed());
    assert_eq!(a.connections() + b.connections(), 0);
}

#[test]
fn close_cancels_a_running_wake() {
    let c = chain(30);
    let slow = Behavior::DelayResponses(Duration::from_millis(300));
    let a = MockPeer::spawn(&c, vec![slow.clone()]);
    let b = MockPeer::spawn(&c, vec![slow]);
    let n = Arc::new(node_with(&[&a, &b], None));
    let budget = Arc::new(WakeBudget::new(60_000));
    let wake = {
        let (n, budget) = (Arc::clone(&n), Arc::clone(&budget));
        thread::spawn(move || n.node.wake_catch_up(budget, 50, 0))
    };
    thread::sleep(Duration::from_millis(800));
    let start = Instant::now();
    assert!(n.node.close(5_000));
    assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
    assert!(budget.is_cancelled());
    let r = wake.join().unwrap();
    assert_eq!(r.outcome, WakeOutcome::Cancelled, "{:?}", r);
}

// ── Review round 2 ───────────────────────────────────────────────────

#[test]
fn wake_reports_tip_disagreement_not_timed_out() {
    // The eclipse alert must survive: a taller fork as the active peer,
    // outvoted by two honest peers, is a tip disagreement.
    let mut honest = FixtureChain::new();
    honest.mine(10);
    let mut fork = FixtureChain::new().fork_at(0);
    fork.mine(12);
    let liar = MockPeer::spawn(&fork, vec![]);
    let a = MockPeer::spawn(&honest, vec![]);
    let b = MockPeer::spawn(&honest, vec![]);
    let n = node_with(&[&liar, &a, &b], None);

    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(20_000)), 50, 1_000);
    assert_eq!(r.outcome, WakeOutcome::Completed, "{:?}", r);
    let s = r.status.expect("status");
    assert!(s.tip_disagreement, "{:?}", s);
    assert!(!s.caught_up);
    assert!(r.timings.headers_checked_ms.is_some(), "headers were checked: they disagree");
    assert_eq!(n.validated(), 0, "nothing from the fork applied");
}

#[test]
fn tip_disagreement_survives_a_tiebreaker_deadline() {
    // The liar is active; the witness contradicts it after 1.5 s; the
    // tiebreaker would answer 1.5 s later, past the deadline. The
    // divergence was seen before the deadline, so the alert must stand.
    let mut honest = FixtureChain::new();
    honest.mine(10);
    let mut fork = FixtureChain::new().fork_at(0);
    fork.mine(12);
    let liar = MockPeer::spawn(&fork, vec![]);
    let slow = Behavior::DelayResponses(Duration::from_millis(1_500));
    let a = MockPeer::spawn(&honest, vec![slow.clone()]);
    let b = MockPeer::spawn(&honest, vec![slow]);
    let n = node_with(&[&liar, &a, &b], None);

    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(2_500)), 50, 0);
    let s = r.status.expect("status");
    assert!(s.tip_disagreement, "{:?}", s);
    assert!(!s.caught_up);
    assert_eq!(n.validated(), 0, "nothing from the fork applied");
}

#[test]
fn header_phase_is_bounded_by_the_budget() {
    // Peers answer getheaders far too late. Unbounded, the request waits
    // out the read timeout; bounded, the wake ends at its deadline as
    // TimedOut (headers never checked), not Failed.
    let c = chain(5);
    let slow = Behavior::DelayResponses(Duration::from_secs(5));
    let a = MockPeer::spawn(&c, vec![slow.clone()]);
    let b = MockPeer::spawn(&c, vec![slow]);
    let n = node_with(&[&a, &b], None);

    let start = Instant::now();
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(1_500)), 50, 0);
    let took = start.elapsed();
    assert!(took < Duration::from_millis(2_500), "overran budget: {:?}", took);
    assert_eq!(r.outcome, WakeOutcome::TimedOut, "{:?}", r);
    assert!(!r.status.expect("status").caught_up);
    // Our deadline cut the peers off: no penalty.
    let store = crate::peer_store::PeerStore::open(
        n._dir.path().join("peers.sqlite3").to_str().unwrap(),
    )
    .unwrap();
    for p in [&a, &b] {
        assert!(store.load_score(&p.addr()).unwrap().map_or(true, |s| s >= 100), "{} penalized", p.addr());
    }
}

#[test]
fn a_wakes_stop_never_reaches_the_next_sync_session() {
    // Sync A runs; the user starts sync B, which queues on the session; a
    // wake W stops A. Whoever gets the session next, B must keep running
    // until the user stops it.
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = Arc::new(node_with(&[&a, &b], None));

    let sync_a = {
        let n = Arc::clone(&n);
        thread::spawn(move || n.node.start_header_sync(Box::new(NoProgress)))
    };
    wait_for("sync A", || n.sync_running());
    let a_id = n.sync_running_id().unwrap();

    let sync_b = {
        let n = Arc::clone(&n);
        thread::spawn(move || n.node.start_header_sync(Box::new(NoProgress)))
    };
    wait_for("sync B registered", || lock(&n.node.sync_sessions).len() == 2);

    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(3_000)), 50, 0);
    assert!(r.preempted_sync, "{:?}", r);
    assert!(sync_a.join().unwrap().is_ok());

    wait_for("sync B running", || n.sync_running_id().is_some_and(|id| id != a_id));
    thread::sleep(Duration::from_millis(300));
    assert!(!sync_b.is_finished(), "W's stop leaked into session B");

    n.node.stop_sync();
    assert!(sync_b.join().unwrap().is_ok());
}

#[test]
fn tor_dir_claim_waits_for_the_previous_client() {
    let dir = TempDir::new().unwrap();
    let first = TorDirClaim::wait_take(dir.path(), || false).unwrap();

    // A second client on the same dir waits...
    let path = dir.path().to_path_buf();
    let waiter = thread::spawn(move || {
        let start = Instant::now();
        let claim = TorDirClaim::wait_take(&path, || false);
        (claim.is_some(), start.elapsed())
    });
    thread::sleep(Duration::from_millis(300));
    assert!(!waiter.is_finished(), "second Arti allowed on a live dir");
    drop(first);
    let (got, waited) = waiter.join().unwrap();
    assert!(got && waited >= Duration::from_millis(250), "{:?}", waited);

    // ...and gives up if its node closes meanwhile.
    let _held = TorDirClaim::wait_take(dir.path(), || false).unwrap();
    assert!(TorDirClaim::wait_take(dir.path(), || true).is_none());
}

#[test]
fn tor_dir_claim_key_is_stable_before_the_dir_exists() {
    // Arti creates the dir only after the claim, and the parent may be a
    // symlink (iOS /var -> /private/var). Claimed before it exists via the
    // link, the dir must still be taken when reached by its real path.
    let root = TempDir::new().unwrap();
    let real = root.path().canonicalize().unwrap().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let _first = TorDirClaim::wait_take(&link.join("tor"), || false).unwrap();
    std::fs::create_dir(real.join("tor")).unwrap();
    assert!(
        TorDirClaim::wait_take(&real.join("tor"), || true).is_none(),
        "second Arti allowed once the dir exists"
    );
}

#[test]
fn join_within_bounds_a_stuck_thread() {
    let stuck = thread::spawn(|| thread::sleep(Duration::from_secs(3)));
    let start = Instant::now();
    assert!(!join_within(stuck, Duration::from_millis(100)));
    assert!(start.elapsed() < Duration::from_millis(400));
    let quick = thread::spawn(|| {});
    assert!(join_within(quick, Duration::from_secs(1)));
}

#[test]
fn closed_node_refuses_the_wallet_api() {
    let c = chain(1);
    let a = MockPeer::spawn(&c, vec![]);
    let n = node_with(&[&a], None);
    assert!(n.node.close(1_000));
    assert!(matches!(n.node.start_wallet_api(), Err(HerculesError::NodeOpen { .. })));
}

#[test]
fn two_wakes_sharing_a_budget_unregister_one_at_a_time() {
    let c = chain(1);
    let a = MockPeer::spawn(&c, vec![]);
    let n = node_with(&[&a], None);
    let budget = Arc::new(WakeBudget::new(1_000));
    lock(&n.node.wakes).push(Arc::clone(&budget));
    lock(&n.node.wakes).push(Arc::clone(&budget));
    {
        let _one = WakeRegistration { node: &n.node, budget: &budget };
    }
    assert_eq!(lock(&n.node.wakes).len(), 1, "only one registration removed");
}

#[test]
fn wake_errors_out_of_time_are_timed_out() {
    let spent = WakeBudget::starting_at(Instant::now() - Duration::from_secs(2), Duration::from_secs(1));
    assert_eq!(wake_error_outcome(&spent), WakeOutcome::TimedOut);
    let live = WakeBudget::new(60_000);
    assert_eq!(wake_error_outcome(&live), WakeOutcome::Failed);
    live.cancel();
    assert_eq!(wake_error_outcome(&live), WakeOutcome::Cancelled);
}

#[test]
fn path_claim_is_per_database_not_per_spelling() {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("hercules-headers.sqlite3");
    let other = dir.path().join(".").join("hercules-headers.sqlite3");
    let _node = HerculesNode::open(db.to_string_lossy().into_owned(), None).unwrap();
    assert!(matches!(
        HerculesNode::open(other.to_string_lossy().into_owned(), None),
        Err(HerculesError::NodeOpen { .. })
    ));
    assert!(matches!(
        reset_database(other.to_string_lossy().into_owned()),
        Err(HerculesError::NodeOpen { .. })
    ));
}

// ── Extreme inputs and vanished peers (tests/network-app) ────────────
//
// `wake_catch_up` is non-throwing over FFI (hercules.udl): a panic on the
// wake path is a `try!` crash in a background wake, so every input must
// come back as an outcome.

#[test]
fn wake_catch_up_turns_any_parameters_into_an_outcome() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    for (budget_ms, max_blocks, min_block_ms) in [
        (0, 50, 0),
        (0, 0, u32::MAX),
        (1, 1, 1),
        (5_000, 0, 0),
        (5_000, 50, u32::MAX),
        (u32::MAX, 0, 0),
        (u32::MAX, 2, 1_000),
        (u32::MAX, u32::MAX, 0),
    ] {
        let start = Instant::now();
        let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(budget_ms)), max_blocks, min_block_ms);
        let took = start.elapsed();
        assert!(took < Duration::from_secs(15), "({}, {}, {}) took {:?}", budget_ms, max_blocks, min_block_ms, took);
        match r.outcome {
            WakeOutcome::Completed => {
                let s = r.status.as_ref().expect("completed without status");
                assert!(s.blocks_validated <= max_blocks, "({}, {}): {:?}", budget_ms, max_blocks, s);
            }
            WakeOutcome::TimedOut | WakeOutcome::TransportSlow => {
                assert!(
                    budget_ms < 10 || min_block_ms > budget_ms,
                    "({}, {}, {}): {:?}",
                    budget_ms,
                    max_blocks,
                    min_block_ms,
                    r
                );
            }
            other => panic!("({}, {}, {}): unexpected {:?}: {:?}", budget_ms, max_blocks, min_block_ms, other, r.error),
        }
        // No phase is stamped later than the wake says it ran.
        for t in [
            r.timings.transport_ready_ms,
            r.timings.peers_ready_ms,
            r.timings.headers_checked_ms,
            r.timings.validated_ms,
        ]
        .into_iter()
        .flatten()
        {
            assert!(t <= r.elapsed_ms, "phase at {} ms after a {} ms wake", t, r.elapsed_ms);
        }
    }
    // The unbounded ones ran to completion.
    assert_eq!(n.validated(), 5);
}

#[test]
fn wake_with_every_peer_gone_fails_cleanly_and_quickly() {
    let c = chain(5);
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    drop(a);
    drop(b);
    let start = Instant::now();
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(20_000)), 50, 1_000);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
    assert_eq!(r.outcome, WakeOutcome::Failed, "{:?}", r);
    assert!(r.error.is_some());
    assert!(r.timings.peers_ready_ms.is_none());
    // The node is still usable for the next wake.
    assert_eq!(n.validated(), 0);
    assert!(n.node.get_status().is_ok());
}

#[test]
fn concurrent_wakes_and_getters_never_deadlock() {
    let c = chain(8);
    let (a, b) = honest_pair(&c);
    let n = Arc::new(node_with(&[&a, &b], None));
    let wakes: Vec<_> = (0..6u32)
        .map(|i| {
            let n = Arc::clone(&n);
            thread::spawn(move || (i, n.node.wake_catch_up(Arc::new(WakeBudget::new(1_000 + 500 * i)), 2, 0)))
        })
        .collect();
    // Getters stay responsive while wakes hold the session.
    let pollers: Vec<_> = (0..2)
        .map(|_| {
            let n = Arc::clone(&n);
            thread::spawn(move || {
                for _ in 0..50 {
                    n.node.get_status().unwrap();
                    let _ = n.node.get_mempool_status();
                    let _ = n.node.get_node_status();
                    let _ = n.node.is_validation_paused();
                    thread::sleep(Duration::from_millis(10));
                }
            })
        })
        .collect();
    let start = Instant::now();
    for w in wakes {
        let (i, r) = w.join().expect("wake panicked");
        assert!(
            matches!(
                r.outcome,
                WakeOutcome::Completed | WakeOutcome::Unconfirmed | WakeOutcome::Busy | WakeOutcome::TimedOut
            ),
            "wake {}: {:?}",
            i,
            r
        );
    }
    for p in pollers {
        p.join().expect("getter panicked");
    }
    assert!(start.elapsed() < Duration::from_secs(20), "{:?}", start.elapsed());
    assert!(n.validated() <= 8);
}

// ── Ticket 054 ───────────────────────────────────────────────────────

#[test]
fn one_peer_with_nothing_new_is_unconfirmed_not_completed() {
    // The only peer says there is nothing past our (old, fixture) tip:
    // one peer's word, so the wake is `Unconfirmed` and not caught up.
    let c = chain(6);
    let only = MockPeer::spawn(&c, vec![]);
    let n = node_with(&[&only], None);
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(15_000)), 50, 0);
    assert_eq!(r.outcome, WakeOutcome::Unconfirmed, "{:?}", r);
    let s = r.status.expect("status");
    assert_eq!(s.blocks_validated, 6, "validated blocks still count: {:?}", s);
    assert!(!s.caught_up && !s.tip_confirmed, "{:?}", s);

    // Two agreeing peers: `Completed` and caught up.
    let (a, b) = honest_pair(&c);
    let n = node_with(&[&a, &b], None);
    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(15_000)), 50, 0);
    assert_eq!(r.outcome, WakeOutcome::Completed, "{:?}", r);
    assert!(r.status.expect("status").caught_up);
}

#[test]
fn open_in_mode_records_the_mode_once_and_reports_the_nodes() {
    let _slot = lmdb_slot();
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("headers.sqlite3").to_str().unwrap().to_string();
    {
        let node = HerculesNode::open_in_mode(db.clone(), None, None).unwrap();
        assert_eq!(node.validation_mode().unwrap(), None);
        assert_eq!(
            node.set_validation_mode(NodeValidationMode::AssumeUtxo).unwrap(),
            NodeValidationMode::AssumeUtxo
        );
        assert!(node.needs_snapshot().unwrap());
    }
    // A later open asking for the other mode gets the recorded one.
    let node = HerculesNode::open_in_mode(db, None, Some(NodeValidationMode::Genesis)).unwrap();
    assert_eq!(node.validation_mode().unwrap(), Some(NodeValidationMode::AssumeUtxo));
}
