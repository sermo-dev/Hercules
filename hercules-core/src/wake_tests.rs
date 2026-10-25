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
use crate::testkit::{Behavior, FixtureChain, MockPeer};

struct Node {
    _dir: TempDir,
    node: HerculesNode,
}

/// A clearnet regtest node pointed at `peers`. With `tor`, the node is in
/// Tor mode and uses that gate as its transport.
fn node_with(peers: &[&MockPeer], tor: Option<Arc<TorGate>>) -> Node {
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
        sync_running: AtomicBool::new(false),
        wallet_rpc: Mutex::new(None),
        wallet_auth_token: Mutex::new(None),
        data_dir: dir.path().to_str().unwrap().to_string(),
    };
    Node { _dir: dir, node }
}

impl Node {
    fn validated(&self) -> u32 {
        self.node.syncer.rpc_validated_height().unwrap()
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
    assert!(s.blocks_validated < 30, "{:?}", s);
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
    while !n.node.sync_running.load(Ordering::SeqCst) {
        assert!(start.elapsed() < Duration::from_secs(10), "sync never started");
        thread::sleep(Duration::from_millis(10));
    }

    let r = n.node.wake_catch_up(Arc::new(WakeBudget::new(30_000)), 50, 1_000);
    assert!(r.preempted_sync, "{:?}", r);
    assert_eq!(r.outcome, WakeOutcome::Completed, "{:?}", r);
    assert!(sync_thread.join().unwrap().is_ok(), "sync loop stops cleanly");
    assert!(!n.node.sync_running.load(Ordering::SeqCst));
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
