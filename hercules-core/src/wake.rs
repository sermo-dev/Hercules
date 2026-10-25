//! Wake budgets, cancellation and transport readiness (ticket 028).
//!
//! iOS gives a silent push about 30 s of wall clock and kills (then
//! throttles) apps that overrun. A `WakeBudget` is created by Swift the
//! moment a wake arrives, so everything after that — opening the node,
//! Tor bootstrap, peer handshakes, block work — counts against the same
//! deadline. It is also the wake's cancellation token: the BG task
//! expiration handler and the push watchdog call `cancel()`, and the
//! catch-up paths check it between steps.
//!
//! A per-wake token rather than a node-wide flag: a cancel that lands
//! before the Rust call starts is not lost, and a stale cancel from one
//! wake can't leak into the next.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Wake phases measured inside Rust. Swift measures the ones it can see
/// itself (node ready, completion handler called).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakePhase {
    /// Tor bootstrapped (or clearnet, which is ready immediately).
    TransportReady,
    /// The wake's peer pool finished its initial handshakes.
    PeersReady,
    /// New headers fetched, cross-checked and stored (or none were new).
    HeadersChecked,
    /// Most recent block download finished.
    BlockDownloaded,
    /// Most recent block fully validated and applied.
    Validated,
}

/// Milliseconds since wake receipt at which each phase was reached.
/// `None` if the wake never got there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhaseMarks {
    pub transport_ready_ms: Option<u64>,
    pub peers_ready_ms: Option<u64>,
    pub headers_checked_ms: Option<u64>,
    pub blocks_downloaded_ms: Option<u64>,
    pub validated_ms: Option<u64>,
}

/// Deadline, cancellation flag and phase timings for one wake. Exposed
/// over FFI as `WakeBudget`.
#[derive(Debug)]
pub struct WakeBudget {
    start: Instant,
    deadline: Instant,
    cancelled: AtomicBool,
    marks: Mutex<PhaseMarks>,
}

impl WakeBudget {
    /// A budget of `budget_ms` starting now.
    pub fn new(budget_ms: u32) -> WakeBudget {
        WakeBudget::starting_at(Instant::now(), Duration::from_millis(budget_ms as u64))
    }

    pub fn starting_at(start: Instant, budget: Duration) -> WakeBudget {
        WakeBudget {
            start,
            deadline: start + budget,
            cancelled: AtomicBool::new(false),
            marks: Mutex::new(PhaseMarks::default()),
        }
    }

    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            log::info!("wake: cancelled at {} ms", self.elapsed_ms());
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub fn remaining_ms(&self) -> u64 {
        self.remaining().as_millis() as u64
    }

    /// True once the wake must stop starting new work: cancelled, or out
    /// of time.
    pub fn should_stop(&self) -> bool {
        self.is_cancelled() || Instant::now() >= self.deadline
    }

    /// Record that `phase` was reached now. Transport, peers and headers
    /// keep their first time; block download and validation keep the
    /// latest (the end of the block work).
    pub fn mark(&self, phase: WakePhase) {
        let now = Some(self.elapsed_ms());
        let mut m = self.marks.lock().unwrap_or_else(|e| e.into_inner());
        match phase {
            WakePhase::TransportReady => {
                m.transport_ready_ms = m.transport_ready_ms.or(now);
            }
            WakePhase::PeersReady => m.peers_ready_ms = m.peers_ready_ms.or(now),
            WakePhase::HeadersChecked => {
                m.headers_checked_ms = m.headers_checked_ms.or(now);
            }
            WakePhase::BlockDownloaded => m.blocks_downloaded_ms = now,
            WakePhase::Validated => m.validated_ms = now,
        }
    }

    pub fn marks(&self) -> PhaseMarks {
        *self.marks.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// How long one poll of a wait loop sleeps before re-checking the budget.
const POLL: Duration = Duration::from_millis(50);

/// Wait until `try_acquire` succeeds, polling every 50 ms. Stops when the
/// budget is spent or cancelled, or when less than `floor` would be left
/// (not enough to do anything useful). `on_busy` runs before each retry;
/// the node uses it to ask a running sync loop to stop.
pub fn acquire_within<T>(
    budget: &WakeBudget,
    floor: Duration,
    mut try_acquire: impl FnMut() -> Option<T>,
    mut on_busy: impl FnMut(),
) -> Option<T> {
    loop {
        if let Some(t) = try_acquire() {
            return Some(t);
        }
        if budget.should_stop() || budget.remaining() < floor {
            return None;
        }
        on_busy();
        std::thread::sleep(POLL.min(budget.remaining()));
    }
}

// ── Transport gate ─────────────────────────────────────────────────

/// Why a wait for the transport ended without it being ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportWait {
    /// Not ready before the deadline (or with less than the floor left).
    Slow,
    /// The budget was cancelled.
    Cancelled,
    /// Bootstrap failed. The next wait starts a fresh attempt.
    Failed(String),
}

enum GateState<T> {
    /// Not started, or the last attempt failed.
    Idle { last_error: Option<String> },
    Bootstrapping,
    Ready(T),
}

type Bootstrap<T> = Box<dyn Fn() -> Result<T, String> + Send + Sync>;

/// A transport that comes up in the background and can be waited on with
/// a deadline. `HerculesNode` uses it for Tor: opening the node starts the
/// bootstrap and returns at once, and each wake waits only as long as its
/// budget allows. A failed bootstrap is retried by the next wait, so a
/// long-lived process recovers without reopening the node.
///
/// Generic so the state machine is testable without Arti.
pub struct TransportGate<T: Clone + Send + 'static> {
    state: Mutex<GateState<T>>,
    changed: Condvar,
    bootstrap: Bootstrap<T>,
    attempts: AtomicU64,
}

impl<T: Clone + Send + 'static> TransportGate<T> {
    pub fn new(bootstrap: impl Fn() -> Result<T, String> + Send + Sync + 'static) -> Self {
        TransportGate {
            state: Mutex::new(GateState::Idle { last_error: None }),
            changed: Condvar::new(),
            bootstrap: Box::new(bootstrap),
            attempts: AtomicU64::new(0),
        }
    }

    /// The transport, if it is up.
    pub fn get(&self) -> Option<T> {
        match &*self.state.lock().unwrap_or_else(|e| e.into_inner()) {
            GateState::Ready(t) => Some(t.clone()),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn is_bootstrapping(&self) -> bool {
        matches!(
            &*self.state.lock().unwrap_or_else(|e| e.into_inner()),
            GateState::Bootstrapping
        )
    }

    /// Start a bootstrap on a background thread unless one is running or
    /// the transport is already up. Returns immediately.
    pub fn start(self: &std::sync::Arc<Self>) {
        let attempt = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !matches!(*state, GateState::Idle { .. }) {
                return;
            }
            *state = GateState::Bootstrapping;
            self.attempts.fetch_add(1, Ordering::SeqCst) + 1
        };
        let gate = std::sync::Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("transport-bootstrap".into())
            .spawn(move || {
                let result = (gate.bootstrap)();
                let mut state = gate.state.lock().unwrap_or_else(|e| e.into_inner());
                *state = match result {
                    Ok(t) => GateState::Ready(t),
                    Err(e) => {
                        log::warn!("transport bootstrap attempt {} failed: {}", attempt, e);
                        GateState::Idle { last_error: Some(e) }
                    }
                };
                gate.changed.notify_all();
            });
        if let Err(e) = spawned {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            *state = GateState::Idle {
                last_error: Some(format!("spawn bootstrap thread: {}", e)),
            };
            self.changed.notify_all();
        }
    }

    /// Wait for the transport within `budget`, giving up once less than
    /// `floor` would remain after it comes up. Starts a bootstrap if none
    /// is running (including a retry after a failure).
    pub fn wait_within(
        self: &std::sync::Arc<Self>,
        budget: &WakeBudget,
        floor: Duration,
    ) -> Result<T, TransportWait> {
        self.wait_until(budget.deadline(), floor, || budget.is_cancelled())
    }

    /// Wait for the transport until `deadline` (minus `floor`).
    pub fn wait_until(
        self: &std::sync::Arc<Self>,
        deadline: Instant,
        floor: Duration,
        cancelled: impl Fn() -> bool,
    ) -> Result<T, TransportWait> {
        self.start();
        let give_up_at = deadline.checked_sub(floor).unwrap_or(deadline);
        // Only a failure of an attempt this wait saw running counts; an
        // older `last_error` was already retried by `start` above.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match &*state {
                GateState::Ready(t) => {
                    return if Instant::now() > give_up_at {
                        Err(TransportWait::Slow)
                    } else {
                        Ok(t.clone())
                    };
                }
                GateState::Idle { last_error } => {
                    return Err(TransportWait::Failed(
                        last_error.clone().unwrap_or_else(|| "transport not started".into()),
                    ));
                }
                GateState::Bootstrapping => {}
            }
            if cancelled() {
                return Err(TransportWait::Cancelled);
            }
            let now = Instant::now();
            if now >= give_up_at {
                return Err(TransportWait::Slow);
            }
            let slice = POLL.min(give_up_at - now);
            state = self
                .changed
                .wait_timeout(state, slice)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    #[test]
    fn budget_counts_from_its_start_not_from_first_use() {
        // A wake that spent 900 ms of a 1 s budget before reaching Rust
        // (e.g. opening the node) has 100 ms left, not 1 s.
        let b = WakeBudget::starting_at(
            Instant::now() - Duration::from_millis(900),
            Duration::from_millis(1000),
        );
        assert!(b.elapsed_ms() >= 900);
        assert!(b.remaining_ms() <= 100);
        assert!(!b.should_stop());
        std::thread::sleep(Duration::from_millis(120));
        assert!(b.should_stop());
        assert!(!b.is_cancelled());
        assert_eq!(b.remaining(), Duration::ZERO);
    }

    #[test]
    fn cancel_stops_before_deadline_and_is_sticky() {
        let b = WakeBudget::new(60_000);
        assert!(!b.should_stop());
        b.cancel();
        b.cancel();
        assert!(b.is_cancelled());
        assert!(b.should_stop());
        assert!(b.remaining_ms() > 50_000, "cancel doesn't consume the clock");
    }

    #[test]
    fn marks_keep_first_transport_and_latest_block() {
        let b = WakeBudget::starting_at(Instant::now() - Duration::from_millis(10), Duration::from_secs(5));
        b.mark(WakePhase::TransportReady);
        b.mark(WakePhase::BlockDownloaded);
        b.mark(WakePhase::Validated);
        let first = b.marks();
        std::thread::sleep(Duration::from_millis(30));
        b.mark(WakePhase::TransportReady);
        b.mark(WakePhase::BlockDownloaded);
        b.mark(WakePhase::Validated);
        let second = b.marks();
        assert_eq!(second.transport_ready_ms, first.transport_ready_ms);
        assert!(second.blocks_downloaded_ms.unwrap() >= first.blocks_downloaded_ms.unwrap() + 30);
        assert!(second.validated_ms.unwrap() >= first.validated_ms.unwrap() + 30);
        assert!(first.transport_ready_ms.unwrap() >= 10);
        assert_eq!(second.peers_ready_ms, None);
        assert_eq!(second.headers_checked_ms, None);
    }

    #[test]
    fn acquire_within_retries_until_free_and_calls_on_busy() {
        let b = WakeBudget::new(5_000);
        let tries = AtomicU32::new(0);
        let mut busy_calls = 0;
        let got = acquire_within(
            &b,
            Duration::ZERO,
            || (tries.fetch_add(1, Ordering::SeqCst) >= 3).then_some(7),
            || busy_calls += 1,
        );
        assert_eq!(got, Some(7));
        assert_eq!(busy_calls, 3);
    }

    #[test]
    fn acquire_within_gives_up_at_floor_and_on_cancel() {
        // 300 ms budget, 200 ms floor: gives up after ~100 ms.
        let b = WakeBudget::new(300);
        let start = Instant::now();
        let got: Option<()> = acquire_within(&b, Duration::from_millis(200), || None, || {});
        assert!(got.is_none());
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(90), "{:?}", waited);
        assert!(waited < Duration::from_millis(250), "{:?}", waited);

        let b = Arc::new(WakeBudget::new(60_000));
        let b2 = Arc::clone(&b);
        let canceller = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            b2.cancel();
        });
        let start = Instant::now();
        let got: Option<()> = acquire_within(&b, Duration::ZERO, || None, || {});
        canceller.join().unwrap();
        assert!(got.is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    fn gate_after(delay: Duration, result: Result<u32, String>) -> Arc<TransportGate<u32>> {
        Arc::new(TransportGate::new(move || {
            std::thread::sleep(delay);
            result.clone()
        }))
    }

    #[test]
    fn transport_ready_within_budget() {
        let gate = gate_after(Duration::from_millis(50), Ok(9));
        let b = WakeBudget::new(5_000);
        assert_eq!(gate.wait_within(&b, Duration::from_secs(1)), Ok(9));
        // Warm: a second wake gets it immediately.
        let start = Instant::now();
        assert_eq!(gate.wait_within(&WakeBudget::new(5_000), Duration::ZERO), Ok(9));
        assert!(start.elapsed() < Duration::from_millis(20));
        assert_eq!(gate.get(), Some(9));
    }

    #[test]
    fn slow_transport_gives_up_at_floor_but_keeps_bootstrapping() {
        // Bootstrap needs 400 ms; the wake has 500 ms with a 300 ms floor,
        // so it must give up after ~200 ms rather than wait it out.
        let gate = gate_after(Duration::from_millis(400), Ok(1));
        let b = WakeBudget::new(500);
        let start = Instant::now();
        assert_eq!(gate.wait_within(&b, Duration::from_millis(300)), Err(TransportWait::Slow));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(180), "{:?}", waited);
        assert!(waited < Duration::from_millis(350), "{:?}", waited);
        assert!(gate.is_bootstrapping());
        // The bootstrap carries on in the background for the next wake.
        assert_eq!(gate.wait_within(&WakeBudget::new(5_000), Duration::ZERO), Ok(1));
    }

    #[test]
    fn transport_wait_observes_cancel() {
        let gate = gate_after(Duration::from_secs(2), Ok(1));
        let b = Arc::new(WakeBudget::new(60_000));
        let b2 = Arc::clone(&b);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            b2.cancel();
        });
        let start = Instant::now();
        assert_eq!(gate.wait_within(&b, Duration::ZERO), Err(TransportWait::Cancelled));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn failed_bootstrap_is_reported_then_retried() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let gate = Arc::new(TransportGate::new(move || {
            if c.fetch_add(1, Ordering::SeqCst) == 0 {
                Err("no network".to_string())
            } else {
                Ok(5u32)
            }
        }));
        let b = WakeBudget::new(5_000);
        assert_eq!(
            gate.wait_within(&b, Duration::ZERO),
            Err(TransportWait::Failed("no network".into()))
        );
        assert_eq!(gate.wait_within(&b, Duration::ZERO), Ok(5));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_waiters_share_one_bootstrap() {
        let calls = Arc::new(AtomicU32::new(0));
        let c = Arc::clone(&calls);
        let gate = Arc::new(TransportGate::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100));
            Ok(3u32)
        }));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let g = Arc::clone(&gate);
                std::thread::spawn(move || g.wait_within(&WakeBudget::new(5_000), Duration::ZERO))
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), Ok(3));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
