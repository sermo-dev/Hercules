//! Per-process cap on live LMDB-backed test nodes (macOS).
//!
//! The vendored LMDB (`lmdb-master-sys`) locks with SysV semaphores on
//! Apple platforms, and every lock it takes uses `SEM_UNDO`. macOS allows a
//! process at most `kern.sysv.semume` (default 10) undo entries at once and
//! fails `semop` past that with `EINVAL`, so the 11th LMDB lock held at the
//! same moment anywhere in the process fails `mdb_txn_begin` with
//! "Invalid argument (os error 22)". A node holds at most one or two
//! (writer mutex during a write txn, reader mutex while registering a
//! reader slot), so production, with one node per process, is far below
//! it. A test binary is not: `cargo test -- --test-threads 32` runs dozens
//! of nodes in one process and their writes collide.
//!
//! Every `UtxoSet` opened in a test build takes a slot for its lifetime
//! (`UtxoSet::open`), so direct LMDB tests are covered as well as harness
//! nodes, which also take one. Slots are counted per
//! acquiring thread: a thread that already holds one takes more for free
//! (a test with a donor node and a node under test), so a test never waits
//! on itself. A slot may be dropped on any thread (nodes are shared with
//! the threads that drive them).

use std::collections::HashMap;
use std::sync::{Condvar, Mutex, OnceLock};
use std::thread::ThreadId;

/// Up to this many concurrent tests, nothing is throttled: a node holds
/// an LMDB lock only during a write, and the suite has always run at 8
/// threads (this machine's default) without hitting the limit.
const UNTHROTTLED_UP_TO: usize = 8;

/// Above that, threads that may hold live harness nodes at once: about
/// two locks each, leaving room under 10 for LMDB tests outside the
/// harness.
const THROTTLED_SLOTS: usize = 4;

/// How many tests this binary runs at once: `--test-threads N` (or `=N`),
/// else `RUST_TEST_THREADS`, else the core count (libtest's default).
fn test_threads() -> usize {
    let args: Vec<String> = std::env::args().collect();
    let from_args = args.iter().enumerate().find_map(|(i, a)| {
        a.strip_prefix("--test-threads=")
            .map(str::to_string)
            .or_else(|| (a == "--test-threads").then(|| args.get(i + 1).cloned()).flatten())
    });
    from_args
        .or_else(|| std::env::var("RUST_TEST_THREADS").ok())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}

/// Threads that may hold live nodes at once.
fn slots() -> usize {
    static SLOTS: OnceLock<usize> = OnceLock::new();
    *SLOTS.get_or_init(|| {
        let threads = test_threads();
        if threads <= UNTHROTTLED_UP_TO {
            threads.max(1)
        } else {
            THROTTLED_SLOTS
        }
    })
}

struct Gate {
    /// Threads currently holding at least one slot.
    threads: usize,
    /// Live slots per acquiring thread.
    held: HashMap<ThreadId, usize>,
}

static GATE: Mutex<Option<Gate>> = Mutex::new(None);
static FREED: Condvar = Condvar::new();

/// Held while a harness node is alive.
pub struct LmdbSlot {
    owner: ThreadId,
}

/// Wait for a slot (immediately, if this thread already holds one).
pub fn lmdb_slot() -> LmdbSlot {
    let me = std::thread::current().id();
    let mut guard = GATE.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let gate = guard.get_or_insert_with(|| Gate { threads: 0, held: HashMap::new() });
        if let Some(n) = gate.held.get_mut(&me) {
            *n += 1;
            break;
        }
        if gate.threads < slots() {
            gate.threads += 1;
            gate.held.insert(me, 1);
            break;
        }
        guard = FREED.wait(guard).unwrap_or_else(|e| e.into_inner());
    }
    LmdbSlot { owner: me }
}

impl Drop for LmdbSlot {
    fn drop(&mut self) {
        let mut guard = GATE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(gate) = guard.as_mut() {
            if let Some(n) = gate.held.get_mut(&self.owner) {
                *n -= 1;
                if *n == 0 {
                    gate.held.remove(&self.owner);
                    gate.threads -= 1;
                    FREED.notify_all();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn nested_slots_on_one_thread_never_wait() {
        let held: Vec<LmdbSlot> = (0..slots() + 3).map(|_| lmdb_slot()).collect();
        drop(held);
    }

    #[test]
    fn slot_may_be_released_on_another_thread() {
        let slot = lmdb_slot();
        std::thread::spawn(move || drop(slot)).join().unwrap();
        // This thread holds nothing now: taking one again must not count
        // the old one (it would leak a unit per test otherwise).
        let again = lmdb_slot();
        drop(again);
    }

    #[test]
    fn at_most_slots_threads_hold_one_at_once() {
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let (live, peak) = (live.clone(), peak.clone());
                std::thread::spawn(move || {
                    let _slot = lmdb_slot();
                    let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    live.fetch_sub(1, Ordering::SeqCst);
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // Other tests in this binary may hold slots too, so only the upper
        // bound is certain.
        assert!(peak.load(Ordering::SeqCst) <= slots());
    }
}
