//! Daily upload cap for serving blocks on a metered network (ticket 049).
//!
//! The owner's decision: serving blocks on cellular is allowed (only when
//! the user enabled cellular data at all, which the app enforces), but on
//! a metered network the blocks we upload are capped per day. The app's
//! `NetworkPolicy` tells us whether the current path is metered
//! (`HerculesNode::set_network_metered`). The window resets after a day,
//! or as soon as we join an unmetered network.
//!
//! Only block uploads count and are capped: they are what costs data
//! (up to ~4 MB each); headers, transactions and inv traffic are small and
//! keep flowing. The count lives in memory, so an app relaunch starts a
//! fresh window. Bitcoin Core's analogue is `-maxuploadtarget`, which also
//! stops serving blocks once reached (`ProcessGetBlockData`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default cap: 100 MB of blocks per day while metered.
pub(crate) const METERED_DAILY_UPLOAD_CAP: u64 = 100 * 1_000_000;

/// How long one window lasts before the count resets.
const WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

pub(crate) struct UploadBudget {
    cap: u64,
    metered: AtomicBool,
    /// Bytes counted in the current window, and when it started.
    window: Mutex<(u64, Instant)>,
}

impl UploadBudget {
    pub(crate) fn new(cap: u64) -> UploadBudget {
        UploadBudget {
            cap,
            metered: AtomicBool::new(false),
            window: Mutex::new((0, Instant::now())),
        }
    }

    /// The network changed. Joining an unmetered network ends the window.
    pub(crate) fn set_metered(&self, metered: bool) {
        let was = self.metered.swap(metered, Ordering::Relaxed);
        if was && !metered {
            *self.window.lock().unwrap() = (0, Instant::now());
        }
    }

    /// Count an upload of `bytes`, if it fits: always on an unmetered
    /// network (nothing is counted), else only within the day's cap.
    pub(crate) fn try_spend(&self, bytes: u64) -> bool {
        self.try_spend_at(bytes, Instant::now())
    }

    fn try_spend_at(&self, bytes: u64, now: Instant) -> bool {
        if !self.metered.load(Ordering::Relaxed) {
            return true;
        }
        let mut window = self.window.lock().unwrap();
        if now.saturating_duration_since(window.1) >= WINDOW {
            *window = (0, now);
        }
        if window.0.saturating_add(bytes) > self.cap {
            return false;
        }
        window.0 += bytes;
        true
    }

    #[cfg(test)]
    pub(crate) fn spent(&self) -> u64 {
        self.window.lock().unwrap().0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmetered_uploads_are_never_capped_or_counted() {
        let b = UploadBudget::new(1_000);
        for _ in 0..10 {
            assert!(b.try_spend(4_000_000));
        }
        assert_eq!(b.spent(), 0);
    }

    #[test]
    fn metered_uploads_stop_at_the_cap() {
        let b = UploadBudget::new(1_000);
        b.set_metered(true);
        assert!(b.try_spend(600));
        assert!(b.try_spend(400), "exactly the cap fits");
        assert!(!b.try_spend(1), "past the cap");
        // A refused upload isn't counted.
        assert_eq!(b.spent(), 1_000);
    }

    #[test]
    fn window_resets_after_a_day() {
        let b = UploadBudget::new(1_000);
        b.set_metered(true);
        let start = Instant::now();
        assert!(b.try_spend_at(1_000, start));
        assert!(!b.try_spend_at(1, start + WINDOW - Duration::from_secs(1)));
        assert!(b.try_spend_at(1_000, start + WINDOW), "a new day");
    }

    #[test]
    fn joining_an_unmetered_network_resets_the_window() {
        let b = UploadBudget::new(1_000);
        b.set_metered(true);
        assert!(b.try_spend(1_000));
        assert!(!b.try_spend(1));
        b.set_metered(false);
        b.set_metered(true);
        assert!(b.try_spend(1_000), "back on cellular with a fresh budget");
        // Staying metered (a repeated signal) keeps the count.
        b.set_metered(true);
        assert!(!b.try_spend(1));
    }
}
