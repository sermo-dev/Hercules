use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{info, warn};
use rusqlite::{params, Connection};

/// Persistent storage for peer reputation scores and ban list.
///
/// Lives in a small SQLite file alongside the headers/utxo/blocks DBs. The
/// in-memory `PeerPool` is the source of truth during a session; this store
/// just lets reputations and bans survive restarts so a peer that was banned
/// on Tuesday can't reconnect on Wednesday by virtue of `nsurlsessiond`
/// killing the process.
///
/// Wall clock times (Unix seconds) are stored on disk and converted to/from
/// `Instant` at the boundary, since `Instant` is monotonic and meaningless
/// across process restarts.
pub struct PeerStore {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct PeerStoreError(pub String);

impl std::fmt::Display for PeerStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerStoreError: {}", self.0)
    }
}

impl std::error::Error for PeerStoreError {}

impl PeerStore {
    /// Open or create the peer store at `path`. Pass `:memory:` for tests.
    pub fn open(path: &str) -> Result<PeerStore, PeerStoreError> {
        let conn =
            Connection::open(path).map_err(|e| PeerStoreError(format!("open: {}", e)))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| PeerStoreError(format!("set WAL: {}", e)))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| PeerStoreError(format!("set synchronous: {}", e)))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS peer_scores (
                addr TEXT PRIMARY KEY,
                score INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS peer_bans (
                addr TEXT PRIMARY KEY,
                expiry_unix INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| PeerStoreError(format!("create tables: {}", e)))?;

        info!("Peer store opened at {}", path);
        Ok(PeerStore {
            conn: Mutex::new(conn),
        })
    }

    /// Persist (or upsert) a single peer's reputation score.
    pub fn save_score(&self, addr: &str, score: i32) -> Result<(), PeerStoreError> {
        let now = unix_now();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO peer_scores (addr, score, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(addr) DO UPDATE SET score = excluded.score, updated_at = excluded.updated_at",
            params![addr, score, now as i64],
        )
        .map_err(|e| PeerStoreError(format!("save_score: {}", e)))?;
        Ok(())
    }

    /// Persist (or upsert) many scores in a single transaction. Used by the
    /// pool's periodic flush so a busy session isn't writing on every reward.
    pub fn save_scores_bulk(&self, entries: &[(String, i32)]) -> Result<(), PeerStoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        let now = unix_now() as i64;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| PeerStoreError(format!("begin tx: {}", e)))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO peer_scores (addr, score, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(addr) DO UPDATE SET score = excluded.score, updated_at = excluded.updated_at",
                )
                .map_err(|e| PeerStoreError(format!("prepare: {}", e)))?;
            for (addr, score) in entries {
                stmt.execute(params![addr, score, now])
                    .map_err(|e| PeerStoreError(format!("save: {}", e)))?;
            }
        }
        tx.commit()
            .map_err(|e| PeerStoreError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Look up a previously persisted score for `addr`, if any.
    pub fn load_score(&self, addr: &str) -> Result<Option<i32>, PeerStoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT score FROM peer_scores WHERE addr = ?1")
            .map_err(|e| PeerStoreError(format!("prepare: {}", e)))?;
        let mut rows = stmt
            .query(params![addr])
            .map_err(|e| PeerStoreError(format!("query: {}", e)))?;
        match rows.next().map_err(|e| PeerStoreError(format!("row: {}", e)))? {
            Some(row) => Ok(Some(
                row.get::<_, i32>(0)
                    .map_err(|e| PeerStoreError(format!("get: {}", e)))?,
            )),
            None => Ok(None),
        }
    }

    /// Persist a ban. `expiry` is an `Instant` in the current process's clock;
    /// we convert to a Unix timestamp on disk.
    pub fn save_ban(&self, addr: &str, expiry: Instant) -> Result<(), PeerStoreError> {
        let expiry_unix = instant_to_unix(expiry);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO peer_bans (addr, expiry_unix) VALUES (?1, ?2)
             ON CONFLICT(addr) DO UPDATE SET expiry_unix = excluded.expiry_unix",
            params![addr, expiry_unix as i64],
        )
        .map_err(|e| PeerStoreError(format!("save_ban: {}", e)))?;
        Ok(())
    }

    /// Remove a ban (e.g., expired or manually cleared).
    pub fn delete_ban(&self, addr: &str) -> Result<(), PeerStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM peer_bans WHERE addr = ?1", params![addr])
            .map_err(|e| PeerStoreError(format!("delete_ban: {}", e)))?;
        Ok(())
    }

    /// Load all currently active (non-expired) bans into a HashMap keyed by
    /// address. Expired entries are pruned during this call so the on-disk
    /// table doesn't grow unbounded.
    pub fn load_active_bans(&self) -> Result<HashMap<String, Instant>, PeerStoreError> {
        let now_unix = unix_now() as i64;
        let mut conn = self.conn.lock().unwrap();

        // Drop anything already expired before we read.
        let pruned = conn
            .execute(
                "DELETE FROM peer_bans WHERE expiry_unix <= ?1",
                params![now_unix],
            )
            .map_err(|e| PeerStoreError(format!("prune expired: {}", e)))?;
        if pruned > 0 {
            info!("PeerStore: pruned {} expired ban(s) on load", pruned);
        }

        let tx = conn
            .transaction()
            .map_err(|e| PeerStoreError(format!("begin tx: {}", e)))?;
        let mut out = HashMap::new();
        {
            let mut stmt = tx
                .prepare("SELECT addr, expiry_unix FROM peer_bans")
                .map_err(|e| PeerStoreError(format!("prepare: {}", e)))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(|e| PeerStoreError(format!("query: {}", e)))?;
            for r in rows {
                let (addr, expiry_unix) =
                    r.map_err(|e| PeerStoreError(format!("row: {}", e)))?;
                if let Some(instant) = unix_to_instant(expiry_unix as u64) {
                    out.insert(addr, instant);
                }
            }
        }
        tx.commit()
            .map_err(|e| PeerStoreError(format!("commit: {}", e)))?;
        Ok(out)
    }
}

/// Current Unix timestamp in seconds. Falls back to 0 if the system clock is
/// before the epoch (won't happen on iOS but the type signature requires it).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_else(|e| {
            warn!("PeerStore: system clock before UNIX_EPOCH: {}", e);
            0
        })
}

/// Convert an `Instant` (relative to the current process's monotonic clock)
/// into an absolute Unix timestamp by walking the offset from `Instant::now()`.
fn instant_to_unix(instant: Instant) -> u64 {
    let now = Instant::now();
    let unix_now_v = unix_now();
    if instant >= now {
        unix_now_v + instant.duration_since(now).as_secs()
    } else {
        unix_now_v.saturating_sub(now.duration_since(instant).as_secs())
    }
}

/// Convert an absolute Unix timestamp back into an `Instant`. Returns `None`
/// if the timestamp is already in the past (the caller treats it as "not a
/// live ban anymore"). Bans far in the future are clamped to one year from
/// now to defend against a corrupted DB row claiming year 2099.
fn unix_to_instant(expiry_unix: u64) -> Option<Instant> {
    let now_unix = unix_now();
    if expiry_unix <= now_unix {
        return None;
    }
    let delta = expiry_unix - now_unix;
    let one_year_secs: u64 = 365 * 24 * 3600;
    let delta = delta.min(one_year_secs);
    Some(Instant::now() + Duration::from_secs(delta))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() -> PeerStore {
        PeerStore::open(":memory:").unwrap()
    }

    #[test]
    fn save_and_load_score_roundtrip() {
        let store = fresh_store();
        store.save_score("1.2.3.4:8333", 150).unwrap();
        assert_eq!(store.load_score("1.2.3.4:8333").unwrap(), Some(150));
        assert_eq!(store.load_score("9.9.9.9:8333").unwrap(), None);
    }

    #[test]
    fn save_score_overwrites_existing() {
        let store = fresh_store();
        store.save_score("peer:8333", 100).unwrap();
        store.save_score("peer:8333", 30).unwrap();
        assert_eq!(store.load_score("peer:8333").unwrap(), Some(30));
    }

    #[test]
    fn bulk_save_writes_all_entries() {
        let store = fresh_store();
        let batch = vec![
            ("a:8333".to_string(), 50),
            ("b:8333".to_string(), 100),
            ("c:8333".to_string(), 200),
        ];
        store.save_scores_bulk(&batch).unwrap();
        assert_eq!(store.load_score("a:8333").unwrap(), Some(50));
        assert_eq!(store.load_score("b:8333").unwrap(), Some(100));
        assert_eq!(store.load_score("c:8333").unwrap(), Some(200));
    }

    #[test]
    fn bulk_save_empty_is_noop() {
        let store = fresh_store();
        store.save_scores_bulk(&[]).unwrap();
    }

    #[test]
    fn save_and_load_active_ban() {
        let store = fresh_store();
        let expiry = Instant::now() + Duration::from_secs(3600);
        store.save_ban("bad.peer:8333", expiry).unwrap();
        let bans = store.load_active_bans().unwrap();
        assert!(bans.contains_key("bad.peer:8333"));
        // The recovered Instant should be in the future.
        assert!(bans["bad.peer:8333"] > Instant::now());
    }

    #[test]
    fn delete_ban_removes_entry() {
        let store = fresh_store();
        let expiry = Instant::now() + Duration::from_secs(3600);
        store.save_ban("bad.peer:8333", expiry).unwrap();
        store.delete_ban("bad.peer:8333").unwrap();
        let bans = store.load_active_bans().unwrap();
        assert!(bans.is_empty());
    }

    #[test]
    fn unix_to_instant_returns_none_for_past_timestamps() {
        // 1970 is way in the past — should be treated as not-a-ban.
        assert!(unix_to_instant(1).is_none());
    }

    #[test]
    fn unix_to_instant_clamps_far_future() {
        // 50 years from now → clamped to 1 year, but still returns Some.
        let fifty_years = unix_now() + 50 * 365 * 24 * 3600;
        let instant = unix_to_instant(fifty_years).unwrap();
        let one_year = Duration::from_secs(366 * 24 * 3600);
        assert!(instant <= Instant::now() + one_year);
    }

    #[test]
    fn instant_to_unix_then_back_roundtrip() {
        let original = Instant::now() + Duration::from_secs(7200);
        let unix = instant_to_unix(original);
        let recovered = unix_to_instant(unix).unwrap();
        // Allow a few seconds of slack for clock reads between calls.
        let diff = if recovered > original {
            recovered.duration_since(original)
        } else {
            original.duration_since(recovered)
        };
        assert!(diff < Duration::from_secs(5));
    }
}
