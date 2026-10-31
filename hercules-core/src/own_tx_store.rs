//! The user's own transactions (ticket 033): submission errors, the
//! private-broadcast hook for ticket 029, and a persisted tracker that
//! drives rebroadcast until each transaction confirms, is replaced, is
//! conflicted out, or expires.
//!
//! The tracker is a small SQLite table next to the block store. The
//! mempool is in memory, so without it an app kill before peers fetched
//! the transaction would lose it silently.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use bitcoin::block::Block;
use bitcoin::consensus::deserialize;
use bitcoin::{OutPoint, Transaction, Txid};
use log::{info, warn};
use rusqlite::{params, Connection, OptionalExtension};

use crate::mempool::MempoolError;

/// How long an unconfirmed own transaction is rebroadcast before we give
/// up and mark it `Expired`. Matches the mempool's 14-day expiry, which is
/// also Bitcoin Core's default, so peers would have forgotten it by then.
pub const PENDING_EXPIRY_SECS: u64 = 14 * 24 * 3600;

/// How long a row in a terminal state (confirmed, replaced, conflicted,
/// expired) is kept for status queries before it is deleted. Longer than
/// the 288-block reorg window (~2 days), so a confirmation that gets
/// reorged out can still be demoted back to pending.
pub const TERMINAL_RETENTION_SECS: u64 = 7 * 24 * 3600;

/// First rebroadcast delay after an announcement; doubles per attempt.
pub const REBROADCAST_BASE_SECS: u64 = 60;

/// Rebroadcast backoff cap while pending. Every new foreground sync
/// session also makes all pending transactions due immediately, whatever
/// their backoff.
pub const REBROADCAST_MAX_SECS: u64 = 3600;

/// Once a peer has announced it back (propagated), an own transaction is
/// resent only every `PROPAGATED_RESEND_MIN_SECS` plus a uniform random
/// part of up to `PROPAGATED_RESEND_JITTER_SECS` (12–36h), like Bitcoin
/// Core's wallet. A fast, regular resend of a tx the network already has
/// is a fingerprint: only the originator keeps re-announcing it.
pub const PROPAGATED_RESEND_MIN_SECS: u64 = 12 * 3600;
pub const PROPAGATED_RESEND_JITTER_SECS: u64 = 24 * 3600;

/// Distinct announcing peers remembered per own transaction. Past this the
/// count stops growing (and nothing more is written), so a peer that
/// reconnects over and over can't turn `inv`s into SQLite writes.
const MAX_SEEN_PEERS_PER_TX: usize = 256;

// ── Submission API types ───────────────────────────────────────────────

/// Result of a successful own-transaction submission.
#[derive(Debug, Clone)]
pub struct OwnTxReceipt {
    pub txid: Txid,
    /// Non-fatal notes, e.g. "our own relay policy would filter this",
    /// meaning similarly-filtering nodes may not relay it either.
    pub warnings: Vec<String>,
}

/// Why an own transaction was refused. Each variant is a different thing
/// for the user to do about it.
#[derive(Debug, Clone, PartialEq)]
pub enum SubmitError {
    /// Bytes don't deserialize as a transaction.
    Decode(String),
    /// Consensus-invalid: bad script/signature, missing or spent input,
    /// immature coinbase, outputs exceed inputs. No node will ever accept
    /// it.
    Consensus(String),
    /// Timelocked: valid only once its nLockTime or a BIP 68 relative lock
    /// is reached, which it isn't for the next block on top of the tip we
    /// validate against (`validated_height`, which may lag the header tip
    /// while the node catches up). Nothing was sent; the same bytes can be
    /// submitted again later. Not a verdict that the tx is invalid.
    NotYetFinal { reason: String, validated_height: u32, tip_height: u32 },
    /// Consensus-valid but fails network standardness (dust, non-standard
    /// output type, too heavy, too many unconfirmed ancestors), so peers
    /// would not relay it.
    NonStandard(String),
    /// Fee rate below the relay floor (or below what a full mempool would
    /// keep). `min` is in sat/vB.
    FeeTooLow { fee_rate: f64, min: f64 },
    /// Absolute fee above the safety ceiling — almost certainly a wallet bug.
    AbsurdFee { fee: u64, limit: u64 },
    /// Double-spends mempool transaction(s) and doesn't qualify as a
    /// replacement (BIP 125 fee rules).
    Conflict { conflicts: Vec<Txid>, reason: String },
    /// Already in our mempool. Not a failure: it is now tracked as an own
    /// transaction and was re-announced. Callers that want idempotent
    /// "send" semantics treat this as success.
    AlreadyKnown { txid: Txid },
    /// Our UTXO set isn't caught up far enough to judge the inputs.
    NotSynced { validated_height: u32, tip_height: u32 },
    /// Local storage/lookup failure.
    Internal(String),
}

impl SubmitError {
    /// Map a mempool rejection of an own transaction. `lagging` is true
    /// when the UTXO set is behind the header tip, in which case a
    /// missing input may just be one we haven't validated yet.
    pub fn from_mempool(
        e: MempoolError,
        lagging: bool,
        validated_height: u32,
        tip_height: u32,
        conflicts: Vec<Txid>,
    ) -> SubmitError {
        use MempoolError as M;
        let msg = e.to_string();
        match e {
            M::MissingInput { .. } if lagging => SubmitError::NotSynced {
                validated_height,
                tip_height,
            },
            // A wallet sets nLockTime to the tip it sees (anti-fee-sniping).
            // If that is the header tip and our UTXO set lags, the tx is
            // final as soon as we catch up (ticket 026 judges finality at
            // validated_height + 1, as Core's CheckFinalTxAtTip).
            M::NonFinal { lock_time, .. }
                if lagging
                    && lock_time < crate::contextual_checks::LOCKTIME_THRESHOLD
                    && lock_time <= tip_height =>
            {
                SubmitError::NotSynced {
                    validated_height,
                    tip_height,
                }
            }
            M::NonFinal { lock_time, .. } => SubmitError::NotYetFinal {
                reason: if lock_time < crate::contextual_checks::LOCKTIME_THRESHOLD {
                    format!("its nLockTime is block height {}", lock_time)
                } else {
                    format!(
                        "its nLockTime is time {} (compared with the median time of recent blocks)",
                        lock_time
                    )
                },
                validated_height,
                tip_height,
            },
            M::NonBip68Final { min_height, min_time, .. } => SubmitError::NotYetFinal {
                // The lock points cover all inputs; either or both can be
                // set (-1 = none), so name every condition that applies.
                reason: {
                    let mut needs = Vec::new();
                    if min_height >= 0 {
                        needs.push(format!("a block after height {}", min_height));
                    }
                    if min_time >= 0 {
                        needs.push(format!(
                            "the median time of recent blocks to pass {}",
                            min_time
                        ));
                    }
                    format!(
                        "an input's relative timelock (BIP 68) needs {}",
                        needs.join(" and ")
                    )
                },
                validated_height,
                tip_height,
            },
            M::CoinbaseTx
            | M::MalformedTx
            | M::DuplicateInput { .. }
            | M::ValueOutOfRange { .. }
            | M::MissingInput { .. }
            | M::ImmatureCoinbase { .. }
            | M::ScriptFailure { .. }
            | M::Inflation
            | M::MathOverflow => SubmitError::Consensus(msg),
            M::OversizedTx { .. }
            | M::DustOutput { .. }
            | M::NonStandardScript { .. }
            | M::NonStandardVersion { .. }
            | M::NonStandardScriptSig { .. }
            | M::TooManySigops { .. }
            | M::PolicyRejection(_)
            | M::TooManyAncestors { .. }
            | M::AncestorSetTooLarge { .. }
            | M::TooManyDescendants { .. } => SubmitError::NonStandard(msg),
            M::InsufficientFee { fee_rate, min_rate } => SubmitError::FeeTooLow {
                fee_rate,
                min: min_rate,
            },
            M::MempoolFull {
                new_fee_rate,
                min_pkg_fee_rate,
            } => SubmitError::FeeTooLow {
                fee_rate: new_fee_rate,
                min: min_pkg_fee_rate,
            },
            M::AbsurdFee { fee, limit } => SubmitError::AbsurdFee { fee, limit },
            M::TooManyReplacements { .. }
            | M::ReplacementAddsUnconfirmed { .. }
            | M::ReplacementFeeTooLow { .. }
            | M::ReplacementFeeInsufficient { .. } => SubmitError::Conflict {
                conflicts,
                reason: msg,
            },
            M::AlreadyInMempool => SubmitError::Internal(
                "already in mempool (should be handled by caller)".into(),
            ),
            M::UtxoLookup(s) | M::ChainContext(s) => SubmitError::Internal(s),
            // Our verifier failed, not the transaction (ticket 047).
            M::ScriptVerifierError { .. } => SubmitError::Internal(msg),
        }
    }

    /// Short machine-readable kind, used by the 014 RPC and FFI.
    pub fn kind(&self) -> &'static str {
        match self {
            SubmitError::Decode(_) => "decode",
            SubmitError::Consensus(_) => "consensus",
            SubmitError::NotYetFinal { .. } => "not_yet_final",
            SubmitError::NonStandard(_) => "non_standard",
            SubmitError::FeeTooLow { .. } => "fee_too_low",
            SubmitError::AbsurdFee { .. } => "absurd_fee",
            SubmitError::Conflict { .. } => "conflict",
            SubmitError::AlreadyKnown { .. } => "already_known",
            SubmitError::NotSynced { .. } => "not_synced",
            SubmitError::Internal(_) => "internal",
        }
    }
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubmitError::Decode(s) => write!(f, "invalid transaction encoding: {}", s),
            SubmitError::Consensus(s) => write!(f, "consensus-invalid: {}", s),
            SubmitError::NotYetFinal {
                reason,
                validated_height,
                tip_height,
            } => {
                write!(
                    f,
                    "timelocked, not valid yet: {}, not reached for the next block \
                     (after height {}); nothing was sent, submit it again once the lock passes",
                    reason, validated_height
                )?;
                if validated_height < tip_height {
                    write!(
                        f,
                        " (this node is still catching up to height {}, so it may already be valid)",
                        tip_height
                    )?;
                }
                Ok(())
            }
            SubmitError::NonStandard(s) => {
                write!(f, "non-standard (peers will not relay it): {}", s)
            }
            SubmitError::FeeTooLow { fee_rate, min } => write!(
                f,
                "fee rate {:.2} sat/vB too low (minimum {:.2} sat/vB)",
                fee_rate, min
            ),
            SubmitError::AbsurdFee { fee, limit } => write!(
                f,
                "absurd fee: {} sats exceeds safety ceiling {} sats",
                fee, limit
            ),
            SubmitError::Conflict { conflicts, reason } => {
                let ids: Vec<String> = conflicts.iter().map(|t| t.to_string()).collect();
                write!(f, "conflicts with mempool tx [{}]: {}", ids.join(", "), reason)
            }
            SubmitError::AlreadyKnown { txid } => write!(f, "transaction {} already known", txid),
            SubmitError::NotSynced {
                validated_height,
                tip_height,
            } => write!(
                f,
                "node not synced: UTXO set at height {}, headers at {}",
                validated_height, tip_height
            ),
            SubmitError::Internal(s) => write!(f, "internal error: {}", s),
        }
    }
}

impl std::error::Error for SubmitError {}

/// Transport for sending own transactions over short-lived connections
/// that are separate from our regular peers (ticket 029 "private
/// broadcast": a few fresh Tor connections, send the tx, disconnect).
///
/// When one is installed with `HeaderSync::set_private_broadcast`, own
/// transactions are handed to it *instead of* being announced on our
/// regular connections, so our regular (possibly clearnet) connections are
/// never the first to relay them. Without one (today's Tor-only node),
/// own transactions are `inv`-announced to every connected peer at once.
pub trait PrivateBroadcast: Send + Sync {
    /// Send `tx`. Returns how many peers took it. An `Err` leaves the
    /// transaction pending; the rebroadcast schedule retries it. It must
    /// not silently fall back to clearnet (029).
    fn broadcast(&self, tx: &Transaction) -> Result<usize, String>;
}

// ── Tracker ────────────────────────────────────────────────────────────

/// Lifecycle of a tracked own transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnTxStatus {
    /// Announced (or waiting to be); no peer has announced it back yet.
    Pending,
    /// At least one peer announced it back to us — it's on the network.
    /// Still rebroadcast (with backoff) until it confirms.
    Propagated,
    Confirmed { height: u32 },
    /// Replaced by another own transaction (RBF fee bump / cancel).
    Replaced { by: Txid },
    /// An input was spent by a different transaction that confirmed.
    Conflicted { by: Txid },
    /// Not confirmed within `PENDING_EXPIRY_SECS`; no longer rebroadcast.
    Expired,
}

impl OwnTxStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, OwnTxStatus::Pending | OwnTxStatus::Propagated)
    }

    pub fn name(&self) -> &'static str {
        match self {
            OwnTxStatus::Pending => "pending",
            OwnTxStatus::Propagated => "propagated",
            OwnTxStatus::Confirmed { .. } => "confirmed",
            OwnTxStatus::Replaced { .. } => "replaced",
            OwnTxStatus::Conflicted { .. } => "conflicted",
            OwnTxStatus::Expired => "expired",
        }
    }

    fn to_row(&self) -> (&'static str, Option<u32>, Option<String>) {
        match self {
            OwnTxStatus::Confirmed { height } => (self.name(), Some(*height), None),
            OwnTxStatus::Replaced { by } | OwnTxStatus::Conflicted { by } => {
                (self.name(), None, Some(by.to_string()))
            }
            _ => (self.name(), None, None),
        }
    }

    fn from_row(name: &str, height: Option<u32>, other: Option<String>) -> OwnTxStatus {
        let other_txid = other.and_then(|s| s.parse::<Txid>().ok());
        match (name, height, other_txid) {
            ("propagated", _, _) => OwnTxStatus::Propagated,
            ("confirmed", Some(h), _) => OwnTxStatus::Confirmed { height: h },
            ("replaced", _, Some(by)) => OwnTxStatus::Replaced { by },
            ("conflicted", _, Some(by)) => OwnTxStatus::Conflicted { by },
            ("expired", _, _) => OwnTxStatus::Expired,
            _ => OwnTxStatus::Pending,
        }
    }
}

/// One tracked own transaction. Times are unix seconds.
#[derive(Debug, Clone)]
pub struct OwnTxRecord {
    pub txid: Txid,
    pub raw: Vec<u8>,
    pub first_sent_at: u64,
    /// 0 until the first announcement.
    pub last_sent_at: u64,
    pub next_attempt_at: u64,
    pub attempts: u32,
    /// Number of distinct peers that announced this tx to us.
    pub seen_from_peers: u32,
    pub status: OwnTxStatus,
    pub updated_at: u64,
}

impl OwnTxRecord {
    pub fn tx(&self) -> Option<Transaction> {
        deserialize(&self.raw).ok()
    }
}

#[derive(Debug)]
pub struct OwnTxStoreError(pub String);

impl std::fmt::Display for OwnTxStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "own tx store: {}", self.0)
    }
}

impl std::error::Error for OwnTxStoreError {}

fn db_err(e: rusqlite::Error) -> OwnTxStoreError {
    OwnTxStoreError(e.to_string())
}

/// Delay before the next rebroadcast of a *pending* tx after `attempts`
/// announcements.
pub fn rebroadcast_backoff_secs(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(16);
    (REBROADCAST_BASE_SECS << shift).min(REBROADCAST_MAX_SECS)
}

/// Randomized resend interval for a *propagated* tx (12–36h).
pub fn propagated_resend_secs() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let r = RandomState::new().build_hasher().finish();
    PROPAGATED_RESEND_MIN_SECS + r % (PROPAGATED_RESEND_JITTER_SECS + 1)
}

/// Persisted tracker of the user's own transactions.
pub struct OwnTxStore {
    conn: Mutex<Connection>,
    /// Txids in an active state -> whether they have propagated, cached so
    /// the per-`inv` / `getdata` / `mempool` checks in the message loop
    /// don't hit SQLite.
    active: Mutex<HashMap<Txid, bool>>,
    /// Txids `on_block` has to look at: active rows plus `replaced` and
    /// `expired` ones, which may still confirm. Empty means blocks (IBD)
    /// skip the hook entirely.
    watched: Mutex<HashSet<Txid>>,
    /// Peers already counted in `seen_from_peers`, per active txid, so an
    /// `inv` flood costs a hash lookup rather than a SQLite write. Backed
    /// by the `own_tx_seen` table so the count stays distinct across
    /// restarts.
    seen_peers: Mutex<HashMap<Txid, HashSet<String>>>,
}

/// Statuses `on_block` settles: active ones (confirm or conflict), and
/// `replaced` / `expired` ones, which can still confirm (the original of
/// an RBF bump wins the race, or a tx we gave up on gets mined).
const WATCHED_STATUSES: &str = "('pending', 'propagated', 'replaced', 'expired')";

const SELECT_COLS: &str = "txid, raw, first_sent_at, last_sent_at, next_attempt_at, attempts, \
     seen_from_peers, status, status_height, status_txid, updated_at";

impl OwnTxStore {
    /// Open or create the tracker at `path` (`":memory:"` for tests).
    pub fn open(path: &str) -> Result<OwnTxStore, OwnTxStoreError> {
        let conn = Connection::open(path).map_err(db_err)?;
        conn.busy_timeout(crate::store::SQLITE_BUSY_TIMEOUT).map_err(db_err)?;
        if path != ":memory:" {
            conn.pragma_update(None, "journal_mode", "WAL").map_err(db_err)?;
        }
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS own_txs (
                txid TEXT PRIMARY KEY,
                raw BLOB NOT NULL,
                first_sent_at INTEGER NOT NULL,
                last_sent_at INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                seen_from_peers INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                status_height INTEGER,
                status_txid TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS own_tx_seen (
                txid TEXT NOT NULL,
                peer TEXT NOT NULL,
                PRIMARY KEY (txid, peer)
            );
            ",
        )
        .map_err(db_err)?;
        let store = OwnTxStore {
            conn: Mutex::new(conn),
            active: Mutex::new(HashMap::new()),
            watched: Mutex::new(HashSet::new()),
            seen_peers: Mutex::new(HashMap::new()),
        };
        store.refresh_active()?;
        Ok(store)
    }

    fn refresh_active(&self) -> Result<(), OwnTxStoreError> {
        let watched = self.query(&format!("WHERE status IN {}", WATCHED_STATUSES), &[])?;
        let active: HashMap<Txid, bool> = watched
            .iter()
            .filter(|r| r.status.is_active())
            .map(|r| (r.txid, r.status == OwnTxStatus::Propagated))
            .collect();
        self.seen_peers
            .lock()
            .unwrap()
            .retain(|t, _| active.contains_key(t));
        *self.watched.lock().unwrap() = watched.iter().map(|r| r.txid).collect();
        *self.active.lock().unwrap() = active;
        Ok(())
    }

    fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<OwnTxRecord> {
        let txid_s: String = row.get(0)?;
        let status: String = row.get(7)?;
        Ok(OwnTxRecord {
            txid: txid_s.parse().map_err(|_| {
                rusqlite::Error::InvalidColumnType(0, "txid".into(), rusqlite::types::Type::Text)
            })?,
            raw: row.get(1)?,
            first_sent_at: row.get::<_, i64>(2)? as u64,
            last_sent_at: row.get::<_, i64>(3)? as u64,
            next_attempt_at: row.get::<_, i64>(4)? as u64,
            attempts: row.get(5)?,
            seen_from_peers: row.get(6)?,
            status: OwnTxStatus::from_row(&status, row.get(8)?, row.get(9)?),
            updated_at: row.get::<_, i64>(10)? as u64,
        })
    }

    fn query(&self, where_sql: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<OwnTxRecord>, OwnTxStoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!("SELECT {} FROM own_txs {}", SELECT_COLS, where_sql);
        let mut stmt = conn.prepare(&sql).map_err(db_err)?;
        let rows = stmt
            .query_map(args, Self::row_to_record)
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;
        Ok(rows)
    }

    /// Start tracking `txid` as pending and due for announcement now. If
    /// it is already tracked: an active row is left alone (but made due);
    /// an expired row is revived. Returns true if a new row was created.
    pub fn track(&self, txid: Txid, raw: &[u8], now: u64) -> Result<bool, OwnTxStoreError> {
        let inserted = {
            let conn = self.conn.lock().unwrap();
            let n = conn
                .execute(
                    "INSERT OR IGNORE INTO own_txs (txid, raw, first_sent_at, next_attempt_at, status, updated_at)
                     VALUES (?1, ?2, ?3, ?3, 'pending', ?3)",
                    params![txid.to_string(), raw, now as i64],
                )
                .map_err(db_err)?;
            if n == 0 {
                conn.execute(
                    "UPDATE own_txs SET next_attempt_at = ?2,
                        status = CASE WHEN status = 'expired' THEN 'pending' ELSE status END,
                        first_sent_at = CASE WHEN status = 'expired' THEN ?2 ELSE first_sent_at END,
                        updated_at = ?2
                     WHERE txid = ?1 AND status IN ('pending', 'propagated', 'expired')",
                    params![txid.to_string(), now as i64],
                )
                .map_err(db_err)?;
            }
            n > 0
        };
        self.refresh_active()?;
        Ok(inserted)
    }

    pub fn get(&self, txid: &Txid) -> Result<Option<OwnTxRecord>, OwnTxStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            &format!("SELECT {} FROM own_txs WHERE txid = ?1", SELECT_COLS),
            params![txid.to_string()],
            Self::row_to_record,
        )
        .optional()
        .map_err(db_err)
    }

    /// Every tracked transaction, newest first.
    pub fn list(&self) -> Result<Vec<OwnTxRecord>, OwnTxStoreError> {
        self.query("ORDER BY first_sent_at DESC, txid", &[])
    }

    /// Transactions still being rebroadcast.
    pub fn active_records(&self) -> Result<Vec<OwnTxRecord>, OwnTxStoreError> {
        self.query("WHERE status IN ('pending', 'propagated') ORDER BY first_sent_at", &[])
    }

    /// Active transactions whose next rebroadcast is due at `now`.
    pub fn due(&self, now: u64) -> Result<Vec<OwnTxRecord>, OwnTxStoreError> {
        let now = now as i64;
        self.query(
            "WHERE status IN ('pending', 'propagated') AND next_attempt_at <= ?1 ORDER BY first_sent_at",
            &[&now],
        )
    }

    /// True if `txid` is tracked and still active (cheap, in-memory).
    pub fn is_active(&self, txid: &Txid) -> bool {
        self.active.lock().unwrap().contains_key(txid)
    }

    /// True if `txid` is active and no peer has announced it back yet
    /// (cheap, in-memory). Such a tx must not leak out other than by our
    /// own deliberate announcement (BIP 35 `mempool`, unsolicited
    /// `getdata`).
    pub fn is_pending(&self, txid: &Txid) -> bool {
        self.active.lock().unwrap().get(txid) == Some(&false)
    }

    /// Record an announcement at `now` and schedule the next one: the
    /// doubling backoff while pending, 12–36h once propagated.
    pub fn record_sent(&self, txid: &Txid, now: u64) -> Result<(), OwnTxStoreError> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(u32, String)> = conn
            .query_row(
                "SELECT attempts, status FROM own_txs WHERE txid = ?1",
                params![txid.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;
        let Some((attempts, status)) = row else { return Ok(()) };
        let attempts = attempts.saturating_add(1);
        let next = if status == "propagated" {
            now + propagated_resend_secs()
        } else {
            now + rebroadcast_backoff_secs(attempts)
        };
        conn.execute(
            "UPDATE own_txs SET attempts = ?2, last_sent_at = ?3, next_attempt_at = ?4 WHERE txid = ?1",
            params![txid.to_string(), attempts, now as i64, next as i64],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Make every pending transaction due now (new foreground session).
    /// Propagated ones keep their 12–36h schedule: the network already has
    /// them, and resending at every app launch would be a fingerprint.
    pub fn make_all_due(&self, now: u64) -> Result<(), OwnTxStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE own_txs SET next_attempt_at = ?1 WHERE status = 'pending'",
            params![now as i64],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// `peer` announced this transaction back to us. Each (peer, txid)
    /// pair is counted, and written, at most once; repeats are an
    /// in-memory lookup. The first one moves a pending tx to propagated
    /// and onto the slow resend schedule.
    pub fn record_seen(&self, txid: &Txid, peer: &str, now: u64) -> Result<(), OwnTxStoreError> {
        if !self.is_active(txid) {
            return Ok(());
        }
        {
            let mut seen = self.seen_peers.lock().unwrap();
            let peers = seen.entry(*txid).or_default();
            if peers.contains(peer) || peers.len() >= MAX_SEEN_PEERS_PER_TX {
                return Ok(());
            }
            peers.insert(peer.to_string());
        }
        let conn = self.conn.lock().unwrap();
        let new_peer = conn
            .execute(
                "INSERT OR IGNORE INTO own_tx_seen (txid, peer) VALUES (?1, ?2)",
                params![txid.to_string(), peer],
            )
            .map_err(db_err)?;
        if new_peer == 0 {
            // Counted in an earlier run.
            return Ok(());
        }
        let propagated_now = conn
            .execute(
                "UPDATE own_txs SET status = 'propagated', next_attempt_at = ?2
                 WHERE txid = ?1 AND status = 'pending'",
                params![txid.to_string(), (now + propagated_resend_secs()) as i64],
            )
            .map_err(db_err)?;
        conn.execute(
            "UPDATE own_txs SET seen_from_peers = seen_from_peers + 1, updated_at = ?2
             WHERE txid = ?1 AND status IN ('pending', 'propagated')",
            params![txid.to_string(), now as i64],
        )
        .map_err(db_err)?;
        drop(conn);
        if propagated_now > 0 {
            if let Some(p) = self.active.lock().unwrap().get_mut(txid) {
                *p = true;
            }
        }
        Ok(())
    }

    /// Write `status`, plus `status_height` for statuses whose variant
    /// doesn't carry one (a conflict's block height), in one UPDATE.
    /// Doesn't refresh the in-memory caches; callers do, once per batch.
    fn write_status(
        &self,
        txid: &Txid,
        status: &OwnTxStatus,
        extra_height: Option<u32>,
        now: u64,
    ) -> Result<(), OwnTxStoreError> {
        let (name, height, other) = status.to_row();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE own_txs SET status = ?2, status_height = ?3, status_txid = ?4, updated_at = ?5
             WHERE txid = ?1",
            params![txid.to_string(), name, height.or(extra_height), other, now as i64],
        )
        .map_err(db_err)?;
        Ok(())
    }

    #[cfg(test)]
    fn set_status(&self, txid: &Txid, status: &OwnTxStatus, now: u64) -> Result<(), OwnTxStoreError> {
        self.write_status(txid, status, None, now)?;
        self.refresh_active()
    }

    /// `old` was replaced in the mempool by the user's own `by`. Own
    /// descendants of `old` lose their inputs with it and are marked
    /// conflicted by `by` (with no height: no block caused it, so a reorg
    /// doesn't undo it).
    pub fn mark_replaced(&self, old: &Txid, by: Txid, now: u64) -> Result<(), OwnTxStoreError> {
        if self.is_active(old) {
            info!("Own tx {} replaced by {}", old, by);
            self.write_status(old, &OwnTxStatus::Replaced { by }, None, now)?;
            self.cascade_conflict(vec![*old], by, None, now)?;
            self.refresh_active()?;
        }
        Ok(())
    }

    /// Mark every active own tx that spends an output of one of `roots`,
    /// transitively, as conflicted by `by`. `height` is the block that
    /// caused it (so `demote_confirmed_above` undoes the whole chain on a
    /// reorg), or None for an RBF replacement. Returns the rows changed.
    fn cascade_conflict(
        &self,
        roots: Vec<Txid>,
        by: Txid,
        height: Option<u32>,
        now: u64,
    ) -> Result<usize, OwnTxStoreError> {
        let mut active: Vec<(Txid, Transaction)> = self
            .active_records()?
            .into_iter()
            .filter_map(|r| Some((r.txid, r.tx()?)))
            .collect();
        let mut queue = roots;
        let mut changed = 0;
        while let Some(parent) = queue.pop() {
            let mut i = 0;
            while i < active.len() {
                if active[i].1.input.iter().any(|inp| inp.previous_output.txid == parent) {
                    let (child, _) = active.swap_remove(i);
                    warn!("Own tx {} conflicted: spends {}, conflicted by {}", child, parent, by);
                    self.write_status(&child, &OwnTxStatus::Conflicted { by }, height, now)?;
                    queue.push(child);
                    changed += 1;
                } else {
                    i += 1;
                }
            }
        }
        Ok(changed)
    }

    /// Block-connect hook. Own transactions in `block` become confirmed:
    /// active ones, and also `replaced` (the original of an RBF bump won)
    /// and `expired` ones. Active ones whose inputs `block` spends with a
    /// different transaction become conflicted, and so do their own
    /// descendants (see `cascade_conflict`); those rows record `height` so
    /// a reorg can undo them. Returns the number of rows changed.
    ///
    /// Idempotent: re-running it for the same block (crash recovery)
    /// changes nothing more.
    pub fn on_block(&self, block: &Block, height: u32, now: u64) -> Result<usize, OwnTxStoreError> {
        if self.watched.lock().unwrap().is_empty() {
            return Ok(0);
        }
        let watched = self.query(
            &format!("WHERE status IN {} ORDER BY first_sent_at", WATCHED_STATUSES),
            &[],
        )?;
        let block_txids: HashSet<Txid> = block.txdata.iter().map(|t| t.compute_txid()).collect();
        let mut changed = 0;
        for rec in &watched {
            if block_txids.contains(&rec.txid) {
                info!(
                    "Own tx {} confirmed at height {} (was {})",
                    rec.txid,
                    height,
                    rec.status.name()
                );
                self.write_status(&rec.txid, &OwnTxStatus::Confirmed { height }, None, now)?;
                changed += 1;
            }
        }
        // Conflicts are judged after confirmations, so a replacement whose
        // original just confirmed is conflicted by it.
        let spent: HashMap<OutPoint, Txid> = block
            .txdata
            .iter()
            .filter(|t| !t.is_coinbase())
            .flat_map(|t| {
                let id = t.compute_txid();
                t.input.iter().map(move |i| (i.previous_output, id))
            })
            .collect();
        let mut by_conflict: HashMap<Txid, Vec<Txid>> = HashMap::new();
        for rec in &watched {
            if !rec.status.is_active() || block_txids.contains(&rec.txid) {
                continue;
            }
            let Some(own) = rec.tx() else { continue };
            let by = own
                .input
                .iter()
                .find_map(|oi| spent.get(&oi.previous_output).filter(|s| **s != rec.txid));
            if let Some(by) = by {
                warn!(
                    "Own tx {} conflicted: input spent by {} at height {}",
                    rec.txid, by, height
                );
                // status_height lets a reorg that removes this block demote
                // it back to pending (see demote_confirmed_above).
                self.write_status(&rec.txid, &OwnTxStatus::Conflicted { by: *by }, Some(height), now)?;
                by_conflict.entry(*by).or_default().push(rec.txid);
                changed += 1;
            }
        }
        for (by, roots) in by_conflict {
            changed += self.cascade_conflict(roots, by, Some(height), now)?;
        }
        if changed > 0 {
            self.refresh_active()?;
        }
        Ok(changed)
    }

    /// Reorg hook: confirmations and conflicts recorded above `fork_height`
    /// are undone, so those transactions go back to pending and are due for
    /// rebroadcast (a re-add that still conflicts is settled again by the
    /// next block). Also run at open with the validated height, to finish
    /// a reorg (or undo a block hook) that a crash interrupted.
    ///
    /// A confirmed row goes back to pending even if it was `replaced` or
    /// `expired` before it confirmed: the prior status isn't kept. The
    /// rebroadcast path settles that again (a replaced original loses the
    /// RBF race in the mempool again; an old one re-expires).
    pub fn demote_confirmed_above(&self, fork_height: u32, now: u64) -> Result<usize, OwnTxStoreError> {
        let n = {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "UPDATE own_txs SET status = 'pending', status_height = NULL, status_txid = NULL,
                        next_attempt_at = ?2, updated_at = ?2
                 WHERE status IN ('confirmed', 'conflicted') AND status_height > ?1",
                params![fork_height, now as i64],
            )
            .map_err(db_err)?
        };
        if n > 0 {
            info!("Reorg: {} own txs demoted to pending", n);
            self.refresh_active()?;
        }
        Ok(n)
    }

    /// Expire stale pending rows and delete old terminal rows. Only call
    /// this when the UTXO set is caught up with the headers: while it lags,
    /// an "unconfirmed" tx may well be in a block we haven't validated yet.
    pub fn expire(&self, now: u64) -> Result<(), OwnTxStoreError> {
        {
            let conn = self.conn.lock().unwrap();
            let expired = conn
                .execute(
                    "UPDATE own_txs SET status = 'expired', updated_at = ?1
                     WHERE status IN ('pending', 'propagated') AND first_sent_at + ?2 <= ?1",
                    params![now as i64, PENDING_EXPIRY_SECS as i64],
                )
                .map_err(db_err)?;
            if expired > 0 {
                warn!("{} own txs expired unconfirmed; rebroadcast stopped", expired);
            }
            conn.execute(
                "DELETE FROM own_txs WHERE status NOT IN ('pending', 'propagated') AND updated_at + ?2 <= ?1",
                params![now as i64, TERMINAL_RETENTION_SECS as i64],
            )
            .map_err(db_err)?;
            conn.execute(
                "DELETE FROM own_tx_seen WHERE txid NOT IN
                    (SELECT txid FROM own_txs WHERE status IN ('pending', 'propagated'))",
                [],
            )
            .map_err(db_err)?;
        }
        self.refresh_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use tempfile::TempDir;

    fn txid(b: u8) -> Txid {
        Txid::from_byte_array([b; 32])
    }

    #[test]
    fn tracks_and_persists_across_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("own_txs.sqlite3");
        let path = path.to_str().unwrap();
        {
            let s = OwnTxStore::open(path).unwrap();
            assert!(s.track(txid(1), &[1, 2, 3], 1000).unwrap());
            assert!(!s.track(txid(1), &[1, 2, 3], 1001).unwrap(), "idempotent");
            s.record_sent(&txid(1), 1000).unwrap();
            s.record_seen(&txid(1), "peer-a", 1002).unwrap();
        }
        let s = OwnTxStore::open(path).unwrap();
        assert!(s.is_active(&txid(1)), "active cache rebuilt on open");
        let r = s.get(&txid(1)).unwrap().unwrap();
        assert_eq!(r.raw, vec![1, 2, 3]);
        assert_eq!(r.attempts, 1);
        assert_eq!(r.seen_from_peers, 1);
        assert_eq!(r.status, OwnTxStatus::Propagated);
        assert_eq!(r.first_sent_at, 1000);
        assert_eq!(r.last_sent_at, 1000);
    }

    #[test]
    fn rebroadcast_schedule_backs_off_and_session_resets() {
        let s = OwnTxStore::open(":memory:").unwrap();
        s.track(txid(1), &[0], 0).unwrap();
        assert_eq!(s.due(0).unwrap().len(), 1, "new tx due immediately");

        s.record_sent(&txid(1), 0).unwrap();
        assert!(s.due(59).unwrap().is_empty());
        assert_eq!(s.due(60).unwrap().len(), 1, "first retry after base delay");

        s.record_sent(&txid(1), 60).unwrap();
        assert!(s.due(60 + 119).unwrap().is_empty());
        assert_eq!(s.due(60 + 120).unwrap().len(), 1, "doubles");

        assert_eq!(rebroadcast_backoff_secs(1), REBROADCAST_BASE_SECS);
        assert_eq!(rebroadcast_backoff_secs(50), REBROADCAST_MAX_SECS, "capped");

        s.record_sent(&txid(1), 200).unwrap();
        assert!(s.due(201).unwrap().is_empty());
        s.make_all_due(201).unwrap();
        assert_eq!(s.due(201).unwrap().len(), 1, "new session makes it due");
    }

    #[test]
    fn replaced_and_expired_stop_rebroadcast() {
        let s = OwnTxStore::open(":memory:").unwrap();
        s.track(txid(1), &[0], 0).unwrap();
        s.track(txid(2), &[0], 0).unwrap();
        s.mark_replaced(&txid(1), txid(3), 5).unwrap();
        assert!(!s.is_active(&txid(1)));
        assert_eq!(
            s.get(&txid(1)).unwrap().unwrap().status,
            OwnTxStatus::Replaced { by: txid(3) }
        );

        s.expire(PENDING_EXPIRY_SECS).unwrap();
        assert_eq!(s.get(&txid(2)).unwrap().unwrap().status, OwnTxStatus::Expired);
        assert!(s.due(PENDING_EXPIRY_SECS).unwrap().is_empty());

        // Terminal rows are deleted after the retention window.
        s.expire(PENDING_EXPIRY_SECS + TERMINAL_RETENTION_SECS).unwrap();
        assert!(s.get(&txid(1)).unwrap().is_none());
        assert!(s.get(&txid(2)).unwrap().is_none());
    }

    #[test]
    fn reorg_demotes_conflicted_above_fork() {
        // A block that conflicted our tx is reorged out: the conflict may no
        // longer exist, so the tx must become pending again (and be retried),
        // while a conflict below the fork stays terminal.
        let s = OwnTxStore::open(":memory:").unwrap();
        s.track(txid(1), &[0], 0).unwrap();
        s.track(txid(2), &[0], 0).unwrap();
        s.write_status(&txid(1), &OwnTxStatus::Conflicted { by: txid(9) }, Some(100), 1).unwrap();
        s.write_status(&txid(2), &OwnTxStatus::Conflicted { by: txid(8) }, Some(90), 1).unwrap();
        s.refresh_active().unwrap();
        assert_eq!(s.demote_confirmed_above(95, 2).unwrap(), 1);
        assert_eq!(s.get(&txid(1)).unwrap().unwrap().status, OwnTxStatus::Pending);
        assert!(s.is_active(&txid(1)));
        assert_eq!(
            s.get(&txid(2)).unwrap().unwrap().status,
            OwnTxStatus::Conflicted { by: txid(8) }
        );
    }

    #[test]
    fn reorg_demotes_confirmed_above_fork() {
        let s = OwnTxStore::open(":memory:").unwrap();
        s.track(txid(1), &[0], 0).unwrap();
        s.track(txid(2), &[0], 0).unwrap();
        s.set_status(&txid(1), &OwnTxStatus::Confirmed { height: 100 }, 1).unwrap();
        s.set_status(&txid(2), &OwnTxStatus::Confirmed { height: 90 }, 1).unwrap();
        assert_eq!(s.demote_confirmed_above(95, 2).unwrap(), 1);
        assert_eq!(s.get(&txid(1)).unwrap().unwrap().status, OwnTxStatus::Pending);
        assert!(s.is_active(&txid(1)));
        assert_eq!(
            s.get(&txid(2)).unwrap().unwrap().status,
            OwnTxStatus::Confirmed { height: 90 }
        );
    }

    /// One-in, one-out tx spending `prev`, made distinct by `tag`.
    fn tx_spending(prev: OutPoint, tag: u8) -> Transaction {
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Sequence, TxIn, TxOut, Witness};
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prev,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000 + tag as u64),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn out(tx: &Transaction) -> OutPoint {
        OutPoint { txid: tx.compute_txid(), vout: 0 }
    }

    fn track_tx(s: &OwnTxStore, tx: &Transaction) -> Txid {
        s.track(tx.compute_txid(), &bitcoin::consensus::serialize(tx), 0).unwrap();
        tx.compute_txid()
    }

    fn block_of(txs: Vec<Transaction>) -> Block {
        let mut b = crate::p2p::tests::synthetic_block(3);
        b.txdata.extend(txs);
        b
    }

    fn status(s: &OwnTxStore, t: &Txid) -> OwnTxStatus {
        s.get(t).unwrap().unwrap().status
    }

    #[test]
    fn propagated_tx_moves_to_slow_randomized_schedule() {
        let s = OwnTxStore::open(":memory:").unwrap();
        s.track(txid(1), &[0], 0).unwrap();
        s.track(txid(2), &[0], 0).unwrap();
        s.record_sent(&txid(1), 0).unwrap();
        s.record_sent(&txid(2), 0).unwrap();
        assert!(s.is_pending(&txid(1)));

        // First peer announcing it back: off the 60s schedule, onto 12-36h.
        s.record_seen(&txid(1), "peer-a", 10).unwrap();
        assert!(!s.is_pending(&txid(1)) && s.is_active(&txid(1)));
        let in_window = |at: u64, from: u64| {
            at >= from + PROPAGATED_RESEND_MIN_SECS
                && at <= from + PROPAGATED_RESEND_MIN_SECS + PROPAGATED_RESEND_JITTER_SECS
        };
        let r = s.get(&txid(1)).unwrap().unwrap();
        assert!(in_window(r.next_attempt_at, 10), "{}", r.next_attempt_at);
        // Further sends stay on it.
        s.record_sent(&txid(1), 100).unwrap();
        let r = s.get(&txid(1)).unwrap().unwrap();
        assert!(in_window(r.next_attempt_at, 100), "{}", r.next_attempt_at);
        let due: Vec<Txid> = s.due(100 + REBROADCAST_MAX_SECS).unwrap().iter().map(|r| r.txid).collect();
        assert_eq!(due, vec![txid(2)], "only the pending tx is on the fast schedule");

        // A new session makes pending txs due, not propagated ones.
        s.make_all_due(200).unwrap();
        let due: Vec<Txid> = s.due(200).unwrap().iter().map(|r| r.txid).collect();
        assert_eq!(due, vec![txid(2)]);
    }

    #[test]
    fn record_seen_counts_distinct_peers_once() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("own_txs.sqlite3");
        let path = path.to_str().unwrap();
        {
            let s = OwnTxStore::open(path).unwrap();
            s.track(txid(1), &[0], 0).unwrap();
            for i in 1..1000 {
                s.record_seen(&txid(1), "peer-a", i).unwrap();
            }
            assert_eq!(s.get(&txid(1)).unwrap().unwrap().seen_from_peers, 1);
            // The flood wrote once: updated_at is from the first inv.
            assert_eq!(s.get(&txid(1)).unwrap().unwrap().updated_at, 1);
            s.record_seen(&txid(1), "peer-b", 5).unwrap();
            assert_eq!(s.get(&txid(1)).unwrap().unwrap().seen_from_peers, 2);
            // Untracked txids are ignored.
            s.record_seen(&txid(9), "peer-a", 5).unwrap();
            assert!(s.get(&txid(9)).unwrap().is_none());
        }
        // Distinct across restarts too.
        let s = OwnTxStore::open(path).unwrap();
        s.record_seen(&txid(1), "peer-a", 6).unwrap();
        assert_eq!(s.get(&txid(1)).unwrap().unwrap().seen_from_peers, 2);
        s.record_seen(&txid(1), "peer-c", 7).unwrap();
        assert_eq!(s.get(&txid(1)).unwrap().unwrap().seen_from_peers, 3);
    }

    #[test]
    fn replaced_or_expired_tx_that_confirms_is_settled() {
        let s = OwnTxStore::open(":memory:").unwrap();
        let prev = OutPoint { txid: txid(50), vout: 0 };
        let a = tx_spending(prev, 1);
        let b = tx_spending(prev, 2); // RBF replacement of a
        let (ta, tb) = (track_tx(&s, &a), track_tx(&s, &b));
        s.mark_replaced(&ta, tb, 1).unwrap();

        // The original wins: it confirms, and the replacement is conflicted
        // by it (at that height, so a reorg would undo it).
        assert_eq!(s.on_block(&block_of(vec![a.clone()]), 100, 2).unwrap(), 2);
        assert_eq!(status(&s, &ta), OwnTxStatus::Confirmed { height: 100 });
        assert_eq!(status(&s, &tb), OwnTxStatus::Conflicted { by: ta });
        assert_eq!(s.demote_confirmed_above(99, 3).unwrap(), 2);

        // A tx we stopped rebroadcasting can still get mined.
        let s = OwnTxStore::open(":memory:").unwrap();
        let c = tx_spending(OutPoint { txid: txid(51), vout: 0 }, 3);
        let tc = track_tx(&s, &c);
        s.expire(PENDING_EXPIRY_SECS).unwrap();
        assert_eq!(status(&s, &tc), OwnTxStatus::Expired);
        assert_eq!(s.on_block(&block_of(vec![c]), 120, PENDING_EXPIRY_SECS).unwrap(), 1);
        assert_eq!(status(&s, &tc), OwnTxStatus::Confirmed { height: 120 });
    }

    #[test]
    fn conflict_cascades_to_descendants_and_reorg_undoes_it() {
        let s = OwnTxStore::open(":memory:").unwrap();
        let prev = OutPoint { txid: txid(50), vout: 0 };
        let parent = tx_spending(prev, 1);
        let child = tx_spending(out(&parent), 2);
        let grandchild = tx_spending(out(&child), 3);
        let unrelated = tx_spending(OutPoint { txid: txid(51), vout: 0 }, 4);
        let ids: Vec<Txid> = [&parent, &child, &grandchild, &unrelated]
            .iter()
            .map(|t| track_tx(&s, t))
            .collect();

        let double_spend = tx_spending(prev, 9);
        let by = double_spend.compute_txid();
        assert_eq!(s.on_block(&block_of(vec![double_spend]), 100, 1).unwrap(), 3);
        for t in &ids[..3] {
            assert_eq!(status(&s, t), OwnTxStatus::Conflicted { by });
            assert!(!s.is_active(t));
        }
        assert!(s.is_active(&ids[3]));

        // All three were conflicted by block 100, so a reorg below it
        // restores all three.
        assert_eq!(s.demote_confirmed_above(99, 2).unwrap(), 3);
        for t in &ids[..3] {
            assert_eq!(status(&s, t), OwnTxStatus::Pending);
        }
    }

    #[test]
    fn replacement_cascades_to_descendants() {
        let s = OwnTxStore::open(":memory:").unwrap();
        let prev = OutPoint { txid: txid(50), vout: 0 };
        let parent = tx_spending(prev, 1);
        let child = tx_spending(out(&parent), 2);
        let grandchild = tx_spending(out(&child), 3);
        let bump = tx_spending(prev, 4);
        let (tp, tc, tg, tb) = (
            track_tx(&s, &parent),
            track_tx(&s, &child),
            track_tx(&s, &grandchild),
            track_tx(&s, &bump),
        );
        s.mark_replaced(&tp, tb, 1).unwrap();
        assert_eq!(status(&s, &tp), OwnTxStatus::Replaced { by: tb });
        assert_eq!(status(&s, &tc), OwnTxStatus::Conflicted { by: tb });
        assert_eq!(status(&s, &tg), OwnTxStatus::Conflicted { by: tb });
        assert!(s.is_active(&tb));
        // No block caused it, so no reorg undoes it.
        assert_eq!(s.demote_confirmed_above(0, 2).unwrap(), 0);
    }

    #[test]
    fn classification_of_mempool_errors() {
        let c = |e| SubmitError::from_mempool(e, false, 10, 10, vec![]);
        assert!(matches!(c(MempoolError::Inflation), SubmitError::Consensus(_)));
        assert!(matches!(
            c(MempoolError::ScriptFailure { input_index: 0, error: "x".into() }),
            SubmitError::Consensus(_)
        ));
        assert!(matches!(
            c(MempoolError::ScriptVerifierError { input_index: 0, error: "x".into() }),
            SubmitError::Internal(_)
        ));
        assert!(matches!(
            c(MempoolError::DustOutput { index: 0, amount: 1, threshold: 294 }),
            SubmitError::NonStandard(_)
        ));
        assert!(matches!(
            c(MempoolError::InsufficientFee { fee_rate: 0.5, min_rate: 1.0 }),
            SubmitError::FeeTooLow { .. }
        ));
        assert!(matches!(
            c(MempoolError::AbsurdFee { fee: 1, limit: 0 }),
            SubmitError::AbsurdFee { .. }
        ));
        let r = SubmitError::from_mempool(
            MempoolError::ReplacementFeeTooLow { replacement: 1.0, conflict: 2.0 },
            false,
            10,
            10,
            vec![txid(9)],
        );
        assert_eq!(r.kind(), "conflict");
        assert!(matches!(r, SubmitError::Conflict { ref conflicts, .. } if conflicts == &vec![txid(9)]));

        // A missing input while the UTXO set lags the headers is NotSynced,
        // not a consensus verdict.
        let missing = || MempoolError::MissingInput { txid: txid(1), vout: 0 };
        assert!(matches!(c(missing()), SubmitError::Consensus(_)));
        assert_eq!(
            SubmitError::from_mempool(missing(), true, 5, 10, vec![]),
            SubmitError::NotSynced { validated_height: 5, tip_height: 10 }
        );

        // Same for a height locktime the header tip already satisfies
        // (ticket 026). Beyond the header tip it is timelocked: not valid
        // *yet*, never a consensus verdict.
        let non_final = |lock_time| MempoolError::NonFinal { lock_time, current_height: 5 };
        assert_eq!(
            SubmitError::from_mempool(non_final(10), true, 5, 10, vec![]),
            SubmitError::NotSynced { validated_height: 5, tip_height: 10 }
        );
        let lagging = SubmitError::from_mempool(non_final(11), true, 5, 10, vec![]);
        assert!(matches!(lagging, SubmitError::NotYetFinal { validated_height: 5, tip_height: 10, .. }));
        assert_eq!(lagging.kind(), "not_yet_final");
        let text = lagging.to_string();
        assert!(text.contains("height 11") && text.contains("catching up"), "{}", text);
        assert!(!text.contains("consensus"), "{}", text);

        let synced = c(non_final(11));
        assert!(matches!(synced, SubmitError::NotYetFinal { .. }), "{:?}", synced);
        assert!(!synced.to_string().contains("catching up"), "{}", synced);
        let time_locked = c(MempoolError::NonFinal { lock_time: 1_700_000_000, current_height: 10 });
        assert!(time_locked.to_string().contains("time 1700000000"), "{}", time_locked);

        let bip68 = c(MempoolError::NonBip68Final { min_height: 20, min_time: -1, current_height: 10 });
        assert!(matches!(bip68, SubmitError::NotYetFinal { .. }), "{:?}", bip68);
        assert!(bip68.to_string().contains("after height 20"), "{}", bip68);
        let bip68_time = c(MempoolError::NonBip68Final { min_height: -1, min_time: 1_700_000_000, current_height: 10 });
        assert!(bip68_time.to_string().contains("pass 1700000000"), "{}", bip68_time);
        assert!(!bip68_time.to_string().contains("a block after height"), "{}", bip68_time);
        let both = c(MempoolError::NonBip68Final { min_height: 20, min_time: 1_700_000_000, current_height: 10 });
        assert!(
            both.to_string().contains("after height 20 and the median time of recent blocks to pass 1700000000"),
            "{}",
            both
        );
        assert!(matches!(
            crate::BroadcastError::from(bip68),
            crate::BroadcastError::NotYetFinal { .. }
        ));
        assert!(matches!(c(MempoolError::ChainContext("x".into())), SubmitError::Internal(_)));
    }

    // ── Data-path pass: every transition, its boundaries, restarts ───

    #[test]
    fn checktransaction_rejections_are_consensus_errors() {
        let c = |e| SubmitError::from_mempool(e, false, 10, 10, vec![]);
        assert_eq!(c(MempoolError::DuplicateInput { input_index: 1 }).kind(), "consensus");
        assert_eq!(c(MempoolError::ValueOutOfRange { what: "output", amount: 1 }).kind(), "consensus");
        // Even while lagging: a duplicate input is never "not synced yet".
        assert_eq!(
            SubmitError::from_mempool(MempoolError::DuplicateInput { input_index: 1 }, true, 5, 10, vec![]).kind(),
            "consensus"
        );
    }

    #[test]
    fn backoff_schedule_doubles_from_a_minute_to_an_hour() {
        let table = [(0u32, 60u64), (1, 60), (2, 120), (3, 240), (4, 480), (5, 960), (6, 1920), (7, 3600), (17, 3600), (u32::MAX, 3600)];
        for (attempts, secs) in table {
            assert_eq!(rebroadcast_backoff_secs(attempts), secs, "after {} attempts", attempts);
        }
    }

    #[test]
    fn propagated_resend_is_jittered_within_12_to_36_hours() {
        let samples: Vec<u64> = (0..2_000).map(|_| propagated_resend_secs()).collect();
        assert!(samples.iter().all(|s| (12 * 3600..=36 * 3600).contains(s)));
        // Jittered, and spread over most of the window.
        let (min, max) = (samples.iter().min().unwrap(), samples.iter().max().unwrap());
        assert!(max - min > 20 * 3600, "{}..{}", min, max);
    }

    #[test]
    fn due_is_inclusive_of_the_scheduled_second() {
        let s = OwnTxStore::open(":memory:").unwrap();
        s.track(txid(1), &[0], 1_000).unwrap();
        assert_eq!(s.due(1_000).unwrap().len(), 1, "due right away");
        s.record_sent(&txid(1), 1_000).unwrap();
        assert!(s.due(1_059).unwrap().is_empty());
        assert_eq!(s.due(1_060).unwrap().len(), 1);
        // A new foreground session makes pending txs due regardless.
        s.record_sent(&txid(1), 1_060).unwrap();
        s.make_all_due(1_061).unwrap();
        assert_eq!(s.due(1_061).unwrap().len(), 1);
    }

    #[test]
    fn expiry_and_retention_boundaries() {
        let s = OwnTxStore::open(":memory:").unwrap();
        let t0 = 1_000_000;
        s.track(txid(1), &[0], t0).unwrap();
        s.expire(t0 + PENDING_EXPIRY_SECS - 1).unwrap();
        assert_eq!(status(&s, &txid(1)), OwnTxStatus::Pending);
        let at = t0 + PENDING_EXPIRY_SECS;
        s.expire(at).unwrap();
        assert_eq!(status(&s, &txid(1)), OwnTxStatus::Expired);
        assert!(!s.is_active(&txid(1)));
        // Terminal rows are kept for exactly the retention window.
        s.expire(at + TERMINAL_RETENTION_SECS - 1).unwrap();
        assert!(s.get(&txid(1)).unwrap().is_some());
        s.expire(at + TERMINAL_RETENTION_SECS).unwrap();
        assert!(s.get(&txid(1)).unwrap().is_none());
    }

    /// `track` revives an expired row (fresh expiry clock) but never
    /// resurrects a confirmed, replaced or conflicted one.
    #[test]
    fn track_revives_only_expired_rows() {
        let s = OwnTxStore::open(":memory:").unwrap();
        for (i, st) in [
            OwnTxStatus::Expired,
            OwnTxStatus::Confirmed { height: 5 },
            OwnTxStatus::Replaced { by: txid(99) },
            OwnTxStatus::Conflicted { by: txid(98) },
        ]
        .into_iter()
        .enumerate()
        {
            let t = txid(i as u8 + 1);
            s.track(t, &[0], 10).unwrap();
            s.set_status(&t, &st, 20).unwrap();
            assert!(!s.track(t, &[0], 30).unwrap(), "{:?}: not a new row", st);
            let rec = s.get(&t).unwrap().unwrap();
            if st == OwnTxStatus::Expired {
                assert_eq!(rec.status, OwnTxStatus::Pending);
                assert_eq!(rec.first_sent_at, 30, "expiry clock restarts");
                assert!(s.is_pending(&t));
            } else {
                assert_eq!(rec.status, st);
                assert!(!s.is_active(&t));
            }
        }
    }

    /// A reorg demotes confirmations and conflicts strictly above the fork
    /// height; the fork block itself stays.
    #[test]
    fn demotion_is_strictly_above_the_fork_height() {
        let s = OwnTxStore::open(":memory:").unwrap();
        let a = tx_spending(OutPoint { txid: txid(60), vout: 0 }, 1);
        let b = tx_spending(OutPoint { txid: txid(61), vout: 0 }, 2);
        let (ta, tb) = (track_tx(&s, &a), track_tx(&s, &b));
        s.on_block(&block_of(vec![a]), 100, 1).unwrap();
        s.on_block(&block_of(vec![b]), 101, 1).unwrap();
        assert_eq!(s.demote_confirmed_above(101, 2).unwrap(), 0);
        assert_eq!(s.demote_confirmed_above(100, 2).unwrap(), 1);
        assert_eq!(status(&s, &ta), OwnTxStatus::Confirmed { height: 100 });
        assert_eq!(status(&s, &tb), OwnTxStatus::Pending);
        assert_eq!(s.due(2).unwrap().len(), 1, "demoted tx is due for rebroadcast");
    }

    #[test]
    fn on_block_is_idempotent() {
        let s = OwnTxStore::open(":memory:").unwrap();
        let prev = OutPoint { txid: txid(70), vout: 0 };
        let mine = tx_spending(prev, 1);
        let other = tx_spending(OutPoint { txid: txid(71), vout: 0 }, 2);
        let (tm, to) = (track_tx(&s, &mine), track_tx(&s, &other));
        let rival = tx_spending(OutPoint { txid: txid(71), vout: 0 }, 9);
        let block = block_of(vec![mine, rival]);
        assert_eq!(s.on_block(&block, 50, 1).unwrap(), 2);
        assert_eq!(s.on_block(&block, 50, 2).unwrap(), 0);
        assert_eq!(status(&s, &tm), OwnTxStatus::Confirmed { height: 50 });
        assert!(matches!(status(&s, &to), OwnTxStatus::Conflicted { .. }));
    }

    #[test]
    fn seen_peers_are_capped_and_inactive_txs_ignored() {
        let s = OwnTxStore::open(":memory:").unwrap();
        s.track(txid(1), &[0], 0).unwrap();
        for p in 0..MAX_SEEN_PEERS_PER_TX + 50 {
            s.record_seen(&txid(1), &format!("10.0.{}.{}:8333", p / 256, p % 256), 1).unwrap();
        }
        assert_eq!(s.get(&txid(1)).unwrap().unwrap().seen_from_peers as usize, MAX_SEEN_PEERS_PER_TX);
        assert_eq!(status(&s, &txid(1)), OwnTxStatus::Propagated);

        s.set_status(&txid(1), &OwnTxStatus::Confirmed { height: 3 }, 2).unwrap();
        s.record_seen(&txid(1), "1.2.3.4:8333", 3).unwrap();
        s.record_seen(&txid(2), "1.2.3.4:8333", 3).unwrap(); // never tracked
        assert_eq!(s.get(&txid(1)).unwrap().unwrap().seen_from_peers as usize, MAX_SEEN_PEERS_PER_TX);
        assert!(s.get(&txid(2)).unwrap().is_none());
    }

    /// Every status, including a block-caused vs an RBF-caused conflict,
    /// survives a restart with its in-memory caches rebuilt, and the
    /// rebuilt watch set still settles a `replaced` / `expired` tx that
    /// confirms after the restart.
    #[test]
    fn every_status_survives_restart() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("own.sqlite3");
        let p = path.to_str().unwrap();
        let txs: Vec<Transaction> = (0..7u8).map(|i| tx_spending(OutPoint { txid: txid(80 + i), vout: 0 }, i)).collect();
        let ids: Vec<Txid> = txs.iter().map(|t| t.compute_txid()).collect();
        let expected = {
            let s = OwnTxStore::open(p).unwrap();
            for t in &txs {
                track_tx(&s, t);
            }
            s.record_seen(&ids[1], "1.1.1.1:8333", 5).unwrap();
            s.on_block(&block_of(vec![txs[2].clone()]), 300, 5).unwrap();
            s.mark_replaced(&ids[3], ids[0], 5).unwrap();
            let rival = tx_spending(OutPoint { txid: txid(84), vout: 0 }, 50);
            s.on_block(&block_of(vec![rival]), 301, 5).unwrap();
            s.set_status(&ids[5], &OwnTxStatus::Expired, 5).unwrap();
            s.set_status(&ids[6], &OwnTxStatus::Conflicted { by: txid(1) }, 5).unwrap();
            ids.iter().map(|t| status(&s, t)).collect::<Vec<_>>()
        };
        let s = OwnTxStore::open(p).unwrap();
        assert_eq!(ids.iter().map(|t| status(&s, t)).collect::<Vec<_>>(), expected);
        assert!(s.is_pending(&ids[0]));
        assert!(s.is_active(&ids[1]) && !s.is_pending(&ids[1]));
        for t in &ids[2..] {
            assert!(!s.is_active(t));
        }
        // Block-caused conflict (301) is undone by a reorg below it; the
        // other two conflict rows aren't.
        assert_eq!(s.demote_confirmed_above(300, 6).unwrap(), 1);
        assert_eq!(status(&s, &ids[4]), OwnTxStatus::Pending);
        assert_eq!(status(&s, &ids[2]), OwnTxStatus::Confirmed { height: 300 });
        // Replaced and expired txs that confirm after the restart settle.
        assert_eq!(s.on_block(&block_of(vec![txs[3].clone(), txs[5].clone()]), 302, 7).unwrap(), 2);
        assert_eq!(status(&s, &ids[3]), OwnTxStatus::Confirmed { height: 302 });
        assert_eq!(status(&s, &ids[5]), OwnTxStatus::Confirmed { height: 302 });
    }

    /// Our child of someone else's transaction: when a rival spend of the
    /// parent's input confirms, the parent can never confirm, so neither
    /// can ours. It should be settled as conflicted, not rebroadcast for
    /// 14 days spending an output that will never exist.
    #[test]
    #[ignore = "BUG: an own tx whose (non-own) mempool parent is conflicted out by a block stays pending until the 14-day expiry; on_block only sees own txs' direct inputs"]
    fn own_child_of_a_conflicted_foreign_parent_is_settled() {
        let s = OwnTxStore::open(":memory:").unwrap();
        let theirs = tx_spending(OutPoint { txid: txid(90), vout: 0 }, 1);
        let mine = tx_spending(out(&theirs), 2);
        let tm = track_tx(&s, &mine);
        // The parent's input is spent by a different tx that confirms.
        let rival = tx_spending(OutPoint { txid: txid(90), vout: 0 }, 3);
        s.on_block(&block_of(vec![rival]), 400, 1).unwrap();
        assert!(matches!(status(&s, &tm), OwnTxStatus::Conflicted { .. }), "{:?}", status(&s, &tm));
    }
}
