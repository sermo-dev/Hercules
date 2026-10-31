use std::sync::Mutex;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rusqlite::{params, Connection};

use log::info;

/// How a node gets its UTXO set (ticket 054): from the AssumeUTXO
/// snapshot, or by validating every block from genesis. Part of the node's
/// identity for one database, recorded in the header store's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    AssumeUtxo,
    Genesis,
}

impl NodeMode {
    fn as_str(self) -> &'static str {
        match self {
            NodeMode::AssumeUtxo => "assumeutxo",
            NodeMode::Genesis => "genesis",
        }
    }

    fn from_str(s: &str) -> Option<NodeMode> {
        match s {
            "assumeutxo" => Some(NodeMode::AssumeUtxo),
            "genesis" => Some(NodeMode::Genesis),
            _ => None,
        }
    }
}

/// Persistent storage for block headers using SQLite.
pub struct HeaderStore {
    conn: Mutex<Connection>,
}

/// How long a SQLite write waits on another connection's lock before
/// failing with `SQLITE_BUSY` (ticket 028). One node per process means
/// there is normally no other connection; this is defense in depth.
pub(crate) const SQLITE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Put `conn` in WAL mode. Two connections switching a new file to WAL at
/// once both hold a shared lock and want it exclusive, and SQLite refuses
/// one of them "database is locked" at once (deadlock avoidance, so the
/// busy handler is never called and `busy_timeout` doesn't cover it): a
/// `PeerPool` that lost that race ran its whole session without saving
/// bans or scores. The mode is stored in the file, so one already in WAL
/// mode is left alone; otherwise retry for as long as the busy timeout
/// would have waited.
pub(crate) fn set_wal(conn: &Connection) -> rusqlite::Result<()> {
    let start = std::time::Instant::now();
    loop {
        let res = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .and_then(|mode| {
                if mode.eq_ignore_ascii_case("wal") {
                    Ok(())
                } else {
                    conn.pragma_update(None, "journal_mode", "WAL")
                }
            });
        match res {
            Err(rusqlite::Error::SqliteFailure(e, _))
                if matches!(e.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                    && start.elapsed() < SQLITE_BUSY_TIMEOUT =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

/// `headers.sqlite3` layout version (`PRAGMA user_version`, ticket 050).
///
/// History:
/// - 1: `headers`, `metadata`, `failed_blocks` (with `rules`) and
///   `failed_block_bans` keyed on (addr, hash). Files from before
///   versioning read 0 and are brought to this by the in-place fixups in
///   `HeaderStore::open`.
pub(crate) const HEADERS_SCHEMA_VERSION: u32 = 1;

/// The layout version (`PRAGMA user_version`) of the SQLite file behind
/// `conn`, read before anything touches its tables (ticket 050). A version
/// above `supported` was written by a newer build (the app was
/// downgraded): refused with an error saying so, since reading or
/// "migrating" a layout we don't know could corrupt it. 0 means the file
/// is new or predates versioning; the caller migrates anything below
/// `supported` and then calls `set_schema_version`.
pub(crate) fn check_schema_version(
    conn: &Connection,
    store: &str,
    supported: u32,
) -> Result<u32, String> {
    let found: u32 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|e| format!("read {} schema version: {}", store, e))?;
    if found > supported {
        return Err(format!(
            "the {} has layout version {}, newer than this build supports ({}): the app \
             was downgraded. Update the app, or reset the node to start over",
            store, found, supported
        ));
    }
    Ok(found)
}

/// Record `version` as the file's layout version, once its tables match it.
pub(crate) fn set_schema_version(conn: &Connection, store: &str, version: u32) -> Result<(), String> {
    conn.pragma_update(None, "user_version", version)
        .map_err(|e| format!("set {} schema version: {}", store, e))
}

impl HeaderStore {
    /// Open or create a header store at the given path.
    pub fn open(path: &str) -> Result<HeaderStore, StoreError> {
        let conn = Connection::open(path).map_err(|e| StoreError(format!("open: {}", e)))?;
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
            .map_err(|e| StoreError(format!("set busy_timeout: {}", e)))?;

        // Set WAL journal mode before any writes so that table creation
        // also benefits from WAL's crash-recovery semantics.
        set_wal(&conn).map_err(|e| StoreError(format!("set WAL: {}", e)))?;

        // Durable commits, matching the UTXO env (ticket 050 review): LMDB
        // commits with F_FULLFSYNC on Apple, and a plain fsync there only
        // reaches the drive's cache, so without this a power loss could
        // keep a block's UTXO apply and drop the `set_validated_height` (or
        // headers) committed after it. `synchronous = FULL` syncs the WAL on
        // every commit (NORMAL wouldn't in WAL mode), `fullfsync` makes
        // that sync an F_FULLFSYNC, `checkpoint_fullfsync` the same for
        // checkpoints. Cost: one F_FULLFSYNC per commit (a few ms to tens of
        // ms on iOS flash), i.e. per header batch and per connected block,
        // next to the one LMDB already pays. No-ops off Apple platforms.
        for (pragma, value) in [
            ("synchronous", "FULL"),
            ("fullfsync", "ON"),
            ("checkpoint_fullfsync", "ON"),
        ] {
            conn.pragma_update(None, pragma, value)
                .map_err(|e| StoreError(format!("set {}: {}", pragma, e)))?;
        }

        let version = check_schema_version(&conn, "header store", HEADERS_SCHEMA_VERSION)
            .map_err(StoreError)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS headers (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL UNIQUE,
                header BLOB NOT NULL,
                timestamp INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_headers_hash ON headers(hash);
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
",
        )
        .map_err(|e| StoreError(format!("create tables: {}", e)))?;

        // Ticket 024's failed-block tables. A development build briefly
        // created `failed_blocks` without the `rules` column; such rows have
        // no known rules version, so they are dropped like any other stale
        // row would be.
        if conn.prepare("SELECT rules FROM failed_blocks LIMIT 0").is_err() {
            conn.execute_batch("DROP TABLE IF EXISTS failed_blocks;")
                .map_err(|e| StoreError(format!("drop old failed_blocks: {}", e)))?;
        }
        // Development builds keyed `failed_block_bans` on `addr` alone, so a
        // peer banned for two failed blocks kept only the last; rekey it on
        // (addr, hash), keeping the rows, in one transaction so a kill
        // midway can't lose the table.
        let old_bans_schema: Option<String> = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'failed_block_bans'",
                [],
                |row| row.get(0),
            )
            .ok();
        if old_bans_schema.is_some_and(|sql| sql.contains("addr TEXT PRIMARY KEY")) {
            conn.execute_batch(
                "
                BEGIN;
                ALTER TABLE failed_block_bans RENAME TO failed_block_bans_old;
                CREATE TABLE failed_block_bans (
                    addr TEXT NOT NULL,
                    hash BLOB NOT NULL,
                    PRIMARY KEY (addr, hash)
                );
                INSERT INTO failed_block_bans (addr, hash)
                    SELECT addr, hash FROM failed_block_bans_old;
                DROP TABLE failed_block_bans_old;
                COMMIT;
                ",
            )
            .map_err(|e| StoreError(format!("rekey failed_block_bans: {}", e)))?;
        }
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS failed_blocks (
                hash BLOB PRIMARY KEY,
                height INTEGER NOT NULL,
                reason TEXT NOT NULL,
                rules TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS failed_block_bans (
                addr TEXT NOT NULL,
                hash BLOB NOT NULL,
                PRIMARY KEY (addr, hash)
            );
            ",
        )
        .map_err(|e| StoreError(format!("create failed-block tables: {}", e)))?;
        if version < HEADERS_SCHEMA_VERSION {
            set_schema_version(&conn, "header store", HEADERS_SCHEMA_VERSION).map_err(StoreError)?;
        }

        let store = HeaderStore {
            conn: Mutex::new(conn),
        };
        info!("Header store opened at {}", path);
        Ok(store)
    }

    /// Store a batch of validated headers starting at the given height.
    pub fn store_headers(
        &self,
        headers: &[Header],
        start_height: u32,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;

        let tx = conn
            .transaction()
            .map_err(|e| StoreError(format!("begin tx: {}", e)))?;

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT OR REPLACE INTO headers (height, hash, header, timestamp) VALUES (?1, ?2, ?3, ?4)",
                )
                .map_err(|e| StoreError(format!("prepare: {}", e)))?;

            for (i, header) in headers.iter().enumerate() {
                let height = start_height + i as u32;
                let hash = header.block_hash();
                let raw = serialize(header);

                stmt.execute(params![height, hash.to_byte_array().as_slice(), raw, header.time])
                    .map_err(|e| StoreError(format!("insert height {}: {}", height, e)))?;
            }
        }

        tx.commit()
            .map_err(|e| StoreError(format!("commit: {}", e)))?;

        Ok(())
    }

    /// Get the current chain tip (highest stored header).
    pub fn tip(&self) -> Result<Option<(u32, BlockHash, Header)>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;

        let result = conn
            .query_row(
                "SELECT height, hash, header FROM headers ORDER BY height DESC LIMIT 1",
                [],
                |row| {
                    let height: u32 = row.get(0)?;
                    let hash_bytes: Vec<u8> = row.get(1)?;
                    let header_bytes: Vec<u8> = row.get(2)?;
                    Ok((height, hash_bytes, header_bytes))
                },
            )
            .optional()
            .map_err(|e| StoreError(format!("query tip: {}", e)))?;

        match result {
            Some((height, hash_bytes, header_bytes)) => {
                let hash_array: [u8; 32] = hash_bytes
                    .try_into()
                    .map_err(|_| StoreError("invalid hash length".into()))?;
                let hash = BlockHash::from_byte_array(hash_array);
                let header: Header = deserialize(&header_bytes)
                    .map_err(|e| StoreError(format!("parse header: {}", e)))?;
                Ok(Some((height, hash, header)))
            }
            None => Ok(None),
        }
    }

    /// Get the last N timestamps for median time calculation.
    pub fn last_timestamps(&self, count: u32) -> Result<Vec<u32>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;

        let mut stmt = conn
            .prepare(
                "SELECT timestamp FROM headers ORDER BY height DESC LIMIT ?1",
            )
            .map_err(|e| StoreError(format!("prepare timestamps: {}", e)))?;

        let timestamps: Vec<u32> = stmt
            .query_map(params![count], |row| row.get(0))
            .map_err(|e| StoreError(format!("query timestamps: {}", e)))?
            .collect::<Result<Vec<u32>, _>>()
            .map_err(|e| StoreError(format!("read timestamp: {}", e)))?;

        // Reverse so they're in ascending height order
        let mut timestamps = timestamps;
        timestamps.reverse();
        Ok(timestamps)
    }

    /// Timestamps of the headers at heights `first..=last`, ascending, in
    /// one query (median-time-past reads 11 per block). Missing heights
    /// are simply absent; callers check the count.
    pub fn get_timestamps_between(&self, first: u32, last: u32) -> Result<Vec<u32>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT timestamp FROM headers WHERE height BETWEEN ?1 AND ?2 ORDER BY height",
            )
            .map_err(|e| StoreError(format!("prepare timestamps: {}", e)))?;
        let rows = stmt
            .query_map(params![first, last], |row| row.get(0))
            .map_err(|e| StoreError(format!("query timestamps {}..={}: {}", first, last, e)))?
            .collect::<Result<Vec<u32>, _>>()
            .map_err(|e| StoreError(format!("read timestamp: {}", e)));
        rows
    }

    /// Get the timestamp of a header at a specific height.
    pub fn get_timestamp_at(&self, height: u32) -> Result<Option<u32>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        conn.prepare_cached("SELECT timestamp FROM headers WHERE height = ?1")
            .and_then(|mut stmt| stmt.query_row(params![height], |row| row.get(0)))
            .optional()
        .map_err(|e| StoreError(format!("get timestamp at {}: {}", height, e)))
    }

    /// Get the block hash at a given height from the header chain.
    pub fn get_hash_at_height(&self, height: u32) -> Result<Option<BlockHash>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let result = conn
            .prepare_cached("SELECT hash FROM headers WHERE height = ?1")
            .and_then(|mut stmt| {
                stmt.query_row(params![height], |row| {
                    let hash_bytes: Vec<u8> = row.get(0)?;
                    Ok(hash_bytes)
                })
            })
            .optional()
            .map_err(|e| StoreError(format!("get hash at {}: {}", height, e)))?;

        match result {
            Some(hash_bytes) => {
                let hash_array: [u8; 32] = hash_bytes
                    .try_into()
                    .map_err(|_| StoreError("invalid hash length".into()))?;
                Ok(Some(BlockHash::from_byte_array(hash_array)))
            }
            None => Ok(None),
        }
    }

    /// Get the highest block height that has been structurally validated.
    /// Returns 0 if no blocks have been validated yet (genesis is implicit).
    pub fn validated_height(&self) -> Result<u32, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let result = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'validated_height'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| StoreError(format!("get validated_height: {}", e)))?;

        match result {
            Some(s) => s
                .parse::<u32>()
                .map_err(|e| StoreError(format!("parse validated_height: {}", e))),
            None => Ok(0),
        }
    }

    /// Update the highest structurally validated block height.
    pub fn set_validated_height(&self, height: u32) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('validated_height', ?1)",
            params![height.to_string()],
        )
        .map_err(|e| StoreError(format!("set validated_height: {}", e)))?;
        Ok(())
    }

    /// The validation mode this node was set up in (ticket 054), or `None`
    /// before one was recorded. Written once, at the first open that knows
    /// it; a mode switch goes through `reset_database`, which deletes this
    /// file, so the row never changes under a live chain.
    pub fn validation_mode(&self) -> Result<Option<NodeMode>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let value = conn
            .query_row(
                "SELECT value FROM metadata WHERE key = 'validation_mode'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| StoreError(format!("get validation_mode: {}", e)))?;
        match value {
            None => Ok(None),
            Some(s) => NodeMode::from_str(&s)
                .map(Some)
                .ok_or_else(|| StoreError(format!("unknown validation_mode {:?}", s))),
        }
    }

    /// Record the validation mode (see `validation_mode`).
    pub fn set_validation_mode(&self, mode: NodeMode) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('validation_mode', ?1)",
            params![mode.as_str()],
        )
        .map_err(|e| StoreError(format!("set validation_mode: {}", e)))?;
        Ok(())
    }

    /// Find the height of a block by its hash. Returns None if not found.
    pub fn find_height_of_hash(&self, hash: BlockHash) -> Result<Option<u32>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let result = conn.query_row(
            "SELECT height FROM headers WHERE hash = ?1",
            params![hash.to_byte_array().as_slice()],
            |row| row.get(0),
        );
        match result {
            Ok(height) => Ok(Some(height)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError(format!("find hash: {}", e))),
        }
    }

    /// Delete all headers above the given height (for reorg rollback).
    pub fn delete_headers_above(&self, height: u32) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let deleted = conn
            .execute("DELETE FROM headers WHERE height > ?1", params![height])
            .map_err(|e| StoreError(format!("delete headers above {}: {}", height, e)))?;
        info!("Deleted {} headers above height {}", deleted, height);
        Ok(())
    }

    /// Build a block locator for the getheaders P2P message.
    /// Returns hashes from the tip backwards: first 10 are consecutive,
    /// then exponentially spaced, always ending with genesis.
    pub fn get_locator_hashes(&self) -> Result<Vec<BlockHash>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;

        let tip_height: Option<u32> = conn
            .query_row("SELECT MAX(height) FROM headers", [], |row| row.get(0))
            .map_err(|e| StoreError(format!("max height: {}", e)))?;

        let tip_height = match tip_height {
            Some(h) => h,
            None => return Ok(Vec::new()),
        };

        // Build height list: first 10 consecutive, then exponentially spaced
        let mut heights = Vec::new();
        let mut h = tip_height as i64;
        let mut step: i64 = 1;
        while h >= 0 {
            heights.push(h as u32);
            if heights.len() >= 10 {
                step *= 2;
            }
            h -= step;
        }
        // Always include genesis
        if *heights.last().unwrap_or(&0) != 0 {
            heights.push(0);
        }

        let mut stmt = conn
            .prepare("SELECT hash FROM headers WHERE height = ?1")
            .map_err(|e| StoreError(format!("prepare locator: {}", e)))?;

        let mut hashes = Vec::new();
        for height in heights {
            let hash_bytes: Vec<u8> = stmt
                .query_row(params![height], |row| row.get(0))
                .map_err(|e| StoreError(format!("locator at {}: {}", height, e)))?;
            let hash_array: [u8; 32] = hash_bytes
                .try_into()
                .map_err(|_| StoreError("invalid hash length in locator".into()))?;
            hashes.push(BlockHash::from_byte_array(hash_array));
        }

        Ok(hashes)
    }

    /// Get the last N timestamps ending at or below the given height.
    /// Used for median time validation during reorgs (where the chain tip
    /// may not be the height we need timestamps for).
    pub fn timestamps_up_to(&self, height: u32, count: u32) -> Result<Vec<u32>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let mut stmt = conn
            .prepare(
                "SELECT timestamp FROM headers WHERE height <= ?1 ORDER BY height DESC LIMIT ?2",
            )
            .map_err(|e| StoreError(format!("prepare timestamps_up_to: {}", e)))?;

        let mut timestamps: Vec<u32> = stmt
            .query_map(params![height, count], |row| row.get(0))
            .map_err(|e| StoreError(format!("query timestamps_up_to: {}", e)))?
            .collect::<Result<Vec<u32>, _>>()
            .map_err(|e| StoreError(format!("read timestamp: {}", e)))?;

        timestamps.reverse(); // ascending height order
        Ok(timestamps)
    }

    /// Get a single header at a given height (hash + deserialized header).
    pub fn get_header_at_height(
        &self,
        height: u32,
    ) -> Result<Option<(BlockHash, Header)>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let result = conn
            .query_row(
                "SELECT hash, header FROM headers WHERE height = ?1",
                params![height],
                |row| {
                    let hash_bytes: Vec<u8> = row.get(0)?;
                    let header_bytes: Vec<u8> = row.get(1)?;
                    Ok((hash_bytes, header_bytes))
                },
            );
        match result {
            Ok((hash_bytes, header_bytes)) => {
                let hash_array: [u8; 32] = hash_bytes
                    .try_into()
                    .map_err(|_| StoreError("invalid hash length".into()))?;
                let hash = BlockHash::from_byte_array(hash_array);
                let header: Header = deserialize(&header_bytes)
                    .map_err(|e| StoreError(format!("parse header at {}: {}", height, e)))?;
                Ok(Some((hash, header)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError(format!("get header at {}: {}", height, e))),
        }
    }

    /// Get headers in a height range [from, to] inclusive. For chainwork comparison.
    pub fn get_headers_in_range(
        &self,
        from: u32,
        to: u32,
    ) -> Result<Vec<Header>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError(format!("lock: {}", e)))?;
        let mut stmt = conn
            .prepare(
                "SELECT header FROM headers WHERE height >= ?1 AND height <= ?2 ORDER BY height",
            )
            .map_err(|e| StoreError(format!("prepare range query: {}", e)))?;

        let rows = stmt
            .query_map(params![from, to], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| StoreError(format!("range query: {}", e)))?
            .collect::<Result<Vec<Vec<u8>>, _>>()
            .map_err(|e| StoreError(format!("range row: {}", e)))?;

        rows.iter()
            .map(|bytes| {
                deserialize(bytes)
                    .map_err(|e| StoreError(format!("parse header in range: {}", e)))
            })
            .collect()
    }

    /// Record a block that failed consensus validation (ticket 024), so its
    /// headers are refused and it is never requested again, across
    /// restarts. Descendants need no entry: they can only connect through
    /// it. `rules` names the validation rules that rejected it (see
    /// `prune_failed_blocks`).
    pub fn mark_failed(
        &self,
        hash: BlockHash,
        height: u32,
        reason: &str,
        rules: &str,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        conn.execute(
            "INSERT OR REPLACE INTO failed_blocks (hash, height, reason, rules)
             VALUES (?1, ?2, ?3, ?4)",
            params![hash.to_byte_array().as_slice(), height, reason, rules],
        )
        .map_err(|e| StoreError(format!("mark failed: {}", e)))?;
        Ok(())
    }

    /// Remember that `addr` was banned for announcing failed block `hash`,
    /// so the ban can be lifted if the block is reconsidered.
    pub fn record_failed_block_ban(&self, addr: &str, hash: BlockHash) -> Result<(), StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        conn.execute(
            "INSERT OR IGNORE INTO failed_block_bans (addr, hash) VALUES (?1, ?2)",
            params![addr, hash.to_byte_array().as_slice()],
        )
        .map_err(|e| StoreError(format!("record failed-block ban: {}", e)))?;
        Ok(())
    }

    /// Drop failed blocks recorded under any rules version other than
    /// `rules`, so an update that fixes a validation bug reconsiders them.
    /// Returns the peers banned because of the dropped blocks; the caller
    /// lifts those bans.
    pub fn prune_failed_blocks(&self, rules: &str) -> Result<Vec<String>, StoreError> {
        self.delete_failed_where("rules != ?1", rules)
    }

    /// Forget every failed block ("reconsider invalid blocks"). Returns the
    /// peers banned because of them.
    pub fn clear_failed_blocks(&self) -> Result<Vec<String>, StoreError> {
        // `?1 = ?1` is always true; the shared query binds one parameter.
        self.delete_failed_where("?1 = ?1", "")
    }

    /// Delete the failed blocks matching `cond` (one parameter, `?1`) and
    /// their recorded bans, returning the addresses whose bans can now be
    /// lifted: those with no ban left for any other still-failed block.
    fn delete_failed_where(&self, cond: &str, param: &str) -> Result<Vec<String>, StoreError> {
        let mut conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        let tx = conn
            .transaction()
            .map_err(|e| StoreError(format!("begin tx: {}", e)))?;
        let stale = format!("SELECT hash FROM failed_blocks WHERE {}", cond);
        let addrs: Vec<String> = {
            let sql = format!("SELECT addr FROM failed_block_bans WHERE hash IN ({})", stale);
            let mut stmt = tx
                .prepare(&sql)
                .map_err(|e| StoreError(format!("prepare failed bans: {}", e)))?;
            let rows = stmt
                .query_map(params![param], |row| row.get::<_, String>(0))
                .map_err(|e| StoreError(format!("query failed bans: {}", e)))?;
            rows.collect::<Result<_, _>>()
                .map_err(|e| StoreError(format!("row failed bans: {}", e)))?
        };
        let del_bans = format!("DELETE FROM failed_block_bans WHERE hash IN ({})", stale);
        let del_blocks = format!("DELETE FROM failed_blocks WHERE {}", cond);
        for sql in [&del_bans, &del_blocks] {
            tx.execute(sql, params![param])
                .map_err(|e| StoreError(format!("delete failed blocks: {}", e)))?;
        }
        // Still banned for another failed block: keep that ban.
        let mut lift = Vec::new();
        for addr in addrs {
            let remaining: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM failed_block_bans WHERE addr = ?1",
                    params![addr],
                    |row| row.get(0),
                )
                .map_err(|e| StoreError(format!("count remaining bans: {}", e)))?;
            if remaining == 0 && !lift.contains(&addr) {
                lift.push(addr);
            }
        }
        tx.commit()
            .map_err(|e| StoreError(format!("commit: {}", e)))?;
        Ok(lift)
    }

    /// Hashes of every block recorded by `mark_failed`. The set is tiny (a
    /// consensus-invalid block with valid proof-of-work is rare and
    /// expensive), so callers check whole header batches against it.
    pub fn failed_hashes(&self) -> Result<std::collections::HashSet<BlockHash>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        let mut stmt = conn
            .prepare("SELECT hash FROM failed_blocks")
            .map_err(|e| StoreError(format!("prepare failed: {}", e)))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|e| StoreError(format!("query failed: {}", e)))?;
        let mut out = std::collections::HashSet::new();
        for row in rows {
            let bytes = row.map_err(|e| StoreError(format!("row failed: {}", e)))?;
            let hash = BlockHash::from_slice(&bytes)
                .map_err(|e| StoreError(format!("parse failed hash: {}", e)))?;
            out.insert(hash);
        }
        Ok(out)
    }

    /// Get the total number of stored headers.
    pub fn count(&self) -> Result<u32, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM headers", [], |row| row.get(0))
            .map_err(|e| StoreError(format!("count: {}", e)))?;
        Ok(count)
    }
}

/// Use rusqlite's optional extension for query_row
trait OptionalExt<T> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for Result<T, rusqlite::Error> {
    fn optional(self) -> Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Header;
    use bitcoin::consensus::deserialize;

    fn genesis_header() -> Header {
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        deserialize(&raw).unwrap()
    }

    fn block1_header() -> Header {
        let raw = hex::decode(
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900\
             00000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e8\
             57233e0e61bc6649ffff001d01e36299",
        )
        .unwrap();
        deserialize(&raw).unwrap()
    }

    #[test]
    fn validation_mode_is_unset_until_recorded_and_survives_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("headers.sqlite3");
        let path = path.to_str().unwrap();
        {
            let store = HeaderStore::open(path).unwrap();
            assert_eq!(store.validation_mode().unwrap(), None);
            store.set_validation_mode(NodeMode::AssumeUtxo).unwrap();
            assert_eq!(store.validation_mode().unwrap(), Some(NodeMode::AssumeUtxo));
        }
        let store = HeaderStore::open(path).unwrap();
        assert_eq!(store.validation_mode().unwrap(), Some(NodeMode::AssumeUtxo));
    }

    #[test]
    fn unknown_validation_mode_is_an_error_not_a_guess() {
        let store = HeaderStore::open(":memory:").unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute("INSERT INTO metadata (key, value) VALUES ('validation_mode', 'turbo')", [])
            .unwrap();
        assert!(store.validation_mode().is_err());
    }

    #[test]
    fn empty_store_has_zero_count() {
        let store = HeaderStore::open(":memory:").unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn empty_store_tip_is_none() {
        let store = HeaderStore::open(":memory:").unwrap();
        assert!(store.tip().unwrap().is_none());
    }

    #[test]
    fn store_and_count_genesis() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();

        store.store_headers(&[genesis], 0).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn store_and_retrieve_tip() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let genesis_hash = genesis.block_hash();

        store.store_headers(&[genesis], 0).unwrap();
        let (height, hash, header) = store.tip().unwrap().unwrap();

        assert_eq!(height, 0);
        assert_eq!(hash, genesis_hash);
        assert_eq!(header.time, 1231006505); // genesis timestamp
    }

    #[test]
    fn store_multiple_headers_updates_tip() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();

        store.store_headers(&[genesis], 0).unwrap();
        store.store_headers(&[block1], 1).unwrap();

        assert_eq!(store.count().unwrap(), 2);

        let (height, hash, _) = store.tip().unwrap().unwrap();
        assert_eq!(height, 1);
        assert_eq!(hash, block1.block_hash());
    }

    #[test]
    fn last_timestamps_returns_ascending_order() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();

        store.store_headers(&[genesis], 0).unwrap();
        store.store_headers(&[block1], 1).unwrap();

        let timestamps = store.last_timestamps(11).unwrap();
        assert_eq!(timestamps.len(), 2);
        assert_eq!(timestamps[0], genesis.time); // genesis first (ascending)
        assert_eq!(timestamps[1], block1.time); // block 1 second
        assert!(timestamps[0] < timestamps[1]);
    }

    /// Ticket 026: median-time-past reads its window in one range query;
    /// a gap must surface as an error, not a shorter window.
    #[test]
    fn timestamps_between_reads_a_range() {
        use crate::contextual_checks::{median_time_past, HeaderTimes};
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();
        store.store_headers(&[genesis], 0).unwrap();
        store.store_headers(&[block1], 1).unwrap();

        assert_eq!(store.get_timestamps_between(0, 1).unwrap(), vec![genesis.time, block1.time]);
        assert_eq!(store.timestamps_between(0, 1).unwrap(), vec![genesis.time, block1.time]);
        assert!(store.timestamps_between(0, 2).is_err(), "missing height 2");
        assert_eq!(median_time_past(&store, 1).unwrap(), block1.time as i64);
        assert!(median_time_past(&store, 2).is_err());
        use bitcoin::hashes::Hash as _;
        assert_eq!(store.header_id_at(1), Some(block1.block_hash().to_byte_array()));
        assert_eq!(store.header_id_at(2), None);
    }

    #[test]
    fn last_timestamps_limits_count() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();

        store.store_headers(&[genesis], 0).unwrap();
        store.store_headers(&[block1], 1).unwrap();

        let timestamps = store.last_timestamps(1).unwrap();
        assert_eq!(timestamps.len(), 1);
        assert_eq!(timestamps[0], block1.time); // only the most recent
    }

    #[test]
    fn get_timestamp_at_existing_height() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();

        store.store_headers(&[genesis], 0).unwrap();
        let ts = store.get_timestamp_at(0).unwrap();
        assert_eq!(ts, Some(genesis.time));
    }

    #[test]
    fn get_timestamp_at_missing_height() {
        let store = HeaderStore::open(":memory:").unwrap();
        let ts = store.get_timestamp_at(999).unwrap();
        assert_eq!(ts, None);
    }

    #[test]
    fn store_headers_batch() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();

        // Store both in one batch
        store.store_headers(&[genesis, block1], 0).unwrap();
        assert_eq!(store.count().unwrap(), 2);

        let ts0 = store.get_timestamp_at(0).unwrap().unwrap();
        let ts1 = store.get_timestamp_at(1).unwrap().unwrap();
        assert_eq!(ts0, genesis.time);
        assert_eq!(ts1, block1.time);
    }

    #[test]
    fn get_hash_at_height_returns_correct_hash() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();

        store.store_headers(&[genesis], 0).unwrap();
        let hash = store.get_hash_at_height(0).unwrap().unwrap();
        assert_eq!(hash, genesis.block_hash());
    }

    #[test]
    fn get_hash_at_missing_height_returns_none() {
        let store = HeaderStore::open(":memory:").unwrap();
        assert!(store.get_hash_at_height(999).unwrap().is_none());
    }

    #[test]
    fn validated_height_defaults_to_zero() {
        let store = HeaderStore::open(":memory:").unwrap();
        assert_eq!(store.validated_height().unwrap(), 0);
    }

    #[test]
    fn set_and_get_validated_height() {
        let store = HeaderStore::open(":memory:").unwrap();
        store.set_validated_height(42).unwrap();
        assert_eq!(store.validated_height().unwrap(), 42);

        // Update it
        store.set_validated_height(100).unwrap();
        assert_eq!(store.validated_height().unwrap(), 100);
    }

    #[test]
    fn find_height_of_hash_returns_correct_height() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        store.store_headers(&[genesis], 0).unwrap();
        let height = store.find_height_of_hash(genesis.block_hash()).unwrap();
        assert_eq!(height, Some(0));
    }

    #[test]
    fn find_height_of_missing_hash_returns_none() {
        let store = HeaderStore::open(":memory:").unwrap();
        let hash = BlockHash::from_byte_array([0xFF; 32]);
        assert_eq!(store.find_height_of_hash(hash).unwrap(), None);
    }

    #[test]
    fn ban_for_two_failed_blocks_lasts_until_both_are_reconsidered() {
        let store = HeaderStore::open(":memory:").unwrap();
        let (h1, h2) = (BlockHash::from_byte_array([1; 32]), BlockHash::from_byte_array([2; 32]));
        store.mark_failed(h1, 10, "bad", "old").unwrap();
        store.mark_failed(h2, 20, "bad", "new").unwrap();
        store.record_failed_block_ban("peer:8333", h1).unwrap();
        store.record_failed_block_ban("peer:8333", h2).unwrap();
        // h1 reconsidered: the ban still stands for h2.
        assert!(store.prune_failed_blocks("new").unwrap().is_empty());
        assert_eq!(store.clear_failed_blocks().unwrap(), vec!["peer:8333".to_string()]);
    }

    #[test]
    fn failed_block_bans_keyed_on_addr_alone_are_rekeyed() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("h.sqlite3");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE failed_block_bans (addr TEXT PRIMARY KEY, hash BLOB NOT NULL);
                 INSERT INTO failed_block_bans VALUES ('peer:8333', x'01');",
            )
            .unwrap();
        }
        let store = HeaderStore::open(path.to_str().unwrap()).unwrap();
        store.record_failed_block_ban("peer:8333", BlockHash::from_byte_array([2; 32])).unwrap();
        let conn = store.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM failed_block_bans", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn delete_headers_above_removes_correct_headers() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();
        store.store_headers(&[genesis, block1], 0).unwrap();
        assert_eq!(store.count().unwrap(), 2);

        store.delete_headers_above(0).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        assert!(store.get_hash_at_height(0).unwrap().is_some());
        assert!(store.get_hash_at_height(1).unwrap().is_none());
    }

    #[test]
    fn get_locator_hashes_includes_tip_and_genesis() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();
        store.store_headers(&[genesis, block1], 0).unwrap();

        let locator = store.get_locator_hashes().unwrap();
        assert!(!locator.is_empty());
        assert_eq!(locator[0], block1.block_hash());
        assert_eq!(*locator.last().unwrap(), genesis.block_hash());
    }

    #[test]
    fn get_headers_in_range_returns_correct_headers() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();
        store.store_headers(&[genesis, block1], 0).unwrap();

        let headers = store.get_headers_in_range(0, 1).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].block_hash(), genesis.block_hash());
        assert_eq!(headers[1].block_hash(), block1.block_hash());
    }

    #[test]
    fn timestamps_up_to_returns_ascending_order() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();
        store.store_headers(&[genesis, block1], 0).unwrap();

        // Ask for timestamps up to height 1
        let ts = store.timestamps_up_to(1, 11).unwrap();
        assert_eq!(ts.len(), 2);
        assert_eq!(ts[0], genesis.time);
        assert_eq!(ts[1], block1.time);

        // Ask for timestamps up to height 0 only
        let ts0 = store.timestamps_up_to(0, 11).unwrap();
        assert_eq!(ts0.len(), 1);
        assert_eq!(ts0[0], genesis.time);
    }

    #[test]
    fn get_header_at_height_returns_correct_header() {
        let store = HeaderStore::open(":memory:").unwrap();
        let genesis = genesis_header();
        let block1 = block1_header();
        store.store_headers(&[genesis, block1], 0).unwrap();

        let (hash, header) = store.get_header_at_height(0).unwrap().unwrap();
        assert_eq!(hash, genesis.block_hash());
        assert_eq!(header.time, genesis.time);

        let (hash1, header1) = store.get_header_at_height(1).unwrap().unwrap();
        assert_eq!(hash1, block1.block_hash());
        assert_eq!(header1.time, block1.time);

        assert!(store.get_header_at_height(999).unwrap().is_none());
    }

    #[test]
    fn failed_blocks_persist_across_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("headers.sqlite3");
        let path = path.to_str().unwrap();
        let hash = block1_header().block_hash();
        {
            let store = HeaderStore::open(path).unwrap();
            assert!(store.failed_hashes().unwrap().is_empty());
            store.mark_failed(hash, 1, "test", "v1").unwrap();
            // Idempotent.
            store.mark_failed(hash, 1, "test again", "v1").unwrap();
        }
        let store = HeaderStore::open(path).unwrap();
        let failed = store.failed_hashes().unwrap();
        assert_eq!(failed.len(), 1);
        assert!(failed.contains(&hash));
    }

    #[test]
    fn prune_failed_blocks_drops_other_rules_versions_and_their_bans() {
        let store = HeaderStore::open(":memory:").unwrap();
        let old = block1_header().block_hash();
        let new = genesis_header().block_hash();
        store.mark_failed(old, 1, "old rules", "v1").unwrap();
        store.mark_failed(new, 2, "new rules", "v2").unwrap();
        store.record_failed_block_ban("1.1.1.1:8333", old).unwrap();
        store.record_failed_block_ban("2.2.2.2:8333", new).unwrap();

        let unbanned = store.prune_failed_blocks("v2").unwrap();
        assert_eq!(unbanned, vec!["1.1.1.1:8333".to_string()]);
        let failed = store.failed_hashes().unwrap();
        assert!(!failed.contains(&old) && failed.contains(&new));

        let unbanned = store.clear_failed_blocks().unwrap();
        assert_eq!(unbanned, vec!["2.2.2.2:8333".to_string()]);
        assert!(store.failed_hashes().unwrap().is_empty());
        assert!(store.clear_failed_blocks().unwrap().is_empty());
    }

    // ── Data-path pass: locator shape, reorgs, persistence, migration ─

    /// `n` linked headers on top of genesis, with distinct hashes and
    /// increasing timestamps (`salt` makes a different branch).
    fn chain_from(parent: Header, n: u32, salt: u32) -> Vec<Header> {
        let mut out = Vec::with_capacity(n as usize);
        let mut prev = parent;
        for i in 0..n {
            let h = Header {
                prev_blockhash: prev.block_hash(),
                time: prev.time + 600,
                nonce: salt.wrapping_mul(1_000_003).wrapping_add(i),
                ..prev
            };
            out.push(h);
            prev = h;
        }
        out
    }

    fn store_with(n: u32) -> (HeaderStore, Vec<Header>) {
        let store = HeaderStore::open(":memory:").unwrap();
        let mut all = vec![genesis_header()];
        all.extend(chain_from(genesis_header(), n, 0));
        store.store_headers(&all, 0).unwrap();
        (store, all)
    }

    /// Locators start at the tip, step back 1 at a time for 10 entries,
    /// then double, always end at genesis, and stay logarithmic.
    #[test]
    fn locator_shape_for_many_tip_heights() {
        let (store, all) = store_with(5_000);
        for tip in [0u32, 1, 2, 9, 10, 11, 12, 20, 100, 1_023, 1_024, 5_000] {
            store.delete_headers_above(tip).unwrap();
            let loc = store.get_locator_hashes().unwrap();
            let heights: Vec<u32> =
                loc.iter().map(|h| store.find_height_of_hash(*h).unwrap().expect("locator hash is stored")).collect();
            assert_eq!(heights[0], tip, "tip {}", tip);
            assert_eq!(*heights.last().unwrap(), 0, "ends at genesis (tip {})", tip);
            assert!(heights.windows(2).all(|w| w[0] > w[1]), "strictly descending: {:?}", heights);
            let consecutive = heights.windows(2).take_while(|w| w[0] - w[1] == 1).count() + 1;
            assert!(consecutive >= heights.len().min(10), "first 10 consecutive: {:?}", heights);
            let bound = 12 + (32 - tip.max(1).leading_zeros()) as usize;
            assert!(heights.len() <= bound, "tip {}: {} entries", tip, heights.len());
            // Re-add what was deleted for the next round.
            store.store_headers(&all[tip as usize + 1..], tip + 1).unwrap();
        }
    }

    /// A reorg as sync performs it: delete above the fork, store the new
    /// branch. Old hashes vanish; lookups and timestamps follow the new
    /// branch; heights below the fork are untouched.
    #[test]
    fn reorg_replaces_the_branch_above_the_fork() {
        let (store, old) = store_with(20);
        let fork = 12u32;
        let new_branch = chain_from(old[fork as usize], 5, 7);
        store.delete_headers_above(fork).unwrap();
        store.store_headers(&new_branch, fork + 1).unwrap();

        let (tip, tip_hash, _) = store.tip().unwrap().unwrap();
        assert_eq!((tip, tip_hash), (17, new_branch[4].block_hash()));
        for h in (fork + 1)..=20 {
            assert_eq!(store.find_height_of_hash(old[h as usize].block_hash()).unwrap(), None, "stale {}", h);
        }
        for (i, hdr) in new_branch.iter().enumerate() {
            assert_eq!(store.find_height_of_hash(hdr.block_hash()).unwrap(), Some(fork + 1 + i as u32));
        }
        assert_eq!(store.get_hash_at_height(fork).unwrap(), Some(old[fork as usize].block_hash()));
        let expected: Vec<u32> = old[8..=12].iter().chain(&new_branch[..2]).map(|h| h.time).collect();
        assert_eq!(store.timestamps_up_to(14, 7).unwrap(), expected);
        assert_eq!(store.count().unwrap(), 18);
    }

    /// Storing a different header at an existing height replaces it (and
    /// its hash), as a one-header reorg does.
    #[test]
    fn storing_over_an_existing_height_replaces_the_header() {
        let (store, old) = store_with(3);
        let rival = chain_from(old[2], 1, 9)[0];
        store.store_headers(&[rival], 3).unwrap();
        assert_eq!(store.get_hash_at_height(3).unwrap(), Some(rival.block_hash()));
        assert_eq!(store.find_height_of_hash(old[3].block_hash()).unwrap(), None);
        assert_eq!(store.count().unwrap(), 4);
    }

    #[test]
    fn timestamp_reads_at_the_edges() {
        let (store, all) = store_with(30);
        let times: Vec<u32> = all.iter().map(|h| h.time).collect();
        assert_eq!(store.last_timestamps(11).unwrap(), times[20..].to_vec());
        assert_eq!(store.last_timestamps(1_000).unwrap(), times);
        assert_eq!(store.timestamps_up_to(5, 11).unwrap(), times[..=5].to_vec(), "fewer than requested near genesis");
        assert_eq!(store.timestamps_up_to(1_000, 3).unwrap(), times[28..].to_vec(), "beyond the tip");
        assert!(store.get_timestamps_between(10, 9).unwrap().is_empty());
        assert_eq!(store.get_timestamps_between(29, 40).unwrap(), times[29..].to_vec());
        // The HeaderTimes view insists on every height being present.
        use crate::contextual_checks::HeaderTimes;
        assert_eq!(HeaderTimes::timestamps_between(&store, 25, 30).unwrap(), times[25..=30].to_vec());
        let err = HeaderTimes::timestamps_between(&store, 25, 31).unwrap_err();
        assert!(err.contains("found 6 of 7"), "{}", err);
        assert!(HeaderTimes::timestamp_at(&store, 31).is_err());
        assert_eq!(store.header_id_at(30), Some(all[30].block_hash().to_byte_array()));
        assert_eq!(store.header_id_at(31), None);
    }

    #[test]
    fn headers_and_validated_height_survive_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("headers.sqlite3");
        let p = path.to_str().unwrap();
        let all = {
            let (mem, all) = store_with(50);
            drop(mem);
            let store = HeaderStore::open(p).unwrap();
            store.store_headers(&all, 0).unwrap();
            store.set_validated_height(42).unwrap();
            all
        };
        let store = HeaderStore::open(p).unwrap();
        assert_eq!(store.count().unwrap(), 51);
        assert_eq!(store.validated_height().unwrap(), 42);
        assert_eq!(store.tip().unwrap().unwrap().1, all[50].block_hash());
        assert_eq!(store.get_header_at_height(17).unwrap().unwrap().1, all[17]);
        store.set_validated_height(u32::MAX).unwrap();
        assert_eq!(store.validated_height().unwrap(), u32::MAX);
    }

    #[test]
    fn corrupt_rows_are_errors_not_defaults() {
        let (store, _) = store_with(2);
        {
            let conn = store.conn.lock().unwrap();
            conn.execute("UPDATE metadata SET value = 'x' WHERE key = 'validated_height'", []).unwrap();
            conn.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('validated_height', 'not a number')", [])
                .unwrap();
            conn.execute("UPDATE headers SET header = X'00' WHERE height = 2", []).unwrap();
            conn.execute("UPDATE headers SET hash = X'0102' WHERE height = 1", []).unwrap();
        }
        assert!(store.validated_height().is_err());
        assert!(store.tip().is_err(), "unparsable tip header");
        assert!(store.get_header_at_height(2).is_err());
        assert!(store.get_headers_in_range(0, 2).is_err());
        assert!(store.get_hash_at_height(1).is_err(), "short hash");
        assert!(store.get_locator_hashes().is_err());
    }

    /// Ticket 024's development-era `failed_blocks` table (no `rules`
    /// column) is dropped and recreated on open; its rows had no rules
    /// version, so they can't be trusted.
    #[test]
    fn failed_blocks_without_rules_column_are_dropped_on_open() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("headers.sqlite3");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE failed_blocks (hash BLOB PRIMARY KEY, height INTEGER NOT NULL, reason TEXT NOT NULL);
                 INSERT INTO failed_blocks VALUES (X'01', 5, 'old');",
            )
            .unwrap();
        }
        let store = HeaderStore::open(path.to_str().unwrap()).unwrap();
        assert!(store.failed_hashes().unwrap().is_empty());
        let hash = genesis_header().block_hash();
        store.mark_failed(hash, 0, "bad", "v1").unwrap();
        assert!(store.failed_hashes().unwrap().contains(&hash));
        // Opening again keeps the new-format rows.
        drop(store);
        let store = HeaderStore::open(path.to_str().unwrap()).unwrap();
        assert!(store.failed_hashes().unwrap().contains(&hash));
    }

    /// Ticket 050: every SQLite store stamps its layout version (an old
    /// file, at 0, is today's layout and keeps its rows), and refuses a
    /// file from a newer build with an error saying the app was downgraded.
    #[test]
    fn sqlite_stores_stamp_their_version_and_refuse_a_newer_one() {
        let dir = tempfile::TempDir::new().unwrap();
        type Opener = fn(&str) -> Result<(), String>;
        let stores: [(&str, Opener); 4] = [
            ("headers.sqlite3", |p| HeaderStore::open(p).map(drop).map_err(|e| e.0)),
            ("blocks.sqlite3", |p| crate::block_store::BlockStore::open(p).map(drop).map_err(|e| e.0)),
            ("own_txs.sqlite3", |p| crate::own_tx_store::OwnTxStore::open(p).map(drop).map_err(|e| e.0)),
            ("peers.sqlite3", |p| crate::peer_store::PeerStore::open(p).map(drop).map_err(|e| e.0)),
        ];
        for (name, open) in stores {
            let path = dir.path().join(name);
            let p = path.to_str().unwrap();
            let version = |v: Option<u32>| {
                let conn = Connection::open(&path).unwrap();
                if let Some(v) = v {
                    conn.pragma_update(None, "user_version", v).unwrap();
                }
                conn.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0)).unwrap()
            };
            open(p).unwrap();
            let current = version(None);
            assert_eq!(current, 1, "{} not stamped", name);

            // A file from before versioning opens and is stamped.
            version(Some(0));
            open(p).unwrap();
            assert_eq!(version(None), current, "{}", name);

            version(Some(current + 1));
            let err = open(p).expect_err(name);
            assert!(err.contains("newer than this build supports") && err.contains("downgraded"), "{}: {}", name, err);
            assert_eq!(version(None), current + 1, "{}: refused file was modified", name);
        }
    }
}
