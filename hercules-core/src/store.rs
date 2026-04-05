use std::sync::Mutex;

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rusqlite::{params, Connection};

use log::info;

/// Persistent storage for block headers using SQLite.
pub struct HeaderStore {
    conn: Mutex<Connection>,
}

impl HeaderStore {
    /// Open or create a header store at the given path.
    pub fn open(path: &str) -> Result<HeaderStore, StoreError> {
        let conn = Connection::open(path).map_err(|e| StoreError(format!("open: {}", e)))?;

        // Set WAL journal mode before any writes so that table creation
        // also benefits from WAL's crash-recovery semantics.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| StoreError(format!("set WAL: {}", e)))?;

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

    /// Get the timestamp of a header at a specific height.
    pub fn get_timestamp_at(&self, height: u32) -> Result<Option<u32>, StoreError> {
        let conn = self.conn.lock().map_err(|e| StoreError(format!("lock: {}", e)))?;
        conn.query_row(
            "SELECT timestamp FROM headers WHERE height = ?1",
            params![height],
            |row| row.get(0),
        )
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
            .query_row(
                "SELECT hash FROM headers WHERE height = ?1",
                params![height],
                |row| {
                    let hash_bytes: Vec<u8> = row.get(0)?;
                    Ok(hash_bytes)
                },
            )
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
}
