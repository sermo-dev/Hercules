use std::sync::Mutex;

use bitcoin::block::Block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rusqlite::{params, Connection};

use log::info;

/// Number of recent blocks to retain for NODE_NETWORK_LIMITED serving (BIP 159).
const SERVING_WINDOW: u32 = 288;

/// `blocks.sqlite3` layout version (`PRAGMA user_version`, ticket 050).
/// History: 1 = one `blocks` row per height (025 moves to hash keys).
const SCHEMA_VERSION: u32 = 1;

/// Persistent storage for recent full blocks using SQLite.
///
/// Stores the last 288 blocks so this node can serve them to peers
/// as required by NODE_NETWORK_LIMITED (BIP 159).
pub struct BlockStore {
    conn: Mutex<Connection>,
}

impl BlockStore {
    /// Open or create a block store at the given path.
    pub fn open(path: &str) -> Result<BlockStore, BlockStoreError> {
        let conn =
            Connection::open(path).map_err(|e| BlockStoreError(format!("open: {}", e)))?;
        conn.busy_timeout(crate::store::SQLITE_BUSY_TIMEOUT)
            .map_err(|e| BlockStoreError(format!("set busy_timeout: {}", e)))?;

        // First, before any table exists: a new file then hands the pages
        // of pruned blocks back to the filesystem (`prune_below`) instead
        // of growing forever (ticket 050). A file created before this keeps
        // `NONE` until `migrate_auto_vacuum`.
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
            .map_err(|e| BlockStoreError(format!("set auto_vacuum: {}", e)))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| BlockStoreError(format!("set WAL: {}", e)))?;

        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| BlockStoreError(format!("set synchronous: {}", e)))?;

        let version = crate::store::check_schema_version(&conn, "block store", SCHEMA_VERSION)
            .map_err(BlockStoreError)?;
        if version < SCHEMA_VERSION {
            // Files from before versioning (0) already have this layout;
            // the CREATE IF NOT EXISTS below covers new ones.
            crate::store::set_schema_version(&conn, "block store", SCHEMA_VERSION)
                .map_err(BlockStoreError)?;
        }

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL UNIQUE,
                data BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);
            ",
        )
        .map_err(|e| BlockStoreError(format!("create tables: {}", e)))?;

        info!("Block store opened at {}", path);
        Ok(BlockStore {
            conn: Mutex::new(conn),
        })
    }

    /// Store a validated block at the given height.
    pub fn store_block(&self, block: &Block, height: u32) -> Result<(), BlockStoreError> {
        let hash = block.block_hash().as_raw_hash().to_byte_array();
        let data = serialize(block);
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO blocks (height, hash, data) VALUES (?1, ?2, ?3)",
            params![height, hash.as_slice(), data],
        )
        .map_err(|e| BlockStoreError(format!("store block at height {}: {}", height, e)))?;
        Ok(())
    }

    /// Retrieve a block by its hash (for responding to getdata requests).
    pub fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Option<Block>, BlockStoreError> {
        let hash_bytes = hash.as_raw_hash().to_byte_array();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT data FROM blocks WHERE hash = ?1")
            .map_err(|e| BlockStoreError(format!("prepare: {}", e)))?;

        let mut rows = stmt
            .query(params![hash_bytes.as_slice()])
            .map_err(|e| BlockStoreError(format!("query: {}", e)))?;

        match rows.next().map_err(|e| BlockStoreError(format!("row: {}", e)))? {
            Some(row) => {
                let data: Vec<u8> = row
                    .get(0)
                    .map_err(|e| BlockStoreError(format!("get data: {}", e)))?;
                let block: Block = deserialize(&data)
                    .map_err(|e| BlockStoreError(format!("deserialize block: {}", e)))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Check whether a block exists in the store.
    pub fn has_block(&self, hash: &BlockHash) -> Result<bool, BlockStoreError> {
        let hash_bytes = hash.as_raw_hash().to_byte_array();
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocks WHERE hash = ?1",
                params![hash_bytes.as_slice()],
                |row| row.get(0),
            )
            .map_err(|e| BlockStoreError(format!("has_block: {}", e)))?;
        Ok(count > 0)
    }

    /// Delete blocks below the given height to stay within the serving
    /// window, returning how many went. One statement, so a kill leaves
    /// either all of them or none. The caller bounds the work per call
    /// (`HeaderSync::maybe_prune`).
    ///
    /// The freed pages are then handed back to the filesystem
    /// (`incremental_vacuum`, which costs about what the delete freed). On a
    /// file still at `auto_vacuum = NONE` that is a no-op and they are only
    /// reused for later blocks; see `migrate_auto_vacuum`.
    pub fn prune_below(&self, height: u32) -> Result<u32, BlockStoreError> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn
            .execute("DELETE FROM blocks WHERE height < ?1", params![height])
            .map_err(|e| BlockStoreError(format!("prune: {}", e)))?;
        if deleted > 0 {
            // Frees one page per step (each step yields a row), so it is
            // stepped to the end.
            let mut stmt = conn
                .prepare("PRAGMA incremental_vacuum")
                .map_err(|e| BlockStoreError(format!("prepare incremental_vacuum: {}", e)))?;
            let mut rows = stmt
                .query([])
                .map_err(|e| BlockStoreError(format!("incremental_vacuum: {}", e)))?;
            while rows
                .next()
                .map_err(|e| BlockStoreError(format!("incremental_vacuum: {}", e)))?
                .is_some()
            {}
        }
        Ok(deleted as u32)
    }

    /// Whether the file predates incremental auto-vacuum (`auto_vacuum =
    /// NONE`, SQLite's default before ticket 050), so pruned blocks are
    /// never given back to the filesystem.
    pub fn needs_auto_vacuum_migration(&self) -> Result<bool, BlockStoreError> {
        let conn = self.conn.lock().unwrap();
        let mode: u32 = conn
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .map_err(|e| BlockStoreError(format!("read auto_vacuum: {}", e)))?;
        // 0 = NONE, 1 = FULL, 2 = INCREMENTAL.
        Ok(mode == 0)
    }

    /// Switch an old file to incremental auto-vacuum, giving back the space
    /// of everything pruned so far. SQLite can only do this by rewriting the
    /// whole file (`VACUUM`), which costs I/O for every live block and as
    /// much free disk again, so `HeaderSync::maybe_prune` calls it once,
    /// only in a processing-length wake and only once pruning has brought
    /// the store down to its window. `VACUUM` is transactional: a kill
    /// leaves the old file as it was, and the next chance retries.
    pub fn migrate_auto_vacuum(&self) -> Result<(), BlockStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
            .map_err(|e| BlockStoreError(format!("set auto_vacuum: {}", e)))?;
        conn.execute_batch("VACUUM;")
            .map_err(|e| BlockStoreError(format!("vacuum: {}", e)))
    }

    /// Get the lowest block height currently stored.
    pub fn lowest_height(&self) -> Result<Option<u32>, BlockStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT MIN(height) FROM blocks", [], |row| row.get(0))
            .map_err(|e| BlockStoreError(format!("lowest_height: {}", e)))
    }

    /// Get the highest block height currently stored.
    pub fn highest_height(&self) -> Result<Option<u32>, BlockStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT MAX(height) FROM blocks", [], |row| row.get(0))
            .map_err(|e| BlockStoreError(format!("highest_height: {}", e)))
    }

    /// Number of blocks currently stored.
    pub fn count(&self) -> Result<u32, BlockStoreError> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn
            .query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
            .map_err(|e| BlockStoreError(format!("count: {}", e)))?;
        Ok(count)
    }

    /// The serving window size (288 blocks per BIP 159).
    pub fn serving_window() -> u32 {
        SERVING_WINDOW
    }
}

/// Errors from the block store.
#[derive(Debug, Clone)]
pub struct BlockStoreError(pub String);

impl std::fmt::Display for BlockStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockStoreError: {}", self.0)
    }
}

impl std::error::Error for BlockStoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;

    /// Create a minimal valid block for testing (the real genesis block).
    fn genesis_block() -> Block {
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c\
             01\
             01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043\
             68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f7574\
             20666f722062616e6b73ffffffff\
             0100f2052a0100000043410467e6e15a2fd55bfccfc89481e77dfe6a9f055e65106e82\
             1e022e084a27a7626cfe82510d2e593a0f1ee44bca55f8c0e28d57e87b5f0c9b6e46a3\
             d6d23df9a13eac\
             00000000",
        )
        .unwrap();
        deserialize(&raw).unwrap()
    }

    #[test]
    fn store_and_retrieve_by_hash() {
        let store = BlockStore::open(":memory:").unwrap();
        let block = genesis_block();
        let hash = block.block_hash();

        store.store_block(&block, 0).unwrap();

        let retrieved = store.get_block_by_hash(&hash).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().block_hash(), hash);
    }

    #[test]
    fn missing_block_returns_none() {
        let store = BlockStore::open(":memory:").unwrap();
        let fake_hash = BlockHash::all_zeros();
        assert!(store.get_block_by_hash(&fake_hash).unwrap().is_none());
    }

    #[test]
    fn has_block_checks_existence() {
        let store = BlockStore::open(":memory:").unwrap();
        let block = genesis_block();
        let hash = block.block_hash();

        assert!(!store.has_block(&hash).unwrap());
        store.store_block(&block, 0).unwrap();
        assert!(store.has_block(&hash).unwrap());
    }

    #[test]
    fn prune_below_removes_old_blocks() {
        let store = BlockStore::open(":memory:").unwrap();
        let block = genesis_block();

        // Store same block at heights 0-5 (reusing genesis for simplicity)
        for h in 0..6 {
            // Use INSERT OR REPLACE — height is PK, hash has UNIQUE.
            // For testing we create a dummy block at each height by re-serializing.
            store
                .conn
                .lock()
                .unwrap()
                .execute(
                    "INSERT OR REPLACE INTO blocks (height, hash, data) VALUES (?1, ?2, ?3)",
                    params![
                        h as u32,
                        format!("hash{}", h).as_bytes(),
                        serialize(&block),
                    ],
                )
                .unwrap();
        }

        assert_eq!(store.count().unwrap(), 6);

        let pruned = store.prune_below(3).unwrap();
        assert_eq!(pruned, 3); // heights 0, 1, 2 removed
        assert_eq!(store.count().unwrap(), 3);
    }

    #[test]
    fn lowest_and_highest_height() {
        let store = BlockStore::open(":memory:").unwrap();

        assert_eq!(store.lowest_height().unwrap(), None);
        assert_eq!(store.highest_height().unwrap(), None);

        let block = genesis_block();
        store.store_block(&block, 100).unwrap();

        assert_eq!(store.lowest_height().unwrap(), Some(100));
        assert_eq!(store.highest_height().unwrap(), Some(100));
    }

    #[test]
    fn count_blocks() {
        let store = BlockStore::open(":memory:").unwrap();
        assert_eq!(store.count().unwrap(), 0);

        let block = genesis_block();
        store.store_block(&block, 0).unwrap();
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn store_replace_at_same_height() {
        let store = BlockStore::open(":memory:").unwrap();
        let block = genesis_block();

        store.store_block(&block, 0).unwrap();
        store.store_block(&block, 0).unwrap(); // should replace, not error
        assert_eq!(store.count().unwrap(), 1);
    }

    // ── Data-path pass ───────────────────────────────────────────────

    /// The genesis block with a distinct header per `tag` (distinct hash).
    fn tagged(tag: u32) -> Block {
        let mut b = genesis_block();
        b.header.nonce = tag;
        b
    }

    #[test]
    fn prune_below_is_exclusive_and_counts_what_it_removed() {
        let store = BlockStore::open(":memory:").unwrap();
        for h in 10..=14 {
            store.store_block(&tagged(h), h).unwrap();
        }
        assert_eq!(store.prune_below(12).unwrap(), 2);
        assert_eq!(store.lowest_height().unwrap(), Some(12));
        assert!(store.has_block(&tagged(12).block_hash()).unwrap());
        assert!(!store.has_block(&tagged(11).block_hash()).unwrap());
        assert_eq!(store.prune_below(12).unwrap(), 0, "idempotent");
        assert_eq!(store.prune_below(u32::MAX).unwrap(), 3);
        assert_eq!((store.lowest_height().unwrap(), store.highest_height().unwrap()), (None, None));
    }

    /// A reorg stores a different block at an existing height: the old
    /// one must no longer be served by hash.
    #[test]
    fn reorg_replacement_stops_serving_the_old_block() {
        let store = BlockStore::open(":memory:").unwrap();
        let (old, new) = (tagged(1), tagged(2));
        store.store_block(&old, 100).unwrap();
        store.store_block(&new, 100).unwrap();
        assert!(store.get_block_by_hash(&old.block_hash()).unwrap().is_none());
        assert_eq!(store.get_block_by_hash(&new.block_hash()).unwrap().unwrap(), new);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn blocks_survive_reopen_and_corrupt_rows_are_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("blocks.sqlite3");
        let p = path.to_str().unwrap();
        {
            let store = BlockStore::open(p).unwrap();
            store.store_block(&tagged(1), 1).unwrap();
            store.store_block(&tagged(2), 2).unwrap();
        }
        let store = BlockStore::open(p).unwrap();
        assert_eq!(store.get_block_by_hash(&tagged(2).block_hash()).unwrap().unwrap(), tagged(2));
        store.conn.lock().unwrap().execute("UPDATE blocks SET data = X'0000' WHERE height = 1", []).unwrap();
        assert!(store.get_block_by_hash(&tagged(1).block_hash()).is_err());
        assert!(store.has_block(&tagged(1).block_hash()).unwrap(), "row still present");
    }

    // ── Ticket 050: auto-vacuum and the layout version ───────────────

    fn pragma(store: &BlockStore, name: &str) -> u32 {
        store
            .conn
            .lock()
            .unwrap()
            .query_row(&format!("PRAGMA {}", name), [], |row| row.get(0))
            .unwrap()
    }

    /// Rows of `size` bytes at heights `from..to` (fake hashes), enough
    /// pages for a prune to be visible in `page_count`.
    fn fill(store: &BlockStore, from: u32, to: u32, size: usize) {
        let conn = store.conn.lock().unwrap();
        for h in from..to {
            conn.execute(
                "INSERT INTO blocks (height, hash, data) VALUES (?1, ?2, ?3)",
                params![h, format!("hash{}", h).as_bytes(), vec![h as u8; size]],
            )
            .unwrap();
        }
    }

    /// A new file gives pruned blocks' pages back to the filesystem.
    #[test]
    fn prune_shrinks_a_new_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = BlockStore::open(dir.path().join("blocks.sqlite3").to_str().unwrap()).unwrap();
        assert!(!store.needs_auto_vacuum_migration().unwrap());
        fill(&store, 0, 40, 64 * 1024);
        let before = pragma(&store, "page_count");
        assert_eq!(store.prune_below(35).unwrap(), 35);
        let after = pragma(&store, "page_count");
        assert!(after * 4 < before, "file did not shrink: {} -> {} pages", before, after);
        assert_eq!(pragma(&store, "freelist_count"), 0);
    }

    /// A file from before auto-vacuum keeps its freed pages until the
    /// one-time migration, which keeps every row.
    #[test]
    fn old_file_is_migrated_to_incremental_auto_vacuum() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("blocks.sqlite3");
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "PRAGMA auto_vacuum = NONE;
                 CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE, data BLOB NOT NULL);",
            )
            .unwrap();
        let store = BlockStore::open(path.to_str().unwrap()).unwrap();
        assert!(store.needs_auto_vacuum_migration().unwrap());
        fill(&store, 0, 40, 64 * 1024);
        let before = pragma(&store, "page_count");
        store.prune_below(35).unwrap();
        assert_eq!(pragma(&store, "page_count"), before, "NONE file shrank without a vacuum");
        assert!(pragma(&store, "freelist_count") > 0);

        store.migrate_auto_vacuum().unwrap();
        assert!(!store.needs_auto_vacuum_migration().unwrap());
        assert!(pragma(&store, "page_count") * 4 < before);
        assert_eq!(store.count().unwrap(), 5);
        drop(store);
        let store = BlockStore::open(path.to_str().unwrap()).unwrap();
        assert!(!store.needs_auto_vacuum_migration().unwrap(), "migration not persisted");
        assert_eq!(pragma(&store, "user_version"), SCHEMA_VERSION);
    }

    /// BIP 159 serving window, kept equal to the 288-block reorg/undo
    /// horizon sync prunes both stores to (`MAX_REORG_DEPTH`).
    #[test]
    fn serving_window_is_288_blocks() {
        assert_eq!(BlockStore::serving_window(), 288);
    }
}
