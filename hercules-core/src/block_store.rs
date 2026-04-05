use std::sync::Mutex;

use bitcoin::block::Block;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rusqlite::{params, Connection};

use log::info;

/// Number of recent blocks to retain for NODE_NETWORK_LIMITED serving (BIP 159).
const SERVING_WINDOW: u32 = 288;

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

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| BlockStoreError(format!("set WAL: {}", e)))?;

        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| BlockStoreError(format!("set synchronous: {}", e)))?;

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

    /// Delete blocks below the given height to stay within the serving window.
    pub fn prune_below(&self, height: u32) -> Result<u32, BlockStoreError> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn
            .execute("DELETE FROM blocks WHERE height < ?1", params![height])
            .map_err(|e| BlockStoreError(format!("prune: {}", e)))?;
        Ok(deleted as u32)
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
}
