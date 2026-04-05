use bitcoin::block::Header;
use bitcoin::consensus::deserialize;

mod block_validation;
mod p2p;
mod store;
mod sync;
mod utxo;
mod validation;

uniffi::include_scaffolding!("hercules");

// ── Phase 0 types (block parsing) ──────────────────────────────────

#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub block_hash: String,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub version: u32,
    pub timestamp: u32,
    pub timestamp_human: String,
    pub bits: u32,
    pub nonce: u32,
}

pub fn parse_block_header(hex_header: String) -> Result<BlockInfo, HerculesError> {
    let bytes = hex::decode(&hex_header).map_err(|e| HerculesError::SyncFailed {
        msg: format!("invalid hex: {}", e),
    })?;
    let header: Header = deserialize(&bytes).map_err(|e| HerculesError::SyncFailed {
        msg: format!("invalid block header: {}", e),
    })?;

    let timestamp = header.time;
    let datetime = chrono_format(timestamp);

    Ok(BlockInfo {
        block_hash: header.block_hash().to_string(),
        prev_block_hash: header.prev_blockhash.to_string(),
        merkle_root: header.merkle_root.to_string(),
        version: header.version.to_consensus() as u32,
        timestamp,
        timestamp_human: datetime,
        bits: header.bits.to_consensus(),
        nonce: header.nonce,
    })
}

pub fn hercules_version() -> String {
    "Hercules v0.1.0".to_string()
}

// ── Phase 1 types (header sync) ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub synced_headers: u32,
    pub peer_height: u32,
    pub peer_addr: String,
    pub peer_user_agent: String,
    pub is_syncing: bool,
    pub validated_blocks: u32,
    pub error: Option<String>,
}

impl From<sync::SyncStatus> for SyncStatus {
    fn from(s: sync::SyncStatus) -> Self {
        SyncStatus {
            synced_headers: s.synced_headers,
            peer_height: s.peer_height,
            peer_addr: s.peer_addr,
            peer_user_agent: s.peer_user_agent,
            is_syncing: s.is_syncing,
            validated_blocks: s.validated_blocks,
            error: s.error,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HerculesError {
    #[error("Sync failed: {msg}")]
    SyncFailed { msg: String },
    #[error("Storage error: {msg}")]
    StorageError { msg: String },
    #[error("Network error: {msg}")]
    NetworkError { msg: String },
}

pub trait SyncCallback: Send + Sync {
    fn on_progress(&self, status: SyncStatus);
}

pub struct HerculesNode {
    syncer: sync::HeaderSync,
}

impl HerculesNode {
    pub fn new(db_path: String) -> Result<Self, HerculesError> {
        let syncer = sync::HeaderSync::new(&db_path).map_err(|e| HerculesError::StorageError {
            msg: format!("{}", e),
        })?;
        Ok(HerculesNode { syncer })
    }

    pub fn get_status(&self) -> Result<SyncStatus, HerculesError> {
        let status = self
            .syncer
            .status()
            .map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })?;
        Ok(status.into())
    }

    pub fn start_header_sync(&self, callback: Box<dyn SyncCallback>) -> Result<(), HerculesError> {
        self.syncer
            .sync(|status| {
                callback.on_progress(status.into());
            })
            .map_err(|e| match e {
                sync::SyncError::NoPeers => HerculesError::NetworkError {
                    msg: "no peers found".into(),
                },
                sync::SyncError::Peer(s) => HerculesError::NetworkError { msg: s },
                sync::SyncError::Validation(s) => HerculesError::SyncFailed { msg: s },
                sync::SyncError::Store(s) => HerculesError::StorageError { msg: s },
            })
    }
}

// ── Utilities ──────────────────────────────────────────────────────

fn chrono_format(timestamp: u32) -> String {
    let secs = timestamp as i64;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let secs_rem = secs % 60;

    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, mins, secs_rem
    )
}

fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS_HEX: &str = "\
        0100000000000000000000000000000000000000000000000000000000000000\
        000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
        4b1e5e4a29ab5f49ffff001d1dac2b7c";

    #[test]
    fn parse_genesis_block_header() {
        let info = parse_block_header(GENESIS_HEX.into()).unwrap();

        assert_eq!(
            info.block_hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(info.version, 1);
        assert_eq!(info.timestamp, 1231006505);
        assert_eq!(info.bits, 486604799); // 0x1d00ffff
        assert_eq!(info.nonce, 2083236893);
    }

    #[test]
    fn parse_invalid_hex_returns_error() {
        let result = parse_block_header("not_hex!!!".into());
        assert!(result.is_err());
    }

    #[test]
    fn parse_truncated_header_returns_error() {
        // Valid hex but too short to be a block header
        let result = parse_block_header("0100000000000000".into());
        assert!(result.is_err());
    }

    #[test]
    fn version_string() {
        let v = hercules_version();
        assert!(v.contains("Hercules"));
        assert!(v.contains("0.1.0"));
    }

    #[test]
    fn chrono_format_genesis_timestamp() {
        // Genesis block: 2009-01-03 18:15:05 UTC
        let formatted = chrono_format(1231006505);
        assert_eq!(formatted, "2009-01-03 18:15:05 UTC");
    }

    #[test]
    fn chrono_format_unix_epoch() {
        let formatted = chrono_format(0);
        assert_eq!(formatted, "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn node_new_and_status() {
        let node = HerculesNode::new(":memory:".into()).unwrap();
        let status = node.get_status().unwrap();

        // Fresh node has genesis stored, so synced_headers = 0 (count 1 minus 1)
        assert_eq!(status.synced_headers, 0);
        assert_eq!(status.peer_height, 0);
        assert!(!status.is_syncing);
        assert!(status.error.is_none());
    }

    #[test]
    fn sync_status_from_internal() {
        let internal = sync::SyncStatus {
            synced_headers: 100,
            peer_height: 800000,
            peer_addr: "1.2.3.4:8333".into(),
            peer_user_agent: "/Satoshi:27.0.0/".into(),
            is_syncing: true,
            validated_blocks: 50,
            error: None,
        };
        let external: SyncStatus = internal.into();
        assert_eq!(external.synced_headers, 100);
        assert_eq!(external.peer_height, 800000);
        assert_eq!(external.peer_addr, "1.2.3.4:8333");
        assert!(external.is_syncing);
        assert_eq!(external.validated_blocks, 50);
    }
}
