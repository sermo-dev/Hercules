use bitcoin::consensus::deserialize;
use bitcoin::block::Header;

uniffi::include_scaffolding!("hercules");

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

/// Parse an 80-byte block header from a hex string and return structured info.
pub fn parse_block_header(hex_header: String) -> BlockInfo {
    let bytes = hex::decode(&hex_header).expect("invalid hex");
    let header: Header = deserialize(&bytes).expect("invalid block header");

    let timestamp = header.time;
    let datetime = chrono_format(timestamp);

    BlockInfo {
        block_hash: header.block_hash().to_string(),
        prev_block_hash: header.prev_blockhash.to_string(),
        merkle_root: header.merkle_root.to_string(),
        version: header.version.to_consensus() as u32,
        timestamp,
        timestamp_human: datetime,
        bits: header.bits.to_consensus(),
        nonce: header.nonce,
    }
}

pub fn hercules_version() -> String {
    "Hercules v0.1.0".to_string()
}

/// Format a unix timestamp as a human-readable UTC string.
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

/// Convert days since epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
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
