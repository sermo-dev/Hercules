use bitcoin::block::Header;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::BlockHash;

use crate::chain_params::ChainParams;

/// Target time for one difficulty epoch (2016 blocks): 2 weeks.
const TARGET_TIMESPAN: i64 = 14 * 24 * 60 * 60;

/// Core's `MAX_FUTURE_BLOCK_TIME`: a header may be at most 2 hours ahead
/// of our clock.
pub const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60;

/// The latest header timestamp acceptable now (`MAX_FUTURE_BLOCK_TIME`
/// past our clock). Later ones are not yet valid (`FutureTimestamp`).
pub fn max_header_time_now() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    now.saturating_add(MAX_FUTURE_BLOCK_TIME)
}

/// Validate a sequence of headers against a known previous header.
/// Returns Ok(()) if all headers are valid, or an error describing the first invalid header.
///
/// `prev_bits` is the compact target of the block at `prev_height`.
/// `epoch_start_time` looks up the timestamp of a header at a given height from the store,
/// used to fetch the first block of a difficulty epoch for retarget calculations.
/// `params` supplies the PoW limit and whether the chain retargets at all.
pub fn validate_headers(
    params: &ChainParams,
    headers: &[Header],
    prev_hash: BlockHash,
    prev_height: u32,
    prev_timestamps: &[u32],
    prev_bits: CompactTarget,
    epoch_start_time: &dyn Fn(u32) -> Result<u32, String>,
) -> Result<(), ValidationError> {
    let mut expected_prev = prev_hash;
    let mut height = prev_height + 1;
    let mut timestamps: Vec<u32> = prev_timestamps.to_vec();
    let mut current_bits = prev_bits;

    for header in headers {
        // 1. Check hash chain linkage
        if header.prev_blockhash != expected_prev {
            return Err(ValidationError::BadPrevHash {
                height,
                expected: expected_prev.to_string(),
                got: header.prev_blockhash.to_string(),
            });
        }

        // 2. Check difficulty target
        if !params.no_retargeting && height % 2016 == 0 && height > 0 {
            // Retarget boundary: verify the new target is correctly calculated
            let epoch_start_height = height - 2016;
            // Our own header store failing to produce the epoch start (a
            // SQLite error, a missing row) says nothing about the peer's
            // header: a local fault, never a difficulty verdict (ticket
            // 052, 024's classes).
            let epoch_start_ts = epoch_start_time(epoch_start_height).map_err(|e| {
                ValidationError::MissingContext {
                    height,
                    what: format!("epoch start timestamp at height {}: {}", epoch_start_height, e),
                }
            })?;

            let prev_time = *timestamps.last().ok_or(ValidationError::MissingContext {
                height,
                what: "previous block timestamp".into(),
            })?;

            let actual_timespan = prev_time as i64 - epoch_start_ts as i64;
            let expected_bits =
                calculate_next_target(current_bits, actual_timespan, params.pow_limit_bits);

            if header.bits != expected_bits {
                return Err(ValidationError::BadDifficulty {
                    height,
                    expected: format!("0x{:08x}", expected_bits.to_consensus()),
                    got: format!("0x{:08x}", header.bits.to_consensus()),
                });
            }
        } else if height > 0 {
            // Between retargets (or on a no-retargeting chain): difficulty
            // must not change
            if header.bits != current_bits {
                return Err(ValidationError::BadDifficulty {
                    height,
                    expected: format!("0x{:08x}", current_bits.to_consensus()),
                    got: format!("0x{:08x}", header.bits.to_consensus()),
                });
            }
        }

        // 3. Check proof of work against the (now-verified) target
        let target = header.target();
        let block_hash = header.block_hash();
        if header.validate_pow(target).is_err() {
            return Err(ValidationError::InsufficientPow {
                height,
                hash: block_hash.to_string(),
            });
        }

        // 4. Check timestamp is greater than the median of the previous
        // 11 blocks, or of all of them below height 11: Core's
        // GetMedianTimePast walks up to 11 ancestors and takes the middle
        // of however many it found (`pbegin[(pend - pbegin) / 2]`), so
        // block 1 must be later than genesis (ticket 052). A caller that
        // passes fewer timestamps than that window (no history before a
        // batch's start) gets no check, as before: the median of a partial
        // window is not Core's median.
        let window = (height as usize).min(11);
        if window > 0 && timestamps.len() >= window {
            let mut recent: Vec<u32> = timestamps[timestamps.len() - window..].to_vec();
            recent.sort();
            let median = recent[window / 2];
            if header.time <= median {
                return Err(ValidationError::BadTimestamp {
                    height,
                    timestamp: header.time,
                    median_past: median,
                });
            }
        }

        // 5. Reject headers more than 2 hours in the future (MAX_FUTURE_BLOCK_TIME)
        let max_future = max_header_time_now();
        if header.time > max_future {
            return Err(ValidationError::FutureTimestamp {
                height,
                timestamp: header.time,
                max_allowed: max_future,
            });
        }

        // 6. Reject outdated block versions once BIP 34/66/65 are active
        // (ContextualCheckBlockHeader, `bad-version`). Signed comparison,
        // as Core's int32 nVersion. Ticket 026: BIP 34's height-in-coinbase
        // check used to reject version 1 as a side effect; it is a byte
        // comparison now, so the version rule lives here as in Core.
        let version = header.version.to_consensus();
        if (version < 2 && height >= params.bip34_height)
            || (version < 3 && height >= params.bip66_height)
            || (version < 4 && height >= params.bip65_height)
        {
            return Err(ValidationError::BadVersion { height, version });
        }

        current_bits = header.bits;
        timestamps.push(header.time);
        expected_prev = block_hash;
        height += 1;
    }

    Ok(())
}

/// Calculate the expected difficulty target at a retarget boundary.
///
/// `prev_bits` is the compact target of the last block in the previous epoch.
/// `actual_timespan` is the elapsed seconds for the previous 2016-block epoch.
/// `pow_limit_bits` is the chain's maximum target (compact form).
fn calculate_next_target(
    prev_bits: CompactTarget,
    actual_timespan: i64,
    pow_limit_bits: u32,
) -> CompactTarget {
    // Clamp actual timespan to [target_timespan/4, target_timespan*4]
    let clamped = actual_timespan
        .max(TARGET_TIMESPAN / 4)
        .min(TARGET_TIMESPAN * 4);

    let prev_target = Target::from_compact(prev_bits);
    let target_bytes = prev_target.to_le_bytes();

    // new_target = prev_target * clamped_timespan / TARGET_TIMESPAN
    let multiplied = u256_mul_u64(target_bytes, clamped as u64);
    let divided = u256_div_u64(multiplied, TARGET_TIMESPAN as u64);
    let new_target = Target::from_le_bytes(divided);

    // Cap at maximum target (genesis difficulty)
    let max_target = Target::from_compact(CompactTarget::from_consensus(pow_limit_bits));
    let final_target = if new_target > max_target {
        max_target
    } else {
        new_target
    };

    final_target.to_compact_lossy()
}

/// Multiply a 256-bit little-endian value by a u64 scalar.
fn u256_mul_u64(bytes: [u8; 32], scalar: u64) -> [u8; 32] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    let scalar = scalar as u128;
    let mut result = [0u64; 4];
    let mut carry: u128 = 0;

    for i in 0..4 {
        let prod = limbs[i] as u128 * scalar + carry;
        result[i] = prod as u64;
        carry = prod >> 64;
    }

    if carry > 0 {
        return [0xFF; 32];
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&result[i].to_le_bytes());
    }
    out
}

/// Divide a 256-bit little-endian value by a u64 scalar.
fn u256_div_u64(bytes: [u8; 32], divisor: u64) -> [u8; 32] {
    if divisor == 0 {
        return [0xFF; 32]; // saturate to max, same as u256_div_u256
    }

    let mut limbs = [0u64; 4];
    for i in 0..4 {
        limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    let divisor = divisor as u128;
    let mut result = [0u64; 4];
    let mut remainder: u128 = 0;

    for i in (0..4).rev() {
        let dividend = (remainder << 64) | limbs[i] as u128;
        result[i] = (dividend / divisor) as u64;
        remainder = dividend % divisor;
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&result[i].to_le_bytes());
    }
    out
}

#[derive(Debug)]
pub enum ValidationError {
    BadPrevHash {
        height: u32,
        expected: String,
        got: String,
    },
    InsufficientPow {
        height: u32,
        hash: String,
    },
    BadTimestamp {
        height: u32,
        timestamp: u32,
        median_past: u32,
    },
    BadDifficulty {
        height: u32,
        expected: String,
        got: String,
    },
    FutureTimestamp {
        height: u32,
        timestamp: u32,
        max_allowed: u32,
    },
    /// The header at the anchor height is not the compiled-in anchor block.
    AnchorMismatch {
        height: u32,
        expected: String,
        got: String,
    },
    /// Block version too low for the active BIP 34/66/65 deployments.
    BadVersion {
        height: u32,
        version: i32,
    },
    /// Context we read from our own store to judge the header (the
    /// retarget epoch's start) was unavailable: a local fault (ticket 052).
    MissingContext {
        height: u32,
        what: String,
    },
}

/// What a `ValidationError` says about the peer that sent the headers
/// (ticket 052, applying 024's classes to headers). Matched exhaustively
/// in `ValidationError::class`, so a new variant must be classified there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderErrorClass {
    /// The header breaks a rule no clock or store can change: the sender
    /// is penalized.
    Invalid,
    /// More than two hours ahead of our clock (Core's `time-too-new`,
    /// `BLOCK_TIME_FUTURE`, which `MaybePunishNodeForBlock` doesn't
    /// punish): it may become valid, and a phone whose clock runs slow sees
    /// every honest tip this way. No penalty; the headers before it are
    /// fine, and it is asked for again later.
    NotYetValid,
    /// Our own store failed: nobody else's fault, no penalty.
    Local,
}

impl ValidationError {
    /// Which of the classes above this error is.
    pub fn class(&self) -> HeaderErrorClass {
        match self {
            ValidationError::FutureTimestamp { .. } => HeaderErrorClass::NotYetValid,
            ValidationError::MissingContext { .. } => HeaderErrorClass::Local,
            ValidationError::BadPrevHash { .. }
            | ValidationError::InsufficientPow { .. }
            | ValidationError::BadTimestamp { .. }
            | ValidationError::BadDifficulty { .. }
            | ValidationError::AnchorMismatch { .. }
            | ValidationError::BadVersion { .. } => HeaderErrorClass::Invalid,
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::BadVersion { height, version } => write!(
                f,
                "block {} has outdated version 0x{:08x}",
                height, version
            ),
            ValidationError::BadPrevHash {
                height,
                expected,
                got,
            } => write!(
                f,
                "block {} has wrong prev hash: expected {}, got {}",
                height, expected, got
            ),
            ValidationError::InsufficientPow { height, hash } => {
                write!(f, "block {} has insufficient PoW: hash {}", height, hash)
            }
            ValidationError::BadTimestamp {
                height,
                timestamp,
                median_past,
            } => write!(
                f,
                "block {} timestamp {} is not greater than median past time {}",
                height, timestamp, median_past
            ),
            ValidationError::BadDifficulty {
                height,
                expected,
                got,
            } => write!(
                f,
                "block {} has wrong difficulty: expected {}, got {}",
                height, expected, got
            ),
            ValidationError::FutureTimestamp {
                height,
                timestamp,
                max_allowed,
            } => write!(
                f,
                "block {} timestamp {} is more than 2 hours in the future (max {})",
                height, timestamp, max_allowed
            ),
            ValidationError::AnchorMismatch {
                height,
                expected,
                got,
            } => write!(
                f,
                "block {} conflicts with the chain anchor: expected {}, got {}",
                height, expected, got
            ),
            ValidationError::MissingContext { height, what } => {
                write!(f, "cannot check block {}: missing local {}", height, what)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

// ── U256 helpers for chainwork computation ──────────────────────────

/// Add two 256-bit little-endian values.
pub fn u256_add(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

/// Subtract b from a (256-bit little-endian). Assumes a >= b.
fn u256_sub(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in 0..32 {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    result
}

/// Bitwise NOT of a 256-bit little-endian value.
fn u256_not(a: [u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = !a[i];
    }
    result
}

/// Check if a >= b (256-bit little-endian).
fn u256_gte(a: [u8; 32], b: [u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

/// Divide a by b (256-bit little-endian), returning the quotient.
/// Uses binary long division.
fn u256_div_u256(numerator: [u8; 32], denominator: [u8; 32]) -> [u8; 32] {
    if denominator == [0u8; 32] {
        return [0xFF; 32];
    }

    let mut quotient = [0u8; 32];
    let mut remainder = [0u8; 32];

    for i in (0..256usize).rev() {
        // Shift remainder left by 1 bit
        let mut carry = 0u8;
        for byte in remainder.iter_mut() {
            let new_carry = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = new_carry;
        }

        // Bring down next bit from numerator
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        remainder[0] |= (numerator[byte_idx] >> bit_idx) & 1;

        if u256_gte(remainder, denominator) {
            remainder = u256_sub(remainder, denominator);
            quotient[byte_idx] |= 1 << bit_idx;
        }
    }

    quotient
}

/// Compare a > b (256-bit little-endian).
pub fn u256_gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false // equal means not greater
}

/// Compute work for a compact target value.
/// Uses Bitcoin Core's formula: (~target / (target + 1)) + 1
fn work_for_compact_target(bits: CompactTarget) -> [u8; 32] {
    let target = Target::from_compact(bits);
    let t = target.to_le_bytes();

    if t == [0u8; 32] {
        return [0u8; 32];
    }

    let one = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };
    let not_t = u256_not(t);
    let t_plus_1 = u256_add(t, one);
    let q = u256_div_u256(not_t, t_plus_1);
    u256_add(q, one)
}

/// Compute cumulative proof-of-work for a sequence of headers.
/// Returns a 256-bit little-endian value representing total chainwork.
pub fn chainwork_for_headers(headers: &[Header]) -> [u8; 32] {
    let mut total = [0u8; 32];
    for header in headers {
        let work = work_for_compact_target(header.bits);
        total = u256_add(total, work);
    }
    total
}

/// Check that a header batch whose first header sits at `start_height`
/// doesn't conflict with the chain anchor: if the batch covers
/// `anchor_height`, the header there must hash to `anchor_hash`. Batches
/// entirely above or below the anchor pass trivially — linkage to a stored
/// chain that already contains the anchor is checked by `validate_headers`.
pub fn check_anchor(
    headers: &[Header],
    start_height: u32,
    anchor_height: u32,
    anchor_hash: &BlockHash,
) -> Result<(), ValidationError> {
    if anchor_height < start_height {
        return Ok(());
    }
    let idx = (anchor_height - start_height) as usize;
    match headers.get(idx) {
        Some(h) if h.block_hash() != *anchor_hash => Err(ValidationError::AnchorMismatch {
            height: anchor_height,
            expected: anchor_hash.to_string(),
            got: h.block_hash().to_string(),
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;

    const MAINNET_POW_LIMIT: u32 = 0x1d00ffff;

    /// Real mainnet genesis block header.
    fn genesis_header() -> bitcoin::block::Header {
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        deserialize(&raw).unwrap()
    }

    /// Real mainnet block 1 header.
    fn block1_header() -> bitcoin::block::Header {
        let raw = hex::decode(
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900\
             00000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e8\
             57233e0e61bc6649ffff001d01e36299",
        )
        .unwrap();
        deserialize(&raw).unwrap()
    }

    // ── U256 arithmetic ─────────────────────────────────────────────

    #[test]
    fn u256_mul_small() {
        let mut bytes = [0u8; 32];
        bytes[0] = 100;
        let result = u256_mul_u64(bytes, 5);
        // 500 = 0x01F4 → LE: [0xF4, 0x01, 0, ...]
        assert_eq!(result[0], 0xF4);
        assert_eq!(result[1], 0x01);
        assert!(result[2..].iter().all(|&b| b == 0));
    }

    #[test]
    fn u256_mul_large() {
        // 2^64 * 3 = 3 * 2^64
        let mut bytes = [0u8; 32];
        bytes[8] = 1; // value = 2^64
        let result = u256_mul_u64(bytes, 3);
        // 3 * 2^64: limb[0]=0, limb[1]=3
        assert_eq!(result[8], 3);
        assert!(result[0..8].iter().all(|&b| b == 0));
        assert!(result[9..].iter().all(|&b| b == 0));
    }

    #[test]
    fn u256_mul_overflow_saturates() {
        let bytes = [0xFF; 32]; // max U256
        let result = u256_mul_u64(bytes, 2);
        // Should saturate to all-ones
        assert_eq!(result, [0xFF; 32]);
    }

    #[test]
    fn u256_div_exact() {
        let mut bytes = [0u8; 32];
        // 1000 = 0x03E8
        bytes[0] = 0xE8;
        bytes[1] = 0x03;
        let result = u256_div_u64(bytes, 4);
        // 1000 / 4 = 250 = 0xFA
        assert_eq!(result[0], 250);
        assert!(result[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn u256_div_rounds_toward_zero() {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        let result = u256_div_u64(bytes, 2);
        // 7 / 2 = 3 (truncated)
        assert_eq!(result[0], 3);
    }

    #[test]
    fn u256_mul_then_div_roundtrip() {
        // target * 4 / 4 should approximately equal target
        let target = Target::from_compact(CompactTarget::from_consensus(0x1d00ffff));
        let bytes = target.to_le_bytes();
        let multiplied = u256_mul_u64(bytes, 1_209_600);
        let divided = u256_div_u64(multiplied, 1_209_600);
        // Should be same (exact roundtrip for this value)
        assert_eq!(divided, bytes);
    }

    // ── Difficulty retarget calculation ──────────────────────────────

    #[test]
    fn retarget_exact_two_weeks_no_change() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let result = calculate_next_target(bits, TARGET_TIMESPAN, MAINNET_POW_LIMIT);
        assert_eq!(result.to_consensus(), bits.to_consensus());
    }

    #[test]
    fn retarget_faster_increases_difficulty() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let result = calculate_next_target(bits, TARGET_TIMESPAN / 2, MAINNET_POW_LIMIT);
        let original = Target::from_compact(bits);
        let adjusted = Target::from_compact(result);
        // Faster mining → lower target → harder difficulty
        assert!(adjusted < original);
    }

    #[test]
    fn retarget_slower_decreases_difficulty() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let result = calculate_next_target(bits, TARGET_TIMESPAN * 2, MAINNET_POW_LIMIT);
        let original = Target::from_compact(bits);
        let adjusted = Target::from_compact(result);
        // Slower mining → higher target → easier difficulty
        // But genesis is already max target, so it gets capped
        assert!(adjusted >= original || adjusted == original);
    }

    #[test]
    fn retarget_clamps_at_4x_increase() {
        // Use a harder difficulty so we have room to increase
        let bits = CompactTarget::from_consensus(0x1c00ffff);
        let result_8x = calculate_next_target(bits, TARGET_TIMESPAN * 8, MAINNET_POW_LIMIT);
        let result_4x = calculate_next_target(bits, TARGET_TIMESPAN * 4, MAINNET_POW_LIMIT);
        // 8x should be clamped to same as 4x
        assert_eq!(result_8x.to_consensus(), result_4x.to_consensus());
    }

    #[test]
    fn retarget_clamps_at_quarter_decrease() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let result_8th = calculate_next_target(bits, TARGET_TIMESPAN / 8, MAINNET_POW_LIMIT);
        let result_4th = calculate_next_target(bits, TARGET_TIMESPAN / 4, MAINNET_POW_LIMIT);
        // 1/8th should be clamped to same as 1/4th
        assert_eq!(result_8th.to_consensus(), result_4th.to_consensus());
    }

    #[test]
    fn retarget_caps_at_max_target() {
        // Start at max target, double the timespan → should stay at max
        let bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT);
        let result = calculate_next_target(bits, TARGET_TIMESPAN * 2, MAINNET_POW_LIMIT);
        assert_eq!(result.to_consensus(), MAINNET_POW_LIMIT);
    }

    // ── Full header validation ──────────────────────────────────────

    /// Mine a regtest header at height 1 with the given version.
    fn regtest_header_with_version(version: i32) -> (bitcoin::block::Header, bitcoin::block::Header) {
        let genesis = ChainParams::regtest().genesis_header();
        let mut h = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(version),
            prev_blockhash: genesis.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: genesis.time + 600,
            bits: genesis.bits,
            nonce: 0,
        };
        while h.validate_pow(h.target()).is_err() {
            h.nonce += 1;
        }
        (genesis, h)
    }

    /// ContextualCheckBlockHeader `bad-version` (ticket 026): versions
    /// below 2/3/4 are rejected once BIP 34/66/65 are active.
    #[test]
    fn rejects_outdated_versions_after_activation() {
        let check = |params: &ChainParams, version: i32| {
            let (genesis, h) = regtest_header_with_version(version);
            validate_headers(params, &[h], genesis.block_hash(), 0, &[genesis.time], genesis.bits, &|_| {
                Err("no retarget".into())
            })
        };
        let all_active = ChainParams::regtest();
        for v in [1, 2, 3, -1, i32::MIN] {
            assert!(
                matches!(check(all_active, v), Err(ValidationError::BadVersion { height: 1, .. })),
                "version {} must be rejected",
                v
            );
        }
        for v in [4, 0x2000_0000, 0x3fff_ffff, i32::MAX] {
            assert!(check(all_active, v).is_ok(), "version {} must be accepted", v);
        }

        // Each threshold separately.
        let only = |bip34, bip66, bip65| -> &'static ChainParams {
            Box::leak(Box::new(ChainParams {
                bip34_height: bip34,
                bip66_height: bip66,
                bip65_height: bip65,
                ..*ChainParams::regtest()
            }))
        };
        let none = only(100, 100, 100);
        assert!(check(none, 1).is_ok(), "pre-BIP-34 version 1 is fine");
        assert!(check(only(1, 100, 100), 1).is_err());
        assert!(check(only(1, 100, 100), 2).is_ok());
        assert!(check(only(1, 1, 100), 2).is_err());
        assert!(check(only(1, 1, 100), 3).is_ok());
        assert!(check(only(1, 1, 1), 3).is_err());
    }

    #[test]
    fn validate_real_block1() {
        let genesis = genesis_header();
        let block1 = block1_header();

        // Sanity check: block 1's hash is well-known
        assert_eq!(
            block1.block_hash().to_string(),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );

        let result = validate_headers(
            ChainParams::mainnet(),
            &[block1],
            genesis.block_hash(),
            0,
            &[genesis.time],
            genesis.bits,
            &|_| Err("should not be called for block 1".into()),
        );
        assert!(result.is_ok(), "block 1 should validate: {:?}", result);
    }

    #[test]
    fn validate_rejects_wrong_prev_hash() {
        let block1 = block1_header();

        let result = validate_headers(
            ChainParams::mainnet(),
            &[block1],
            BlockHash::all_zeros(),
            0,
            &[1231006505],
            CompactTarget::from_consensus(0x1d00ffff),
            &|_| Err("unused".into()),
        );
        assert!(matches!(result, Err(ValidationError::BadPrevHash { .. })));
    }

    #[test]
    fn validate_rejects_difficulty_change_between_retargets() {
        let genesis = genesis_header();
        let block1 = block1_header();

        // Claim the previous block had different difficulty
        let wrong_bits = CompactTarget::from_consensus(0x1c00ffff);

        let result = validate_headers(
            ChainParams::mainnet(),
            &[block1],
            genesis.block_hash(),
            0,
            &[genesis.time],
            wrong_bits,
            &|_| Err("unused".into()),
        );
        assert!(
            matches!(result, Err(ValidationError::BadDifficulty { .. })),
            "should reject difficulty change between retargets: {:?}",
            result
        );
    }

    #[test]
    fn validate_rejects_bad_pow() {
        let genesis = genesis_header();

        // Block 1 with tampered nonce (all zeros)
        let raw = hex::decode(
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900\
             00000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e8\
             57233e0e61bc6649ffff001d00000000",
        )
        .unwrap();
        let bad_header: bitcoin::block::Header = deserialize(&raw).unwrap();

        let result = validate_headers(
            ChainParams::mainnet(),
            &[bad_header],
            genesis.block_hash(),
            0,
            &[genesis.time],
            genesis.bits,
            &|_| Err("unused".into()),
        );
        assert!(
            matches!(result, Err(ValidationError::InsufficientPow { .. })),
            "tampered nonce should fail PoW: {:?}",
            result
        );
    }

    // ── Chainwork ────────────────────────────────────────────────────

    #[test]
    fn work_for_genesis_difficulty() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let work = super::work_for_compact_target(bits);
        assert!(work != [0u8; 32]);
        // At genesis difficulty, work ≈ 2^32
        let work_u64 = u64::from_le_bytes(work[0..8].try_into().unwrap());
        assert!(work_u64 > 0);
        assert!(work_u64 < 1 << 33);
    }

    #[test]
    fn chainwork_sums_correctly() {
        let genesis = genesis_header();
        let block1 = block1_header();
        let single = super::chainwork_for_headers(&[genesis]);
        let double = super::chainwork_for_headers(&[genesis, block1]);
        assert!(super::u256_gt(&double, &single));
    }

    #[test]
    fn u256_add_basic() {
        let mut a = [0u8; 32];
        a[0] = 200;
        let mut b = [0u8; 32];
        b[0] = 100;
        let result = super::u256_add(a, b);
        assert_eq!(result[0], 0x2C);
        assert_eq!(result[1], 0x01);
    }

    #[test]
    fn u256_div_u256_basic() {
        let mut a = [0u8; 32];
        a[0] = 100;
        let mut b = [0u8; 32];
        b[0] = 10;
        let result = super::u256_div_u256(a, b);
        assert_eq!(result[0], 10);
        assert!(result[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn u256_gt_works() {
        let mut a = [0u8; 32];
        a[0] = 5;
        let mut b = [0u8; 32];
        b[0] = 3;
        assert!(super::u256_gt(&a, &b));
        assert!(!super::u256_gt(&b, &a));
        assert!(!super::u256_gt(&a, &a));
    }

    #[test]
    fn validate_rejects_bad_timestamp() {
        let genesis = genesis_header();
        let block1 = block1_header();

        // Provide 11 fake timestamps all higher than block 1's timestamp
        // Block 1 timestamp is 1231469665
        let future_timestamps: Vec<u32> = (0..11).map(|i| 1231469665 + 1000 + i).collect();

        let result = validate_headers(
            ChainParams::mainnet(),
            &[block1],
            genesis.block_hash(),
            11, // pretend we're at height 11 so the median check activates
            &future_timestamps,
            genesis.bits,
            &|_| Err("unused".into()),
        );
        assert!(
            matches!(result, Err(ValidationError::BadTimestamp { .. })),
            "timestamp behind median should fail: {:?}",
            result
        );
    }

    // ── u256 edge case tests ──────────────────────────────────────

    #[test]
    fn u256_add_overflow_wraps() {
        let max = [0xFF; 32];
        let one = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        // max + 1 wraps to zero (carry discarded)
        let result = super::u256_add(max, one);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn u256_add_zero_identity() {
        let zero = [0u8; 32];
        let val = {
            let mut b = [0u8; 32];
            b[0] = 42;
            b
        };
        assert_eq!(super::u256_add(val, zero), val);
        assert_eq!(super::u256_add(zero, val), val);
    }

    #[test]
    fn u256_sub_basic() {
        let a = {
            let mut b = [0u8; 32];
            b[0] = 200;
            b
        };
        let b = {
            let mut v = [0u8; 32];
            v[0] = 100;
            v
        };
        let result = super::u256_sub(a, b);
        assert_eq!(result[0], 100);
        assert!(result[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn u256_sub_self_is_zero() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 0xFF;
            b[7] = 0xAB;
            b
        };
        let result = super::u256_sub(val, val);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn u256_mul_by_zero() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 42;
            b
        };
        let result = super::u256_mul_u64(val, 0);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn u256_mul_by_one() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 99;
            b[8] = 0x12;
            b
        };
        let result = super::u256_mul_u64(val, 1);
        assert_eq!(result, val);
    }

    #[test]
    fn u256_div_u64_by_one() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 77;
            b[16] = 0xFF;
            b
        };
        let result = super::u256_div_u64(val, 1);
        assert_eq!(result, val);
    }

    #[test]
    fn u256_div_u64_by_zero_saturates() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 42;
            b
        };
        let result = super::u256_div_u64(val, 0);
        assert_eq!(result, [0xFF; 32]);
    }

    #[test]
    fn u256_div_u256_equal_is_one() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 100;
            b[16] = 0xAB;
            b
        };
        let result = super::u256_div_u256(val, val);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(result, expected);
    }

    #[test]
    fn u256_div_u256_smaller_numerator_is_zero() {
        let small = {
            let mut b = [0u8; 32];
            b[0] = 5;
            b
        };
        let big = {
            let mut b = [0u8; 32];
            b[0] = 10;
            b
        };
        let result = super::u256_div_u256(small, big);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn u256_div_u256_by_one() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 0xDE;
            b[1] = 0xAD;
            b
        };
        let one = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        let result = super::u256_div_u256(val, one);
        assert_eq!(result, val);
    }

    #[test]
    fn u256_div_u256_by_zero_saturates() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 42;
            b
        };
        let result = super::u256_div_u256(val, [0u8; 32]);
        assert_eq!(result, [0xFF; 32]);
    }

    #[test]
    fn u256_gte_equal_values() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 0xFF;
            b[31] = 0x01;
            b
        };
        assert!(super::u256_gte(val, val));
    }

    #[test]
    fn u256_gt_equal_returns_false() {
        let val = {
            let mut b = [0u8; 32];
            b[0] = 42;
            b
        };
        assert!(!super::u256_gt(&val, &val));
    }

    #[test]
    fn u256_not_zero_is_max() {
        let result = super::u256_not([0u8; 32]);
        assert_eq!(result, [0xFF; 32]);
    }

    #[test]
    fn u256_not_max_is_zero() {
        let result = super::u256_not([0xFF; 32]);
        assert_eq!(result, [0u8; 32]);
    }

    // ── chainwork edge cases ───���─────────────────────────��────────

    #[test]
    fn chainwork_empty_headers_is_zero() {
        let result = super::chainwork_for_headers(&[]);
        assert_eq!(result, [0u8; 32]);
    }

    // ── check_anchor ────────────────────────────────────────────────

    #[test]
    fn check_anchor_accepts_matching_header() {
        let headers = [genesis_header(), block1_header()];
        let anchor = block1_header().block_hash();
        assert!(check_anchor(&headers, 0, 1, &anchor).is_ok());
    }

    #[test]
    fn check_anchor_rejects_conflicting_header() {
        let headers = [genesis_header(), block1_header()];
        let anchor = genesis_header().block_hash();
        let err = check_anchor(&headers, 0, 1, &anchor).unwrap_err();
        assert!(matches!(err, ValidationError::AnchorMismatch { height: 1, .. }));
    }

    #[test]
    fn check_anchor_ignores_batches_not_covering_anchor() {
        let headers = [block1_header()];
        let anchor = genesis_header().block_hash();
        // Entirely above the anchor.
        assert!(check_anchor(&headers, 1, 0, &anchor).is_ok());
        // Entirely below the anchor.
        assert!(check_anchor(&headers, 1, 5, &anchor).is_ok());
    }

    #[test]
    fn work_for_zero_target_is_zero() {
        // A zero target (invalid) should return zero work
        use bitcoin::CompactTarget;
        let result = super::work_for_compact_target(CompactTarget::from_consensus(0));
        assert_eq!(result, [0u8; 32]);
    }

    // ── validate_headers edge cases ────────��──────────────────────

    #[test]
    fn validate_skips_mtp_with_few_timestamps() {
        // With < 11 timestamps, the MTP check should be skipped
        let genesis = genesis_header();
        let block1 = block1_header();

        // Only 2 timestamps — MTP check should not activate
        let timestamps = vec![genesis.time, genesis.time + 1];

        let result = validate_headers(
            ChainParams::mainnet(),
            &[block1],
            genesis.block_hash(),
            0,
            &timestamps,
            genesis.bits,
            &|_| Err("unused".into()),
        );
        assert!(result.is_ok(), "should pass with < 11 timestamps: {:?}", result);
    }

    // ── Chain params (ticket 027) ─────────────────────────────────

    /// A regtest-difficulty header on `prev`, mined until its PoW is valid.
    fn mined_regtest_header(prev: &Header) -> Header {
        let mut h = Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: prev.time + 600,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        while h.validate_pow(h.target()).is_err() {
            h.nonce += 1;
        }
        h
    }

    #[test]
    fn regtest_does_not_retarget_at_epoch_boundary() {
        let prev = ChainParams::regtest().genesis_header();
        let next = mined_regtest_header(&prev);
        // Height 2016 is a retarget boundary on mainnet. Regtest keeps the
        // parent's bits and never consults the epoch-start lookup.
        let result = validate_headers(
            ChainParams::regtest(),
            &[next],
            prev.block_hash(),
            2015,
            &[prev.time],
            prev.bits,
            &|_| Err("must not be called".into()),
        );
        assert!(result.is_ok(), "{:?}", result);

        // Same input under mainnet rules is a retarget and must be checked:
        // the lookup is consulted (and its failure is ours, ticket 052).
        let result = validate_headers(
            ChainParams::mainnet(),
            &[next],
            prev.block_hash(),
            2015,
            &[prev.time],
            prev.bits,
            &|_| Err("no epoch start".into()),
        );
        assert!(matches!(result, Err(ValidationError::MissingContext { height: 2016, .. })), "{:?}", result);
    }

    #[test]
    fn regtest_rejects_bits_change() {
        let prev = ChainParams::regtest().genesis_header();
        let mut next = mined_regtest_header(&prev);
        next.bits = CompactTarget::from_consensus(0x2007ffff);
        let result = validate_headers(
            ChainParams::regtest(),
            &[next],
            prev.block_hash(),
            2015,
            &[prev.time],
            prev.bits,
            &|_| Err("unused".into()),
        );
        assert!(matches!(result, Err(ValidationError::BadDifficulty { .. })), "{:?}", result);
    }

    // ── Data-path pass: real retargets, oracles, exact boundaries ────

    fn hdr(hex_str: &str) -> bitcoin::block::Header {
        deserialize(&hex::decode(hex_str).unwrap()).unwrap()
    }

    /// Real mainnet retargets: (height H, header H-2016 = epoch start,
    /// header H-1, header H). Raw headers, public chain data.
    fn mainnet_retargets() -> Vec<(u32, bitcoin::block::Header, bitcoin::block::Header, bitcoin::block::Header)> {
        vec![
            // First retarget: the epoch took far longer than two weeks, so
            // the 4x clamp applies and the result is capped at the PoW limit.
            (
                2016,
                genesis_header(),
                hdr("01000000e25509cde707c3d02a693e4fe9e7cdd57c38a0d2c8d6341f20dae84b000000000c113df1185e162ee92d031fe21d1400ff7d705a3e9b9c860eea855313cd8ca26c087f49ffff001d30b73231"),
                hdr("010000006397bb6abd4fc521c0d3f6071b5650389f0b4551bc40b4e6b067306900000000ace470aecda9c8818c8fe57688cd2a772b5a57954a00df0420a7dd546b6d2c576b0e7f49ffff001d33f0192f"),
            ),
            // First difficulty increase: 0x1d00ffff -> 0x1d00d86a.
            (
                32256,
                hdr("01000000e6bf7fd7f7790a63786faa878d0dc7fd8f2ff365732e45862c66075100000000700d342f65c7b6834dffb615358a1897016f0448913372190cbe3d27a4b53355b1512b4bffff001dbfb02519"),
                hdr("0100000049c1daab3b6536ff1b2633c3a316a6e06ec287676cdeec4ca7baae6b00000000ac10b36b8f354b3353207de15940a5edbc05bb8364af75b4b5409e7823f2b48923ec3a4bffff001dbd5fa412"),
                hdr("010000004b0360d834a330ec7833e30e1f523ee05a0793361e29a73421964f980000000027b64a020af294e903feed93768705336a20090612a043f47af462a2f5e5b564f8ee3a4b6ad8001dd3a43707"),
            ),
            // The largest decrease on record (2021 China mining ban).
            (
                689472,
                hdr("040000207346ca53de43c0a2176e8a12f3bf1788613b892844460100000000000000000018c096ec291c41b8192048a22398bcbcb238fb5e52a4a5c37ca318a536fff92e7465c660f91e0e175f89e127"),
                hdr("0400002010c7e39c457b1037a11ed5ae40b5552292a4d509e266000000000000000000003de5a2921399777aa73ed267590b64996940122c5e4b70857b8da9df0309f7dabd02e060f91e0e17500b5b04"),
                hdr("0420d1297c65a9842c11702870b6fd4fc29c7a0e431dab16c8cb090000000000000000002d035269665426c99644d1cf3cdde1caac14de3c0737b0c29b3868eb164f0178de04e060ce9813172f3f2398"),
            ),
            // The last retarget before the AssumeUTXO anchor (943,500).
            (
                943488,
                hdr("00a04e38373d0c01c28991ba80faec5d306ae89732ab13800b7201000000000000000000b9ff0d1552f4c89dbb9c1b4825da6c49354ea5037cc16aa837c0f20244a1d94a0bc2bd69911a021700e00e14"),
                hdr("0000003a0d341c29548cd4f35eb3dda1721983df65f5cf3ba8e401000000000000000000862623e067e30da1020d1ad71f7b39f8bbd1dcdf61c171c2ac238a77a87141e42987cf69911a0217fcf6d8d1"),
                hdr("0080f52c6930038c2610c7b36fe5363acf2af590e7eb08d93fb600000000000000000000e9dfa2b7f7d61fec8f003a73092d493b8f5a60d19567a0e9621e16612bbf7fab4888cf69840602179cb05d27"),
            ),
        ]
    }

    /// The retarget arithmetic (clamp, 256-bit multiply/divide, PoW-limit
    /// cap, compact rounding) reproduces every real retarget, and
    /// `validate_headers` reads the epoch start at exactly H - 2016.
    #[test]
    fn real_mainnet_retargets_are_reproduced_exactly() {
        let params = ChainParams::mainnet();
        for (h, start, last, new) in mainnet_retargets() {
            assert_eq!(new.prev_blockhash, last.block_hash(), "fixture linkage at {}", h);
            let span = last.time as i64 - start.time as i64;
            assert_eq!(calculate_next_target(last.bits, span, MAINNET_POW_LIMIT), new.bits, "retarget at {}", h);

            let start_time = start.time;
            let epoch = |want: u32| move |at: u32| -> Result<u32, String> {
                if at == want { Ok(start_time) } else { Err(format!("asked for {}", at)) }
            };
            let check = |hdr: &bitcoin::block::Header, lookup: &dyn Fn(u32) -> Result<u32, String>| {
                validate_headers(params, &[*hdr], last.block_hash(), h - 1, &[last.time], last.bits, lookup)
            };
            check(&new, &epoch(h - 2016)).unwrap_or_else(|e| panic!("real header {}: {}", h, e));
            // Off-by-one epoch starts are never consulted.
            for wrong in [Some(h - 2015), h.checked_sub(2017)].into_iter().flatten() {
                assert!(check(&new, &epoch(wrong)).is_err(), "{} consulted epoch start {}", h, wrong);
            }
            // Any other bits at the boundary are refused before PoW.
            let mut tampered = new;
            tampered.bits = CompactTarget::from_consensus(new.bits.to_consensus() - 1);
            assert!(matches!(check(&tampered, &epoch(h - 2016)), Err(ValidationError::BadDifficulty { .. })));
            // One block earlier (not a boundary) the same change is refused.
            if new.bits != last.bits {
                assert!(matches!(
                    validate_headers(params, &[last], last.prev_blockhash, h - 2, &[], new.bits, &epoch(0)),
                    Err(ValidationError::BadDifficulty { .. })
                ));
            }
        }
    }

    fn arb_mainnet_bits() -> impl proptest::strategy::Strategy<Value = CompactTarget> {
        use proptest::prelude::*;
        // Normalized compact targets from the PoW limit down to tiny ones.
        (0x04u32..=0x1d, 0x0080_00u32..=0x7f_ffff).prop_filter_map("above the PoW limit", |(exp, mant)| {
            let bits = CompactTarget::from_consensus((exp << 24) | mant);
            let target = bitcoin::pow::Target::from_compact(bits);
            (target <= bitcoin::pow::Target::from_compact(CompactTarget::from_consensus(MAINNET_POW_LIMIT)))
                .then_some(bits)
        })
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// Differential: rust-bitcoin's independent port of Core's
        /// `CalculateNextWorkRequired` agrees for any target and timespan,
        /// including negative timespans (timestamps may go backwards) and
        /// both clamps.
        #[test]
        fn retarget_matches_rust_bitcoin(bits in arb_mainnet_bits(), span in -3 * TARGET_TIMESPAN..10 * TARGET_TIMESPAN) {
            let ours = calculate_next_target(bits, span, MAINNET_POW_LIMIT);
            let theirs = CompactTarget::from_next_work_required(bits, span.max(0) as u64, bitcoin::params::Params::MAINNET);
            proptest::prop_assert_eq!(ours, theirs);
        }

        /// Differential: chainwork per header equals rust-bitcoin's
        /// `Target::to_work` (Core's GetBlockProof: ~t / (t + 1) + 1).
        #[test]
        fn work_matches_rust_bitcoin(bits in arb_mainnet_bits()) {
            let target = bitcoin::pow::Target::from_compact(bits);
            proptest::prop_assert_eq!(work_for_compact_target(bits), target.to_work().to_le_bytes());
        }

        /// u256 helpers against u128 arithmetic on values that fit.
        #[test]
        fn u256_helpers_match_u128(a in proptest::prelude::any::<u128>(), b in 1u128..) {
            let le = |x: u128| { let mut o = [0u8; 32]; o[..16].copy_from_slice(&x.to_le_bytes()); o };
            let (a32, b32) = (le(a), le(b));
            proptest::prop_assert_eq!(u256_div_u256(a32, b32), le(a / b));
            proptest::prop_assert_eq!(u256_gt(&a32, &b32), a > b);
            proptest::prop_assert_eq!(u256_gte(a32, b32), a >= b);
            if a >= b {
                proptest::prop_assert_eq!(u256_sub(a32, b32), le(a - b));
            }
            if let Some(s) = a.checked_add(b) {
                proptest::prop_assert_eq!(u256_add(a32, b32), le(s));
            }
            let small = (b % (1 << 63)) as u64 + 1;
            proptest::prop_assert_eq!(u256_div_u64(a32, small), le(a / small as u128));
            if let Some(p) = a.checked_mul(small as u128) {
                proptest::prop_assert_eq!(u256_mul_u64(a32, small), le(p));
            }
        }
    }

    fn now_secs() -> u32 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32
    }

    fn regtest_header_at(prev: &bitcoin::block::Header, time: u32) -> bitcoin::block::Header {
        let mut h = mined_regtest_header(prev);
        h.time = time;
        h.nonce = 0;
        while h.validate_pow(h.target()).is_err() {
            h.nonce += 1;
        }
        h
    }

    /// MAX_FUTURE_BLOCK_TIME: now + 2 h is accepted, one second more is
    /// not. The clock is read inside `validate_headers`, so the rejection
    /// is only asserted for a run where the second didn't tick over.
    #[test]
    fn future_time_limit_is_exactly_two_hours() {
        let params = ChainParams::regtest();
        let prev = params.genesis_header();
        let check = |h: bitcoin::block::Header| {
            validate_headers(params, &[h], prev.block_hash(), 0, &[prev.time], prev.bits, &|_| Err("unused".into()))
        };
        let now = now_secs();
        check(regtest_header_at(&prev, now + 7200)).expect("now + 7200 s is allowed");
        for _ in 0..50 {
            let before = now_secs();
            let header = regtest_header_at(&prev, before + 7201);
            let result = check(header);
            if now_secs() == before {
                assert!(
                    matches!(result, Err(ValidationError::FutureTimestamp { max_allowed, .. }) if max_allowed == before + 7200),
                    "{:?}",
                    result
                );
                return;
            }
        }
        panic!("clock ticked during every attempt");
    }

    /// Version rules switch on at exactly the activation height, inside a
    /// single batch: a v1 header at BIP34 height - 1 is fine, at the
    /// height it isn't (and the error names that height).
    #[test]
    fn version_rule_activates_at_exactly_its_height() {
        let params: &'static ChainParams =
            Box::leak(Box::new(ChainParams { bip34_height: 2, bip66_height: 100, bip65_height: 100, ..*ChainParams::regtest() }));
        let prev = params.genesis_header();
        let v1 = |parent: &bitcoin::block::Header| {
            let mut h = mined_regtest_header(parent);
            h.version = bitcoin::block::Version::from_consensus(1);
            while h.validate_pow(h.target()).is_err() {
                h.nonce += 1;
            }
            h
        };
        let h1v1 = v1(&prev);
        let h2 = v1(&h1v1);
        let r = validate_headers(params, &[h1v1, h2], prev.block_hash(), 0, &[prev.time], prev.bits, &|_| Err("unused".into()));
        assert!(matches!(r, Err(ValidationError::BadVersion { height: 2, version: 1 })), "{:?}", r);
        validate_headers(params, &[h1v1], prev.block_hash(), 0, &[prev.time], prev.bits, &|_| Err("unused".into()))
            .expect("v1 is fine one block before activation");
    }

    /// Errors name the height of the first bad header in a batch, and
    /// headers before it are not enough to make the batch pass.
    #[test]
    fn batch_errors_name_the_failing_height() {
        let params = ChainParams::regtest();
        let prev = params.genesis_header();
        let a = mined_regtest_header(&prev);
        let b = mined_regtest_header(&a);
        let mut c = mined_regtest_header(&b);
        c.prev_blockhash = a.block_hash(); // skips b
        let r = validate_headers(params, &[a, b, c], prev.block_hash(), 40, &[prev.time], prev.bits, &|_| Err("unused".into()));
        assert!(matches!(r, Err(ValidationError::BadPrevHash { height: 43, .. })), "{:?}", r);
    }

    /// Median-time-past over an unsorted 11-block window: equal to the
    /// median is too early, one second later is fine.
    #[test]
    fn mtp_boundary_with_an_unsorted_window() {
        let params = ChainParams::regtest();
        let prev = params.genesis_header();
        // Median of these 11 is base + 50.
        let base = prev.time - 1_000;
        let window: Vec<u32> = [90u32, 10, 50, 100, 0, 70, 20, 80, 30, 60, 40].iter().map(|d| base + d).collect();
        let check = |t: u32| {
            validate_headers(params, &[regtest_header_at(&prev, t)], prev.block_hash(), 20, &window, prev.bits, &|_| {
                Err("unused".into())
            })
        };
        assert!(matches!(check(base + 50), Err(ValidationError::BadTimestamp { median_past, .. }) if median_past == base + 50));
        check(base + 51).expect("one second past the median");
    }

    #[test]
    fn check_anchor_at_batch_edges() {
        let params = ChainParams::regtest();
        let g = params.genesis_header();
        let a = mined_regtest_header(&g);
        let b = mined_regtest_header(&a);
        let batch = [a, b];
        // Anchor at the first and the last header of the batch.
        assert!(check_anchor(&batch, 10, 10, &a.block_hash()).is_ok());
        assert!(check_anchor(&batch, 10, 11, &b.block_hash()).is_ok());
        assert!(matches!(check_anchor(&batch, 10, 10, &b.block_hash()), Err(ValidationError::AnchorMismatch { height: 10, .. })));
        assert!(matches!(check_anchor(&batch, 10, 11, &a.block_hash()), Err(ValidationError::AnchorMismatch { height: 11, .. })));
        // Just past either end: not this batch's business.
        assert!(check_anchor(&batch, 10, 12, &g.block_hash()).is_ok());
        assert!(check_anchor(&batch, 10, 9, &g.block_hash()).is_ok());
        assert!(check_anchor(&[], 10, 10, &g.block_hash()).is_ok());
    }

    /// Core's GetMedianTimePast uses every ancestor when there are fewer
    /// than 11, so block 1 must be later than genesis.
    #[test]
    fn mtp_applies_with_fewer_than_eleven_ancestors() {
        let params = ChainParams::regtest();
        let prev = params.genesis_header();
        let same_time = regtest_header_at(&prev, prev.time);
        let r = validate_headers(params, &[same_time], prev.block_hash(), 0, &[prev.time], prev.bits, &|_| Err("unused".into()));
        assert!(matches!(r, Err(ValidationError::BadTimestamp { .. })), "{:?}", r);
    }

    /// A failure to read *our own* header store for the epoch start is a
    /// local fault, not evidence against the peer's header.
    #[test]
    fn epoch_start_lookup_failure_is_not_a_bad_difficulty_verdict() {
        let (h, _, last, new) = mainnet_retargets().remove(1);
        let r = validate_headers(ChainParams::mainnet(), &[new], last.block_hash(), h - 1, &[last.time], last.bits, &|_| {
            Err("database is locked".into())
        });
        assert!(r.is_err());
        assert!(!matches!(r, Err(ValidationError::BadDifficulty { .. })), "{:?}", r);
        assert_eq!(r.unwrap_err().class(), HeaderErrorClass::Local);
    }

    /// The MTP window grows with the chain below height 11: at height 3
    /// the median is the middle of genesis, 1 and 2 (Core's
    /// `pbegin[(pend - pbegin) / 2]` of the sorted ancestors), and at
    /// height 2 the later of the two (index 1 of 2).
    #[test]
    fn mtp_window_below_height_eleven_is_every_ancestor() {
        let params = ChainParams::regtest();
        let g = params.genesis_header();
        // Ancestors' times: genesis, g+1000, g+10 (block 2 may be earlier
        // than block 1 as long as it beats their median).
        let b1 = regtest_header_at(&g, g.time + 1000);
        let check_at_2 = |t: u32| {
            validate_headers(params, &[regtest_header_at(&b1, t)], b1.block_hash(), 1, &[g.time, b1.time], g.bits, &|_| {
                Err("unused".into())
            })
        };
        // Window {g, g+1000}: index 1 is g+1000.
        assert!(matches!(check_at_2(g.time + 1000), Err(ValidationError::BadTimestamp { median_past, .. }) if median_past == g.time + 1000));
        check_at_2(g.time + 1001).expect("past the median of two");
        let b2 = regtest_header_at(&b1, g.time + 1001);
        // Window {g, g+1000, g+1001}: median g+1000.
        let check_at_3 = |t: u32| {
            validate_headers(params, &[regtest_header_at(&b2, t)], b2.block_hash(), 2, &[g.time, b1.time, b2.time], g.bits, &|_| {
                Err("unused".into())
            })
        };
        assert!(matches!(check_at_3(g.time + 1000), Err(ValidationError::BadTimestamp { .. })));
        check_at_3(g.time + 1001).expect("one second past the median of three");
    }

    /// A header from more than two hours ahead is "not yet valid", not
    /// invalid, and is past `max_header_time_now` (what sync cuts batches
    /// at).
    #[test]
    fn future_timestamp_is_not_yet_valid() {
        let params = ChainParams::regtest();
        let g = params.genesis_header();
        let a = mined_regtest_header(&g);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
        let b = regtest_header_at(&a, now + 3 * 3600);
        let e = validate_headers(params, &[a, b], g.block_hash(), 0, &[g.time], g.bits, &|_| Err("unused".into()))
            .unwrap_err();
        assert!(matches!(e, ValidationError::FutureTimestamp { height: 2, .. }), "{:?}", e);
        assert_eq!(e.class(), HeaderErrorClass::NotYetValid);
        assert!(b.time > max_header_time_now() && a.time <= max_header_time_now());
    }
}
