use bitcoin::block::Header;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::BlockHash;

/// Target time for one difficulty epoch (2016 blocks): 2 weeks.
const TARGET_TIMESPAN: i64 = 14 * 24 * 60 * 60;

/// Maximum target (minimum difficulty), same as genesis block.
const MAX_TARGET_BITS: u32 = 0x1d00ffff;

/// Validate a sequence of headers against a known previous header.
/// Returns Ok(()) if all headers are valid, or an error describing the first invalid header.
///
/// `prev_bits` is the compact target of the block at `prev_height`.
/// `epoch_start_time` looks up the timestamp of a header at a given height from the store,
/// used to fetch the first block of a difficulty epoch for retarget calculations.
pub fn validate_headers(
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
        if height % 2016 == 0 && height > 0 {
            // Retarget boundary: verify the new target is correctly calculated
            let epoch_start_height = height - 2016;
            let epoch_start_ts = epoch_start_time(epoch_start_height).map_err(|e| {
                ValidationError::BadDifficulty {
                    height,
                    expected: format!("epoch start timestamp at height {}", epoch_start_height),
                    got: e,
                }
            })?;

            let prev_time = *timestamps.last().ok_or(ValidationError::BadDifficulty {
                height,
                expected: "previous block timestamp".into(),
                got: "no timestamps available".into(),
            })?;

            let actual_timespan = prev_time as i64 - epoch_start_ts as i64;
            let expected_bits = calculate_next_target(current_bits, actual_timespan);

            if header.bits != expected_bits {
                return Err(ValidationError::BadDifficulty {
                    height,
                    expected: format!("0x{:08x}", expected_bits.to_consensus()),
                    got: format!("0x{:08x}", header.bits.to_consensus()),
                });
            }
        } else if height > 0 {
            // Between retargets: difficulty must not change
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

        // 4. Check timestamp is greater than median of last 11 blocks
        if timestamps.len() >= 11 {
            let mut recent: Vec<u32> = timestamps[timestamps.len() - 11..].to_vec();
            recent.sort();
            let median = recent[5];
            if header.time <= median {
                return Err(ValidationError::BadTimestamp {
                    height,
                    timestamp: header.time,
                    median_past: median,
                });
            }
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
fn calculate_next_target(prev_bits: CompactTarget, actual_timespan: i64) -> CompactTarget {
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
    let max_target = Target::from_compact(CompactTarget::from_consensus(MAX_TARGET_BITS));
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
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
        }
    }
}

impl std::error::Error for ValidationError {}

// ── U256 helpers for chainwork computation ──────────────────────────

/// Add two 256-bit little-endian values.
fn u256_add(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;

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
        let result = calculate_next_target(bits, TARGET_TIMESPAN);
        assert_eq!(result.to_consensus(), bits.to_consensus());
    }

    #[test]
    fn retarget_faster_increases_difficulty() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let result = calculate_next_target(bits, TARGET_TIMESPAN / 2);
        let original = Target::from_compact(bits);
        let adjusted = Target::from_compact(result);
        // Faster mining → lower target → harder difficulty
        assert!(adjusted < original);
    }

    #[test]
    fn retarget_slower_decreases_difficulty() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let result = calculate_next_target(bits, TARGET_TIMESPAN * 2);
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
        let result_8x = calculate_next_target(bits, TARGET_TIMESPAN * 8);
        let result_4x = calculate_next_target(bits, TARGET_TIMESPAN * 4);
        // 8x should be clamped to same as 4x
        assert_eq!(result_8x.to_consensus(), result_4x.to_consensus());
    }

    #[test]
    fn retarget_clamps_at_quarter_decrease() {
        let bits = CompactTarget::from_consensus(0x1d00ffff);
        let result_8th = calculate_next_target(bits, TARGET_TIMESPAN / 8);
        let result_4th = calculate_next_target(bits, TARGET_TIMESPAN / 4);
        // 1/8th should be clamped to same as 1/4th
        assert_eq!(result_8th.to_consensus(), result_4th.to_consensus());
    }

    #[test]
    fn retarget_caps_at_max_target() {
        // Start at max target, double the timespan → should stay at max
        let bits = CompactTarget::from_consensus(MAX_TARGET_BITS);
        let result = calculate_next_target(bits, TARGET_TIMESPAN * 2);
        assert_eq!(result.to_consensus(), MAX_TARGET_BITS);
    }

    // ── Full header validation ──────────────────────────────────────

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
}
