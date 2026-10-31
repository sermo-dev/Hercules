//! Contextual consensus rules ported from Bitcoin Core (ticket 026).
//!
//! The block-level rules that need more than the block itself: the height
//! and median-time-past it is mined at, and the coins it spends. Each
//! function is a direct port of the Core function named in its doc comment
//! (references are to Core v26, the version our script library is pinned
//! to; none of these functions changed in later releases except for type
//! cleanups). They are pure: callers supply heights, header timestamps and
//! spent scripts.
//!
//! - `is_final_tx`: nLockTime finality (`IsFinalTx`), with the BIP 113
//!   median-time-past cutoff chosen by the caller.
//! - `calculate_sequence_locks` / `evaluate_sequence_locks`: BIP 68
//!   relative lock-times (`CalculateSequenceLocks`, `EvaluateSequenceLocks`).
//! - `transaction_sigop_cost`: legacy + P2SH + witness sigops
//!   (`GetTransactionSigOpCost`).
//! - `coinbase_script_len_ok`: coinbase scriptSig of 2..=100 bytes
//!   (`CheckTransaction`, `bad-cb-length`).
//! - `coinbase_commits_height`: BIP 34 (`ContextualCheckBlock`,
//!   `bad-cb-height`), including Core's `OP_1..OP_16` encoding of heights
//!   1..=16.
//!
//! The libbitcoinkernel spike (ticket 047) found full kernel block
//! validation blocked on missing API, so these rules live here in Rust.

use std::collections::HashMap;

use bitcoin::{Transaction, Witness};

use crate::chain_params::{SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_WITNESS};
use crate::store::HeaderStore;

// ── Constants (Core names) ───────────────────────────────────────────

/// nLockTime values below this are block heights, at or above are Unix
/// times (`LOCKTIME_THRESHOLD`, script/script.h).
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// nSequence value that opts an input out of nLockTime
/// (`CTxIn::SEQUENCE_FINAL`).
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// BIP 68: if set, nSequence is not a relative lock-time
/// (`CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`).
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// BIP 68: if set, the relative lock is in units of 512 seconds, else blocks
/// (`CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG`).
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

/// BIP 68: the lock value itself (`CTxIn::SEQUENCE_LOCKTIME_MASK`).
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;

/// BIP 68: time-based locks are `value << 9` seconds
/// (`CTxIn::SEQUENCE_LOCKTIME_GRANULARITY`).
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

/// Maximum sigop cost per block (BIP 141, `MAX_BLOCK_SIGOPS_COST`).
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// Legacy and P2SH sigops cost this much each; witness sigops cost 1
/// (`WITNESS_SCALE_FACTOR`).
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Inaccurate CHECKMULTISIG count (`MAX_PUBKEYS_PER_MULTISIG`).
const MAX_PUBKEYS_PER_MULTISIG: u64 = 20;

/// Coinbase scriptSig length bounds (`CheckTransaction`, `bad-cb-length`).
pub const MIN_COINBASE_SCRIPT_LEN: usize = 2;
pub const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// Number of blocks in the median-time-past window
/// (`CBlockIndex::nMedianTimeSpan`).
const MEDIAN_TIME_SPAN: u32 = 11;

/// BIP 30 (no transaction may overwrite an unspent output with the same
/// txid) is implied by BIP 34 only below this height (Core's
/// `BIP34_IMPLIES_BIP30_LIMIT`, `ConnectBlock`). Some pre-BIP-34 coinbases
/// happen to start with a push that reads as a height; the lowest such
/// height above the current chain is 1,983,702, where a miner could repeat
/// that old coinbase byte for byte. Core turns explicit BIP 30 checking
/// back on from there.
///
/// Hercules doesn't implement the explicit check (ticket 026): its UTXO
/// snapshot starts far above the historical BIP 30 exceptions (91,842 and
/// 91,880) and far below this limit, and `UtxoSet::apply_block` logs and
/// asserts if a write would ever overwrite an unspent output.
/// **Revisit before mainnet reaches this height (around 2045).**
pub const BIP34_IMPLIES_BIP30_LIMIT: u32 = 1_983_702;

// Compile-time reminder: once the snapshot anchor reaches the limit, blocks
// Hercules validates need Core's explicit BIP 30 check (`bad-txns-BIP30`:
// no output of the block may already be in the UTXO set). Implement it
// before moving the anchor past this point.
const _: () = assert!(
    crate::assumeutxo::MAINNET_ANCHOR.height < BIP34_IMPLIES_BIP30_LIMIT,
    "BIP 30 must be enforced explicitly from height 1,983,702 (ticket 026)"
);

// Script opcodes used by the parsers below.
const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_EQUAL: u8 = 0x87;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_INVALIDOPCODE: u8 = 0xff;

// ── Header timestamps and median-time-past ──────────────────────────

/// Timestamps of the headers on the chain being validated, by height.
pub trait HeaderTimes {
    fn timestamp_at(&self, height: u32) -> Result<u32, String>;

    /// Timestamps for heights `first..=last`, ascending. Implementations
    /// backed by a database should override this with one range read:
    /// every block's median-time-past needs 11 of them.
    fn timestamps_between(&self, first: u32, last: u32) -> Result<Vec<u32>, String> {
        (first..=last).map(|h| self.timestamp_at(h)).collect()
    }

    /// Identity of the header at `height` (its hash), if the source can
    /// give one cheaply. Lets callers cache a value derived from the chain
    /// up to `height` (the mempool's tip MTP) without missing a reorg.
    /// `None` means "can't tell": callers must not cache.
    fn header_id_at(&self, _height: u32) -> Option<[u8; 32]> {
        None
    }
}

impl HeaderTimes for HeaderStore {
    fn timestamp_at(&self, height: u32) -> Result<u32, String> {
        self.get_timestamp_at(height)
            .map_err(|e| format!("{}", e))?
            .ok_or_else(|| format!("no header at height {}", height))
    }

    fn timestamps_between(&self, first: u32, last: u32) -> Result<Vec<u32>, String> {
        let times = self
            .get_timestamps_between(first, last)
            .map_err(|e| format!("{}", e))?;
        let expected = (last - first + 1) as usize;
        if times.len() != expected {
            return Err(format!(
                "headers {}..={}: found {} of {}",
                first,
                last,
                times.len(),
                expected
            ));
        }
        Ok(times)
    }

    fn header_id_at(&self, height: u32) -> Option<[u8; 32]> {
        use bitcoin::hashes::Hash as _;
        self.get_hash_at_height(height)
            .ok()
            .flatten()
            .map(|h| h.to_byte_array())
    }
}

impl<F: Fn(u32) -> Result<u32, String>> HeaderTimes for F {
    fn timestamp_at(&self, height: u32) -> Result<u32, String> {
        self(height)
    }
}

/// Median-time-past of the block at `height`: the median of its timestamp
/// and those of up to 10 ancestors (`CBlockIndex::GetMedianTimePast`).
pub fn median_time_past(times: &dyn HeaderTimes, height: u32) -> Result<i64, String> {
    let first = height.saturating_sub(MEDIAN_TIME_SPAN - 1);
    let mut window: Vec<i64> = times
        .timestamps_between(first, height)?
        .into_iter()
        .map(i64::from)
        .collect();
    if window.is_empty() {
        return Err(format!("no header timestamps for height {}", height));
    }
    window.sort_unstable();
    Ok(window[window.len() / 2])
}

/// `median_time_past` with a per-block memo: BIP 68 time locks look up the
/// MTP at each spent coin's height, and many inputs share one.
pub struct MedianTimes<'a> {
    times: &'a dyn HeaderTimes,
    cache: HashMap<u32, i64>,
}

impl<'a> MedianTimes<'a> {
    pub fn new(times: &'a dyn HeaderTimes) -> MedianTimes<'a> {
        MedianTimes { times, cache: HashMap::new() }
    }

    /// Median-time-past of the block at `height`.
    pub fn at(&mut self, height: u32) -> Result<i64, String> {
        if let Some(&mtp) = self.cache.get(&height) {
            return Ok(mtp);
        }
        let mtp = median_time_past(self.times, height)?;
        self.cache.insert(height, mtp);
        Ok(mtp)
    }
}

// ── Rule 1 + 2: nLockTime finality with BIP 113 ─────────────────────

/// Whether `tx` may appear in a block at `block_height` whose locktime
/// cutoff is `block_time` (`IsFinalTx`, consensus/tx_verify.cpp).
///
/// The cutoff is the caller's choice, as in Core: the parent block's
/// median-time-past once BIP 113 is active (`ContextualCheckBlock`; the
/// tip's MTP for the mempool, `CheckFinalTxAtTip`), the block's own
/// timestamp before. Note the strict `<`: nLockTime is the last height or
/// time at which the transaction is *not* yet valid.
pub fn is_final_tx(tx: &Transaction, block_height: u32, block_time: i64) -> bool {
    let lock_time = tx.lock_time.to_consensus_u32() as i64;
    if lock_time == 0 {
        return true;
    }
    let cutoff = if lock_time < LOCKTIME_THRESHOLD as i64 {
        block_height as i64
    } else {
        block_time
    };
    if lock_time < cutoff {
        return true;
    }
    // An unsatisfied nLockTime is ignored if every input opts out.
    tx.input.iter().all(|txin| txin.sequence.0 == SEQUENCE_FINAL)
}

// ── Rule 3: BIP 68 relative lock-times ──────────────────────────────

/// The last invalid height and time implied by a transaction's relative
/// locks; -1 means unconstrained (Core's `std::pair<int, int64_t>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPoints {
    pub min_height: i64,
    pub min_time: i64,
}

/// Compute `tx`'s BIP 68 lock points (`CalculateSequenceLocks`).
///
/// `prev_heights[i]` is the height of the block that created the coin
/// spent by input `i` (the block's own height for an in-block spend; tip+1
/// for a mempool parent). `mtp` must answer for the chain the transaction
/// is being validated on. `enforce_bip68` is Core's
/// `flags & LOCKTIME_VERIFY_SEQUENCE`: on in blocks from the CSV
/// activation height, always on for the mempool.
pub fn calculate_sequence_locks(
    tx: &Transaction,
    enforce_bip68: bool,
    prev_heights: &[u32],
    mtp: &mut MedianTimes,
) -> Result<LockPoints, String> {
    assert_eq!(prev_heights.len(), tx.input.len());
    let mut lock = LockPoints { min_height: -1, min_time: -1 };

    // nVersion is signed in the serialization; Core casts it to unsigned so
    // that "negative" versions also opt in.
    if !(tx.version.0 as u32 >= 2 && enforce_bip68) {
        return Ok(lock);
    }

    for (txin, &coin_height) in tx.input.iter().zip(prev_heights) {
        let sequence = txin.sequence.0;
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }
        let value = (sequence & SEQUENCE_LOCKTIME_MASK) as i64;
        if sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            // Measured from the MTP of the block *before* the coin's block,
            // the earliest timestamp the coin's block could have had.
            let coin_time = mtp.at(coin_height.saturating_sub(1))?;
            lock.min_time = lock
                .min_time
                .max(coin_time + (value << SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            lock.min_height = lock.min_height.max(coin_height as i64 + value - 1);
        }
    }
    Ok(lock)
}

/// Whether lock points are satisfied in a block at `block_height` whose
/// parent has median-time-past `prev_block_mtp` (`EvaluateSequenceLocks`).
pub fn evaluate_sequence_locks(block_height: u32, prev_block_mtp: i64, lock: LockPoints) -> bool {
    !(lock.min_height >= block_height as i64 || lock.min_time >= prev_block_mtp)
}

// ── Rule 4: signature-operation cost ────────────────────────────────

/// One step of Core's script parser (`GetScriptOp`, script/script.cpp):
/// the opcode at `*pc` and, for a push, its data. `None` on a truncated
/// push or at the end of the script, as Core returns false.
fn get_op<'s>(script: &'s [u8], pc: &mut usize) -> Option<(u8, &'s [u8])> {
    let opcode = *script.get(*pc)?;
    *pc += 1;
    if opcode > OP_PUSHDATA4 {
        return Some((opcode, &[]));
    }
    let rest = script.len() - *pc;
    let size = match opcode {
        OP_PUSHDATA1 => {
            if rest < 1 {
                return None;
            }
            let n = script[*pc] as usize;
            *pc += 1;
            n
        }
        OP_PUSHDATA2 => {
            if rest < 2 {
                return None;
            }
            let n = u16::from_le_bytes([script[*pc], script[*pc + 1]]) as usize;
            *pc += 2;
            n
        }
        OP_PUSHDATA4 => {
            if rest < 4 {
                return None;
            }
            let b = &script[*pc..*pc + 4];
            let n = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
            *pc += 4;
            n
        }
        n => n as usize,
    };
    if script.len() - *pc < size {
        return None;
    }
    let data = &script[*pc..*pc + size];
    *pc += size;
    Some((opcode, data))
}

/// Sigops in one script (`CScript::GetSigOpCount(bool fAccurate)`).
///
/// CHECKMULTISIG counts 20, or with `accurate` the preceding `OP_1..OP_16`
/// key count. Counting stops at the first unparsable opcode, as in Core.
pub fn script_sigop_count(script: &[u8], accurate: bool) -> u64 {
    let mut n = 0u64;
    let mut pc = 0usize;
    let mut last_opcode = OP_INVALIDOPCODE;
    while pc < script.len() {
        let Some((opcode, _)) = get_op(script, &mut pc) else { break };
        if opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY {
            n += 1;
        } else if opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY {
            if accurate && (OP_1..=OP_16).contains(&last_opcode) {
                n += (last_opcode - OP_1 + 1) as u64;
            } else {
                n += MAX_PUBKEYS_PER_MULTISIG;
            }
        }
        last_opcode = opcode;
    }
    n
}

/// `CScript::IsPayToScriptHash`.
fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 23 && script[0] == OP_HASH160 && script[1] == 0x14 && script[22] == OP_EQUAL
}

/// `CScript::IsPushOnly`: every opcode is a push or `OP_1NEGATE..OP_16`.
fn is_push_only(script: &[u8]) -> bool {
    let mut pc = 0usize;
    while pc < script.len() {
        match get_op(script, &mut pc) {
            Some((opcode, _)) if opcode <= OP_16 => {}
            _ => return false,
        }
    }
    true
}

/// The last item a push-only scriptSig pushes (empty for `OP_N`, as
/// Core's `GetOp` clears its output buffer on every opcode). `None` if the
/// scriptSig is not push-only.
fn last_push(script_sig: &[u8]) -> Option<&[u8]> {
    let mut pc = 0usize;
    let mut data: &[u8] = &[];
    while pc < script_sig.len() {
        let (opcode, d) = get_op(script_sig, &mut pc)?;
        if opcode > OP_16 {
            return None;
        }
        data = d;
    }
    Some(data)
}

/// `CScript::IsWitnessProgram`: version and program, if `script` is one.
fn witness_program(script: &[u8]) -> Option<(u8, &[u8])> {
    if script.len() < 4 || script.len() > 42 {
        return None;
    }
    let version = match script[0] {
        OP_0 => 0,
        op @ OP_1..=OP_16 => op - OP_1 + 1,
        _ => return None,
    };
    if script[1] as usize + 2 == script.len() {
        Some((version, &script[2..]))
    } else {
        None
    }
}

/// Sigops of a P2SH spend: the accurate count of the redeem script, the
/// last item the scriptSig pushes (`CScript::GetSigOpCount(const CScript&
/// scriptSig)` on a P2SH scriptPubKey). Zero if the scriptSig isn't push
/// only.
fn p2sh_redeem_sigop_count(script_sig: &[u8]) -> u64 {
    match last_push(script_sig) {
        Some(redeem) => script_sigop_count(redeem, true),
        None => 0,
    }
}

/// Legacy sigops in every scriptSig and scriptPubKey of `tx`
/// (`GetLegacySigOpCount`). This is also the `CheckBlock` count.
pub fn legacy_sigop_count(tx: &Transaction) -> u64 {
    let ins: u64 = tx.input.iter().map(|i| script_sigop_count(i.script_sig.as_bytes(), false)).sum();
    let outs: u64 =
        tx.output.iter().map(|o| script_sigop_count(o.script_pubkey.as_bytes(), false)).sum();
    ins + outs
}

/// Redeem-script sigops of `tx`'s P2SH inputs (`GetP2SHSigOpCount`).
/// `spent[i]` is the scriptPubKey spent by input `i`.
pub fn p2sh_sigop_count(tx: &Transaction, spent: &[&[u8]]) -> u64 {
    if tx.is_coinbase() {
        return 0;
    }
    tx.input
        .iter()
        .zip(spent)
        .filter(|(_, spk)| is_p2sh(spk))
        .map(|(txin, _)| p2sh_redeem_sigop_count(txin.script_sig.as_bytes()))
        .sum()
}

/// `WitnessSigOps` (script/interpreter.cpp): P2WPKH costs 1, P2WSH the
/// accurate count of its witness script; other versions (Taproot has its
/// own per-input budget) cost 0.
fn witness_program_sigops(version: u8, program: &[u8], witness: &Witness) -> u64 {
    if version == 0 {
        if program.len() == 20 {
            return 1;
        }
        if program.len() == 32 {
            if let Some(script) = witness.last() {
                return script_sigop_count(script, true);
            }
        }
    }
    0
}

/// Witness sigops of one input (`CountWitnessSigOps`): native witness
/// programs, and witness programs nested in P2SH.
pub fn witness_sigop_count(script_sig: &[u8], script_pubkey: &[u8], witness: &Witness, flags: u32) -> u64 {
    if flags & SCRIPT_VERIFY_WITNESS == 0 {
        return 0;
    }
    if let Some((version, program)) = witness_program(script_pubkey) {
        return witness_program_sigops(version, program, witness);
    }
    if is_p2sh(script_pubkey) && is_push_only(script_sig) {
        let redeem = last_push(script_sig).unwrap_or(&[]);
        if let Some((version, program)) = witness_program(redeem) {
            return witness_program_sigops(version, program, witness);
        }
    }
    0
}

/// Total sigop cost of `tx` (`GetTransactionSigOpCost`): legacy × 4,
/// plus P2SH × 4 and witness × 1 for non-coinbase transactions.
///
/// `spent[i]` is the scriptPubKey spent by input `i` (ignored for a
/// coinbase). `flags` are the block's script flags; Core v26 passes
/// `GetBlockScriptFlags`, which has P2SH and WITNESS on from genesis,
/// while ours follow the activation table. The two agree at every height
/// Hercules validates (mainnet from the snapshot height, regtest from 0).
pub fn transaction_sigop_cost(tx: &Transaction, spent: &[&[u8]], flags: u32) -> u64 {
    let mut cost = legacy_sigop_count(tx) * WITNESS_SCALE_FACTOR;
    if tx.is_coinbase() {
        return cost;
    }
    if flags & SCRIPT_VERIFY_P2SH != 0 {
        cost += p2sh_sigop_count(tx, spent) * WITNESS_SCALE_FACTOR;
    }
    for (txin, spk) in tx.input.iter().zip(spent) {
        cost += witness_sigop_count(txin.script_sig.as_bytes(), spk, &txin.witness, flags);
    }
    cost
}

// ── Rule 5: coinbase scriptSig length ───────────────────────────────

/// A coinbase's scriptSig must be 2..=100 bytes (`CheckTransaction`,
/// `bad-cb-length`). Callers apply it to the coinbase only.
pub fn coinbase_script_len_ok(coinbase: &Transaction) -> bool {
    let len = coinbase.input[0].script_sig.len();
    (MIN_COINBASE_SCRIPT_LEN..=MAX_COINBASE_SCRIPT_LEN).contains(&len)
}

// ── Rule 7: BIP 34 coinbase height ──────────────────────────────────

/// `CScriptNum::serialize`: minimal little-endian with a sign bit.
fn script_num_serialize(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let neg = value < 0;
    let mut abs = value.unsigned_abs();
    let mut out = Vec::new();
    while abs > 0 {
        out.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if out.last().unwrap() & 0x80 != 0 {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        *out.last_mut().unwrap() |= 0x80;
    }
    out
}

/// The bytes a BIP 34 coinbase scriptSig must start with at `height`:
/// `CScript() << nHeight` (`CScript::push_int64`). Heights 1..=16 are the
/// single opcodes `OP_1..OP_16` and 0 is `OP_0`; anything else is a direct
/// push of the minimal script number.
pub fn bip34_height_prefix(height: u32) -> Vec<u8> {
    match height {
        0 => vec![OP_0],
        1..=16 => vec![OP_1 + (height as u8 - 1)],
        _ => {
            let num = script_num_serialize(height as i64);
            // At most 5 bytes for a u32, so always a direct push.
            let mut out = Vec::with_capacity(num.len() + 1);
            out.push(num.len() as u8);
            out.extend_from_slice(&num);
            out
        }
    }
}

/// Whether `coinbase`'s scriptSig starts with the BIP 34 encoding of
/// `height` (`ContextualCheckBlock`, `bad-cb-height`). A byte-prefix
/// comparison, exactly as Core does it.
pub fn coinbase_commits_height(coinbase: &Transaction, height: u32) -> bool {
    coinbase.input[0].script_sig.as_bytes().starts_with(&bip34_height_prefix(height))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::script::Builder;
    use bitcoin::transaction::Version;
    use bitcoin::{absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid};

    fn tx(version: i32, lock_time: u32, sequences: &[u32]) -> Transaction {
        Transaction {
            version: Version(version),
            lock_time: LockTime::from_consensus(lock_time),
            input: sequences
                .iter()
                .enumerate()
                .map(|(i, &s)| TxIn {
                    previous_output: OutPoint::new(Txid::from_byte_array([i as u8 + 1; 32]), 0),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence(s),
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::new() }],
        }
    }

    // ── median_time_past ────────────────────────────────────────────

    #[test]
    fn mtp_is_median_of_last_eleven() {
        // Timestamps out of order on purpose: MTP sorts.
        let ts = [10u32, 30, 20, 50, 40, 70, 60, 90, 80, 110, 100, 5];
        let times = |h: u32| -> Result<u32, String> { Ok(ts[h as usize]) };
        // Heights 1..=11: {30,20,50,40,70,60,90,80,110,100,5} → median 60.
        assert_eq!(median_time_past(&times, 11).unwrap(), 60);
        // Near genesis the window is shorter: {10,30,20} → 20.
        assert_eq!(median_time_past(&times, 2).unwrap(), 20);
        assert_eq!(median_time_past(&times, 0).unwrap(), 10);
        // Even-sized window takes the upper middle, as Core's `[n/2]`.
        assert_eq!(median_time_past(&times, 1).unwrap(), 30);
    }

    #[test]
    fn mtp_lookup_error_propagates() {
        let times = |h: u32| -> Result<u32, String> {
            if h < 5 { Ok(h) } else { Err(format!("no header at height {}", h)) }
        };
        assert!(median_time_past(&times, 7).is_err());
        let mut m = MedianTimes::new(&times);
        assert_eq!(m.at(4).unwrap(), 2);
    }

    // ── is_final_tx (IsFinalTx) ─────────────────────────────────────

    #[test]
    fn locktime_zero_is_always_final() {
        assert!(is_final_tx(&tx(2, 0, &[0]), 0, 0));
    }

    #[test]
    fn height_locktime_boundary() {
        // Valid in a block at height H only if nLockTime < H.
        let t = tx(2, 100, &[0xffff_fffe]);
        assert!(is_final_tx(&t, 101, 0));
        assert!(!is_final_tx(&t, 100, 0));
        assert!(!is_final_tx(&t, 99, 0));
    }

    #[test]
    fn time_locktime_boundary_uses_cutoff_not_height() {
        let lock = 1_600_000_000u32;
        let t = tx(2, lock, &[0]);
        assert!(is_final_tx(&t, 1, lock as i64 + 1));
        assert!(!is_final_tx(&t, 1, lock as i64));
        // A huge height doesn't satisfy a time lock.
        assert!(!is_final_tx(&t, u32::MAX, lock as i64 - 1));
    }

    #[test]
    fn locktime_threshold_splits_height_and_time() {
        // 499,999,999 is a height, 500,000,000 a time.
        let h = tx(2, LOCKTIME_THRESHOLD - 1, &[0]);
        assert!(is_final_tx(&h, LOCKTIME_THRESHOLD, 0));
        assert!(!is_final_tx(&h, LOCKTIME_THRESHOLD - 1, i64::MAX));
        let t = tx(2, LOCKTIME_THRESHOLD, &[0]);
        assert!(!is_final_tx(&t, u32::MAX, LOCKTIME_THRESHOLD as i64));
        assert!(is_final_tx(&t, 0, LOCKTIME_THRESHOLD as i64 + 1));
    }

    #[test]
    fn all_final_sequences_override_locktime() {
        let t = tx(2, 1_000, &[SEQUENCE_FINAL, SEQUENCE_FINAL]);
        assert!(is_final_tx(&t, 1, 0));
        // One non-final input is enough to enforce it.
        let t = tx(2, 1_000, &[SEQUENCE_FINAL, SEQUENCE_FINAL - 1]);
        assert!(!is_final_tx(&t, 1, 0));
    }

    // ── BIP 68 (CalculateSequenceLocks / EvaluateSequenceLocks) ─────

    /// Timestamps 1000 + 600·h, so MTP(h) = 1000 + 600·(h − 5) for h ≥ 10.
    fn spaced(h: u32) -> Result<u32, String> {
        Ok(1_000 + 600 * h)
    }

    fn locks(t: &Transaction, enforce: bool, heights: &[u32]) -> LockPoints {
        let times = spaced;
        let mut mtp = MedianTimes::new(&times);
        calculate_sequence_locks(t, enforce, heights, &mut mtp).unwrap()
    }

    #[test]
    fn height_lock_boundary() {
        // CSV(10) on a coin from height 100: first valid in block 110.
        let t = tx(2, 0, &[10]);
        let lp = locks(&t, true, &[100]);
        assert_eq!(lp, LockPoints { min_height: 109, min_time: -1 });
        assert!(evaluate_sequence_locks(110, 0, lp));
        assert!(!evaluate_sequence_locks(109, 0, lp));
    }

    #[test]
    fn zero_relative_lock_allows_same_block() {
        let t = tx(2, 0, &[0]);
        let lp = locks(&t, true, &[100]);
        assert!(evaluate_sequence_locks(100, 0, lp));
    }

    #[test]
    fn time_lock_boundary() {
        // Type flag, 2 units = 1024 s, coin at height 100.
        // Coin time = MTP(99) = 1000 + 600·94 = 57,400; min_time = 58,423.
        let t = tx(2, 0, &[SEQUENCE_LOCKTIME_TYPE_FLAG | 2]);
        let lp = locks(&t, true, &[100]);
        let coin_time = median_time_past(&spaced, 99).unwrap();
        assert_eq!(coin_time, 57_400);
        assert_eq!(lp, LockPoints { min_height: -1, min_time: coin_time + 1024 - 1 });
        assert!(evaluate_sequence_locks(200, coin_time + 1024, lp));
        assert!(!evaluate_sequence_locks(200, coin_time + 1023, lp));
    }

    #[test]
    fn disable_flag_and_version_one_are_not_locks() {
        let t = tx(2, 0, &[SEQUENCE_LOCKTIME_DISABLE_FLAG | 0xffff]);
        assert_eq!(locks(&t, true, &[100]), LockPoints { min_height: -1, min_time: -1 });
        let t = tx(1, 0, &[0xffff]);
        assert_eq!(locks(&t, true, &[100]), LockPoints { min_height: -1, min_time: -1 });
        // Before CSV activation nothing is enforced.
        let t = tx(2, 0, &[0xffff]);
        assert_eq!(locks(&t, false, &[100]), LockPoints { min_height: -1, min_time: -1 });
    }

    #[test]
    fn negative_version_enforces_bip68() {
        // Core casts nVersion to uint32_t: 0xffffffff >= 2.
        let t = tx(-1, 0, &[5]);
        assert_eq!(locks(&t, true, &[100]).min_height, 104);
    }

    #[test]
    fn bits_outside_mask_are_ignored() {
        // Bits 16..21 and 23..30 carry no meaning: value 3 in blocks.
        let t = tx(2, 0, &[0x003f_0003 | (1 << 23)]);
        assert_eq!(locks(&t, true, &[100]).min_height, 102);
    }

    #[test]
    fn strictest_input_wins() {
        let t = tx(2, 0, &[5, 20, SEQUENCE_LOCKTIME_TYPE_FLAG | 1, SEQUENCE_LOCKTIME_TYPE_FLAG | 3]);
        let lp = locks(&t, true, &[200, 100, 50, 60]);
        assert_eq!(lp.min_height, 204);
        let mtp59 = median_time_past(&spaced, 59).unwrap();
        assert_eq!(lp.min_time, mtp59 + 3 * 512 - 1);
    }

    #[test]
    fn coin_at_genesis_uses_genesis_mtp() {
        // max(nCoinHeight - 1, 0)
        let t = tx(2, 0, &[SEQUENCE_LOCKTIME_TYPE_FLAG | 1]);
        let lp = locks(&t, true, &[0]);
        assert_eq!(lp.min_time, 1_000 + 512 - 1);
    }

    // ── Sigop counting (Core's sigopcount_tests.cpp) ────────────────

    fn s(b: Builder) -> Vec<u8> {
        b.into_script().into_bytes()
    }

    /// `GetSigOpCount` vectors from Core's `sigopcount_tests/GetSigOpCount`.
    #[test]
    fn core_get_sigop_count_vectors() {
        use bitcoin::opcodes::all::*;
        assert_eq!(script_sigop_count(&[], false), 0);
        assert_eq!(script_sigop_count(&[], true), 0);

        let dummy = [0u8; 20];
        let s1 = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(dummy)
            .push_slice(dummy)
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_CHECKMULTISIG);
        assert_eq!(script_sigop_count(&s(s1.clone()), true), 2);
        let s1 = s1.push_opcode(OP_IF).push_opcode(OP_CHECKSIG).push_opcode(OP_ENDIF);
        let s1 = s(s1);
        assert_eq!(script_sigop_count(&s1, true), 3);
        assert_eq!(script_sigop_count(&s1, false), 21);

        // P2SH: counted from the scriptSig's last push.
        let p2sh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(s1.clone()).script_hash());
        let script_sig = s(Builder::new().push_opcode(OP_PUSHBYTES_0).push_slice(
            bitcoin::script::PushBytesBuf::try_from(s1.clone()).unwrap(),
        ));
        assert!(is_p2sh(p2sh.as_bytes()));
        assert_eq!(p2sh_redeem_sigop_count(&script_sig), 3);

        // 1-of-3 multisig.
        let pk = [2u8; 33];
        let s2 = s(Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(pk)
            .push_slice(pk)
            .push_slice(pk)
            .push_opcode(OP_PUSHNUM_3)
            .push_opcode(OP_CHECKMULTISIG));
        assert_eq!(script_sigop_count(&s2, true), 3);
        assert_eq!(script_sigop_count(&s2, false), 20);

        let p2sh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(s2.clone()).script_hash());
        assert_eq!(script_sigop_count(p2sh.as_bytes(), true), 0);
        assert_eq!(script_sigop_count(p2sh.as_bytes(), false), 0);
        let script_sig2 = s(Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(dummy)
            .push_slice(dummy)
            .push_slice(bitcoin::script::PushBytesBuf::try_from(s2).unwrap()));
        assert_eq!(p2sh_redeem_sigop_count(&script_sig2), 3);
    }

    #[test]
    fn sigop_count_stops_at_truncated_push() {
        // CHECKSIG, then PUSHDATA1 claiming 10 bytes with 1 left, then a
        // CHECKSIG byte inside the would-be push: Core stops at the bad op.
        assert_eq!(script_sigop_count(&[OP_CHECKSIG, OP_PUSHDATA1, 10, OP_CHECKSIG], false), 1);
        // Push data is never counted.
        assert_eq!(script_sigop_count(&[0x02, OP_CHECKSIG, OP_CHECKSIG], false), 0);
        assert_eq!(script_sigop_count(&[OP_CHECKSIGVERIFY, OP_CHECKMULTISIGVERIFY], false), 21);
    }

    #[test]
    fn p2sh_scriptsig_must_be_push_only() {
        // A non-push opcode in the scriptSig makes the P2SH count zero.
        let redeem = [OP_CHECKSIG];
        let sig = [0x01, redeem[0], OP_CHECKSIG];
        assert_eq!(p2sh_redeem_sigop_count(&sig), 0);
        // OP_N as the last item pushes nothing countable.
        assert_eq!(p2sh_redeem_sigop_count(&[0x01, OP_CHECKSIG, OP_1]), 0);
        // Truncated push: zero (Core returns 0 on GetOp failure).
        assert_eq!(p2sh_redeem_sigop_count(&[0x01, OP_CHECKSIG, OP_PUSHDATA2, 5]), 0);
    }

    /// The spending half of Core's `BuildTxs`: one input with the given
    /// scriptSig and witness (the spent scriptPubKey is passed separately).
    fn spending(script_sig: Vec<u8>, witness: Vec<Vec<u8>>) -> Transaction {
        let mut t = tx(1, 0, &[SEQUENCE_FINAL]);
        t.input[0].script_sig = ScriptBuf::from_bytes(script_sig);
        t.input[0].witness = Witness::from_slice(&witness);
        t
    }

    const FLAGS: u32 = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;

    /// Vectors from Core's `sigopcount_tests/GetTxSigOpCost`.
    #[test]
    fn core_get_tx_sigop_cost_vectors() {
        use bitcoin::opcodes::all::*;
        let pk = [2u8; 33];
        let multisig = s(Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(pk)
            .push_slice(pk)
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_CHECKMULTISIGVERIFY));
        let push = |b: &[u8]| bitcoin::script::PushBytesBuf::try_from(b.to_vec()).unwrap();

        // Bare multisig: the spender has no sigops; the creating tx's
        // scriptPubKey counts 20 (inaccurate) × 4.
        let creation = {
            let mut t = tx(1, 0, &[SEQUENCE_FINAL]);
            t.output[0].script_pubkey = ScriptBuf::from_bytes(multisig.clone());
            t
        };
        let spend = spending(s(Builder::new().push_opcode(OP_PUSHBYTES_0).push_opcode(OP_PUSHBYTES_0)), vec![]);
        assert_eq!(transaction_sigop_cost(&spend, &[&multisig], FLAGS), 0);
        assert_eq!(transaction_sigop_cost(&creation, &[&[]], FLAGS), 20 * 4);

        // Multisig nested in P2SH: accurate count 2 × 4.
        let p2sh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(multisig.clone()).script_hash()).into_bytes();
        let spend = spending(
            s(Builder::new()
                .push_opcode(OP_PUSHBYTES_0)
                .push_opcode(OP_PUSHBYTES_0)
                .push_slice(push(&multisig))),
            vec![],
        );
        assert_eq!(transaction_sigop_cost(&spend, &[&p2sh], FLAGS), 2 * 4);

        // P2WPKH: 1, and 0 without the WITNESS flag.
        let wpkh = {
            let mut v = vec![0x00, 0x14];
            v.extend_from_slice(&[7u8; 20]);
            v
        };
        let spend = spending(vec![], vec![vec![], vec![]]);
        assert_eq!(transaction_sigop_cost(&spend, &[&wpkh], FLAGS), 1);
        assert_eq!(transaction_sigop_cost(&spend, &[&wpkh], FLAGS & !SCRIPT_VERIFY_WITNESS), 0);
        // Witness version != 0 costs nothing.
        let mut v1 = wpkh.clone();
        v1[0] = OP_1;
        assert_eq!(transaction_sigop_cost(&spend, &[&v1], FLAGS), 0);
        // A coinbase's witness is not counted.
        let mut cb = spend.clone();
        cb.input[0].previous_output = OutPoint::null();
        assert!(cb.is_coinbase());
        assert_eq!(transaction_sigop_cost(&cb, &[&wpkh], FLAGS), 0);

        // P2WPKH nested in P2SH: 1.
        let p2sh_wpkh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(wpkh.clone()).script_hash()).into_bytes();
        let spend = spending(s(Builder::new().push_slice(push(&wpkh))), vec![vec![], vec![]]);
        assert_eq!(transaction_sigop_cost(&spend, &[&p2sh_wpkh], FLAGS), 1);

        // P2WSH: accurate count of the witness script (2), 0 without WITNESS.
        let wsh = ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(multisig.clone()).wscript_hash()).into_bytes();
        let spend = spending(vec![], vec![vec![], vec![], multisig.clone()]);
        assert_eq!(transaction_sigop_cost(&spend, &[&wsh], FLAGS), 2);
        assert_eq!(transaction_sigop_cost(&spend, &[&wsh], FLAGS & !SCRIPT_VERIFY_WITNESS), 0);

        // P2WSH nested in P2SH: 2.
        let p2sh_wsh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(wsh.clone()).script_hash()).into_bytes();
        let spend = spending(s(Builder::new().push_slice(push(&wsh))), vec![vec![], vec![], multisig]);
        assert_eq!(transaction_sigop_cost(&spend, &[&p2sh_wsh], FLAGS), 2);
    }

    #[test]
    fn p2sh_sigops_need_p2sh_flag() {
        let redeem = vec![OP_CHECKSIG; 3];
        let p2sh = ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(redeem.clone()).script_hash()).into_bytes();
        let mut sig = vec![redeem.len() as u8];
        sig.extend_from_slice(&redeem);
        let spend = spending(sig, vec![]);
        assert_eq!(transaction_sigop_cost(&spend, &[&p2sh], FLAGS), 3 * 4);
        assert_eq!(transaction_sigop_cost(&spend, &[&p2sh], 0), 0);
    }

    #[test]
    fn taproot_spend_costs_nothing() {
        let mut tr = vec![OP_1, 0x20];
        tr.extend_from_slice(&[9u8; 32]);
        let spend = spending(vec![], vec![vec![OP_CHECKSIG; 50]]);
        assert_eq!(transaction_sigop_cost(&spend, &[&tr], FLAGS), 0);
    }

    // ── Coinbase scriptSig length ───────────────────────────────────

    #[test]
    fn coinbase_script_length_bounds() {
        let mut cb = tx(1, 0, &[SEQUENCE_FINAL]);
        cb.input[0].previous_output = OutPoint::null();
        for (len, ok) in [(0, false), (1, false), (2, true), (100, true), (101, false)] {
            cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00; len]);
            assert_eq!(coinbase_script_len_ok(&cb), ok, "len {}", len);
        }
    }

    /// Core's `tx_valid.json` "Coinbase of size 2/100" and `tx_invalid.json`
    /// "Coinbase of size 1/101" (`BADTX`): the same bytes, rebuilt from
    /// their common template (scriptSig = n × OP_1).
    #[test]
    fn core_tx_vectors_coinbase_size() {
        use bitcoin::consensus::deserialize;
        let vector = |n: usize| -> Transaction {
            let hex = format!(
                "01000000010000000000000000000000000000000000000000000000000000000000000000\
                 ffffffff{:02x}{}ffffffff010000000000000000015100000000",
                n,
                "51".repeat(n)
            );
            deserialize(&hex::decode(hex).unwrap()).unwrap()
        };
        assert_eq!(
            bitcoin::consensus::serialize(&vector(1)),
            hex::decode(
                "01000000010000000000000000000000000000000000000000000000000000000000000000\
                 ffffffff0151ffffffff010000000000000000015100000000"
            )
            .unwrap()
        );
        for (n, valid) in [(1, false), (2, true), (100, true), (101, false)] {
            let tx = vector(n);
            assert!(tx.is_coinbase());
            assert_eq!(coinbase_script_len_ok(&tx), valid, "size {}", n);
        }
    }

    // ── BIP 34 prefix (CScript() << nHeight) ────────────────────────

    #[test]
    fn bip34_prefix_matches_core_encoding() {
        assert_eq!(bip34_height_prefix(0), vec![0x00]);
        assert_eq!(bip34_height_prefix(1), vec![0x51]);
        assert_eq!(bip34_height_prefix(16), vec![0x60]);
        assert_eq!(bip34_height_prefix(17), vec![0x01, 0x11]);
        assert_eq!(bip34_height_prefix(127), vec![0x01, 0x7f]);
        // Sign bit: 128 needs a padding byte.
        assert_eq!(bip34_height_prefix(128), vec![0x02, 0x80, 0x00]);
        assert_eq!(bip34_height_prefix(300), vec![0x02, 0x2c, 0x01]);
        // Mainnet activation height and the snapshot era.
        assert_eq!(bip34_height_prefix(227_931), vec![0x03, 0x5b, 0x7a, 0x03]);
        assert_eq!(bip34_height_prefix(943_500), vec![0x03, 0x8c, 0x65, 0x0e]);
        assert_eq!(bip34_height_prefix(8_388_608), vec![0x04, 0x00, 0x00, 0x80, 0x00]);
        assert_eq!(bip34_height_prefix(u32::MAX), vec![0x05, 0xff, 0xff, 0xff, 0xff, 0x00]);
    }

    #[test]
    fn bip34_prefix_agrees_with_rust_bitcoin_push_int() {
        for h in (0u32..=20_000).chain([227_931, 943_500, 1_983_702, 16_777_215, 16_777_216]) {
            let expected = Builder::new().push_int(h as i64).into_script().into_bytes();
            assert_eq!(bip34_height_prefix(h), expected, "height {}", h);
        }
    }

    #[test]
    fn coinbase_height_is_a_prefix_match() {
        let mut cb = tx(1, 0, &[SEQUENCE_FINAL]);
        cb.input[0].previous_output = OutPoint::null();
        cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x03, 0x8c, 0x65, 0x0e, 0xde, 0xad]);
        assert!(coinbase_commits_height(&cb, 943_500));
        assert!(!coinbase_commits_height(&cb, 943_501));
        // OP_5 followed by extra nonce data, Core's height-5 encoding.
        cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x55, 0x04, 1, 2, 3, 4]);
        assert!(coinbase_commits_height(&cb, 5));
        // A data push of 5 is not Core's encoding.
        cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0x05, 0x00]);
        assert!(!coinbase_commits_height(&cb, 5));
        // Non-minimal (PUSHDATA1) encodings of a large height are rejected.
        cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x4c, 0x03, 0x8c, 0x65, 0x0e]);
        assert!(!coinbase_commits_height(&cb, 943_500));
        // Too short to hold the prefix.
        cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x03, 0x8c]);
        assert!(!coinbase_commits_height(&cb, 943_500));
    }

    // ── Data-path pass: oracles and invariants ───────────────────────

    mod props {
        use super::*;
        use proptest::prelude::*;

        /// Script bytes biased towards what the sigop parser cares about:
        /// CHECKSIG family, OP_1..OP_16 before CHECKMULTISIG, every push
        /// form (including truncated ones), and arbitrary bytes.
        fn arb_script() -> impl Strategy<Value = Vec<u8>> {
            let byte = prop_oneof![
                3 => prop::sample::select(vec![0xacu8, 0xad, 0xae, 0xaf]),
                2 => 0x51u8..=0x60,
                1 => Just(0x00u8),
                1 => 0x01u8..=0x4b,
                1 => prop::sample::select(vec![0x4cu8, 0x4d, 0x4e]),
                2 => any::<u8>(),
            ];
            prop::collection::vec(byte, 0..120)
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1024))]

            /// Differential: rust-bitcoin's `count_sigops_legacy` (an
            /// independent port of Core's GetSigOpCount, stopping at the
            /// first unparsable op), and for accurate counting a reference
            /// written from Core over rust-bitcoin's tokenizer (see
            /// `rust_bitcoin_accurate_sigops_diverge_from_core`).
            #[test]
            fn sigop_count_matches_independent_implementations(script in arb_script()) {
                let s = bitcoin::Script::from_bytes(&script);
                prop_assert_eq!(script_sigop_count(&script, false), s.count_sigops_legacy() as u64);
                prop_assert_eq!(script_sigop_count(&script, false), core_reference_sigops(&script, false));
                prop_assert_eq!(script_sigop_count(&script, true), core_reference_sigops(&script, true));
            }

            /// The P2SH / witness parsers never panic, and a redeem or
            /// witness script's count is the accurate count.
            #[test]
            fn sigop_cost_parsers_are_total(
                sig in arb_script(),
                spk in arb_script(),
                witness in prop::collection::vec(arb_script(), 0..4),
                flags in any::<u32>(),
            ) {
                let mut t = tx(2, 0, &[SEQUENCE_FINAL]);
                t.input[0].script_sig = ScriptBuf::from_bytes(sig.clone());
                t.input[0].witness = Witness::from_slice(&witness);
                let cost = transaction_sigop_cost(&t, &[&spk], flags);
                prop_assert!(cost >= legacy_sigop_count(&t) * WITNESS_SCALE_FACTOR);
                let _ = witness_sigop_count(&sig, &spk, &t.input[0].witness, flags);
                let _ = is_push_only(&sig);
                let _ = last_push(&sig);
            }

            #[test]
            fn bip34_prefix_is_push_int_for_every_height(h in any::<u32>()) {
                let expected = Builder::new().push_int(h as i64).into_script().into_bytes();
                prop_assert_eq!(bip34_height_prefix(h), expected);
            }

            /// Median-time-past is the middle of the sorted window of up to
            /// 11 timestamps ending at `height`, whatever their order.
            #[test]
            fn mtp_is_the_median_of_the_window(times in prop::collection::vec(any::<u32>(), 1..40), pick in any::<prop::sample::Index>()) {
                let height = pick.index(times.len()) as u32;
                let lookup = |h: u32| -> Result<u32, String> { times.get(h as usize).copied().ok_or("none".into()) };
                let first = height.saturating_sub(10) as usize;
                let mut window: Vec<u32> = times[first..=height as usize].to_vec();
                window.sort_unstable();
                prop_assert_eq!(median_time_past(&lookup, height).unwrap(), window[window.len() / 2] as i64);
                // The memoized version agrees, twice.
                let mut m = MedianTimes::new(&lookup);
                prop_assert_eq!(m.at(height).unwrap(), window[window.len() / 2] as i64);
                prop_assert_eq!(m.at(height).unwrap(), window[window.len() / 2] as i64);
            }

            /// IsFinalTx in closed form: lock 0, or lock below the cutoff
            /// (height or time by LOCKTIME_THRESHOLD), or every input final.
            #[test]
            fn is_final_tx_closed_form(
                lock in any::<u32>(),
                height in any::<u32>(),
                time in any::<u32>(),
                seqs in prop::collection::vec(prop_oneof![Just(SEQUENCE_FINAL), any::<u32>()], 1..4),
            ) {
                let t = tx(2, lock, &seqs);
                let cutoff = if lock < LOCKTIME_THRESHOLD { height as i64 } else { time as i64 };
                let expected = lock == 0 || (lock as i64) < cutoff || seqs.iter().all(|s| *s == SEQUENCE_FINAL);
                prop_assert_eq!(is_final_tx(&t, height, time as i64), expected);
            }

            /// BIP 68 lock points in closed form for height locks; off for
            /// version < 2, the disable flag, or when not enforced.
            #[test]
            fn height_sequence_locks_closed_form(
                version in prop_oneof![Just(1i32), Just(2), any::<i32>()],
                seqs in prop::collection::vec(any::<u32>(), 1..4),
                coin_heights in prop::collection::vec(0u32..1_000_000, 4),
                enforce in any::<bool>(),
            ) {
                // Height locks only (time locks need an MTP source).
                let seqs: Vec<u32> = seqs.into_iter().map(|s| s & !SEQUENCE_LOCKTIME_TYPE_FLAG).collect();
                let t = tx(version, 0, &seqs);
                let heights = &coin_heights[..seqs.len()];
                let never = |_: u32| -> Result<u32, String> { Err("no time locks here".into()) };
                let mut mtp = MedianTimes::new(&never);
                let lock = calculate_sequence_locks(&t, enforce, heights, &mut mtp).unwrap();
                let mut min_height = -1i64;
                if enforce && version as u32 >= 2 {
                    for (s, h) in seqs.iter().zip(heights) {
                        if s & SEQUENCE_LOCKTIME_DISABLE_FLAG == 0 {
                            min_height = min_height.max(*h as i64 + (s & SEQUENCE_LOCKTIME_MASK) as i64 - 1);
                        }
                    }
                }
                prop_assert_eq!(lock, LockPoints { min_height, min_time: -1 });
                // Satisfied exactly from the block after min_height.
                if min_height >= 0 && min_height < u32::MAX as i64 {
                    prop_assert!(!evaluate_sequence_locks(min_height as u32, i64::MAX, lock));
                    prop_assert!(evaluate_sequence_locks(min_height as u32 + 1, i64::MAX, lock));
                }
            }
        }

        /// Core's `CScript::GetSigOpCount(fAccurate)`, with rust-bitcoin
        /// as the tokenizer: `lastOpcode` is updated after *every* opcode.
        fn core_reference_sigops(script: &[u8], accurate: bool) -> u64 {
            use bitcoin::script::Instruction;
            let mut n = 0u64;
            let mut last: Option<u8> = None;
            for ins in bitcoin::Script::from_bytes(script).instructions() {
                let op = match ins {
                    Err(_) => break,
                    // Pushes are never OP_1..OP_16 (those are opcodes).
                    Ok(Instruction::PushBytes(_)) => None,
                    Ok(Instruction::Op(o)) => Some(o.to_u8()),
                };
                match op {
                    Some(0xac) | Some(0xad) => n += 1,
                    Some(0xae) | Some(0xaf) => {
                        n += match last {
                            Some(l @ 0x51..=0x60) if accurate => (l - 0x50) as u64,
                            _ => 20,
                        }
                    }
                    _ => {}
                }
                last = op;
            }
            n
        }

        /// Found by the differential test: rust-bitcoin 0.32's accurate
        /// `count_sigops` keeps the last OP_N across an intervening
        /// CHECKSIG, so `OP_1 OP_CHECKSIG OP_CHECKMULTISIG` counts the
        /// multisig as 1. Core resets on every opcode (20). Ours follows
        /// Core; pinned here so nobody "fixes" it to match the library.
        #[test]
        fn rust_bitcoin_accurate_sigops_diverge_from_core() {
            let script = [0x51, 0xac, 0xae];
            assert_eq!(script_sigop_count(&script, true), 1 + 20);
            assert_eq!(core_reference_sigops(&script, true), 21);
            assert_eq!(bitcoin::Script::from_bytes(&script).count_sigops(), 2, "rust-bitcoin's count");
        }

        /// Accurate counting of a P2WSH 2-of-3 witness script and a P2SH
        /// 15-of-15 redeem script: the key count, not 20.
        #[test]
        fn witness_and_p2sh_multisig_use_the_key_count() {
            let ms = |m: u8, n: u8| {
                let mut s = vec![0x50 + m];
                for _ in 0..n {
                    s.push(33);
                    s.extend_from_slice(&[0x02; 33]);
                }
                s.extend_from_slice(&[0x50 + n, 0xae]);
                s
            };
            let ws = ms(2, 3);
            let wsh = {
                use bitcoin::hashes::{sha256, Hash};
                let mut spk = vec![0x00, 0x20];
                spk.extend_from_slice(sha256::Hash::hash(&ws).as_byte_array());
                spk
            };
            let witness = Witness::from_slice(&[vec![], vec![0x30; 71], vec![0x30; 71], ws.clone()]);
            assert_eq!(witness_sigop_count(&[], &wsh, &witness, SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH), 3);
            assert_eq!(witness_sigop_count(&[], &wsh, &witness, SCRIPT_VERIFY_P2SH), 0, "pre-SegWit: none");

            let redeem = ms(15, 15);
            let mut sig = vec![0x00];
            sig.push(0x4d);
            sig.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
            sig.extend_from_slice(&redeem);
            let p2sh = {
                let mut spk = vec![0xa9, 0x14];
                spk.extend_from_slice(&[0x11; 20]);
                spk.push(0x87);
                spk
            };
            let mut t = tx(2, 0, &[SEQUENCE_FINAL]);
            t.input[0].script_sig = ScriptBuf::from_bytes(sig);
            assert_eq!(p2sh_sigop_count(&t, &[&p2sh]), 15);
            assert_eq!(transaction_sigop_cost(&t, &[&p2sh], SCRIPT_VERIFY_P2SH), 15 * WITNESS_SCALE_FACTOR);
            assert_eq!(transaction_sigop_cost(&t, &[&p2sh], 0), 0, "pre-BIP16: no P2SH sigops");
        }
    }
}
