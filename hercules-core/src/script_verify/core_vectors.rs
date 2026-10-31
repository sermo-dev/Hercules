//! Loaders for Bitcoin Core's script/tx test vectors (`testdata/`, copied
//! from the pinned release's `src/test/data/`), mapped onto the seven
//! consensus flags both backends accept. Test-only; ported from the ticket
//! 047 spike.
//!
//! Vectors that also rely on policy flags (STRICTENC, LOW_S, CLEANSTACK,
//! ...) still run with their consensus subset, but Core's expected result
//! does not apply to that subset, so for those only backend-vs-backend
//! agreement is checked (`expect_valid: None`).

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use serde_json::Value;

use super::script_asm::parse_script;
use super::{SpentOutput, SCRIPT_VERIFY_ALL_CONSENSUS};
use crate::chain_params::*;

pub const SCRIPT_TESTS: &str = include_str!("testdata/script_tests.json");
pub const TX_VALID: &str = include_str!("testdata/tx_valid.json");
pub const TX_INVALID: &str = include_str!("testdata/tx_invalid.json");
/// Core's legacy `SignatureHash` vectors (same release).
pub const SIGHASH: &str = include_str!("testdata/sighash.json");

#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub tx: Transaction,
    pub spent: Vec<SpentOutput>,
    pub flags: u32,
    /// Core's expected result where it is meaningful in the consensus-only
    /// flag space: Some(true) = every input valid, Some(false) = some
    /// input invalid.
    pub expect_valid: Option<bool>,
}

/// Cases loaded from one vector file, plus how many were skipped.
pub struct Loaded {
    pub cases: Vec<Case>,
    pub skipped: usize,
}

fn consensus_flag(name: &str) -> Option<u32> {
    Some(match name {
        "NONE" | "" => SCRIPT_VERIFY_NONE,
        "P2SH" => SCRIPT_VERIFY_P2SH,
        "DERSIG" => SCRIPT_VERIFY_DERSIG,
        "NULLDUMMY" => SCRIPT_VERIFY_NULLDUMMY,
        "CHECKLOCKTIMEVERIFY" => SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
        "CHECKSEQUENCEVERIFY" => SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
        "WITNESS" => SCRIPT_VERIFY_WITNESS,
        "TAPROOT" => SCRIPT_VERIFY_TAPROOT,
        _ => return None,
    })
}

/// (consensus bits, whether every name was a consensus flag).
fn parse_flags(s: &str) -> (u32, bool) {
    let mut bits = 0;
    let mut exact = true;
    for n in s.split(',') {
        match consensus_flag(n) {
            Some(b) => bits |= b,
            None => exact = false,
        }
    }
    (bits, exact)
}

fn load(json: &str) -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(json).expect("vector file is a JSON array")
}

/// `script_tests.json`: one crediting + one spending tx per vector, built
/// like Core's `BuildCreditingTransaction` / `BuildSpendingTransaction`.
/// Skips vectors using `#SCRIPT#` / `#CONTROLBLOCK#` (they need Core's
/// taproot builder) and any whose asm we can't parse.
pub fn script_tests() -> Loaded {
    let mut cases = vec![];
    let mut skipped = 0;
    for (idx, t) in load(SCRIPT_TESTS).iter().enumerate() {
        let a = t.as_array().unwrap();
        let mut pos = 0;
        let mut witness: Vec<Vec<u8>> = vec![];
        let mut value_sat: u64 = 0;
        if a.first().map(|v| v.is_array()) == Some(true) {
            let w = a[0].as_array().unwrap();
            let items = &w[..w.len() - 1];
            if items.iter().any(|e| e.as_str().unwrap().starts_with('#')) {
                skipped += 1;
                continue;
            }
            witness = items.iter().map(|e| hex::decode(e.as_str().unwrap()).unwrap()).collect();
            value_sat = (w[w.len() - 1].as_f64().unwrap() * 1e8).round() as u64;
            pos = 1;
        }
        if a.len() < 4 + pos {
            continue; // comment line
        }
        let (sig, spk) = match (
            parse_script(a[pos].as_str().unwrap()),
            parse_script(a[pos + 1].as_str().unwrap()),
        ) {
            (Ok(sig), Ok(spk)) => (sig, spk),
            _ => {
                skipped += 1;
                continue;
            }
        };
        let flag_str = a[pos + 2].as_str().unwrap();
        let expected = a[pos + 3].as_str().unwrap();
        let (mut flags, exact) = parse_flags(flag_str);
        if flag_str.split(',').any(|f| f == "CLEANSTACK") {
            flags |= SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS; // as Core's DoTest
        }
        let credit = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value_sat),
                script_pubkey: ScriptBuf::from_bytes(spk.clone()),
            }],
        };
        let spend = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: credit.compute_txid(), vout: 0 },
                script_sig: ScriptBuf::from_bytes(sig),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&witness),
            }],
            output: vec![TxOut { value: Amount::from_sat(value_sat), script_pubkey: ScriptBuf::new() }],
        };
        cases.push(Case {
            name: format!("script_tests[{idx}] flags={flag_str} expect={expected}"),
            tx: spend,
            spent: vec![(value_sat, spk)],
            flags,
            expect_valid: exact.then(|| expected == "OK"),
        });
    }
    Loaded { cases, skipped }
}

/// `tx_valid.json` (flags = excluded set) and `tx_invalid.json` (flags =
/// set under which it fails).
pub fn tx_tests(valid_file: bool) -> Loaded {
    let mut cases = vec![];
    let mut skipped = 0;
    let json = if valid_file { TX_VALID } else { TX_INVALID };
    for (idx, t) in load(json).iter().enumerate() {
        let a = t.as_array().unwrap();
        if a.len() < 3 || !a[0].is_array() {
            continue; // comment line
        }
        let mut prevouts: HashMap<OutPoint, SpentOutput> = HashMap::new();
        let mut bad = false;
        for p in a[0].as_array().unwrap() {
            let p = p.as_array().unwrap();
            let txid = bitcoin::Txid::from_str(p[0].as_str().unwrap()).unwrap();
            let vout = p[1].as_i64().unwrap() as i32 as u32;
            match parse_script(p[2].as_str().unwrap()) {
                Ok(spk) => {
                    let value = p.get(3).and_then(|v| v.as_i64()).unwrap_or(0) as u64;
                    prevouts.insert(OutPoint { txid, vout }, (value, spk));
                }
                Err(_) => bad = true,
            }
        }
        let raw = hex::decode(a[1].as_str().unwrap()).unwrap();
        let tx: Transaction = match deserialize(&raw) {
            Ok(t) => t,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let coinbase = tx.input.iter().any(|i| {
            i.previous_output.txid == bitcoin::Txid::all_zeros() && i.previous_output.vout == u32::MAX
        });
        let spent: Option<Vec<SpentOutput>> =
            tx.input.iter().map(|i| prevouts.get(&i.previous_output).cloned()).collect();
        let (Some(spent), false, false) = (spent, bad, coinbase) else {
            skipped += 1; // coinbase / unparsable: not a script-verify case
            continue;
        };
        let flag_str = a[2].as_str().unwrap();
        let (case_flags, expect_valid) = if valid_file {
            // Valid under ALL minus the excluded flags (soft forks are monotone).
            let (excl, _) = parse_flags(flag_str);
            (SCRIPT_VERIFY_ALL_CONSENSUS & !excl, Some(true))
        } else if flag_str == "BADTX" {
            // Fails CheckTransaction, not scripts: compare backends only.
            (SCRIPT_VERIFY_ALL_CONSENSUS, None)
        } else {
            let (bits, exact) = parse_flags(flag_str);
            (bits, exact.then_some(false))
        };
        // WITNESS requires P2SH. Mirror Core's transaction_tests TrimFlags
        // (valid: drop WITNESS if P2SH excluded) and FillFlags (invalid:
        // add P2SH if WITNESS set).
        let flags = if valid_file {
            if case_flags & SCRIPT_VERIFY_P2SH == 0 {
                case_flags & !SCRIPT_VERIFY_WITNESS
            } else {
                case_flags
            }
        } else if case_flags & SCRIPT_VERIFY_WITNESS != 0 {
            case_flags | SCRIPT_VERIFY_P2SH
        } else {
            case_flags
        };
        let kind = if valid_file { "tx_valid" } else { "tx_invalid" };
        cases.push(Case {
            name: format!("{kind}[{idx}] flags={flag_str}"),
            tx,
            spent,
            flags,
            expect_valid,
        });
    }
    Loaded { cases, skipped }
}
