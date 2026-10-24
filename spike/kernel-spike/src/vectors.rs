//! Loaders for Bitcoin Core's script/tx test vectors, mapped onto the
//! consensus-only flag space both libraries expose.
//!
//! Both libbitcoinconsensus and libbitcoinkernel only accept the 7 consensus
//! flags. Vectors that also rely on policy flags (STRICTENC, LOW_S, CLEANSTACK,
//! ...) are still run with the consensus subset; for those we only check that
//! the two libraries agree with each other, not Core's expected result.

use crate::{asm::parse_script, Spent};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub tx: Vec<u8>,
    pub spent: Vec<Spent>,
    pub flags: u32,
    /// Core's expected result, when it is meaningful in the consensus-only
    /// flag space: Some(true) = all inputs valid, Some(false) = some input invalid.
    pub expect_valid: Option<bool>,
}

fn consensus_flag(name: &str) -> Option<u32> {
    Some(match name {
        "NONE" | "" => 0,
        "P2SH" => crate::VERIFY_P2SH,
        "DERSIG" => crate::VERIFY_DERSIG,
        "NULLDUMMY" => crate::VERIFY_NULLDUMMY,
        "CHECKLOCKTIMEVERIFY" => crate::VERIFY_CHECKLOCKTIMEVERIFY,
        "CHECKSEQUENCEVERIFY" => crate::VERIFY_CHECKSEQUENCEVERIFY,
        "WITNESS" => crate::VERIFY_WITNESS,
        "TAPROOT" => crate::VERIFY_TAPROOT,
        _ => return None,
    })
}

/// Returns (consensus bits, all names were consensus flags).
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

fn load(path: &str) -> Vec<Value> {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str::<Vec<Value>>(&s).unwrap()
}

/// `script_tests.json`: one crediting + one spending tx per vector, built like
/// Core's BuildCreditingTransaction / BuildSpendingTransaction.
/// Skips the 15 vectors using `#SCRIPT#`/`#CONTROLBLOCK#` (need a taproot builder).
pub fn script_tests(path: &str) -> (Vec<Case>, usize) {
    use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    let mut cases = vec![];
    let mut skipped = 0;
    for (idx, t) in load(path).iter().enumerate() {
        let a = t.as_array().unwrap();
        let mut pos = 0;
        let mut witness: Vec<Vec<u8>> = vec![];
        let mut value_sat: u64 = 0;
        if a.first().map(|v| v.is_array()) == Some(true) {
            let w = a[0].as_array().unwrap();
            let mut ok = true;
            for e in &w[..w.len() - 1] {
                let s = e.as_str().unwrap();
                if s.starts_with('#') {
                    ok = false;
                    break;
                }
                witness.push(hex::decode(s).unwrap());
            }
            if !ok {
                skipped += 1;
                continue;
            }
            let btc = w[w.len() - 1].as_f64().unwrap();
            value_sat = (btc * 1e8).round() as u64;
            pos = 1;
        }
        if a.len() < 4 + pos {
            continue; // comment
        }
        let sig = parse_script(a[pos].as_str().unwrap());
        let spk = parse_script(a[pos + 1].as_str().unwrap());
        let (sig, spk) = match (sig, spk) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                skipped += 1;
                continue;
            }
        };
        let flag_str = a[pos + 2].as_str().unwrap();
        let expected = a[pos + 3].as_str().unwrap();
        let (mut flags, exact) = parse_flags(flag_str);
        if flag_str.split(',').any(|f| f == "CLEANSTACK") {
            flags |= crate::VERIFY_P2SH | crate::VERIFY_WITNESS; // as Core's DoTest
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
            output: vec![TxOut { value: Amount::from_sat(value_sat), script_pubkey: ScriptBuf::from_bytes(spk.clone()) }],
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
            tx: serialize(&spend),
            spent: vec![Spent { value: value_sat, spk }],
            flags,
            expect_valid: if exact { Some(expected == "OK") } else { None },
        });
    }
    (cases, skipped)
}

/// `tx_valid.json` (flags = excluded) and `tx_invalid.json` (flags = failing set).
pub fn tx_tests(path: &str, valid_file: bool) -> (Vec<Case>, usize) {
    let mut cases = vec![];
    let mut skipped = 0;
    for (idx, t) in load(path).iter().enumerate() {
        let a = t.as_array().unwrap();
        if a.len() < 3 || !a[0].is_array() {
            continue; // comment
        }
        let mut prevouts: HashMap<(bitcoin::Txid, u32), Spent> = HashMap::new();
        let mut bad = false;
        for p in a[0].as_array().unwrap() {
            let p = p.as_array().unwrap();
            let txid = bitcoin::Txid::from_str(p[0].as_str().unwrap()).unwrap();
            let vout = p[1].as_i64().unwrap() as i32 as u32;
            let spk = match parse_script(p[2].as_str().unwrap()) {
                Ok(s) => s,
                Err(_) => {
                    bad = true;
                    break;
                }
            };
            let value = p.get(3).and_then(|v| v.as_i64()).unwrap_or(0) as u64;
            prevouts.insert((txid, vout), Spent { value, spk });
        }
        let raw = hex::decode(a[1].as_str().unwrap()).unwrap();
        let tx: bitcoin::Transaction = match deserialize(&raw) {
            Ok(t) => t,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if bad || tx.input.iter().any(|i| i.previous_output.txid == bitcoin::Txid::all_zeros() && i.previous_output.vout == u32::MAX) {
            skipped += 1; // coinbase / unparsable: not a script-verify case
            continue;
        }
        let spent: Option<Vec<Spent>> = tx
            .input
            .iter()
            .map(|i| prevouts.get(&(i.previous_output.txid, i.previous_output.vout)).cloned())
            .collect();
        let Some(spent) = spent else {
            skipped += 1;
            continue;
        };
        let flag_str = a[2].as_str().unwrap();
        let (case_flags, expect_valid) = if valid_file {
            // Excluded flags: valid under ALL minus excluded (soft-fork monotone).
            let (excl, _) = parse_flags(flag_str);
            (crate::VERIFY_ALL & !excl, Some(true))
        } else if flag_str == "BADTX" {
            // Fails CheckTransaction, not scripts: compare libs only.
            (crate::VERIFY_ALL, None)
        } else {
            let (bits, exact) = parse_flags(flag_str);
            (bits, if exact { Some(false) } else { None })
        };
        // WITNESS requires P2SH (kernel refuses the combination). Mirror Core's
        // transaction_tests TrimFlags (valid: drop WITNESS if P2SH excluded) and
        // FillFlags (invalid: add P2SH if WITNESS set).
        let flags = if valid_file {
            if case_flags & crate::VERIFY_P2SH == 0 { case_flags & !crate::VERIFY_WITNESS } else { case_flags }
        } else if case_flags & crate::VERIFY_WITNESS != 0 {
            case_flags | crate::VERIFY_P2SH
        } else {
            case_flags
        };
        cases.push(Case {
            name: format!("{}[{idx}] flags={flag_str}", if valid_file { "tx_valid" } else { "tx_invalid" }),
            tx: raw,
            spent,
            flags,
            expect_valid,
        });
    }
    (cases, skipped)
}
