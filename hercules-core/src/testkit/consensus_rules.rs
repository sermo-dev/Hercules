//! Block-level tests of the contextual consensus rules (ticket 026).
//!
//! Each test mines real regtest blocks with `FixtureChain` (valid PoW,
//! signed spends, witness commitments) and runs them through Hercules'
//! own `validate_block` + `validate_block_scripts`, exactly as sync does,
//! with the chain itself as the header-timestamp source. Every rule gets
//! a block on each side of its boundary.
//!
//! Fixture timestamps are `T0 + 600·h` (salt 0), with T0 the regtest
//! genesis time, so `MTP(h) = T0 + 600·(h − 5)` once `h ≥ 10`.

use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_ENDIF, OP_IF, OP_PUSHNUM_1};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use tempfile::TempDir;

use super::FixtureChain;
use crate::block_validation::{validate_block, validate_block_scripts, BlockValidationError};
use crate::chain_params::ChainParams;
use crate::contextual_checks::{median_time_past, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG};
use crate::utxo::UtxoSet;

/// Validate every block of `chain` under `params`; on failure return the
/// height and error.
fn validate_chain_with(chain: &FixtureChain, params: &ChainParams) -> Result<(), (u32, BlockValidationError)> {
    let dir = TempDir::new().unwrap();
    let utxo = UtxoSet::open(dir.path().join("utxo").to_str().unwrap()).unwrap();
    for h in 1..=chain.tip_height() {
        let block = chain.block(h);
        validate_block(block, h, params).map_err(|e| (h, e))?;
        validate_block_scripts(block, h, &utxo, params, chain).map_err(|e| (h, e))?;
        utxo.apply_block(block, h).unwrap();
    }
    Ok(())
}

fn validate_chain(chain: &FixtureChain) -> Result<(), (u32, BlockValidationError)> {
    validate_chain_with(chain, FixtureChain::params())
}

/// Regtest with BIP 68 / BIP 113 not yet active (CSV far in the future).
fn pre_csv_params() -> &'static ChainParams {
    Box::leak(Box::new(ChainParams { csv_height: 10_000, ..*ChainParams::regtest() }))
}

/// 101 blocks, then block 102 splits coinbase 1 into a fresh P2WPKH coin.
/// Returns the chain and that coin (confirmed at height 102).
fn chain_with_fresh_coin() -> (FixtureChain, OutPoint) {
    let mut c = FixtureChain::new();
    c.mine(101);
    let cb = c.coinbase_outpoint(1);
    let v = c.output(&cb).value - Amount::from_sat(1_000);
    let tx = c.spend(&[cb], vec![TxOut { value: v, script_pubkey: c.p2wpkh_script() }]);
    c.mine_block(vec![tx.clone()]);
    (c, OutPoint::new(tx.compute_txid(), 0))
}

/// Spend `coin` to the test key with the given version / nLockTime /
/// nSequence (all signed over).
fn timelocked_spend(c: &FixtureChain, coin: OutPoint, version: i32, lock_time: u32, sequence: u32) -> Transaction {
    let v = c.output(&coin).value - Amount::from_sat(1_000);
    c.spend_with(&[coin], vec![TxOut { value: v, script_pubkey: c.p2wpkh_script() }], |tx| {
        tx.version = Version(version);
        tx.lock_time = LockTime::from_consensus(lock_time);
        tx.input[0].sequence = Sequence(sequence);
    })
}

/// Mine empty blocks until the tip is `height`.
fn mine_to(c: &mut FixtureChain, height: u32) {
    let n = height - c.tip_height();
    c.mine(n);
}

fn assert_rejected_at(res: Result<(), (u32, BlockValidationError)>, height: u32, what: &str) {
    match res {
        Err((h, e)) => {
            assert_eq!(h, height, "rejected at the wrong height: {}", e);
            assert!(format!("{:?}", e).contains(what), "expected {}, got {:?}", what, e);
        }
        Ok(()) => panic!("block {} should fail with {}", height, what),
    }
}

// ── Rule 1: nLockTime (IsFinalTx) ────────────────────────────────────

#[test]
fn height_locktime_boundary_in_blocks() {
    let (base, coin) = chain_with_fresh_coin();
    // Included in block 103: nLockTime 102 is final, 103 is not.
    for (lock, ok) in [(102u32, true), (103, false)] {
        let mut c = base.clone();
        let tx = timelocked_spend(&c, coin, 2, lock, 0xffff_fffe);
        c.mine_block(vec![tx]);
        let res = validate_chain(&c);
        if ok {
            res.unwrap_or_else(|(h, e)| panic!("lock {}: rejected at {}: {}", lock, h, e));
        } else {
            assert_rejected_at(res, 103, "NonFinalTx");
        }
    }
    // Final sequences ignore an unmet nLockTime.
    let mut c = base.clone();
    let tx = timelocked_spend(&c, coin, 2, 1_000, 0xffff_ffff);
    c.mine_block(vec![tx]);
    validate_chain(&c).expect("SEQUENCE_FINAL overrides nLockTime");
}

#[test]
fn time_locktime_uses_median_time_past() {
    let (base, coin) = chain_with_fresh_coin();
    let mtp = median_time_past(&base, 102).unwrap() as u32;
    let next_block_time = base.block(102).header.time + 600;
    // nLockTime = MTP: not final (strict <), even though the block's own
    // timestamp is well past it. This is what BIP 113 changes.
    assert!(mtp < next_block_time - 600);
    for (lock, ok) in [(mtp - 1, true), (mtp, false), (next_block_time - 1, false)] {
        let mut c = base.clone();
        let tx = timelocked_spend(&c, coin, 2, lock, 0);
        c.mine_block(vec![tx]);
        let res = validate_chain(&c);
        if ok {
            res.unwrap_or_else(|(h, e)| panic!("lock {}: rejected at {}: {}", lock, h, e));
        } else {
            assert_rejected_at(res, 103, "NonFinalTx");
        }
    }
}

#[test]
fn pre_bip113_locktime_uses_block_time() {
    // Before CSV activation the cutoff is the block's own timestamp: a
    // lock between MTP and the block time is final.
    let (mut c, coin) = chain_with_fresh_coin();
    let lock = median_time_past(&c, 102).unwrap() as u32 + 1;
    let tx = timelocked_spend(&c, coin, 2, lock, 0);
    c.mine_block(vec![tx]);
    validate_chain_with(&c, pre_csv_params()).expect("block time satisfies lock pre-BIP 113");
    assert_rejected_at(validate_chain(&c), 103, "NonFinalTx");
}

#[test]
fn coinbase_locktime_is_checked_too() {
    // ContextualCheckBlock runs IsFinalTx on every transaction.
    for (lock, ok) in [(4u32, true), (5, false)] {
        let mut c = FixtureChain::new();
        c.mine(4);
        c.mine_custom(vec![], |b| {
            b.txdata[0].lock_time = LockTime::from_consensus(lock);
            b.txdata[0].input[0].sequence = Sequence(0);
        });
        let res = validate_chain(&c);
        if ok {
            res.expect("coinbase nLockTime 4 in block 5");
        } else {
            assert_rejected_at(res, 5, "NonFinalTx");
        }
    }
}

// ── Rule 3: BIP 68 relative lock-times (SequenceLocks) ───────────────

#[test]
fn csv_height_lock_boundary() {
    // The ticket's scenario: a CSV(10) spend of a coin confirmed at 102
    // is rejected 9 blocks later (111) and accepted at 10 (112).
    let (base, coin) = chain_with_fresh_coin();
    for (height, ok) in [(111u32, false), (112, true)] {
        let mut c = base.clone();
        mine_to(&mut c, height - 1);
        let tx = timelocked_spend(&c, coin, 2, 0, 10);
        c.mine_block(vec![tx]);
        let res = validate_chain(&c);
        if ok {
            res.unwrap_or_else(|(h, e)| panic!("rejected at {}: {}", h, e));
        } else {
            assert_rejected_at(res, height, "SequenceLockNotMet");
        }
    }
}

#[test]
fn csv_time_lock_boundary() {
    // 3 units = 1,536 s from MTP(101) = T0 + 57,600. A block at H needs
    // MTP(H − 1) = T0 + 600·(H − 6) > T0 + 59,135: first valid at H = 105.
    let (base, coin) = chain_with_fresh_coin();
    let t0 = base.block(0).header.time as i64;
    assert_eq!(median_time_past(&base, 101).unwrap(), t0 + 57_600);
    for (height, ok) in [(104u32, false), (105, true)] {
        let mut c = base.clone();
        mine_to(&mut c, height - 1);
        let tx = timelocked_spend(&c, coin, 2, 0, SEQUENCE_LOCKTIME_TYPE_FLAG | 3);
        c.mine_block(vec![tx]);
        let res = validate_chain(&c);
        if ok {
            res.unwrap_or_else(|(h, e)| panic!("rejected at {}: {}", h, e));
        } else {
            assert_rejected_at(res, height, "SequenceLockNotMet");
        }
    }
}

#[test]
fn bip68_not_enforced_for_v1_disabled_or_pre_csv() {
    let (base, coin) = chain_with_fresh_coin();
    // A 100-block lock, spent in the very next block.
    let early = |version: i32, sequence: u32| {
        let mut c = base.clone();
        let tx = timelocked_spend(&c, coin, version, 0, sequence);
        c.mine_block(vec![tx]);
        c
    };
    validate_chain(&early(1, 100)).expect("version 1: nSequence is not a lock");
    validate_chain(&early(2, SEQUENCE_LOCKTIME_DISABLE_FLAG | 100)).expect("disable flag");
    validate_chain_with(&early(2, 100), pre_csv_params()).expect("BIP 68 inactive");
    assert_rejected_at(validate_chain(&early(2, 100)), 103, "SequenceLockNotMet");
}

#[test]
fn bip68_in_block_parent_has_this_blocks_height() {
    // A child spending an output of an earlier tx in the same block: the
    // coin's height is the block's own, so only a zero lock passes.
    let (base, coin) = chain_with_fresh_coin();
    for (sequence, ok) in [(0u32, true), (1, false)] {
        let mut c = base.clone();
        let parent = timelocked_spend(&c, coin, 2, 0, 0xffff_ffff);
        let mut scratch = c.clone();
        scratch.mine_block(vec![parent.clone()]);
        let child = timelocked_spend(&scratch, OutPoint::new(parent.compute_txid(), 0), 2, 0, sequence);
        c.mine_block(vec![parent, child]);
        let res = validate_chain(&c);
        if ok {
            res.unwrap_or_else(|(h, e)| panic!("rejected at {}: {}", h, e));
        } else {
            assert_rejected_at(res, 103, "SequenceLockNotMet");
        }
    }
}

// ── Rule 4: sigop cost (GetTransactionSigOpCost) ─────────────────────

/// `OP_0 OP_IF <multisig × CHECKMULTISIG> <checksig × CHECKSIG> OP_ENDIF
/// OP_1`: always true, never executes a signature check, but statically
/// counts 20 per CHECKMULTISIG and 1 per CHECKSIG. Up to 199 opcodes in
/// the branch stays within the 201-op limit.
fn sigop_script(multisig: usize, checksig: usize) -> ScriptBuf {
    assert!(multisig + checksig <= 199);
    let mut b = Builder::new().push_int(0).push_opcode(OP_IF);
    for _ in 0..multisig {
        b = b.push_opcode(OP_CHECKMULTISIG);
    }
    for _ in 0..checksig {
        b = b.push_opcode(OP_CHECKSIG);
    }
    b.push_opcode(OP_ENDIF).push_opcode(OP_PUSHNUM_1).into_script()
}

/// Fund one output per script (P2WSH or P2SH), then spend them all in one
/// tx in the next block. Returns the chain and the spending block height.
fn sigop_chain(scripts: &[ScriptBuf], p2sh: bool) -> (FixtureChain, u32) {
    let mut c = FixtureChain::new();
    c.mine(101);
    let cb = c.coinbase_outpoint(1);
    let each = Amount::from_sat(10_000);
    let outputs: Vec<TxOut> = scripts
        .iter()
        .map(|s| TxOut {
            value: each,
            script_pubkey: if p2sh {
                ScriptBuf::new_p2sh(&s.script_hash())
            } else {
                ScriptBuf::new_p2wsh(&s.wscript_hash())
            },
        })
        .collect();
    let fund = c.spend(&[cb], outputs);
    c.mine_block(vec![fund.clone()]);

    let txid = fund.compute_txid();
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: scripts
            .iter()
            .enumerate()
            .map(|(i, s)| TxIn {
                previous_output: OutPoint::new(txid, i as u32),
                script_sig: if p2sh {
                    Builder::new()
                        .push_slice(PushBytesBuf::try_from(s.to_bytes()).unwrap())
                        .into_script()
                } else {
                    ScriptBuf::new()
                },
                sequence: Sequence::MAX,
                witness: if p2sh { Witness::new() } else { Witness::from_slice(&[s.as_bytes()]) },
            })
            .collect(),
        output: vec![TxOut {
            value: each * scripts.len() as u64 - Amount::from_sat(5_000),
            script_pubkey: c.p2wpkh_script(),
        }],
    };
    c.mine_block(vec![spend]);
    let height = c.tip_height();
    (c, height)
}

#[test]
fn witness_sigop_cost_boundary() {
    // 20 inputs × 199 × 20 = 79,600, plus 20 × 20 = 400: exactly 80,000
    // witness sigops (cost 1 each). One more CHECKSIG makes 80,001.
    let mut scripts = vec![sigop_script(199, 0); 20];
    scripts.push(sigop_script(20, 0));
    let (c, h) = sigop_chain(&scripts, false);
    validate_chain(&c).unwrap_or_else(|(h, e)| panic!("80,000 rejected at {}: {}", h, e));

    *scripts.last_mut().unwrap() = sigop_script(20, 1);
    let (c, _) = sigop_chain(&scripts, false);
    assert_rejected_at(validate_chain(&c), h, "ExcessiveSigopCost");
}

#[test]
fn p2sh_sigop_cost_boundary() {
    // P2SH redeem-script sigops cost 4: 5 × 3,980 × 4 = 79,600, plus
    // 5 × 20 × 4 = 400 → 80,000. One more CHECKSIG → 80,004.
    let mut scripts = vec![sigop_script(199, 0); 5];
    scripts.push(sigop_script(5, 0));
    let (c, h) = sigop_chain(&scripts, true);
    validate_chain(&c).unwrap_or_else(|(h, e)| panic!("80,000 rejected at {}: {}", h, e));

    *scripts.last_mut().unwrap() = sigop_script(5, 1);
    let (c, _) = sigop_chain(&scripts, true);
    assert_rejected_at(validate_chain(&c), h, "ExcessiveSigopCost");
}

// ── Rule 5: coinbase scriptSig length ────────────────────────────────

#[test]
fn coinbase_script_length_boundaries() {
    // Block 5: BIP 34 wants the scriptSig to start with OP_5 (0x55), which
    // is one byte on its own.
    for (len, ok) in [(1usize, false), (2, true), (100, true), (101, false)] {
        let mut c = FixtureChain::new();
        c.mine(4);
        c.mine_custom(vec![], |b| {
            let mut sig = vec![0x55];
            sig.resize(len, 0x00);
            b.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(sig);
        });
        let res = validate_chain(&c);
        if ok {
            res.unwrap_or_else(|(h, e)| panic!("len {} rejected at {}: {}", len, h, e));
        } else {
            assert_rejected_at(res, 5, "BadCoinbaseLength");
        }
    }
}

// ── Mainnet regression ───────────────────────────────────────────────

/// Real mainnet blocks through `validate_block` + `validate_block_scripts`
/// with real median-time-past and real coin heights: the new rules must
/// reject none of them. Data is public chain data fetched by
/// `tools/fetch_mainnet_context.py` into `$HERCULES_MAINNET_CTX_DIR`
/// (several MB per block, so not checked in).
#[test]
#[ignore = "needs HERCULES_MAINNET_CTX_DIR (see tools/fetch_mainnet_context.py)"]
fn mainnet_blocks_pass_contextual_rules() {
    use crate::contextual_checks::{transaction_sigop_cost, SEQUENCE_LOCKTIME_DISABLE_FLAG as DISABLE};
    use crate::utxo::UtxoEntry;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;
    use std::collections::{HashMap, HashSet};

    let dir = std::env::var("HERCULES_MAINNET_CTX_DIR").expect("HERCULES_MAINNET_CTX_DIR");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("mainnet_ctx_"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no mainnet_ctx_*.json in {}", dir);

    let params = ChainParams::mainnet();
    for path in files {
        let j: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let height = j["height"].as_u64().unwrap() as u32;
        let block: bitcoin::Block = deserialize(&hex::decode(j["block_hex"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(block.block_hash().to_string(), j["hash"].as_str().unwrap());
        let ts: HashMap<u32, u32> = j["timestamps"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.parse().unwrap(), v.as_u64().unwrap() as u32))
            .collect();
        let times = |h: u32| -> Result<u32, String> { ts.get(&h).copied().ok_or(format!("no ts {}", h)) };

        // Seed every spent coin from outside the block. Maturity isn't
        // under test (is_coinbase = false); heights are real wherever
        // BIP 68 can constrain the input.
        let utxo_dir = TempDir::new().unwrap();
        let utxo = UtxoSet::open(utxo_dir.path().join("utxo").to_str().unwrap()).unwrap();
        let prevouts = j["prevouts"].as_array().unwrap();
        let in_block: HashSet<_> = block.txdata.iter().map(|t| t.compute_txid()).collect();
        let (mut sigop_cost, mut relative_locks, mut time_locks) = (0u64, 0usize, 0usize);
        for (tx, row) in block.txdata.iter().skip(1).zip(prevouts) {
            let row = row.as_array().unwrap();
            assert_eq!(row.len(), tx.input.len());
            let mut spks = Vec::new();
            for (txin, p) in tx.input.iter().zip(row) {
                let spk = hex::decode(p[1].as_str().unwrap()).unwrap();
                let op = txin.previous_output;
                if !in_block.contains(&op.txid) {
                    utxo.test_insert_utxo(
                        op.txid.to_byte_array(),
                        op.vout,
                        UtxoEntry {
                            amount: p[0].as_u64().unwrap(),
                            script_pubkey: spk.clone(),
                            height: p[2].as_u64().unwrap() as u32,
                            is_coinbase: false,
                        },
                    )
                    .unwrap();
                }
                if tx.version.0 as u32 >= 2 && txin.sequence.0 & DISABLE == 0 {
                    relative_locks += 1;
                    time_locks += (txin.sequence.0 & SEQUENCE_LOCKTIME_TYPE_FLAG != 0) as usize;
                }
                spks.push(spk);
            }
            let refs: Vec<&[u8]> = spks.iter().map(|s| s.as_slice()).collect();
            sigop_cost += transaction_sigop_cost(tx, &refs, params.script_flags(height));
        }
        sigop_cost += transaction_sigop_cost(&block.txdata[0], &[], params.script_flags(height));

        validate_block(&block, height, params).unwrap_or_else(|e| panic!("{}: {}", height, e));
        validate_block_scripts(&block, height, &utxo, params, &times)
            .unwrap_or_else(|e| panic!("{}: {}", height, e));
        eprintln!(
            "mainnet {}: ok — {} txs, sigop cost {}, MTP {}, {} BIP 68 inputs ({} time-based)",
            height,
            block.txdata.len(),
            sigop_cost,
            median_time_past(&times, height - 1).unwrap(),
            relative_locks,
            time_locks
        );
    }
}

// ── Rule 7: BIP 34 at heights 1..=16 ─────────────────────────────────

#[test]
fn bip34_low_heights_validate_end_to_end() {
    // Core's regtest encoding (OP_1..OP_16) through the full validator,
    // and a block that commits to the wrong height is rejected.
    let mut c = FixtureChain::new();
    c.mine(17);
    validate_chain(&c).expect("heights 1..=17 with BIP 34 from height 1");

    let mut bad = FixtureChain::new();
    bad.mine(2);
    bad.mine_custom(vec![], |b| {
        b.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x52, 0x00]); // OP_2
    });
    assert_rejected_at(validate_chain(&bad), 3, "BadCoinbaseHeight");
}
