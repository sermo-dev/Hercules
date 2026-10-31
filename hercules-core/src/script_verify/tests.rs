//! Script backend tests (ticket 047).
//!
//! Every test runs each backend compiled in (`Backend::ENABLED`). With both
//! backends on (`cargo test --features script-differential`) the
//! `differential_*` tests also compare the two input by input, and every
//! other test in the crate that verifies a script goes through
//! `verify_differential` too.

use bitcoin::consensus::serialize;
use bitcoin::{Amount, OutPoint, Transaction, TxOut};

use super::core_vectors::{self, Case};
use super::*;
use crate::chain_params::{ChainParams, SCRIPT_VERIFY_NONE};
use crate::testkit::{FixtureChain, Invalid};

/// Every input's outcome (no early exit), after the shared precheck.
fn outcomes(backend: Backend, c: &Case) -> Result<InputResults, ScriptVerifyError> {
    precheck(&c.tx, &c.spent, c.flags).map_err(|f| f.error)?;
    backend.verify_inputs(&serialize(&c.tx), &c.spent, c.flags, false)
}

fn all_valid(r: &Result<InputResults, ScriptVerifyError>) -> bool {
    matches!(r, Ok(v) if v.iter().all(|i| i.is_ok()))
}

/// All Core vector cases plus the block_validation Taproot fixture and its
/// mutations under every historical mainnet flag era.
fn vector_cases() -> Vec<Case> {
    let script = core_vectors::script_tests();
    let valid = core_vectors::tx_tests(true);
    let invalid = core_vectors::tx_tests(false);
    // Guard against a loader regression silently shrinking coverage.
    assert!(script.cases.len() > 1_200, "script_tests: {} cases", script.cases.len());
    assert!(valid.cases.len() > 100, "tx_valid: {} cases", valid.cases.len());
    assert!(invalid.cases.len() > 80, "tx_invalid: {} cases", invalid.cases.len());
    eprintln!(
        "Core vectors: script_tests {} (+{} skipped), tx_valid {} (+{}), tx_invalid {} (+{})",
        script.cases.len(),
        script.skipped,
        valid.cases.len(),
        valid.skipped,
        invalid.cases.len(),
        invalid.skipped
    );
    let mut cases = taproot_fixture_cases();
    cases.extend(script.cases);
    cases.extend(valid.cases);
    cases.extend(invalid.cases);
    cases
}

fn taproot_fixture_cases() -> Vec<Case> {
    const TX: &str = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00";
    const SPK: &str = "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0";
    let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(TX).unwrap()).unwrap();
    let spk = hex::decode(SPK).unwrap();
    let mut bad = tx.clone();
    let mut sig = bad.input[0].witness.to_vec()[0].clone();
    sig[0] ^= 0x80;
    bad.input[0].witness = bitcoin::Witness::from_slice(&[sig]);
    let mainnet = ChainParams::mainnet();
    let f = mainnet.script_flags(709_635);
    let case = |name: &str, tx: &Transaction, value: u64, flags, expect_valid| Case {
        name: format!("taproot_fixture {name}"),
        tx: tx.clone(),
        spent: vec![(value, spk.clone())],
        flags,
        expect_valid,
    };
    let mut cases = vec![
        case("valid", &tx, 88_480, f, Some(true)),
        case("corrupted_sig", &bad, 88_480, f, Some(false)),
        case("wrong_amount", &tx, 88_481, f, Some(false)),
    ];
    // Before Taproot the v1 witness program is anyone-can-spend; before
    // SegWit the witness is ignored. Agreement only.
    for a in mainnet.script_flag_activations {
        for h in [a.height - 1, a.height] {
            cases.push(case(&format!("era h{h}"), &bad, 88_480, mainnet.script_flags(h), None));
        }
    }
    cases
}

/// (tx, spent outputs, flags, expected all-valid) for every non-coinbase
/// tx of a regtest fixture chain (ticket 027 testkit): P2WPKH and P2TR
/// key-path spends, a two-input mixed v0/v1 spend, an in-block
/// parent/child pair, a corrupted ECDSA signature, and every honest spend
/// again with its witness stripped.
fn fixture_chain_cases() -> Vec<Case> {
    let mut c = FixtureChain::new();
    c.mine(101);
    let value = c.block(1).txdata[0].output[0].value;
    let split = c.spend(
        &[c.coinbase_outpoint(1)],
        vec![
            TxOut { value: value / 2, script_pubkey: c.p2tr_script() },
            TxOut { value: value / 2 - Amount::from_sat(500), script_pubkey: c.p2wpkh_script() },
        ],
    );
    c.mine_block(vec![split.clone()]);
    let merge = c.spend(
        &[OutPoint::new(split.compute_txid(), 0), OutPoint::new(split.compute_txid(), 1)],
        vec![TxOut { value: value - Amount::from_sat(2_000), script_pubkey: c.p2wpkh_script() }],
    );
    c.mine_block(vec![merge]);
    let parent = c.spend(
        &[c.coinbase_outpoint(2)],
        vec![TxOut { value: value - Amount::from_sat(1_000), script_pubkey: c.p2tr_script() }],
    );
    let mut scratch = c.clone();
    scratch.mine_block(vec![parent.clone()]);
    let child = scratch.spend(
        &[OutPoint::new(parent.compute_txid(), 0)],
        vec![TxOut { value: value - Amount::from_sat(3_000), script_pubkey: c.p2wpkh_script() }],
    );
    c.mine_block(vec![parent, child]);
    c.mine(2);
    let bad_sig_height = c.tip_height() + 1;
    c.mine_invalid(Invalid::BadSignature);

    let mut outputs: std::collections::HashMap<OutPoint, TxOut> = Default::default();
    let mut cases = vec![];
    let params = FixtureChain::params();
    for (height, block) in c.blocks().iter().enumerate() {
        let flags = params.script_flags(height as u32);
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, out) in tx.output.iter().enumerate() {
                outputs.insert(OutPoint::new(txid, vout as u32), out.clone());
            }
            if tx.is_coinbase() {
                continue;
            }
            let spent: Vec<SpentOutput> = tx
                .input
                .iter()
                .map(|i| {
                    let o = &outputs[&i.previous_output];
                    (o.value.to_sat(), o.script_pubkey.to_bytes())
                })
                .collect();
            let honest = height as u32 != bad_sig_height;
            let mut stripped = tx.clone();
            stripped.input.iter_mut().for_each(|i| i.witness.clear());
            cases.push(Case {
                name: format!("regtest h{height} {txid}"),
                tx: tx.clone(),
                spent: spent.clone(),
                flags,
                expect_valid: Some(honest),
            });
            cases.push(Case {
                name: format!("regtest h{height} {txid} stripped"),
                tx: stripped,
                spent,
                flags,
                expect_valid: Some(false),
            });
        }
    }
    assert_eq!(cases.len(), 2 * 5, "fixture chain should yield 5 spends");
    cases
}

fn check_expected(cases: &[Case]) {
    for &backend in Backend::ENABLED {
        let mut checked = 0;
        let wrong: Vec<String> = cases
            .iter()
            .filter_map(|c| {
                let want = c.expect_valid?;
                checked += 1;
                let r = outcomes(backend, c);
                (all_valid(&r) != want).then(|| format!("{}: want valid={} got {:?}", c.name, want, r))
            })
            .collect();
        assert!(wrong.is_empty(), "{}: {} unexpected results:\n{}", backend.name(), wrong.len(), wrong.join("\n"));
        eprintln!("{}: {} cases match Core's expected result", backend.name(), checked);
    }
}

#[test]
fn core_vectors_match_core_expected_results() {
    check_expected(&vector_cases());
}

/// Every Core vector is loaded except a known few (the 5 script_tests
/// that need Core's taproot builder, `#SCRIPT#`/`#CONTROLBLOCK#`, and the
/// tx vectors that are coinbases or don't deserialize), and the number
/// checked against Core's own verdict doesn't shrink. A loader change that
/// silently drops vectors fails here.
#[test]
fn core_vector_coverage_is_pinned() {
    let script = core_vectors::script_tests();
    let valid = core_vectors::tx_tests(true);
    let invalid = core_vectors::tx_tests(false);
    assert_eq!(
        (script.cases.len(), script.skipped, valid.cases.len(), valid.skipped, invalid.cases.len(), invalid.skipped),
        (1232, 5, 119, 2, 89, 4)
    );
    let with_verdict = vector_cases().iter().filter(|c| c.expect_valid.is_some()).count();
    assert!(with_verdict >= 436, "{} cases with Core's verdict", with_verdict);
}

/// Core's `OP_CODESEPARATOR`-stripping scriptCode serialization
/// (`CTransactionSignatureSerializer::SerializeScriptCode`), for scripts
/// that parse to the end. `None` if a push is truncated: Core then
/// serializes a partial script, which no `&Script` can express.
fn core_script_code(script: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(script.len());
    let mut pc = 0;
    while pc < script.len() {
        let op = script[pc];
        let (header, len) = match op {
            0x01..=0x4b => (1, op as usize),
            0x4c => (2, *script.get(pc + 1)? as usize),
            0x4d => (3, u16::from_le_bytes(script.get(pc + 1..pc + 3)?.try_into().unwrap()) as usize),
            0x4e => (5, u32::from_le_bytes(script.get(pc + 1..pc + 5)?.try_into().unwrap()) as usize),
            _ => (1, 0),
        };
        let end = pc.checked_add(header)?.checked_add(len)?;
        if end > script.len() {
            return None;
        }
        if op != 0xab {
            out.extend_from_slice(&script[pc..end]);
        }
        pc = end;
    }
    Some(out)
}

/// Core's legacy `SignatureHash` vectors (sighash.json: every hash type,
/// ANYONECANPAY, NONE, the SIGHASH_SINGLE out-of-range "1" result, random
/// scripts with OP_CODESEPARATORs) against rust-bitcoin's
/// `legacy_signature_hash`, which the fixture chain signs with today and
/// the wallet will. (Verification itself uses the kernel's own
/// SignatureHash, covered by the script vectors above.)
#[test]
fn core_sighash_vectors_match_rust_bitcoin() {
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::SighashCache;
    let rows: Vec<serde_json::Value> = serde_json::from_str(core_vectors::SIGHASH).unwrap();
    let (mut checked, mut skipped) = (0, 0);
    for row in rows.iter().skip(1) {
        let a = row.as_array().unwrap();
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(a[0].as_str().unwrap()).unwrap()).unwrap();
        let script = hex::decode(a[1].as_str().unwrap()).unwrap();
        let index = a[2].as_u64().unwrap() as usize;
        let hash_type = a[3].as_i64().unwrap() as i32 as u32;
        let Some(code) = core_script_code(&script) else {
            skipped += 1;
            continue;
        };
        let got = SighashCache::new(&tx)
            .legacy_signature_hash(index, bitcoin::Script::from_bytes(&code), hash_type)
            .unwrap();
        // Core prints uint256 in reversed byte order.
        let mut bytes = got.to_byte_array();
        bytes.reverse();
        assert_eq!(hex::encode(bytes), a[4].as_str().unwrap(), "vector {:?}", a);
        checked += 1;
    }
    assert_eq!(checked + skipped, rows.len() - 1);
    eprintln!("sighash.json: {} checked, {} skipped (truncated push)", checked, skipped);
    assert_eq!((checked, skipped), (500, 0));
}

#[test]
fn fixture_chain_spends_verify_as_expected() {
    check_expected(&fixture_chain_cases());
}

#[test]
fn verify_transaction_reports_first_failing_input() {
    let cases = fixture_chain_cases();
    let merge = cases.iter().find(|c| c.tx.input.len() == 2).unwrap();
    assert_eq!(verify_transaction(&merge.tx, &merge.spent, merge.flags), Ok(()));
    // Corrupt only the second input's (P2WPKH) signature.
    let mut tx = merge.tx.clone();
    let mut items = tx.input[1].witness.to_vec();
    items[0][10] ^= 0x01;
    tx.input[1].witness = bitcoin::Witness::from_slice(&items);
    assert_eq!(
        verify_transaction(&tx, &merge.spent, merge.flags),
        Err(ScriptVerifyFailure { input_index: 1, error: ScriptVerifyError::ScriptFailed })
    );
}

/// Requests that would abort libbitcoinkernel (or, for WITNESS without
/// P2SH, libbitcoinconsensus) must be refused before reaching either.
#[test]
fn precheck_refuses_bad_flags_and_spent_outputs() {
    let c = &fixture_chain_cases()[0];
    let invalid_flags = |flags| {
        Err(ScriptVerifyFailure { input_index: 0, error: ScriptVerifyError::InvalidFlags(flags) })
    };
    for &backend in Backend::ENABLED {
        // Policy flag bit (SCRIPT_VERIFY_STRICTENC, 1 << 1).
        let f = c.flags | (1 << 1);
        assert_eq!(backend.verify_transaction(&c.tx, &c.spent, f), invalid_flags(f));
        let f = SCRIPT_VERIFY_WITNESS;
        assert_eq!(backend.verify_transaction(&c.tx, &c.spent, f), invalid_flags(f));
        assert_eq!(
            backend.verify_transaction(&c.tx, &[], c.flags),
            Err(ScriptVerifyFailure {
                input_index: 0,
                error: ScriptVerifyError::SpentOutputsMismatch { inputs: 1, spent: 0 },
            })
        );
        // No inputs: refused up front (the libraries disagree on it).
        let mut empty = c.tx.clone();
        empty.input.clear();
        assert_eq!(
            backend.verify_transaction(&empty, &[], c.flags),
            Err(ScriptVerifyFailure { input_index: 0, error: ScriptVerifyError::NoInputs })
        );
        // No flags at all is a valid request (pre-BIP16 rules).
        assert!(backend.verify_transaction(&c.tx, &c.spent, SCRIPT_VERIFY_NONE).is_ok());
    }
}

/// What the precheck protects against: the raw libraries really do
/// disagree on a zero-input tx, so it must never reach either.
#[cfg(feature = "script-differential")]
#[test]
fn differential_raw_libraries_disagree_on_zero_input_tx() {
    let mut tx = fixture_chain_cases()[0].tx.clone();
    tx.input.clear();
    let bytes = serialize(&tx);
    let kernel = Backend::Kernel.verify_inputs(&bytes, &[], SCRIPT_VERIFY_NONE, false);
    let legacy = Backend::ConsensusLegacy.verify_inputs(&bytes, &[], SCRIPT_VERIFY_NONE, false);
    assert_ne!(kernel, legacy);
    // Through the public entry point both agree (and nothing aborts).
    assert_eq!(
        verify_transaction(&tx, &[], SCRIPT_VERIFY_NONE),
        Err(ScriptVerifyFailure { input_index: 0, error: ScriptVerifyError::NoInputs })
    );
}

/// Differential mode over every Core vector, the Taproot fixture eras and
/// the regtest fixture chain: the two backends must agree on every input,
/// including cases where Core's expected result doesn't apply.
#[cfg(feature = "script-differential")]
#[test]
fn differential_backends_agree_on_every_case() {
    let cases: Vec<Case> = vector_cases().into_iter().chain(fixture_chain_cases()).collect();
    let mut inputs = 0;
    let mut mismatches = vec![];
    for c in &cases {
        let k = outcomes(Backend::Kernel, c);
        let l = outcomes(Backend::ConsensusLegacy, c);
        inputs += c.tx.input.len();
        if k != l {
            mismatches.push(format!("{}: kernel {:?} vs legacy {:?}", c.name, k, l));
        }
        // The production entry point (verify_differential) agrees too.
        let _ = verify_transaction(&c.tx, &c.spent, c.flags);
    }
    assert!(mismatches.is_empty(), "{} mismatches:\n{}", mismatches.len(), mismatches.join("\n"));
    eprintln!("differential: {} cases / {} inputs, 0 mismatches", cases.len(), inputs);
}

/// Per-block script-verify benchmark on real mainnet blocks, every enabled
/// backend in the same process. Not run by default. Fetch blocks with
/// `python3 -I tools/fetch_mainnet_block.py tip-6 <dir>`, then:
///
/// ```text
/// HERCULES_BENCH_BLOCKS=<dir> cargo test --release --features script-differential \
///     --lib bench_mainnet_block_script_verify -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn bench_mainnet_block_script_verify() {
    let dir = std::env::var("HERCULES_BENCH_BLOCKS").expect("set HERCULES_BENCH_BLOCKS");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("mainnet_block_"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no mainnet_block_*.json in {}", dir);
    for path in files {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let height = v["height"].as_u64().unwrap() as u32;
        let block: bitcoin::Block = bitcoin::consensus::deserialize(
            &hex::decode(v["block_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let flags = ChainParams::mainnet().script_flags(height);
        let txs: Vec<(Vec<u8>, Vec<SpentOutput>)> = block
            .txdata
            .iter()
            .skip(1)
            .zip(v["prevouts"].as_array().unwrap())
            .map(|(tx, p)| {
                let spent = p
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| (o[0].as_u64().unwrap(), hex::decode(o[1].as_str().unwrap()).unwrap()))
                    .collect();
                (serialize(tx), spent)
            })
            .collect();
        let inputs: usize = txs.iter().map(|t| t.1.len()).sum();
        // Backends alternate run by run so background load hits both alike.
        const RUNS: usize = 7;
        let mut ms = vec![vec![]; Backend::ENABLED.len()];
        for _ in 0..RUNS {
            for (b, &backend) in Backend::ENABLED.iter().enumerate() {
                let t = std::time::Instant::now();
                for (tx, spent) in &txs {
                    let r = backend.verify_inputs(tx, spent, flags, true).unwrap();
                    assert!(r.iter().all(|i| i.is_ok()), "block {} has an invalid input", height);
                }
                ms[b].push(t.elapsed().as_secs_f64() * 1e3);
            }
        }
        for (b, &backend) in Backend::ENABLED.iter().enumerate() {
            let runs = &mut ms[b];
            runs.sort_by(|x, y| x.partial_cmp(y).unwrap());
            eprintln!(
                "block {} ({} txs, {} inputs) {}: median {:.1} ms, min {:.1} ms",
                height,
                block.txdata.len(),
                inputs,
                backend.name(),
                runs[RUNS / 2],
                runs[0]
            );
        }
    }
}
