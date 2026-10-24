//! Step-1 comparison cases, run through whichever engine this build links.
//! Lines: <name>\t<flags hex>\t<outcomes: V=valid I=invalid R=rejected, per input>

use crate::{mainnet_height_to_flags, vectors, verify_tx, Outcome, Spent, ENGINE};
use std::path::Path;
use std::time::Instant;

const TAPROOT_FIXTURE_TX_HEX: &str = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00";
const TAPROOT_FIXTURE_PREV_SPK_HEX: &str = "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0";

fn code(v: &[Outcome]) -> String {
    v.iter()
        .map(|o| match o {
            Outcome::Valid => 'V',
            Outcome::Invalid => 'I',
            Outcome::Rejected => 'R',
        })
        .collect()
}

fn spent_from_json(v: &serde_json::Value) -> Vec<Spent> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|o| Spent { value: o[0].as_u64().unwrap(), spk: hex::decode(o[1].as_str().unwrap()).unwrap() })
        .collect()
}

/// Run all cases; returns (one TSV line per case, JSON summary incl. timings).
pub fn run(dir: &Path) -> (String, serde_json::Value) {
    let mut tsv = String::new();
    let mut summary = serde_json::json!({ "engine": ENGINE });
    let mut cases: Vec<vectors::Case> = vec![];

    // 1. The block_validation.rs Taproot fixture (block 709635) and mutations.
    let tx = hex::decode(TAPROOT_FIXTURE_TX_HEX).unwrap();
    let spk = hex::decode(TAPROOT_FIXTURE_PREV_SPK_HEX).unwrap();
    let good = vec![Spent { value: 88_480, spk: spk.clone() }];
    let mut t: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx).unwrap();
    let mut sig = t.input[0].witness.to_vec()[0].clone();
    sig[0] ^= 0x80;
    t.input[0].witness = bitcoin::Witness::from_slice(&[sig]);
    let badsig = bitcoin::consensus::serialize(&t);
    let f = mainnet_height_to_flags(709_635);
    let mk = |name: &str, tx: &[u8], spent: Vec<Spent>, flags, exp| vectors::Case {
        name: name.into(), tx: tx.to_vec(), spent, flags, expect_valid: exp };
    cases.push(mk("taproot_fixture valid", &tx, good.clone(), f, Some(true)));
    cases.push(mk("taproot_fixture corrupted_sig", &badsig, good.clone(), f, Some(false)));
    cases.push(mk("taproot_fixture wrong_amount", &tx, vec![Spent { value: 88_481, spk: spk.clone() }], f, Some(false)));
    for h in [0u32, 173_805, 363_725, 388_381, 419_328, 481_824, 709_632] {
        cases.push(mk(&format!("taproot_fixture era h{h}"), &badsig, good.clone(), mainnet_height_to_flags(h), None));
    }

    // 2. Core's vectors.
    let mut skipped = vec![];
    for (label, (c, s)) in [
        ("script_tests", vectors::script_tests(dir.join("script_tests.json").to_str().unwrap())),
        ("tx_valid", vectors::tx_tests(dir.join("tx_valid.json").to_str().unwrap(), true)),
        ("tx_invalid", vectors::tx_tests(dir.join("tx_invalid.json").to_str().unwrap(), false)),
    ] {
        skipped.push(format!("{label}: {} cases, {s} skipped", c.len()));
        cases.extend(c);
    }

    // 3. Every tx of the 206-block regtest chain, spent outputs from kernel undo data.
    if let Ok(s) = std::fs::read_to_string(dir.join("regtest_inputs.jsonl")) {
        for l in s.lines() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            cases.push(vectors::Case {
                name: v["name"].as_str().unwrap().into(),
                tx: hex::decode(v["tx"].as_str().unwrap()).unwrap(),
                spent: spent_from_json(&v["spent"]),
                flags: crate::VERIFY_ALL,
                expect_valid: Some(true),
            });
        }
    }

    let t0 = Instant::now();
    let mut unexpected = vec![];
    for c in &cases {
        let r = verify_tx(&c.tx, &c.spent, c.flags);
        if let Some(want) = c.expect_valid {
            if r.iter().all(|o| *o == Outcome::Valid) != want {
                unexpected.push(format!("{}: want valid={want} got {}", c.name, code(&r)));
            }
        }
        tsv += &format!("{}\t{:#x}\t{}\n", c.name, c.flags, code(&r));
    }
    summary["cases"] = serde_json::json!(cases.len());
    summary["cases_ms"] = serde_json::json!(t0.elapsed().as_secs_f64() * 1e3);
    summary["vector_files"] = serde_json::json!(skipped);
    summary["unexpected_vs_core"] = serde_json::json!(unexpected);
    let mut blocks = vec![];

    // 4. Real mainnet blocks (testdata/mainnet_block_*.json, see fetch_mainnet_block.py).
    let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path())
        .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with("mainnet_block_")).collect();
    files.sort();
    for p in files {
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let height = v["height"].as_u64().unwrap() as u32;
        let block: bitcoin::Block = bitcoin::consensus::deserialize(&hex::decode(v["block_hex"].as_str().unwrap()).unwrap()).unwrap();
        let prev = v["prevouts"].as_array().unwrap();
        let flags = mainnet_height_to_flags(height);
        let txs: Vec<(Vec<u8>, Vec<Spent>)> = block.txdata.iter().skip(1).zip(prev)
            .map(|(tx, p)| (bitcoin::consensus::serialize(tx), spent_from_json(p))).collect();
        let inputs: usize = txs.iter().map(|t| t.1.len()).sum();
        let mut times = vec![];
        let mut all = String::new();
        for _ in 0..5 {
            let t = Instant::now();
            all = txs.iter().map(|(tx, s)| code(&verify_tx(tx, s, flags))).collect::<Vec<_>>().join(",");
            times.push(t.elapsed().as_secs_f64() * 1e3);
        }
        let valid = all.chars().filter(|c| *c == 'V').count();
        tsv += &format!("mainnet {height}\t{flags:#x}\t{all}\n");
        blocks.push(serde_json::json!({ "height": height, "txs": block.txdata.len(), "inputs": inputs,
            "valid_inputs": valid, "single_thread_script_verify_ms_per_run": times }));
    }
    summary["mainnet_blocks"] = serde_json::json!(blocks);
    (tsv, summary)
}
