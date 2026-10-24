//! Spike 047 benchmark CLI (macOS host, or iOS simulator via `xcrun simctl spawn`).
//!
//!   kernel-bench run <dir>            regtest connect / reopen / script benches (JSON)
//!   kernel-bench killtest <dir> <n>   SIGKILL a writer mid-sync n times, check recovery
//!   kernel-bench writer <dir>         (internal) process regtest blocks, slowly
//!   kernel-bench open <dir>           one process-cold open + destroy of an existing chainstate
//!   kernel-bench gen <dir> <n>        mine + connect n empty regtest blocks (mainnet-sized block index)
//!   kernel-bench blockcheck <file>    Block::check on a mainnet block fixture
//!   kernel-bench dump-regtest <dir> <out.jsonl>  regtest chain txs + spent outputs

use bitcoinkernel::Block;
use kernel_spike::bench;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("run") => {
            let r = bench::run_all(&PathBuf::from(&args[2])).unwrap();
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
        }
        Some("writer") => {
            bitcoinkernel::disable_logging();
            let dir = PathBuf::from(&args[2]);
            let k = bench::regtest_context();
            let cm = bench::open(&k, &dir);
            let start = cm.active_chain().height() as usize;
            for raw in bench::regtest_blocks().iter().skip(start) {
                cm.process_block(&Block::new(raw).unwrap());
                // Progress marker for killtest; slow down so kills land mid-sync.
                std::fs::write(dir.join("progress"), cm.active_chain().height().to_string()).unwrap();
                std::thread::sleep(Duration::from_millis(2));
            }
            println!("writer done at {}", cm.active_chain().height());
        }
        Some("killtest") => killtest(PathBuf::from(&args[2]), args[3].parse().unwrap()),
        Some("blockcheck") => blockcheck(&args[2]),
        Some("gen") => gen_chain(PathBuf::from(&args[2]), args[3].parse().unwrap()),
        Some("open") => {
            // One process-cold open of an existing chainstate (run as a fresh process).
            let t0 = Instant::now();
            bitcoinkernel::disable_logging();
            let k = bench::regtest_context();
            let t1 = Instant::now();
            let cm = bench::open(&k, &PathBuf::from(&args[2]));
            let open_ms = t1.elapsed().as_secs_f64() * 1e3;
            let h = cm.active_chain().height();
            let (fp, peak) = bench::mem_mb();
            println!("after open: phys_footprint {fp:.1} MB, resident peak {peak:.1} MB");
            let t2 = Instant::now();
            drop(cm); // ForceFlushStateToDisk + close
            let close_ms = t2.elapsed().as_secs_f64() * 1e3;
            println!("height {h}: context+open {:.1} ms (open {open_ms:.1}), destroy/flush {close_ms:.1} ms", t0.elapsed().as_secs_f64() * 1e3 - close_ms);
        }
        Some("dump-regtest") => dump_regtest(&args[2], &args[3]),
        _ => eprintln!("usage: kernel-bench run|killtest|writer|blockcheck|dump-regtest ..."),
    }
}

/// Spawn a writer, SIGKILL it after a varying delay, then reopen and finish
/// the sync in-process. Checks the chainstate opens and reaches the tip.
fn killtest(base: PathBuf, rounds: u32) {
    bitcoinkernel::disable_logging();
    let exe = std::env::current_exe().unwrap();
    let mut results = vec![];
    for i in 0..rounds {
        let dir = base.join(format!("kill-{i}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let delay = Duration::from_millis(150 + (i as u64 * 53) % 500);
        let mut child = Command::new(&exe).arg("writer").arg(&dir).spawn().unwrap();
        std::thread::sleep(delay);
        let _ = child.kill(); // SIGKILL
        let _ = child.wait();
        let t = Instant::now();
        let k = bench::regtest_context();
        let data = dir.join("data");
        let blocks = dir.join("blocks");
        let r = bitcoinkernel::ChainstateManager::new(&k.context, data.to_str().unwrap(), blocks.to_str().unwrap());
        match r {
            Err(e) => results.push(format!("round {i} kill@{delay:?}: REOPEN FAILED {e:?}")),
            Ok(cm) => {
                let reopened_at = cm.active_chain().height();
                let progress = std::fs::read_to_string(dir.join("progress")).unwrap_or_else(|_| "none".into());
                let open_ms = t.elapsed().as_secs_f64() * 1000.0;
                for raw in bench::regtest_blocks() {
                    cm.process_block(&Block::new(&raw).unwrap());
                }
                let h = cm.active_chain().height();
                results.push(format!(
                    "round {i} kill@{delay:?}: writer had connected {progress}; reopened at height {reopened_at} in {open_ms:.1} ms, resynced to {h} {}",
                    if h == 206 { "OK" } else { "FAIL" }
                ));
            }
        }
    }
    for r in results {
        println!("{r}");
    }
}

/// Context-free Block::check timing on a real mainnet block fixture.
fn blockcheck(path: &str) {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let raw = hex::decode(v["block_hex"].as_str().unwrap()).unwrap();
    let params = bitcoinkernel::ChainParams::new(bitcoinkernel::ChainType::Mainnet);
    for _ in 0..3 {
        let t = Instant::now();
        let kb = Block::new(&raw).unwrap();
        let parse_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let chk = kb.check(&params, bitcoinkernel::BLOCK_CHECK_ALL);
        println!("height {} bytes {}: parse {parse_ms:.2} ms, Block::check(ALL) {:.2} ms -> {chk:?}",
            v["height"], raw.len(), t.elapsed().as_secs_f64() * 1000.0);
    }
}

/// Write every regtest-chain tx + spent outputs (from kernel undo data) as JSONL.
fn dump_regtest(dir: &str, out: &str) {
    bitcoinkernel::disable_logging();
    let dir = PathBuf::from(dir);
    bench::bench_connect(&dir);
    let mut s = String::new();
    for (name, raw, spent) in bench::chain_tx_cases(&dir) {
        let sp: Vec<_> = spent.iter().map(|o| serde_json::json!([o.value, hex::encode(&o.spk)])).collect();
        s += &serde_json::json!({"name": name, "tx": hex::encode(raw), "spent": sp}).to_string();
        s.push('\n');
    }
    std::fs::write(out, s).unwrap();
}

/// Mine `n` coinbase-only regtest blocks (trivial PoW) and connect them, to get
/// a block index with mainnet's entry count. Coins DB stays tiny, so this
/// isolates block-index load cost + memory at cold open.
fn gen_chain(dir: PathBuf, n: u32) {
    use bitcoin::blockdata::{opcodes, script::Builder};
    use bitcoin::{block, absolute::LockTime, transaction::Version, Amount, CompactTarget, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    bitcoinkernel::disable_logging();
    let k = bench::regtest_context();
    let cm = bench::open(&k, &dir);
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let start_h = cm.active_chain().height() as u32;
    let mut prev = if start_h == 0 { genesis.block_hash() } else {
        let e = cm.active_chain().tip();
        let raw = cm.read_block_data(&e).unwrap().consensus_encode().unwrap();
        bitcoin::consensus::deserialize::<bitcoin::Block>(&raw).unwrap().block_hash()
    };
    let t0 = Instant::now();
    let mut t_proc = 0.0;
    for h in (start_h + 1)..=(start_h + n) {
        let cb = bitcoin::Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(h as i64).push_opcode(opcodes::OP_0).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }],
        };
        let mut header = block::Header {
            version: block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_raw_hash(cb.compute_txid().to_raw_hash()),
            time: genesis.header.time + h,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        while header.validate_pow(header.target()).is_err() {
            header.nonce += 1;
        }
        let b = bitcoin::Block { header, txdata: vec![cb] };
        let raw = bitcoin::consensus::serialize(&b);
        let t = Instant::now();
        let r = cm.process_block(&Block::new(&raw).unwrap());
        t_proc += t.elapsed().as_secs_f64();
        assert!(r.is_new_block() && !r.is_rejected(), "gen block {h} rejected");
        prev = b.block_hash();
        if h % 100_000 == 0 {
            eprintln!("height {h}: {:.0}s elapsed, process_block total {:.0}s", t0.elapsed().as_secs_f64(), t_proc);
        }
    }
    let h = cm.active_chain().height();
    let t = Instant::now();
    drop(cm);
    println!("gen done: tip {h}, {:.0}s wall, process_block total {t_proc:.1}s, final destroy/flush {:.1}s",
        t0.elapsed().as_secs_f64(), t.elapsed().as_secs_f64());
}
