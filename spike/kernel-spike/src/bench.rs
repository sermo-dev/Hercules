//! Kernel chainstate benchmarks that can run without mainnet data:
//! regtest chain from the bitcoinkernel crate's 206-block fixture.
//!
//! All numbers produced here describe a *tiny regtest chainstate*. They bound
//! fixed costs (library init, LevelDB open, VerifyDB over a few blocks), not
//! the mainnet case where the coins DB is ~10+ GB.

use crate::{Outcome, Spent};
use bitcoinkernel::{
    prelude::*, Block, ChainType, ChainstateManager, Context, ContextBuilder,
};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub const REGTEST_BLOCKS_HEX: &str = include_str!("../testdata/regtest_blocks.hex");

pub fn regtest_blocks() -> Vec<Vec<u8>> {
    REGTEST_BLOCKS_HEX
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| hex::decode(l).unwrap())
        .collect()
}

/// Process memory as iOS jetsam sees it (phys_footprint), plus peak RSS.
pub fn mem_mb() -> (f64, f64) {
    #[repr(C)]
    #[derive(Default)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
        _rest: [u64; 32],
    }
    extern "C" {
        static mach_task_self_: u32;
        fn task_info(task: u32, flavor: i32, info: *mut TaskVmInfo, count: *mut u32) -> i32;
    }
    const TASK_VM_INFO: i32 = 22;
    let mut info = TaskVmInfo::default();
    let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
    let kr = unsafe { task_info(mach_task_self_, TASK_VM_INFO, &mut info, &mut count) };
    if kr != 0 {
        return (-1.0, -1.0);
    }
    let mb = |b: u64| b as f64 / (1024.0 * 1024.0);
    (mb(info.phys_footprint), mb(info.resident_size_peak))
}

pub struct Kernel {
    pub connected: Arc<AtomicUsize>,
    pub context: Context,
}

pub fn regtest_context() -> Kernel {
    let connected = Arc::new(AtomicUsize::new(0));
    let c2 = connected.clone();
    let context = ContextBuilder::new()
        .chain_type(ChainType::Regtest)
        // Wallet-scanner hook point: fires once per connected block.
        .with_block_connected_validation(move |_block: Block, _entry: bitcoinkernel::BlockTreeEntry<'_>| {
            c2.fetch_add(1, Ordering::Relaxed);
        })
        .build()
        .expect("context");
    Kernel { connected, context }
}

pub fn open(k: &Kernel, dir: &Path) -> ChainstateManager {
    let data = dir.join("data");
    let blocks = dir.join("blocks");
    ChainstateManager::new(&k.context, data.to_str().unwrap(), blocks.to_str().unwrap()).expect("chainman")
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn stats(v: &mut [f64]) -> Value {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    json!({
        "n": n,
        "min_ms": v[0],
        "median_ms": v[n / 2],
        "p90_ms": v[(n * 9) / 10],
        "max_ms": v[n - 1],
        "total_ms": v.iter().sum::<f64>(),
    })
}

/// Process all regtest blocks from scratch (process_block = full Core
/// validation + connect + flush policy), timing each.
pub fn bench_connect(dir: &Path) -> Value {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let blocks = regtest_blocks();
    let (mem0, _) = mem_mb();
    let t_ctx = Instant::now();
    let k = regtest_context();
    let ctx_ms = ms(t_ctx);
    let t_open = Instant::now();
    let cm = open(&k, dir);
    let fresh_open_ms = ms(t_open);
    let mut per_block = vec![];
    for raw in &blocks {
        let b = Block::new(raw).unwrap();
        let t = Instant::now();
        let r = cm.process_block(&b);
        per_block.push(ms(t));
        assert!(r.is_new_block() && !r.is_rejected(), "regtest block rejected");
    }
    let height = cm.active_chain().height();
    let (mem1, peak) = mem_mb();
    drop(cm);
    json!({
        "blocks": blocks.len(),
        "tip_height": height,
        "block_connected_callbacks": k.connected.load(Ordering::Relaxed),
        "context_create_ms": ctx_ms,
        "fresh_chainstate_create_ms": fresh_open_ms,
        "process_block": stats(&mut per_block),
        "phys_footprint_mb_before": mem0,
        "phys_footprint_mb_after": mem1,
        "resident_peak_mb": peak,
    })
}

/// Reopen an existing chainstate N times: context + ChainstateManager::new
/// (LoadChainstate + VerifyLoadedChainstate + ActivateBestChains).
pub fn bench_cold_open(dir: &Path, n: usize) -> Value {
    let mut ctx = vec![];
    let mut open_ms = vec![];
    let mut height = 0;
    for _ in 0..n {
        let t = Instant::now();
        let k = regtest_context();
        ctx.push(ms(t));
        let t = Instant::now();
        let cm = open(&k, dir);
        open_ms.push(ms(t));
        height = cm.active_chain().height();
    }
    json!({
        "tip_height_after_open": height,
        "context_create": stats(&mut ctx),
        "chainstate_open": stats(&mut open_ms),
        "note": "process-warm (same process, OS file cache warm); a true cold push-wake also pays process launch + dyld + page-ins",
    })
}

/// Read every block + undo data back from kernel (exercises
/// `btck_block_read` / `btck_block_spent_outputs_read`) and return each
/// non-coinbase tx with its spent outputs: these become Step-1 comparison
/// cases (`testdata/regtest_inputs.jsonl`).
pub fn chain_tx_cases(dir: &Path) -> Vec<(String, Vec<u8>, Vec<Spent>)> {
    let k = regtest_context();
    let cm = open(&k, dir);
    let chain = cm.active_chain();
    let mut out = vec![];
    for h in 1..=chain.height() {
        let entry = chain.at_height(h as usize).unwrap();
        let block = cm.read_block_data(&entry).unwrap();
        let undo = cm.read_spent_outputs(&entry).unwrap();
        assert_eq!(undo.count() + 1, block.transaction_count(), "undo = one entry per non-coinbase tx");
        for (ti, txs) in undo.iter().enumerate() {
            let tx = block.transaction(ti + 1).unwrap();
            let raw = tx.consensus_encode().unwrap();
            let spent: Vec<Spent> = (0..txs.count())
                .map(|i| {
                    let c = txs.coin(i).unwrap();
                    let o = c.output();
                    Spent { value: o.value() as u64, spk: o.script_pubkey().to_bytes() }
                })
                .collect();
            out.push((format!("regtest h{h} tx{}", ti + 1), raw, spent));
        }
    }
    out
}

/// Kernel-only script verify over every input of the regtest chain.
pub fn bench_scripts_from_chain(dir: &Path) -> Value {
    let cases = chain_tx_cases(dir);
    let t = Instant::now();
    let mut inputs = 0;
    let mut valid = 0;
    for (_, raw, spent) in &cases {
        let r = crate::verify_kernel_tx(raw, spent, crate::VERIFY_ALL);
        inputs += r.len();
        valid += r.iter().filter(|o| **o == Outcome::Valid).count();
    }
    json!({ "txs": cases.len(), "inputs": inputs, "valid_inputs": valid, "kernel_verify_total_ms": ms(t) })
}

pub fn run_all(base: &Path) -> Result<Value, String> {
    bitcoinkernel::disable_logging();
    let dir = base.join("kernel-spike-regtest");
    let t = Instant::now();
    let connect = bench_connect(&dir);
    let cold = bench_cold_open(&dir, 10);
    let scripts = bench_scripts_from_chain(&dir);
    let (mem, peak) = mem_mb();
    Ok(json!({
        "target": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        "connect_206_regtest_blocks": connect,
        "reopen_existing_chainstate": cold,
        "scripts_from_chain": scripts,
        "phys_footprint_mb_end": mem,
        "resident_peak_mb_end": peak,
        "wall_ms": ms(t),
    }))
}
