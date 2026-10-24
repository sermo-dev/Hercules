# Ticket 047: libbitcoinkernel — Replace libbitcoinconsensus, Spike Full Kernel Validation

## Summary

Hercules verifies scripts with a patched, frozen **libbitcoinconsensus v26** (`hercules-core/patches/bitcoinconsensus/`). Bitcoin Core deprecated that library in v27 and removed it in v28; its successor is **libbitcoinkernel**, Core's effort to expose its whole validation engine as a library. This ticket has two parts:

1. **Step 1 — swap script verification** to kernel's script-verify API, keeping the rest of our architecture. Small; keeps us on maintained Core code.
2. **Step 2 — spike: full kernel validation.** In a throwaway branch, run Core's own C++ block validation and chainstate on iPhone and measure it against our Rust engine on the same blocks. Decide with data whether to migrate.

## Background

### Why libbitcoinconsensus was removed

- Narrow scope: it only verified a single input's script, given the spent outputs supplied by the caller. Every other consensus rule was the caller's problem (ticket 026 is our list of the ones we still miss).
- It invited the misconception that it was enough to build a consensus-compatible node.
- Low usage with ongoing maintenance cost, and superseded by the kernel project.

### Why staying on v26 is a problem

- **Future soft forks.** A frozen script library won't enforce rules activated after v26. Hercules would still follow the chain (soft forks are backward compatible) but as an *un-upgraded* node, not fully validating. That undercuts the product's core claim.
- We carry local patches to build an unmaintained library for iOS.

### What kernel is (verify all API details during the spike)

- A C API (`bitcoinkernel.h`) over Core's validation code: script verification, block validation, chainstate management (UTXO set + block storage), and notifications when blocks connect/disconnect.
- Rust bindings exist (`rust-bitcoinkernel` / `bitcoinkernel` crate). The API is **recent and marked experimental**; expect breaking changes. Confirm which Core release first shipped the C API and what the Rust crate currently covers.
- It contains **no P2P, no mempool policy, no wallet**. Those stay ours regardless.

## Step 1 — Script verification swap

- Replace the `bitcoinconsensus` dependency with kernel's script-verify function, called from the same place in `block_validation.rs` (and the mempool's script checks).
- Pass the same inputs: script, amount, spending tx, all spent outputs (Taproot), and flags.
- **Flags:** we currently derive them from `bitcoinconsensus::height_to_flags` with mainnet heights. Move to an explicit, tested flag table (also needed by ticket 027's regtest params).
- Build: replace `patches/bitcoinconsensus` with a kernel build in `build-ios.sh` for device + simulator. This build work is shared with Step 2.
- Verification: run Core's `script_tests.json` / `tx_valid.json` / `tx_invalid.json` vectors through the new path; full mainnet replay of recent blocks must produce identical results to the current engine.

## Step 2 — Full-kernel spike (branch `spike/047-kernel`, never merged)

### What kernel would replace

| Ours today | Kernel equivalent |
|---|---|
| `block_validation.rs` (structure + scripts + subsidy) | Core block validation (includes every rule in 026) |
| `utxo.rs` (LMDB UTXO set, undo data, rollback) | Core chainstate (LevelDB coins DB + undo files) |
| Reorg logic in `sync.rs` | Core's activate-best-chain (covers 025) |
| `block_store.rs` + pruning | Core block files + pruning |
| HUTX snapshot format + `convert_snapshot.rs` | Core's native snapshot format, if kernel exposes snapshot loading (verify). Would simplify ticket 032 |

What stays ours: P2P and peer pool, Tor/clearnet transport, mempool and relay policy (needs UTXO lookups through kernel; verify the API allows this), wallet scanner (hook into kernel's block-connected notifications), push-wake orchestration, UI.

### Measurements (same iPhone, same block range, ours vs kernel)

| Metric | Why it matters | Target to beat |
|---|---|---|
| Builds for iOS arm64 device + simulator | Feasibility | Must build reproducibly from `build-ios.sh` |
| Binary size delta | App download size | Record; flag if > ~20 MB |
| **Cold open of chainstate → ready** | Push wakes have ~30 s total | Few seconds at most |
| Validate + connect one recent mainnet block | Core of every wake | ≤ our engine, or within budget |
| Throughput over ~1,000 consecutive blocks | Catch-up after offline / new install | Record blocks/min |
| Peak memory (dbcache settings) | iOS jetsam limits, lower in background | Under foreground and background limits |
| Disk footprint after pruning | User storage | Comparable to today (~10–12 GB incl. UTXO) |
| Kill mid-write, relaunch | iOS kills apps without warning | Recovers without corruption or full resync |
| Locked-phone wake | File protection (ticket 030) | Chainstate readable after first unlock |
| Snapshot load time | New-install onboarding | Record |

### Method

1. Build kernel for iOS; link via the Rust bindings into a minimal test harness inside the app.
2. Start both engines from the same UTXO state at a fixed height (load the same snapshot into each; for kernel, via Core's format).
3. Feed both the same ~1,000 mainnet blocks from disk (no network, so only validation is measured), then measure single-block wake scenarios cold and warm.
4. Record everything in this ticket under "Spike results".

### Decision criteria

- **Migrate** if kernel fits the wake budget and memory limits and its API is stable enough to pin. Payoff: exact Core consensus, and tickets 025/026 mostly disappear.
- **Stay** (Step 1 only) if cold start or memory can't fit iOS wakes, or the API is too unstable. Then 025/026 proceed as written.

## Files touched

| File | Action |
|---|---|
| `hercules-core/Cargo.toml` | Step 1: replace `bitcoinconsensus` with kernel bindings |
| `hercules-core/src/block_validation.rs`, `mempool.rs` | Step 1: script-verify call sites, explicit flag table |
| `hercules-core/patches/bitcoinconsensus/` | Step 1: remove |
| `build-ios.sh` | Step 1: build kernel for device + simulator |
| `spike/047-kernel` branch | Step 2: harness + benchmarks (not merged) |
| `tickets/047-libbitcoinkernel-migration.md` | Spike results + decision |

## Dependencies

- Step 1: none, but land after or with 027 so replay/regression tests exist.
- Step 2: none. **Run it before starting 025 and 026**, since a "migrate" result replaces most of both. 023, 024, 027 proceed regardless.

## Estimated effort

- Step 1: 3–5 days (most of it is the iOS build).
- Step 2 spike: 1–2 weeks, time-boxed.
- A full migration, if chosen, is a separate multi-week ticket.

## Open questions

- Does the Rust binding expose UTXO lookups for our mempool, and snapshot (AssumeUTXO) loading?
- Can kernel's chainstate start fast enough on a cold push wake, or does it need the process to stay alive (ticket 028's single-node host)?
- Pinning strategy for an experimental API: vendor a specific Core commit and upgrade deliberately.

## Roadmap position

Step 1 after 027. Step 2 spike in parallel with 023/024/027, **before 025/026**.
