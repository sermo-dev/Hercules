# Ticket 047: libbitcoinkernel — Replace libbitcoinconsensus, Spike Full Kernel Validation

## Decisions (2026-10-24)

- **Step 1 (script-verify swap): GO.** Kernel's script verification builds for iOS device + simulator (with a small `build.rs` patch), matched our current engine on all 1,462 cases with 0 differences, is faster on full mainnet blocks, and adds ~0.14 MB. It must fully replace `bitcoinconsensus` in one change: the two libraries share ~230 identically named symbols from different Core versions and the linker silently picks one. Pin an exact Core commit.
- **Step 2 (full kernel validation): BLOCKED.** The kernel API currently lacks UTXO lookup by outpoint (needed by our mempool), AssumeUTXO snapshot loading, pruning, and an explicit flush. Revisit when Core PR #36630 (pruning) and #35187 (validate a block against caller-supplied UTXOs; possibly the best long-term path) land.
- **Tickets 025 and 026 are released from the hold** and proceed as written.
- Spike branch: `spike/047-kernel` (commits `fc6eab4`, `47d654b`; not merged). Device harness for on-iPhone numbers: `spike/KernelSpikeHarness` on that branch.

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

## Spike results (2026-10-24)

Branch `spike/047-kernel` (throwaway, never merge). Code: `spike/kernel-spike/` (Rust crate: benches, Step-1 comparison), `spike/KernelSpikeHarness/` (minimal iOS app for owner-run device numbers). Third-party sources live in gitignored `spike-deps/`.

**Where the numbers come from.** Every number below was measured on a MacBook (Apple M2, 8 cores, macOS 26.3, Xcode 26.3 / iphoneos SDK 26.2), either natively or in the iOS Simulator (iPhone 17 Pro, which runs arm64 code on the Mac's CPU). **None were measured on an iPhone.** "Verified" means I ran it. "Inferred" means it comes from reading source or docs.

### 1. Versions and API status (verified from source)

| Item | Value |
|---|---|
| First Core release with `src/kernel/bitcoinkernel.h` | **v31.0** (tag 2026-04-15, `6574cb40869b`). C API PR bitcoin/bitcoin#30595 merged 2025-11-04 (`4da01123df0f`). Not in v30.x. |
| Latest release | v32.0 (tag 2026-10-21, `465dde277447`). |
| Stability | The header in both v31.0 and v32.0 says: *"unversioned and not stable yet. Users should expect breaking changes. It is also not yet included in releases of Bitcoin Core."* `BUILD_KERNEL_LIB` is `OFF` by default and labelled "experimental". Release notes for v31.0/v32.0 do not mention it. |
| API churn | v31.0 has 116 `btck_*` functions; v32.0 has 136 (+20, none removed). Master (2026-10-23) has already **removed 5 logging functions** after v32.0 (#34374, a breaking change). The open PRs that matter to us (prune target #36630, external-UTXO block validation #35187, new block-tree store #32427) all change the API or on-disk format. |
| Rust crate | `bitcoinkernel` 0.3.2 / `libbitcoinkernel-sys` 0.4.1 (2026-10-06, repo sedited/rust-bitcoinkernel `f27eff2051e4`). It vendors Core as a git subtree at **`70d9ec7f3d45`** (master of 2026-07-14, version 31.99, so pre-v32). It builds Core with cmake from `build.rs`, which needs cmake and Boost headers. 0.2→0.3 changed public signatures. |

**What the C API exposes (v32.0 / crate 0.3.2):**
- Script verification: `btck_script_pubkey_verify` + `btck_PrecomputedTransactionData`, using the same 7 consensus flags with **the same bit values** as libbitcoinconsensus.
- Context-free checks: `btck_block_check` (size, weight, merkle, PoW, sigops), `btck_transaction_check`.
- Chainstate manager: `process_block` (full Core validation, connect, ActivateBestChain), `process_block_header`, `import_blocks` (reindex), active chain / block-tree iteration, and reading block and undo (spent-output) data back from disk.
- Options: data/blocks dirs, worker threads, wipe DBs, in-memory DBs. **dbcache** is in v32.0 (`set_database_cache_bytes`) but not in the crate's subtree, so the crate is fixed at Core's default of **450 MiB**.
- Callbacks: block tip, header tip, progress, warnings, flush/fatal errors, and validation-interface `block_checked`, `pow_valid_block`, **`block_connected`, `block_disconnected`** (each hands over the full block).
- **Missing, which answers the ticket's open questions:**
  - No UTXO / coin lookup by outpoint. The only `btck_Coin` access is through a block's undo data.
  - No AssumeUTXO snapshot loading or creation.
  - No prune option (open PR #36630, created 2026-10-23).
  - No explicit flush. State is flushed only by Core's periodic or cache-full policy, or when the chainstate manager is destroyed.
  - No mempool.
  - No VerifyDB depth setting: open always runs `VerifyLoadedChainstate` with Core's defaults (6 blocks, level 3).

### 2. Builds

| Build | Result |
|---|---|
| macOS host (aarch64-apple-darwin), crate as-is | ✅ Builds in ~50 s. **All 452 crate tests pass** (283 unit, 26 integration, 143 doc). Needs `brew install cmake boost` (cmake 4.4.4, boost 1.92.0). |
| iOS device / sim, crate as-is | ⚠️ **Silently wrong.** `build.rs` passes no cross-compile flags for `ios`, so cmake builds a **macOS** `libbitcoinkernel.a` (`LC_BUILD_VERSION platform 1`). `cargo build --lib` still "succeeds"; the error only shows up when the final binary links. |
| iOS device `aarch64-apple-ios`, patched | ✅ With `spike/kernel-spike/build-rs-ios.patch` (adds `-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0 -DCMAKE_FIND_ROOT_PATH_MODE_{PACKAGE,INCLUDE}=BOTH`, plus `BOOST_ROOT`). The output has platform 2 (iOS), minos 17.0. The linked executables and a Release `.app` build. No Core source patches were needed. The only compiler warning was a harmless `-Wundef` (`HAVE_SYSTEM`). |
| iOS simulator `aarch64-apple-ios-sim`, patched | ✅ Same patch with `iphonesimulator` (platform 7). Every bench and the Step-1 run **execute correctly in the simulator** (`xcrun simctl spawn`), as does the harness app. |
| Harness app (`spike/KernelSpikeHarness`, xcodegen) | ✅ Builds for simulator and for `generic/platform=iOS` (unsigned). Runs in the simulator with `-autorun`. |

Exact commands: `BOOST_ROOT=$(brew --prefix boost) IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build --release --target aarch64-apple-ios[-sim] --no-default-features --features kernel`, run in `spike/kernel-spike` (or `spike/KernelSpikeHarness/build-lib.sh`). One kernel cmake build takes about 40 s per target on the M2. The `.a` is 75 MB because `build.rs` uses RelWithDebInfo; the linked size is what matters (below).

**🚩 Link conflict (verified):** `libbitcoinkernel.a` and our `libbitcoinconsensus.a` define **230 identical global symbols** (for example `SignatureHashSchnorr<CTransaction>`, `CSHA256`/`CRIPEMD160`, secp256k1 helpers, `CastToBool`) compiled from different Core versions. They link without any error, and the linker quietly picks one copy for both libraries. That is an ODR violation: one library can end up calling the other version's code. Consequences:
- Kernel and bitcoinconsensus can never ship in the same binary, so there is no "shadow-verify with both" transition. Step 1 has to be a clean swap.
- The spike runs each engine in a separate binary (`compile_error!` if both features are enabled) and compares outputs across processes.

### 3. Step 1 check: identical results (verified)

`spike/kernel-spike/run-step1.sh` builds `verify-dump` twice, once linking kernel only and once linking our patched bitcoinconsensus v26 only. It runs the same cases through both with the same flags and diffs every input's outcome:

| Case set | Cases | Result |
|---|---|---|
| `block_validation.rs` Taproot fixture (block 709635 key-path spend): valid, corrupted Schnorr sig, wrong spent amount, and all 7 historical mainnet flag eras (`height_to_flags`) | 10 | identical |
| Core `script_tests.json` (built like Core's `BuildCreditingTransaction`/`BuildSpendingTransaction`; 5 skipped that need `#SCRIPT#`/`#CONTROLBLOCK#` taproot builders) | 1,217 | identical |
| Core `tx_valid.json` / `tx_invalid.json` (2 + 4 skipped: coinbase or unparsable) | 119 + 89 | identical |
| Every tx of the 206-block regtest fixture, spent outputs read back from kernel undo data | 25 txs / 26 inputs | identical |
| **Mainnet block 972818** (6,358 txs) and **972962** (6,848 txs), all prevouts fetched from mempool.space (`tools/fetch_mainnet_block.py`) | 15,495 inputs | identical, all valid |

- **Total: 1,462 cases, 0 differences, 0 results that disagree with Core's expected result.**
- This holds on the Mac and again in the iOS Simulator.
- Policy-only flags (STRICTENC, LOW_S, …) aren't exposed by either library. Vectors that depend on them are compared library-to-library only, not against Core's expected result.

Single-threaded script verification of a full mainnet block, median of 5 runs:

| Block | Kernel (Mac) | bitcoinconsensus v26 (Mac) | Kernel (Simulator) | bitcoinconsensus v26 (Simulator) |
|---|---|---|---|---|
| 972818 (7,687 inputs) | 215 ms | 338 ms | 216 ms | 340 ms |
| 972962 (7,808 inputs) | 208 ms | 276 ms | 210 ms | 275 ms |

Kernel is 25–37% faster here. The likely reason (inferred) is that our call pattern makes libbitcoinconsensus deserialize the tx and rebuild `PrecomputedTransactionData` for **every input**, while kernel builds it once per tx. Core's `Block::check` on 972962 (1.6 MB) takes 0.9 ms, and parsing the block 4.6 ms.

### 4. Benchmarks (Mac and Simulator only)

**Binary size delta, iOS device, Release, stripped (verified):**

| Build | Size | Delta vs bitcoinconsensus | gzip -9 |
|---|---|---|---|
| CLI `verify-dump`, bitcoinconsensus v26 | 1.80 MB | — | 1.42 MB |
| CLI `verify-dump`, kernel (script verify only, dead-stripped) | 1.94 MB | **+0.14 MB** | 1.48 MB |
| Harness `.app` executable, bitcoinconsensus | 1.87 MB | — | 1.44 MB |
| Harness `.app` executable, full kernel (chainstate manager, LevelDB, validation) | 3.30 MB | **+1.43 MB** | 2.06 MB (+0.62 MB) |

Both are far under the ~20 MB flag.

**Chainstate (regtest; Core's 206-block fixture plus a generated chain):**

| Metric | Mac | Simulator |
|---|---|---|
| Context create | 1.3 ms | 1.3 ms |
| Fresh chainstate create (empty dirs) | 31 ms | 38–40 ms |
| Reopen of the 206-block chainstate, same process, median of 10 (LoadChainstate + VerifyDB + ActivateBestChains) | 28 ms | 30–38 ms |
| Reopen in a fresh process (`kernel-bench open`), 5 runs | 24–66 ms (whole process 0.13–0.40 s) | 27–33 ms |
| Destroy (= forced flush) | 6–12 ms | 6–12 ms |
| `process_block`, 206 tiny regtest blocks, median / p90 / max | 0.08 / 0.10 / 1.3 ms | 0.13 / 0.14–0.34 / 3–4.6 ms |
| phys_footprint after connecting 206 blocks | 35 MB | 44 MB |
| `block_connected` callbacks | 207 (genesis + 206) | 207 |

**Mainnet-sized block index: attempted, not obtained (time-boxed).** `kernel-bench gen` mines empty regtest blocks to build a 972k-entry block index, so cold open could be timed at mainnet scale.
- It reached only 100k blocks in 15 min, at ~9 ms per block and getting slower. The cause (verified in source) is that regtest chainparams set `fDefaultConsistencyChecks = true`, so Core runs the O(n) `CheckBlockIndex` on every block, and the C API has no option to turn it off.
- I stopped the run. The mainnet numbers for block-index load time and memory are still open and need a real mainnet datadir.
- Regtest `process_block` numbers above include this check, which is small at 206 blocks.


**Kill mid-write, then relaunch (verified, Mac and Simulator).** `kernel-bench killtest` starts a writer process that connects regtest blocks, `SIGKILL`s it 150–627 ms in, then reopens the chainstate.
- 16 of 16 kills recovered with **no corruption**: the chainstate reopened in 19–46 ms and resynced to the tip.
- But **every block connected since the last flush was lost**. For example, the writer had connected 168 blocks and the chainstate reopened at height 0.
- Core flushes coins and the block index only periodically, when the cache is full, or on destroy, and the C API has no flush call. On iOS that means every wake must end with `btck_chainstate_manager_destroy` (a forced flush). Otherwise a jetsam or kill throws away the wake's work.
- What this does to cold opens is covered under the open-question answers in section 5.

**Not measured (owner, on a device):**
- Every iPhone number.
- Mainnet chainstate cold open with a real ~10 GB coins DB.
- 1,000-block mainnet throughput.
- Peak memory under catch-up with the 450 MiB default dbcache.
- Pruned disk footprint (not possible: no prune API).
- Locked-phone wake with file protection.
- Snapshot load time (not possible: no snapshot API).

There is no mainnet chainstate on this Mac. Building one needs a full IBD, which kernel can't shortcut without the snapshot API.

### 5. API gaps vs the ticket's open questions

| Question | Answer |
|---|---|
| UTXO lookups for our mempool? | **No** (verified: no outpoint→coin function in v32.0 or master). Mempool would need its own UTXO index (a second UTXO set on the phone), or a local patch exposing a `CoinsTip()` lookup under `cs_main`. Open PR #35187 goes the *other* way: Core validates a block against coins **we** supply through a callback. That would let us keep our LMDB UTXO set and get Core's exact `ConnectBlock` rules, a promising middle path, but it is unmerged. |
| AssumeUTXO snapshot loading? | **No** (verified: no snapshot functions; no open PR found). Inferred: even with a patch, Core's AssumeUTXO always starts a background chainstate that validates from genesis, which a phone can't do. We would have to patch that off, which is exactly the "trusted snapshot" model we already run with HUTX. Ticket 032 does not get simpler. |
| Block-connected notifications for the wallet scanner? | **Yes** (verified): `block_connected` / `block_disconnected` deliver the full block plus its block-tree entry. Spent outputs come from `read_spent_outputs`. |
| Pruning? | **No** (verified). PR #36630 (opened 2026-10-23) adds `set_prune_target`. Without it kernel keeps every block file, which is disqualifying on a phone. |
| Cold start fast enough for a push wake? | Fixed costs are small: open ~30 ms on a small chainstate, library init ~1 ms. Mainnet block-index load is not measured: Core loads the whole block index (~970k entries) into RAM at open, a cost that grows with chain height (inferred from Core's design; magnitude not measured here). Inferred: mainnet adds VerifyDB (re-reads and disconnects the last 6 full blocks at level 3, with no API to lower that) plus LevelDB page-ins on the 10 GB coins DB. **Needs device measurement.** Also, because nothing is flushed until destroy, the process can't just be left alive between wakes and killed safely. Every wake either pays open + destroy, or the process must be kept alive and flushed deliberately (ticket 028). |
| Pinning strategy | Required. The header is explicitly unstable, master already broke the v32.0 API, and the crate trails Core by months (its subtree predates v32.0, so it has no dbcache setter). We would vendor a specific Core commit plus our own build patch and treat every bump as a project. |

### 6. Risks
- **API instability.** The API is officially unversioned and broke within days of v32.0. The crate lags Core. We would carry local patches for: the iOS build, prune, coin lookup, flush, snapshot, and VerifyDB depth.
- **ODR conflict.** Kernel can't coexist with libbitcoinconsensus, or with any other library that embeds Core code, in one binary. Step 1 has to be a single clean swap.
- **Memory.** Default dbcache is 450 MiB and the crate can't change it without a crate update. The block index is held in RAM: ~970k `CBlockIndex` entries, order of 100+ MB (inferred, not measured). Background jetsam limits are much lower than foreground.
- **Disk.** No pruning means unbounded disk use. No snapshot means first install is a full IBD.
- **Durability.** No explicit flush; lose-since-last-flush behaviour (verified above). It is safe from corruption but wasteful on iOS.
- **Build.** Needs cmake and Boost (headers only) on dev and CI machines, plus our `build.rs` patch. There are no Core source patches today.

### 7. Provisional recommendation

**Step-1-only now. Full migration is blocked as of v32.0. Confidence: high for Step 1, medium-high for "blocked".**

- **Step 1 (script verify swap): go.**
  - It builds for device and simulator with a small `build.rs` patch.
  - It gave byte-for-byte identical results on 1,462 cases, including 15.5k real mainnet inputs.
  - It is ~25–37% faster on our call pattern and costs +0.14 MB.
  - Notes for implementation: vendor a pinned Core commit, upstream or keep the iOS `build.rs` patch, use one `PrecomputedTransactionData` per tx, and remove `bitcoinconsensus` completely (ODR).
- **Step 2 (full kernel): blocked.** Today's API can't prune, can't load a snapshot, can't look up a coin for the mempool, and can't flush on demand. Each of those is a hard requirement for Hercules.
  - Revisit when #36630 (prune) and #35187 (external-UTXO block validation) land.
  - #35187 in particular may give a better hybrid than full migration: Core's full block rules (tickets 025/026 mostly solved) against our own UTXO store and snapshot format.
  - Until then, 025/026 should proceed as written, perhaps after checking whether #35187 is close to merging.
- **What would change this:** device numbers showing that even the fixed costs don't fit a push wake (unlikely, given the simulator numbers), or upstream adding prune + coin lookup + snapshot load in one release.

### 8. Reproduce / owner device run

```sh
# deps (dev tools only)
brew install cmake boost xcodegen
mkdir -p spike-deps && git clone https://github.com/sedited/rust-bitcoinkernel spike-deps/rust-bitcoinkernel
git -C spike-deps/rust-bitcoinkernel checkout f27eff2051e4e4d153b65fc7273c9a05dcd673fe   # v0.3.2
git -C spike-deps/rust-bitcoinkernel apply ../../spike/kernel-spike/build-rs-ios.patch

# optional: real mainnet blocks for the script-verify bench (~3.5 MB each, gitignored)
python3 -I spike/kernel-spike/tools/fetch_mainnet_block.py tip-6 spike/kernel-spike/testdata

# Step 1 comparison (Mac)
spike/kernel-spike/run-step1.sh
# Chainstate benches / kill test (Mac)
cd spike/kernel-spike && cargo run --release --bin kernel-bench -- run /tmp/ks && cargo run --release --bin kernel-bench -- killtest /tmp/ks 10
```

**On an iPhone (owner):**
1. `cd spike/KernelSpikeHarness && ./build-lib.sh && xcodegen generate && open KernelSpikeHarness.xcodeproj`
2. Set your Team under Signing, choose the phone, and pick the **Release** configuration in Edit Scheme → Run.
3. Run. Tap **Chainstate bench** and then **Script verify bench**. Results go to the Xcode console as `KERNEL_SPIKE …` lines and to `Documents/kernel-spike-results.txt` (Devices window → Download Container).
4. For a cold-launch number, add launch argument `-autorun` in the scheme. The app then runs both benches before the first frame, and `started_ms_after_launch` covers dyld and static init.
5. For our engine's numbers on the same phone, run `ENGINE=consensus ./build-lib.sh`, rebuild, and run "Script verify bench" again.
6. Paste the JSON lines into this ticket.

The harness only covers the regtest chainstate and script verification. Mainnet chainstate numbers need a synced kernel datadir, and kernel can't produce one on a phone (no snapshot, no prune).
