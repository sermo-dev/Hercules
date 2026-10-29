# Ticket 026: Consensus Completeness — The Contextual Block Rules We Don't Enforce Yet

## Summary

Hercules validates scripts through libbitcoinconsensus. It also checks block structure, money, BIP34 and the witness commitment itself. A handful of **block-level** consensus rules are missing. Bitcoin Core enforces them, so on these points Hercules would accept a block that every Core node rejects.

None of the gaps can be exploited cheaply. Each one requires a block with full proof-of-work that the honest network rejects. In practice that means an attacker throws away a block reward (several BTC) to fool specific Hercules users. But Hercules' whole promise is "validates like Core". Each gap is a place where that promise is false and where Hercules could follow an invalid chain or show a payment that doesn't exist on the real network.

This ticket collects the missing rules into one module with tests for each rule.

**Severity: Medium.** Exploiting these takes PoW, but they are real divergences from consensus.


## Amendment (2026-10-24, finding from the 027 harness)

- **BIP34 heights 1–16.** Our coinbase-height check can't parse Core's encoding for heights 1–16 (`OP_1`..`OP_16`, plus `OP_0` handling). Unreachable on mainnet (BIP34 activates at 227,931) but a real divergence, and it blocks regtest fixtures that activate BIP34 at low heights. The 027 harness has an `#[ignore]`d test for it.

## Implementation (2026-10-24, branch `ticket-026-consensus-completeness`)

- **New module `contextual_checks.rs`.** These are direct ports of Core v26: `IsFinalTx`, `CalculateSequenceLocks`/`EvaluateSequenceLocks`, `GetMedianTimePast`, `GetLegacySigOpCount`/`GetP2SHSigOpCount`/`CountWitnessSigOps`/`GetTransactionSigOpCost` (with Core's own `GetScriptOp` parser), `bad-cb-length`, and the BIP34 `CScript() << nHeight` prefix check. A `HeaderTimes` trait supplies header timestamps. The header store implements it, and so do the fixture chain and plain closures.
- **`validate_block`.** Adds the coinbase length check. Legacy sigops are now counted by the ported `GetLegacySigOpCount`. BIP34 is now Core's byte-prefix comparison, so heights 1–16 work and regtest uses `bip34_height = 1` like Core. The comment that called the in-block duplicate-txid check "BIP30" is corrected.
- **`validate_block_scripts(..., times)`.** Checks finality for every tx using the MTP cutoff (BIP113), then BIP68 per tx once the spent coins are resolved, then the full sigop cost before any script runs.
- **Header rule `bad-version`** (`validate_headers`). The old BIP34 parser rejected version-1 blocks as a side effect. The new check covers that, plus Core's BIP66 and BIP65 version floors.
- **Activation heights** are now in `ChainParams`: `bip66_height`, `bip65_height` and `csv_height`. A test pins them to the script-flag table.
- **Mempool.** Finality now follows `CheckFinalTxAtTip`: it checks for the next block using the tip's MTP. Before, it allowed `nLockTime = tip+1` and compared time locks to the wall clock. BIP68 follows `CheckSequenceLocksAtTip`, with mempool parents counted at tip+1.
- **BIP30.** `BIP34_IMPLIES_BIP30_LIMIT` is documented, and a compile-time assert fails the build if the snapshot anchor reaches it. `apply_block` writes with `NO_OVERWRITE`; if an overwrite ever happens it logs an error and `debug_assert!`s.
- **Not done.**
  - A full adapter over `tx_valid.json`/`tx_invalid.json`. Those vectors exercise the script interpreter (047 Step 1 runs them), not `IsFinalTx`/`SequenceLocks`. Only the coinbase-size vectors are relevant to this ticket, and they are ported.
  - Mempool re-checking of finality/BIP68 after a reorg (Core's `removeForReorg`).
- **Mainnet check.** The ignored test `mainnet_blocks_pass_contextual_rules` (data from `tools/fetch_mainnet_context.py`) passed on blocks 972818, 972962 and 973011–973013. It used real MTP and real coin heights for 265 BIP68-constrained inputs. Zero rejections.

## Follow-up after merging main (2026-10-26)

- **024 classes for the new errors.** `BadCoinbaseLength`, `NonFinalTx`, `SequenceLockNotMet` and `ExcessiveSigopCost` are consensus failures. `MissingContext` is a local fault, so a block is never marked invalid because *we* lack header times. `VALIDATION_RULES_VERSION` is now 2, so `failed_blocks` rows recorded under v1 are reconsidered.
- **Witness commitment matches Core's `CheckWitnessMalleation`.** `validate_block` no longer calls rust-bitcoin's `Block::check_witness_commitment`, which returns true early when no transaction has witness data. Because of that early return, it accepted a commitment with an empty coinbase witness. It also never checked witnesses before SegWit. `validate_block` and `check_block_mutation` now share `check_witness_malleation`, and every failure in it counts as a mutation (bad delivery), as with Core's `BLOCK_MUTATED`.

### Review fixes (2026-10-26)

- **MTP cost.** Every block's median-time-past was 11 single-row SQLite reads, each re-preparing its statement under the store mutex (regtest has CSV from height 1, so the eclipse sync tests paid this for ~6,000 blocks). `HeaderTimes::timestamps_between` now reads the window in one cached range query. The mempool caches the tip MTP per tip header hash (`header_id_at`), so a reorg never serves a stale value. Profiling `eclipse_fork_beyond_a_full_batch_of_shared_headers_recovers`: MTP went from ~1,040 samples to ~245. Wall time is now even with main (three alternating runs each: 43.1 s branch, 44.8 s main). Its wall time is dominated by `UtxoSet::apply_block` disk I/O, which swings widely with machine load. The 60 s timeout flakes on main too under load.
- **Own timelocked txs** are `SubmitError::NotYetFinal` (`not_yet_final`; FFI `BroadcastError::NotYetFinal`), not `Consensus`. The text says the tx is not valid *yet*, names the lock, and mentions the catch-up when the UTXO set lags the headers. The lagging height-lock case is still `NotSynced`.
- **`validate_block` order.** The witness-malleation check now runs right after the merkle root, before the weight check. A copy padded with junk witness data is then a mutation, not `ExcessiveWeight`.

### Follow-ups

- **Mainnet regression over 288 blocks.** `mainnet_blocks_pass_contextual_rules` still covers 5 blocks; extend `tools/fetch_mainnet_context.py` to the last 288 as the Verification section asks.
- **`bad-version` on already-stored headers.** The new header rule applies to headers validated after the upgrade; headers stored before it never get the check. Negligible: exploiting it needs a low-version header with real PoW that was already in our store.
- **Rules version.** PR #25 also bumps `VALIDATION_RULES_VERSION` to 2; whichever lands second bumps to 3.

## Background: what we check today

`validate_block` (`hercules-core/src/block_validation.rs:62`) checks:

- the coinbase is present and first, and is the only coinbase
- the merkle root
- weight
- `MAX_MONEY`
- **legacy-only** sigops (`block_validation.rs:~120-140`)
- duplicate txids
- BIP34 height (`BIP34_HEIGHT = 227_931`)
- the witness commitment

`validate_block_scripts` (`block_validation.rs:221`) resolves prevouts, enforces coinbase maturity, runs `bitcoinconsensus::verify_with_flags` using `height_to_flags(height)`, and checks input/output value and that coinbase ≤ subsidy + fees.

The only place `nLockTime` is checked is the **mempool** (`mempool.rs:222-250`). nSequence relative locks are not checked anywhere.

## The missing rules, one at a time

### 1. Transaction finality: nLockTime (`IsFinalTx`)

- **The rule.** A transaction can set `nLockTime` to a block height (if < 500,000,000) or a Unix time. It may not appear in a block until that height or time has passed. The exception is when every input has `nSequence = 0xFFFFFFFF`, which marks the transaction as final.
- **Real-world use.**
  - Time-locked payments and inheritance setups.
  - Lightning commitment transactions.
  - Core sets `nLockTime` to the current height on every transaction it sends, as anti-fee-sniping.
- **Without it.** A block containing a not-yet-final transaction is valid to Hercules and invalid to everyone else. That transaction could be one spending a time-locked inheritance early.
- **Fix.** For every transaction in the block, check `IsFinalTx(tx, height, lock_time_cutoff)`. The cutoff is the median-time-past of the previous 11 blocks (see rule 2).

### 2. BIP113: median-time-past for time locks

- **The rule.** For time-based locks (`nLockTime`, and the time-based form of BIP68), compare against the **median of the previous 11 block timestamps**, not the block's own timestamp. Miners can skew a single timestamp but can't easily move the median.
- **Without it.** A naive check against `block.header.time` would let a miner unlock time-locked coins up to about 2 hours early. That's the future-timestamp tolerance.
- **Fix.** Pass MTP into rules 1 and 3. The header store already provides it: `store.last_timestamps(11)` is used at `sync.rs:~1575`.

### 3. BIP68: relative lock-times via nSequence

- **The rule.** Since CSV activated (height 419,328), an input's `nSequence` can say "this input can't be spent until N blocks, or N×512 seconds, after the coin it spends was confirmed". This applies when the transaction version is ≥ 2 and the disable bit is unset.
- **Real-world use.**
  - **Lightning** (`to_self_delay` on every channel's penalty path)
  - vaults
  - Liquid peg-outs
  - every miniscript `older()` policy
- **Subtle point.** libbitcoinconsensus *does* check `OP_CHECKSEQUENCEVERIFY` (BIP112), but only as "the script's required delay ≤ this input's own nSequence". It has no way to know whether the coin is actually that old, because it never sees the block height of the spent coin. The **block-level** BIP68 check enforces the age: input height + relative lock ≤ current height, or the MTP equivalent. Without it, a transaction can claim `nSequence = 144` and spend a coin confirmed one block ago, and our script check passes.
- **Without it.** We'd accept a block in which someone sweeps a Lightning channel's penalty output before the counterparty's dispute window opens.
- **Fix.** For each input, compute the lock from `nSequence` and compare it against the spent coin's height (we have `UtxoEntry.height`). For time-based locks, compare against the MTP **at the coin's confirmation height**, which needs a header-timestamp lookup by height. That already exists via `store.get_timestamp_at`.

### 4. Full signature-operation cost

- **The rule.** A block may contain at most 80,000 "sigop cost" units (`MAX_BLOCK_SIGOPS_COST`, `block_validation.rs:29`). Core's `GetTransactionSigOpCost` counts:
  - legacy sigops × 4,
  - **P2SH** redeem-script sigops × 4 (these need the prevout), and
  - **witness** sigops × 1 (P2WSH witness script, P2WPKH = 1; Taproot is excluded and has its own per-input budget).
- **Today.** Only legacy sigops are counted (`count_script_sigops` over scriptPubKeys and scriptSigs, `block_validation.rs:~110-140`).
- **Without it.** A block packed with P2SH or P2WSH multisig spends that exceeds the limit is accepted by us and rejected by Core. The limit exists to bound how expensive a block is to validate, and it is a consensus rule.
- **Fix.** Move the sigop-cost check into `validate_block_scripts`, where the prevouts are resolved. Add P2SH sigops (accurate count of the last scriptSig push as a script) and witness sigops (`count_witness_sigops`).

### 5. Coinbase scriptSig length (2–100 bytes)

- **The rule.** The coinbase input's scriptSig must be between 2 and 100 bytes.
- **Today.** There is no check. The weight test at `block_validation.rs:~1045` builds a coinbase with a scriptSig over 1 MB, and the only thing that fails it is the weight limit.
- **Fix.** Add a single check in `validate_block`. This is trivial.

### 6. BIP30: duplicate unspent txids — document, guard, don't implement yet

- **The rule.** A transaction may not have the same txid as an earlier transaction whose outputs are still unspent. This was a real problem in 2010, when two coinbases were byte-identical.
- **Why it's moot until height 1,983,702.** BIP34 put the block height in every coinbase, so coinbases at different heights can't collide. Bitcoin Core skips the BIP30 check for blocks after BIP34 activation for this reason. There is one known exception: blocks from **1,983,702** onward could in theory repeat the coinbase of an early pre-BIP34 block whose scriptSig happened to encode that height. Our snapshot starts at 943,500, so the historical BIP30 exceptions (blocks 91,842 and 91,880) are also out of scope.
- **Today.** The "BIP-30" comment at `block_validation.rs:142` is really an *intra-block* duplicate-txid check (good, but a different rule). `apply_block` uses `put`, which would silently overwrite.
- **Fix.** Fix the comment. Add `debug_assert!`/error logging in `apply_block` if a `put` would overwrite an existing outpoint. Add a constant plus a compile-time note at 1,983,702 so this decision gets revisited about 20 years from now.

## Proposed implementation

- **A new module `hercules-core/src/contextual_checks.rs`** with pure functions:
  - `check_finality(tx, height, mtp)`
  - `check_sequence_locks(tx, spent: &[UtxoEntry], height, mtp_lookup)`
  - `transaction_sigop_cost(tx, spent)`
  - `check_coinbase_script_len(tx)`
- **Call them from `validate_block_scripts`**, which already has the prevouts in hand. Also call them from `mempool::accept_tx` where relevant: BIP68 also needs to apply to mempool admission, which it doesn't today.
- **Add a parameter**: `validate_block_scripts(block, height, utxo, ctx: &BlockContext)`, where `BlockContext { mtp, timestamp_at: impl Fn(u32)->u32 }`. Callers in `sync.rs` build it from the header store.

### Tests

- **Unit tests per rule:** boundary cases for each check:
  - locktime exactly at height or MTP versus one past it
  - nSequence disable bit, type flag, and version 1 vs 2
  - sigop cost at 80,000 vs 80,001
  - scriptSig of 1, 2, 100 and 101 bytes
- **Bitcoin Core's test data.** `src/test/data/tx_valid.json` and `tx_invalid.json` include many locktime and sequence vectors. These are transaction-level, so they need a small adapter that supplies the prevouts and the height/MTP context. Uncertain: some vectors are policy rather than consensus and will need filtering by their flags column.
- **Block-level tests** use hand-built regtest blocks from ticket 027's `FixtureChain` (for example, a block that spends a CSV output one block early).

## Alternative worth evaluating: libbitcoinkernel

**Decided (2026-10-24, ticket 047):** kernel *script* verification is go (047 Step 1), but full kernel *block* validation is blocked: the API lacks UTXO lookup by outpoint, AssumeUTXO loading, pruning and explicit flush. So the block-level rules in this ticket are implemented in our Rust code, as below. Revisit when Core PRs #36630 (pruning) and #35187 (validate a block against caller-supplied UTXOs) land; the original evaluation follows.

Bitcoin Core has been extracting its validation engine as **libbitcoinkernel**, which has a C API, and community Rust bindings exist. Using it would give whole-block validation with exactly Core's semantics, including every rule above, and it would stay current with Core automatically.

Downsides:

- It brings its own chainstate and block-storage model (LevelDB, `blocks/` directory). That conflicts with our LMDB UTXO set, our HUTX snapshots and our pruning. Adopting it is closer to a rewrite of the validation layer than a dependency swap.
- It's less mature as an API, and the iOS cross-compile is unproven.

Related maintenance note: **libbitcoinconsensus** (we pin 0.106.0+26.0 under `hercules-core/patches/bitcoinconsensus`) was deprecated and removed from newer Bitcoin Core releases. Our script-validation dependency is frozen at v26 semantics. That's fine until the next soft fork (for example, any covenant or post-quantum opcode), at which point we'd need either a kernel-based path or a maintained fork.

Recommendation: implement rules 1–5 by hand now; they're small and well specified. Open a separate future ticket for a kernel evaluation, timed with the next soft fork discussion. I'm uncertain about the current state of the kernel C API and its iOS buildability; verify before scoping.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/contextual_checks.rs` | **New**: rules 1–5 plus their tests |
| `hercules-core/src/block_validation.rs` | Coinbase length check; `BlockContext` param; move sigop-cost check; fix BIP30 comment |
| `hercules-core/src/utxo.rs` | Overwrite guard in `apply_block` (rule 6) |
| `hercules-core/src/sync.rs` | Build `BlockContext` (MTP, timestamp lookup) at all three validation sites |
| `hercules-core/src/mempool.rs` | Use the shared finality/sequence-lock functions; switch the time locktime from wall-clock to MTP |
| `hercules-core/tests/core_tx_vectors.rs` | **New**: adapter over Core's `tx_valid.json` / `tx_invalid.json` |

## Dependencies

- **027** for block-level regtest fixtures. The unit tests can land first.
- Independent of 022–025.

## Estimated effort

About 3–4 days. BIP68 with time-based locks and the P2SH/witness sigop counting are the fiddly parts. The others are an hour each.

## Verification

- Each rule has a passing and a failing unit test at its exact boundary.
- Core's tx vectors, as adapted, all match Core's verdicts, except vectors marked as policy-only.
- Regtest: a block that spends a CSV(10) output 9 blocks after confirmation is rejected; at 10 it is accepted.
- Regtest: a block containing a transaction with a future height locktime is rejected.
- Mainnet regression: re-validate the last 288 blocks from `block_store` with the new checks enabled. Zero rejections expected.

## Open questions

- **Mempool time locktime.** `mempool.rs:~240` compares time-based `nLockTime` with the **wall clock**. Core uses MTP + 1 for mempool admission. Fix it here or in the mempool work? Recommendation: here, since we share the function anyway.
- **Kernel evaluation.** Should it get its own future ticket now? Recommendation: yes, a small one in `tickets/future/`.

## Roadmap position

Safety tier: **022 → 023 → 024 → 027 → 025/026**. It can run in parallel with 025 once 027's fixtures exist.

## Status (2026-10-28)

Merged in PR #26 (`1c1e0a2`), on top of the libbitcoinkernel switch (#25). `VALIDATION_RULES_VERSION` = 3.

**Follow-ups:**
- Not done: re-checking mempool finality and BIP 68 after a reorg (Core's `removeForReorg`). Belongs with ticket 025 (reorg hardening).
- `mainnet_blocks_pass_contextual_rules` is ignored and needs `tools/fetch_mainnet_context.py` data. Re-run it when the contextual rules change.
