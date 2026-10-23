# Ticket 023: Chain Anchoring — Bind the Snapshot to the Chain, Add a Minimum-Work Floor

## Summary

Hercules has two trust anchors, and neither is fully connected to the chain it actually follows:

1. **The AssumeUTXO snapshot.** The contents of the snapshot are verified, but the file's own header (its `height` and `block_hash`) is not. Nothing checks that the snapshot's block is actually in our header chain at that height.
2. **Header sync has no minimum-work floor.** A freshly installed node that is eclipsed can be handed a cheap, low-difficulty header chain, and it has no way to tell that chain is fake.

This ticket closes both gaps. Part A binds the snapshot header to compiled-in constants and to the header chain. Part B adds an `nMinimumChainWork`-style floor and an anchor-block requirement to header sync.

**Severity: High.**

## Background

### Part A: the snapshot header is unauthenticated

`UtxoSet::load_snapshot` (`hercules-core/src/utxo.rs:~700-760`) reads the HUTX header in this order: magic, version, `height` (u32), `block_hash` (32 bytes), `utxo_count`, `file_hash`. Then:

- `file_hash` is compared to `expected_hash`, which is `ASSUMEUTXO_HASH`, passed from `lib.rs:401`.
- The streaming hasher (`utxo.rs:~819-882`) covers **only the entries**: txid, vout, amount, script, entry height, coinbase flag. The comparison `loaded_hash != file_hash` happens at `utxo.rs:~931`.
- The `height` from the header is written as `META_KEY_ASSUME_VALID_FLOOR` (`utxo.rs:~948`). `HeaderSync::load_snapshot` (`sync.rs:485`) then calls `set_validated_height(meta.height)`.
- The `block_hash` from the header is read and then discarded.

In `assumeutxo.rs`, `ASSUMEUTXO_HEIGHT` (943,500) and `ASSUMEUTXO_BLOCK_HASH` appear only in the module's own unit tests (`assumeutxo.rs:50`). No production code reads them.

The doc comment on `ASSUMEUTXO_HASH` says the hash is "recomputed during insertion to detect tampering of either the body or the header". That claim is wrong for the header.

**Consequence:** someone who edits only the `height` field leaves both hashes valid. The node then sets `validated_height` to the wrong value:

- If the height is set too high, the node silently skips blocks. Their spends are never applied, so coins that were already spent remain in the set.
- If it is set too low, the node replays blocks against a UTXO set that already includes them. Those blocks then fail with missing-input errors, or worse.

This is exploitable by anyone who controls the download (the R2 URL, a mirror, or a MITM if TLS pinning is ever relaxed). They don't need any mining power.

### Part B: no minimum chainwork, so a fresh node can be eclipsed

Header validation (`validation.rs:17`) checks linkage, retargeting, PoW against the declared bits, MTP, and the 2-hour future limit. It does not check the following:

- **Minimum total work.** Bitcoin Core rejects any header chain below `nMinimumChainWork` until it is synced. Hercules has no equivalent.
- **Checkpoint or anchor block.** Nothing requires that the chain contain `ASSUMEUTXO_BLOCK_HASH` at 943,500.

The header cross-check (`cross_check_headers`, `sync.rs:712`) only compares the **first** hash of each batch against one witness peer. It accepts the batch when:

- only one peer is connected (`sync.rs:~722`), or
- the witness fails to respond (`sync.rs:~735`).

**Attack:** a fresh install whose Tor or clearnet peers are all controlled by an attacker can be fed a chain of about 943k headers that obeys the retarget rules but sits at minimum difficulty. Producing it costs a few CPU-hours. The node would accept it as the tip and then try to validate snapshot-era blocks against it. Even with Part A in place, an attacker-chosen chain should never reach the snapshot-loading step.

### How this relates to earlier tickets

- **017** added MuHash (displayed for out-of-band comparison) and the forward-validated counter. That makes the *UTXO contents* auditable. This ticket makes the *position* of the snapshot on the chain verifiable.
- **016** cross-checks the header tip on each wake. That helps once synced, but doesn't help on first sync.

## Proposed fix

### Part A: snapshot binding

1. **Check the header fields against the constants.** In `UtxoSet::load_snapshot`, take an `expected: SnapshotAnchor { height, block_hash, utxo_hash }` and reject the file if `height != expected.height` or `block_hash != expected.block_hash`. Do this **before** writing the crash marker, so a rejected file never touches the database.
2. **Bind the anchor to the header chain.** In `HeaderSync::load_snapshot` (`sync.rs:461`), before calling `set_validated_height`, require that `store.get_hash_at_height(ASSUMEUTXO_HEIGHT) == ASSUMEUTXO_BLOCK_HASH`.
   - If headers haven't reached that height yet, refuse and return a "sync headers first" error.
   - The Swift flow already syncs headers before offering the snapshot. Confirm that and make it an explicit precondition.
3. **Protect the anchor during reorgs.** Never accept a reorg whose fork point is at or below `ASSUMEUTXO_HEIGHT`. This complements the existing `assume_valid_floor` rollback guard.
4. **Version bump for the format (v2).** Include `height` and `block_hash` in the hashed preimage, so the file is self-authenticating. Keep v1 loading accepted for the current snapshot until ticket 032's pipeline publishes a v2 file. Coordinate with **032**, whose signed manifest commits to `(height, block_hash, utxo_hash, muhash)`.
5. **Fix the misleading doc comment** on `ASSUMEUTXO_HASH`.

### Part B: header-sync anchor

1. **Add a `MIN_CHAIN_WORK` constant** (a 32-byte u256, updated with each release, the same way Core updates `nMinimumChainWork`). Until the stored chain's cumulative work exceeds it:
   - the node is in "header sync" state, never "synced",
   - `validate_latest_block` / `catch_up_blocks` don't run block validation,
   - snapshot load is refused.

   Cumulative work can be computed incrementally. `chainwork_for_headers` already exists at `validation.rs:409`, so store the running chainwork per header in `store.rs`.
2. **Require the anchor block.** Any header chain that passes height `ASSUMEUTXO_HEIGHT` must have `ASSUMEUTXO_BLOCK_HASH` at that height. A header batch that conflicts with it is treated as misbehavior and the peer is banned.
3. **Tighten the cross-check during initial sync.** During first sync only, reject a batch (and retry) when the witness doesn't respond, instead of accepting it. While below `MIN_CHAIN_WORK`, require at least two distinct peers to agree. Steady-state behavior is unchanged.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/assumeutxo.rs` | `SnapshotAnchor` struct; `MIN_CHAIN_WORK` constant; fix doc comment |
| `hercules-core/src/utxo.rs` | Validate header height/hash against the anchor before writing anything; HUTX v2 preimage includes header fields |
| `hercules-core/src/sync.rs` | Anchor-in-chain precondition in `load_snapshot`; min-work gating; stricter IBD cross-check; reject reorgs at or below the anchor |
| `hercules-core/src/store.rs` | Persist cumulative chainwork per header (or the tip's running total) |
| `hercules-core/src/validation.rs` | Reuse `chainwork_for_headers`; add an anchor check helper |
| `hercules-core/src/bin/convert_snapshot.rs` | Emit HUTX v2 (hash covers the header) |
| `HerculesApp/HerculesApp/ContentView.swift` | Show a "Verifying chain work…" state while below min work |

## Dependencies

- None to start Part A.
- **032 (snapshot publishing pipeline)** owns where new anchors come from (v2 format, signed manifest). The two tickets should agree on the v2 header layout.
- **027** for end-to-end tests of the eclipse scenario. Regtest needs its own `MIN_CHAIN_WORK` (zero) via `ChainParams`.

## Estimated effort

- Part A: about 1 day.
- Part B: about 2 days (chainwork persistence, gating, tests).

## Verification

- A tampered snapshot with `height` changed (entries untouched) is rejected before the database is touched. Test with an in-memory HUTX fixture.
- A tampered snapshot with `block_hash` changed is rejected.
- Snapshot load before headers reach 943,500 returns "sync headers first", and `validated_height` is unchanged.
- A header chain with a different hash at 943,500 is rejected and the peer is penalized (027 harness, regtest anchor).
- A low-work header chain from a single peer never reaches the "synced" state (027 harness with regtest `MIN_CHAIN_WORK` set above the fixture's work).
- A reorg proposing a fork at or below the anchor height is refused.
- Regression: a normal first launch on mainnet still syncs headers, loads the snapshot, and validates forward.

## Open questions

- **Where the `MIN_CHAIN_WORK` value comes from.** Take it from Bitcoin Core's `chainparams.cpp` for the release nearest our build, or compute it from our own anchor block. Recommendation: use the chainwork at `ASSUMEUTXO_HEIGHT`. It's self-consistent and gets updated in the same release step as the anchor (032).
- **Accepting v1 snapshots.** Once 032 ships v2, drop v1 support entirely. Users who haven't loaded a snapshot yet would download the new one anyway.
- **Hardcoding vs. a signed manifest.** If 032 moves to frequently refreshed snapshots, the anchor can't be a compiled constant. This ticket assumes compiled constants. See 032's trust discussion.

## Roadmap position

This is safety tier step 2: **022 → 023 → 024 → 027 → 025/026**. Part A can ship in the same week as 022. Part B pairs naturally with 027, because a fake low-work chain is the first thing the harness should simulate.
