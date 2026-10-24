# Ticket 034: Wallet Engine — Library Stack (No BDK)

## Status

**Complete (2026-10-24).** Spike passed on branch `spike/034-wallet-stack` (commit `aa65188`, not merged; prototype crate at `spikes/wallet-engine/`). The no-BDK stack is adopted. Regtest end-to-end verification (mempool acceptance + mining against `bitcoind`) is deferred to `future/048-wallet-regtest-verification.md`.

## Decisions (2026-10-24)

- **Decided: no BDK.** The wallet is our own, built directly on the same Rust libraries BDK itself is built on. This reaffirms ticket 020's original decision (`020-in-app-wallet.md:256`).
- **Decided: the wallet does not hand-roll cryptography or script logic.** Every money-critical primitive comes from a widely used library. The only code we write is wallet *state* (which coins are ours, labels, history) and a port of Bitcoin Core's coin selection algorithms, tested against Core's own test cases.
- Watching / coin discovery is ticket 035 (our own scanner, same model as Bitcoin Core's built-in wallet).

## Summary

Pin down exactly which code builds, signs, and tracks transactions in the in-app wallet, and prove the stack end-to-end on regtest before ticket 035+ build on it. The output is a short decision record in this file plus a throwaway prototype, not production code.

## Background

### Why not Bitcoin Core's wallet code directly

Bitcoin Core's wallet (coin selection, fee/change, signing) lives inside `bitcoind`'s C++ wallet module. It is **not shipped as a library**:
- `libbitcoinconsensus` (which Hercules uses for script verification, v26.0 via patches) only verifies scripts, and it was removed from Core in v28.
- `libbitcoinkernel`, Core's library effort, deliberately covers validation only, not the wallet.

So Core's wallet can't be linked in. What we *can* do is port its **coin selection algorithms** (well documented, with extensive unit tests) to Rust.

"libbitcoin" is an unrelated C++ project, not part of Bitcoin Core. It has a much smaller user base and would need C++ FFI. Not recommended.

### "Legacy" terminology

- **Legacy addresses** (`1…`, P2PKH): fully supported by this stack. `rust-bitcoin` computes legacy sighashes; `miniscript` handles `pkh()` descriptors. Bitcoin Core also still signs them (`pkh()` descriptors).
- **Legacy wallets** in Core means the old BDB wallet *file format*, removed from Core in favor of descriptor wallets. Irrelevant to us; we are descriptor-based from day one.

The real limitation for legacy *spends* is **data, not library support**. Signing a legacy (non-segwit) input, or giving a PSBT to most hardware wallets, needs the full previous transaction. Coins found by the UTXO-set walk (035) only have `(outpoint, value, scriptPubKey, height, coinbase)`. Bitcoin Core on a pruned node has the same limitation: it can't rescan pruned blocks either. Fix, owned by 035:
1. Going forward, the scanner stores the full funding transaction for every wallet coin it sees in a block.
2. For pre-snapshot coins that need a parent tx, fetch that single historical block (height is in the UTXO entry) from an archival peer, verify it against our own header chain and merkle root, and extract the tx. Trustless; no server.

Native segwit (BIP84) and Taproot (BIP86) spends from our own hot wallet need only `witness_utxo` (amount + script), which the UTXO set already provides.

## The stack

| Concern | Library | Notes |
|---|---|---|
| Keys, BIP32 derivation, addresses, scripts, sighash, PSBT | `bitcoin` (rust-bitcoin, already a dependency at 0.32) | Same crate Hercules already uses for consensus data |
| ECDSA / Schnorr signing | `secp256k1` (libsecp256k1 bindings, transitive via `bitcoin`) | The same C library Bitcoin Core uses |
| Descriptors → scripts, satisfaction, PSBT finalization | `miniscript` (rust-miniscript) | Canonical Rust descriptor implementation |
| Mnemonics, BIP39 passphrases | `bip39` | Small, widely used |
| Coin selection | **Our port of Bitcoin Core's algorithms** (BnB, CoinGrinder, Knapsack, SRD + waste metric) | Port Core's `coinselector_tests` cases as Rust tests; diff behavior against Core on regtest |
| Fee / change / dust | Ours, on top of the above | Small; tested against Core regtest via `walletcreatefundedpsbt` comparisons |
| Silent payments (043) | Evaluate `rust-silentpayments`; otherwise implement against BIP352's official test vectors | Maturity **unverified** |

## Spike plan

1. Derive BIP84 and BIP86 addresses from the official BIP test-vector mnemonics; match byte-for-byte.
2. Build a PSBT spending a coin known only from `(outpoint, value, scriptPubKey)` (no parent tx), sign with `secp256k1`, finalize with `miniscript`, broadcast to `bitcoind -regtest`, confirm it mines.
3. Same for a P2PKH input with the parent tx supplied (proves the legacy path).
4. Port BnB + one fallback algorithm from Core with a handful of Core's test cases; check selected sets match.
5. Measure iOS static-lib size delta.

## Files touched

| File | Action |
|---|---|
| `tickets/034-wallet-engine-selection.md` | Record spike results (crates + pinned versions, size delta, gaps) |
| `spikes/wallet-engine/` (throwaway, not merged to main) | Prototype crate |
| `tickets/020-in-app-wallet.md` | Point its engine section here |
| `README.md` | Remove "Wallet API: BDK (future)" (handled by 044) |

## Dependencies

None. Can run in parallel with the node-safety tier (023–027).

## Estimated effort

2–4 days for the spike. The production coin-selection port is roughly 1 week including test porting, and lands with the send flow (020 Phase 2).

## Verification

- BIP84/BIP86 test vectors match exactly
- Regtest `bitcoind` accepts and mines the segwit spend built without a parent tx, and the legacy spend built with one
- Ported coin-selection tests pass and agree with Core on the sampled cases

## Open questions

- **Which Core coin-selection algorithms to port first.** Recommendation: BnB (changeless) + CoinGrinder or Knapsack fallback; SRD later.
- **Hardware-wallet PSBTs (020 Phase 3):** confirm which signers require `non_witness_utxo` even for segwit, and therefore when the historical-block fetch above is needed.

## Roadmap position

First wallet ticket: **034 → 035 → 036 (design) → 037 → …**. Touches no node code.

## Spike results (2026-10-24)

Branch `spike/034-wallet-stack` (throwaway, never merged). Crate: `spikes/wallet-engine/` (standalone `[workspace]`, not part of hercules-core's build). `cargo test`: **18 passed, 0 failed** (3 BIP vectors, 7 spend, 6 Core coin-selection ports, 2 select-then-spend).

### Pinned crates

| Crate | Version | Notes |
|---|---|---|
| `bitcoin` | 0.32.8 | Same version as `hercules-core/Cargo.lock` |
| `secp256k1` / `secp256k1-sys` | 0.29.1 / 0.10.1 | Transitive via `bitcoin`, same as hercules-core |
| `miniscript` | 13.2.0 | Latest. Built on `bitcoin` 0.32, so there is one copy of every rust-bitcoin type |
| `bip39` | 2.2.2 | Shares `bitcoin_hashes` 0.14 with `bitcoin` 0.32. 3.0.0 exists, but 2.2.x avoids a second hashes version |
| New transitive crates | `hex-conservative` 1.3.0 (a second major alongside 0.2.2, via miniscript), `unicode-normalization` 0.1.26 + `tinyvec` (via bip39) | Everything else is already in hercules-core's lockfile |
| Test-only | `bitcoinconsensus` 0.106.0+26.0 via hercules-core's `patches/` | Independent script verifier |

### What passed

1. **BIP84/BIP86 vectors match exactly** (`tests/bip_vectors.rs`). The vectors are copied verbatim from bitcoin/bips @ `24e96e870fffaa257b465ce1f0370c14aac588e8`. The test chain is bip39 mnemonic → seed → BIP32 master → miniscript `wpkh([fp/84'/0'/0']xpub/<0;1>/*)` / `tr([fp/86'/0'/0']xpub/…)`. Matched values:
   - BIP84 root and account zprv/zpub. These are re-encoded with SLIP-132 version bytes; the key material is unchanged.
   - BIP84 WIF, pubkey and address for 0/0, 0/1 and 1/0.
   - BIP86 root and account xprv/xpub, plus per-address xprv/xpub, internal key, output key, scriptPubKey and address for 0/0, 0/1 and 1/0.
   - A `pkh()` (BIP44) cross-check: the descriptor address equals rust-bitcoin's `Address::p2pkh`.
2. **P2WPKH spend from `(outpoint, value, scriptPubKey)` only.** The PSBT has no `non_witness_utxo` anywhere. The flow is: `miniscript::PsbtExt::update_input_with_descriptor` fills key origins, `bitcoin::Psbt::sign(&master)` signs (ECDSA via libsecp256k1), `PsbtExt::finalize_mut` finalizes (it also runs miniscript's interpreter check), then `extract_tx`. The **P2TR key-path** spend uses the same flow with a 64-byte BIP340 sig (SIGHASH_DEFAULT).
3. **P2PKH (legacy) spend with the parent tx supplied** (`non_witness_utxo`) passes. Miniscript **refuses** a legacy input that has no parent tx, or whose parent's txid doesn't match the outpoint. A segwit input that carries both fields is also checked for consistency: a mismatched amount is rejected. One transaction mixing P2WPKH (UTXO-only), P2TR (UTXO-only) and P2PKH (with parent) signs and verifies, which exercises BIP341's all-prevouts sighash.
4. **Regtest: NOT run.** `bitcoind` is not installed on this machine (no binary on PATH and no app in /Applications), and per instructions it was not installed. Instead, every input of every produced transaction is verified with **libbitcoinconsensus v26.0** (Core's own script interpreter, the same patched build hercules-core links), with all pre-taproot flags plus `VERIFY_TAPROOT` and the full spent-outputs array. Each happy path has a negative twin that must fail: amount off by 1 sat (P2WPKH, P2TR), a flipped signature byte, and the wrong scriptPubKey (P2PKH). This proves script/signature validity. It does **not** prove mempool policy (`testmempoolaccept`), relay, or mining. That still needs a regtest pass.
5. **Coin selection port** (`src/coinselection.rs`), line-for-line from bitcoin/bitcoin @ `a773e1e33b349dc819b5a0edc1c7a4839dc73b48` (`src/wallet/coinselection.{h,cpp}`, `src/policy/feerate.cpp`). It covers `SelectCoinsBnB` (current master version, with the high-feerate waste cut and the skip-equal-amount optimisation), **CoinGrinder**, `RecalculateWaste`/`GetChange`, `OutputGroup::Insert` and `CFeeRate::GetFee` (round-up). Ported tests, all passing:
   - `coinselection_tests.cpp`: `bnb_test` across all 10 feerates, `bnb_exhaustion_with_solution_test`, `bnb_feerate_sensitivity_test`.
   - `coinselector_tests.cpp`: `coin_grinder_tests` cases 1–8, `waste_test`.
   - **The tests check Core's exact `GetSelectionsEvaluated()` counts**, e.g. 51,765 / 87,957 BnB attempts and 37 / 92 / 38 / 7 / 87,525 CoinGrinder attempts. So the port walks the search tree node-for-node like Core, not just landing on the same answer.
   - Mutation check: disabling BnB's high-feerate cut, or CoinGrinder's CUT-vs-SHIFT branch, makes these tests fail.

   **Fallback choice: CoinGrinder over Knapsack.**
   - CoinGrinder is deterministic, so Core's tests pin exact inputs and attempt counts, which gives a hard regression oracle. Knapsack is randomized (shuffles and random passes), and its Core tests are statistical.
   - CoinGrinder shares BnB's DFS skeleton, so it is very little extra code.
   - It minimises input weight at high feerates, which is when fees matter most on a phone wallet.
   - Knapsack/SRD are still needed as the always-available low-feerate fallback with change. They are deferred to the production port.
6. **Select-then-spend glue.** Input weights come from the descriptor (`max_weight_to_satisfy`). The spike-level `choose()` returns BnB's changeless pick at 5 s/vB and CoinGrinder's single-input-with-change pick at 60 s/vB. Both transactions verify and meet the target feerate.

Input weight estimates (miniscript) against Core's figures, checked as true upper bounds over 64 signatures each: P2WPKH 272 WU (= Core's 68 vB; actual 271/272), P2TR 231 WU (Core 230; actual always 230), P2PKH 592 WU (= Core's 148 vB; actual 588/592).

### iOS size delta (aarch64-apple-ios, release, default profile = hercules-core's, which sets no `[profile]`)

Comparison: `--features stack` (bip39 + miniscript) against `--no-default-features`. Both builds export one probe symbol that runs the same derive → PSBT → sign → finalize → extract flow for wpkh + tr. The baseline does it with rust-bitcoin only: raw seed, hand-filled key origins, a hand-written finalizer.

| Measure | Baseline | With miniscript + bip39 | Delta |
|---|---|---|---|
| Static lib `.a` (what `build-ios.sh` ships into the xcframework) | 20.19 MB | 26.22 MB | **+6.0 MB** |
| Linked, `-dead_strip`, `strip -x` dylib (approximates what lands in the app binary) | 1.77 MB | 3.38 MB | **+1.6 MB** |

Of the linked `__TEXT` delta, about 0.71 MB is miniscript's own code. About 0.5 MB is `core`/`alloc` generic instantiations that miniscript pulls in (descriptor parsing, Display, the interpreter). bip39's code is about 5 KB plus its wordlist and normalization tables. LTO / `opt-level="z"` were not tried, because hercules-core uses neither. The `.a` number overstates the app impact, since Xcode dead-strips at link time.

### Gaps / risks

- **No regtest end-to-end.** Policy and standardness (`testmempoolaccept`), broadcast and mining are unverified. Run spike step 4 on a machine with bitcoind before 035 builds on this. The spike has no RPC code; add a small harness then.
- **Hardware-wallet `non_witness_utxo`:**
  - Since the June 2020 segwit fee-attack disclosure, Trezor and Ledger firmware require the full previous tx for **segwit v0** inputs. Per-device/version behaviour was not tested here.
  - Taproot-only input sets avoid this, because the BIP341 sighash commits to every input amount.
  - Consequence for 035: wpkh coins destined for a hardware signer need the parent-tx retention / historical-block fetch path. Hot-wallet wpkh and tr spends do not.
  - `build_psbt` already attaches a parent when one is known, and miniscript checks that it is consistent.
- **Signing details:**
  - `bitcoin::Psbt::sign` (0.32) does not grind low-R. About half its ECDSA sigs are 1 byte larger than Core's typical size. They stay within the 72-byte bound used by both Core and miniscript (verified), so fees are never underpaid. The cost is about 0.125 vB more per P2WPKH input (0.5 vB per P2PKH input) than Core on average. A low-R re-sign via `sign_ecdsa_low_r` would close this; it is optional.
  - BIP340 signing uses no aux randomness unless `bitcoin`'s `rand-std` feature is enabled. Enable it in production.
- **Coin selection not yet ported:** Knapsack, SRD, `GroupOutputs` (avoid-partial-spends grouping, eligibility filters), ancestor bump fees, `ChooseSelectionResult`'s full policy (SFFO, max-weight retries) and `GenerateChangeTarget` randomisation. `choose()` is a spike stand-in.
- miniscript adds a second major of `hex-conservative`. This is harmless, but it is one more crate to audit.
- Using SLIP-132 zpub/zprv needs our own version-byte re-encoding (rust-bitcoin only speaks xpub/tpub). It is only needed for importing/exporting zpub-style strings; descriptors make it unnecessary internally.

### Recommendation

**Adopt the no-BDK stack as specified:** `bitcoin` 0.32.8 + `miniscript` 13.2.0 + `bip39` 2.2.2, plus our port of Core's coin selection.
- Every money-critical step in the spike was done by a library: derivation, script generation, sighash, signing, finalization and UTXO/parent consistency checks.
- The coin-selection port reproduces Core's own test oracles exactly.
- The size cost (about +1.6 MB linked) is acceptable next to what hercules-core already ships.

Before 035:
1. Run the regtest leg (fund → spend → `testmempoolaccept` → mine) for the P2WPKH-no-parent, P2TR and P2PKH-with-parent paths.
2. Make taproot (BIP86) the default receive type, so hardware-wallet flows do not depend on parent-tx retention.
3. In the production port (020 Phase 2), add Knapsack + SRD and `GroupOutputs`, each with their Core tests.
