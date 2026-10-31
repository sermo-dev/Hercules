# Ticket 055: Core Foundations Before Wallet Code — Crates, Panic Policy, Logging

## Summary

Groundwork the architecture reviewer recommended before any wallet code lands in the Rust core (2026-10-28 team review of main @ 7732755). None of it is a bug users hit today; all of it is much cheaper before the wallet exists than after.

1. **Split the crate into a workspace:** node, wallet and FFI. Wallet logic can then be tested without cmake, Boost, the Core fetch or Arti, and never reaches node internals.
2. **Decide the panic policy.** Today a panic under a lock poisons it, and the app later crashes on a `try!` from a non-throwing FFI call. Wallet state is money-critical in memory, so a caught panic that leaves it half-updated is not acceptable.
3. **Install a logger with redaction.** No Rust logger is set, so field failures can't be diagnosed. Hooking one up naively would publish own-tx txids, peer IPs and half of the wallet-API credential.
4. **Fix the `start_wallet_api` race.** Two starts can leave a second server running that still accepts the old token after rotation.
5. **Build hygiene:**
   - `--locked`;
   - a pinned toolchain;
   - bindgen out of the shipped library's dependencies;
   - release profile settings.

**Severity: Medium** (foundational). Item 4 is a real bug, Low/Medium.

## Background

Line numbers are at main 7732755.

### Panics

- There is no `[profile.release]`, so panics unwind and overflow checks are off in release.
- `lib.rs` uses a poison-tolerant `lock()`, but stores, `peer_pool`, mempool and tor use about 100 `.lock().unwrap()` calls.
- The mempool has invariant `expect`s (`mempool.rs:597, 635, 968`) that run under the mempool mutex on relayed transactions.
- **Chain of failure:**
  1. A mempool `expect` fires.
  2. UniFFI turns the panic into a thrown error, and the mutex is now poisoned.
  3. The next `getMempoolStatus()` (non-throwing, `ContentView.swift:210`) panics, and Swift's `try!` crashes the app.
  4. Every later session panics on its first tx.
- **Wake path:** `wakeCatchUp` and the status getters are non-throwing in `hercules.udl:170`, so any panic there crashes a background wake.
- **Background threads:** `transport-bootstrap` (`wake.rs:229`) and `wallet-rpc` die silently on panic, and the Tor gate then sits in `Bootstrapping` forever.

### Logging

- No `set_logger` anywhere, so all `log::` output is dropped on device.
- Existing log lines that would leak once a logger is hooked up:
  - own-tx txids: `sync.rs:1420-1423`, `own_tx_store.rs:718, 749`;
  - the wallet-API onion address, which is half of the credential: `lib.rs:1297`, `tor.rs:468`;
  - peer IPs.
- `safelog` is already a dependency.

### `start_wallet_api` race

`lib.rs:1251-1295`:
- The wallet RPC slot is checked, released, and assigned unconditionally later.
- Two concurrent calls each spawn a server; the second assignment drops the first handle without `stop()`.
- The Settings toggle's getter (`SettingsView.swift:418-426`) stays false until the start finishes, so the toggle snaps back and invites a second tap.
- **Result:** the leaked thread keeps pulling from the shared accept channel (`tor.rs:516`) with the old token, even after `rotate_wallet_auth_token`. It also holds `Arc<PathClaim>` forever, so `reset_database` is refused until relaunch.

### Build

- No `rust-toolchain.toml`; `build-ios.sh` doesn't pass `--locked`.
- `uniffi` with the `cli` feature sits in `[dependencies]`, pulling `uniffi_bindgen`, `clap`, `goblin` and others into the iOS staticlib's dependency graph.
- `hercules_version()` is hardcoded instead of using `CARGO_PKG_VERSION`.
- FFI functions Swift never calls:
  - `new` (blocks up to 150 s)
  - `parse_block_header`
  - `validate_latest_block`
  - `catch_up_blocks`
  - `reconsider_invalid_blocks` (a "Reconsider invalid blocks" diagnostics action should call it; see ticket 024 follow-ups and the PR #27 consensus finding)
  - `get_wallet_api_connection_string`
- The API is stringly typed: `OwnTxInfo.status` is a String, every `HerculesError` variant carries only `msg: String`, and "node busy" arrives as `SyncFailed`.

## Proposed fix

### 1. Workspace

| Crate | Contents |
|---|---|
| `hercules-node` | Today's core minus UniFFI. Owns the chain, mempool, P2P and stores. |
| `hercules-wallet` | Pure logic on `bitcoin` / `miniscript` / `bip39` / `zeroize`: keys, descriptors, coin selection (the 034 spike's Core port), PSBT signing. Talks to the chain only through small `ChainView` / `ChainEvents` traits that the node implements. No `sync.rs`, no network. |
| `hercules-ffi` | The staticlib, using UniFFI proc-macros or the UDL. `build-ios.sh` already uses `--library` mode, so multiple crates work. |

- **Wallet FFI objects:** the wallet gets its own UniFFI objects (`WalletManager`, `Wallet`), not more methods on `HerculesNode`. It uses a typed `WalletError`, enums for statuses, and amounts as u64 sats.
- **Wallet storage:** wallet state lives under `Wallet/` in its own SQLite DB (037), never in the chain LMDB env. A reset or failed import deletes that env wholesale (ticket 020 line 276 proposes otherwise; correct it).
- **Phasing, to avoid conflicts with the hardening branches** (all of which edit `hercules-core/src`):
  - **055a, now:** turn the repo into a workspace and add an empty `hercules-wallet` crate beside the unchanged `hercules-core`. Nothing moves, so it conflicts with nothing, and wallet-engine work (M0) can start.
  - **055b, after 049–054 and 025 merge:** split `hercules-core` into `hercules-node` and `hercules-ffi`. A mechanical move with no behavior change, done in one PR at a quiet point.

### 2. Panic policy

- `panic = "abort"` and `overflow-checks = true` in `[profile.release]`. The durable stores are already crash-consistent, while in-memory state after a caught panic is not.
- Turn the mempool invariant `expect`s into errors.
- Background threads: a panic is logged and surfaced as a state (e.g. the Tor gate goes to `Failed`), not a silent stall.
- Fuzz the wake path's inputs (the `tests/network-app` PR may add targets).

### 3. Logging

- An os_log backend for `log` (subsystem `io.hercules.core`), installed at first FFI call.
- Txids of own transactions, peer IPs, onion addresses and anything key-adjacent are logged through `safelog` / os_log `private`.
- Key types have no `Debug` / `Display` and never reach `log!` (enforced by review and a clippy lint where possible).

### 4. `start_wallet_api`

- A `Stopped` / `Starting` / `Running` state held under the mutex (single-flight).
- `Drop` on `WalletRpcHandle` stops the server.
- The Settings toggle reflects `Starting`.

### 5. Build

- `rust-toolchain.toml`; `--locked` in `build-ios.sh` and CI.
- Bindgen as a separate bin crate or `[dev-dependencies]` tool.
- `hercules_version()` from `CARGO_PKG_VERSION`.
- Remove the unused FFI functions (except `reconsider_invalid_blocks`, which gets a diagnostics button).
- Typed error variants for `Busy` and `NotSetUp`.

## Files touched

| File | Action |
|---|---|
| `Cargo.toml` (workspace), `hercules-core/` → crates | Split |
| `build-ios.sh` | `--locked`; multi-crate bindgen |
| `hercules-core/src/lib.rs`, `hercules.udl` | Wallet API race; error variants; unused functions; version |
| `hercules-core/src/mempool.rs` | `expect`s → errors |
| New `logging.rs` | os_log backend with redaction |
| `HerculesApp/.../SettingsView.swift` | Toggle state; "Reconsider invalid blocks" in diagnostics |

## Dependencies

- The CI from the `tests/network-app` PR should land first, so the split is checked by CI.

## Estimated effort

3–4 days:
- workspace split: 1.5 days, mechanical
- panic policy and `expect`s: 0.5 day
- logger: 0.5 day
- wallet API race: 0.5 day
- build hygiene: 0.5 day

## Verification

- **Build and tests:** `cargo test --workspace` and `build-ios.sh` plus the simulator build pass; `hercules-wallet` tests run without cmake installed.
- **Wallet API race:** two concurrent `start_wallet_api` calls, then rotate. One server thread, the old token rejected, and `reset_database` succeeds after close.
- **Panic policy:** a panic injected under the mempool lock (test hook) aborts in release; documented behavior.
- **Logging:** release logs on a device show `<private>` for txids, IPs and onions.

## Roadmap position

In parallel with the hardening block (049–054, 025), since it touches structure rather than behavior. The workspace split should land before the first wallet-engine PR (milestone M0 in 035's plan).
