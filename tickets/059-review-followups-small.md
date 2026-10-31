# Ticket 059: Small Follow-ups From the 2026-10-31 Deep Review

Smaller findings from the deep review of main at `d627836` that don't belong to a running ticket. Item 1 should land before 035, the wallet scanner.

## 1. The crash-recovery connect skips the mutation check (medium)

- **The code:** in `connect_block` (`sync.rs` ~2216), the branch where the UTXO set already has the block (`Connected::Recovered`) never calls `check_block`, so `check_block_mutation` doesn't run there. It then stores the block and runs `on_block_connected` with it.
- **Scenario:**
  1. The app is killed after the UTXO apply and before `set_validated_height`. Ticket 050 is built around exactly this case.
  2. On the next connect, a peer serves a copy with the same hash but stripped witnesses or duplicated txs (CVE-2012-2459).
  3. That copy is accepted as `Recovered` and written to `blocks.sqlite3`.
- **Effect:**
  - We then serve a mutated block to peers (BIP 159), which Core treats as misbehavior.
  - Hooks get a tx list that differs from what the header commits to.
  - Once the 035 wallet hook joins, duplicated txs could double-count an incoming payment.
- **Confirmed** by the reviewer's scratch test in `testkit/connect_paths.rs`:
  - kill at `ConnectStep::Applied`, then connect a witness-stripped copy;
  - result: `Ok(Connected::Recovered)`, with the stripped block stored.
- **Fix:**
  - Run `check_block_mutation` at the top of `connect_block` on both branches and return `Delivery` when it fails.
  - Add that test as a regression test.

## 2. The wallet RPC serves unvalidated chain data without marking it (low)

- `wallet_rpc.rs` ~375–460: `get_block_header` and `get_block_hash` return headers above `validated_height`.
- `wallet_rpc.rs` ~483: `get_utxo` reads LMDB rows while a snapshot import is partial or pending.
- **Fix:** add a `validated: false` flag, or refuse; refuse `get_utxo` while a load is in progress. Coordinate with 035 / 014.

## 3. Small Swift / FFI items (low)

- The Wallet API toggle is disabled once sync stops, so the onion RPC can't be turned off (`SettingsView.swift` ~430).
- `close` racing `start_wallet_api` leaks the server thread and its `PathClaim` (`lib.rs` ~807–817 vs ~1271–1325). This is a second trigger for the race in ticket 055.
- The widget isn't cleared on reset (`ContentView.swift` ~129, ~177–194).
- From 054: Switch & Wipe deletes pending own txs; it should warn first, or keep them.
- From 054: installs the old bug converted to genesis are recorded as genesis; show a one-time notice explaining why (owner decision, 2026-10-31).
- Unchecked `UInt32` subtraction `targetHeight - currentHeight` (`NotificationManager.swift` ~727, ~873). Defensive only; no known way to reach it.

## 4. Plausible, not confirmed (investigate)

- **Cheap chain during initial sync:** below minimum work, two colluding peers can keep extending a cheap fake chain just short of the anchor. Each one-header extension resets `scratch_stall_rounds`, which delays replacement by the honest chain. Fits 025 or a headers-presync design.
- **Transient read error deletes the snapshot:** a transient EIO during snapshot load maps to `SnapshotInvalid`, and the 8.8 GB download is deleted. Costs only a re-download; distinguish I/O errors from content errors.
