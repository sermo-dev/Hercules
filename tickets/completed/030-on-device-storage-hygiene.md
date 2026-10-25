# Ticket 030: On-Device Storage Hygiene: Backup Exclusion, File Protection, LMDB Map, Memory, Disk

## Summary

Hercules keeps about 10–12 GB of chain data in the app's `Documents` directory with default settings. That means:

- It's **included in iCloud and Finder backups**.
- It has whatever data-protection class iOS assigns by default.
- The LMDB environment reserves a 64 GB virtual memory map that has never been checked on a real device.
- The mempool may use up to 150 MB of RAM.
- There's no free-disk check anywhere.

This ticket moves chain data to a non-backed-up location, defines a deliberate file-protection plan (ready for wallet data arriving in 020/036), and closes the iOS storage and memory questions left open in tickets 004 and 005.

## Background (verified)

**Chain data lives in `Documents`.**
- `dbPath()` = `Documents/hercules-headers.sqlite3` (`NotificationManager.swift:456-459`, `ContentView.swift:525-528`).
- The UTXO LMDB, blocks, and peers sit next to it via `derive_sibling_path`: `utxo-lmdb`, `blocks.sqlite3`, `peers.sqlite3` (`sync.rs:374-397`, `lib.rs:78`).
- The Arti state is at `Documents/tor` (`NotificationManager.swift:461-464`).
- The ticket 014 wallet API token is a plaintext file at `<data_dir>/wallet_auth_token` (`lib.rs:608`).

**No backup exclusion, no protection class.** A grep of `HerculesApp/` finds no `isExcludedFromBackup`, `FileProtectionType`, or `NSFileProtection*` anywhere. Everything therefore gets the iOS default, `completeUntilFirstUserAuthentication`, and is backed up.

**The snapshot download is handled correctly.** It goes to `Caches` (`SnapshotDownloader.swift:98-101`), which isn't backed up, and the file is deleted after import.

**LMDB map size.** `INITIAL_MAP_SIZE` = 64 GB (`utxo.rs:26-30`). The comment assumes this "easily fits in the 64-bit virtual address space available on iOS". iOS limits per-process virtual address space well below the hardware limit unless the app has the `com.apple.developer.kernel.extended-virtual-addressing` entitlement. **Unverified on device.** Ticket 005's action items to evaluate the map-size strategy for iOS and to test mmap on device are still unchecked (`tickets/completed/005-lmdb-utxo-backend.md:58-59`).

**Mempool cap.** `DEFAULT_MAX_SIZE` = 150 MB (`mempool.rs:21`). Doc comments at `mempool.rs:82` and `:113` still say 50 MB.

**No free-disk check.** Ticket 004 lists "Disk monitoring: warn user if available storage drops below threshold" (`004…md:144`), and its storage acceptance criteria are unchecked (`:166-168`).

## Should chain data go into iCloud backup?

**Pros**
- A phone restored from backup comes up with a synced node immediately, with no 8.8 GB snapshot download and no catch-up.

**Cons**
- **Quota.** 10–12 GB is more than double the free 5 GB iCloud tier. When a backup doesn't fit, iOS fails the *whole* backup, so the user's photos and messages stop backing up because of us. This alone is disqualifying.
- **Churn.** The LMDB data file and SQLite databases change every block. Backups are incremental per file, so multi-GB files get re-uploaded over and over.
- **Consistency.** A backup copy of a live, memory-mapped LMDB environment and WAL-mode SQLite databases taken mid-write may restore corrupted or inconsistent. The node would then either fail to start or, worse, start on an inconsistent UTXO set.
- **App Review.** Apple's iOS Data Storage Guidelines say data that can be re-downloaded or regenerated must not be backed up. Apps have been rejected for putting large re-downloadable data in `Documents`.
- **It buys little.** Everything here can be re-fetched and re-verified from the network (that's the point of a node), and the snapshot is hash-pinned.

**Decision: exclude all chain data from backup.** Back up only small, user-authored data that can't be recreated: settings, and later wallet labels, payees, and watch-only descriptors (subject to 036/039 privacy decisions). **Never** back up key material in files.

## Proposed changes

### 1. Directory layout
```
Library/Application Support/Chain/     (isExcludedFromBackup = true on the directory)
    hercules-headers.sqlite3, blocks.sqlite3, peers.sqlite3, utxo-lmdb/, tor/
Library/Application Support/Wallet/    (backed up; small; contents decided in 036/039)
```
Do **not** use `Caches` for chain data, because iOS deletes `Caches` under storage pressure and the node would silently disappear. Set the backup-exclusion flag on the directory at creation and re-assert it at every launch (cheap, idempotent).

### 2. Migration
On first launch after upgrade, if `Documents/hercules-headers.sqlite3` exists:
1. Move (same volume, so it's a rename, not a copy) each chain file or directory into `Chain/`.
2. Write a migration marker.
3. Make the move crash-safe: per-item moves, and resume if a marker says it's incomplete.

`dbPath()` and `torDataDir()` move into a single `StoragePaths` helper used by `NodeHost` (028).

### 3. File protection plan

| Data | Class | Why |
|---|---|---|
| Chain data (SQLite, LMDB, blocks) | `completeUntilFirstUserAuthentication` | Push wakes happen while the phone is locked and must read and write it |
| Arti state (`Chain/tor`) | same | Tor-mode wakes (029) need warm consensus/state |
| Wallet watch data: derived script set, UTXO cache, labels | same | 020's arrival notifications need it during locked wakes |
| Seed / master key | **Keychain**, `WhenUnlockedThisDeviceOnly`, Secure Enclave-wrapped (036) | Never in a file, never readable while locked |
| Wallet API token (`wallet_auth_token`) | Move to Keychain `AfterFirstUnlockThisDeviceOnly` | Shouldn't be a plaintext file |

Apply classes explicitly (`FileManager` attributes / `Data.write(options:)`) rather than relying on defaults, and add an assertion test that checks them.

**After a reboot, before first unlock:** all `completeUntilFirstUserAuthentication` files are unreadable. A wake in that state must detect it (an `open(2)` failure on one of our own files), record "device locked since reboot — skipped", and complete immediately rather than erroring or retrying.

> **Note: don't use `UIApplication.isProtectedDataAvailable` for this.** An earlier draft suggested it. It reflects the `complete` protection class, so it goes false about 10 s after *every* passcode lock, not just before first unlock. Gating wakes on it would skip every push that arrives while the phone is in a pocket. Our files are `completeUntilFirstUserAuthentication`, so the only reliable check is to try opening one: `StoragePaths.protectedDataReadable` probes with `open(2)`, which fails (EPERM/EACCES) only between reboot and first unlock. It's a plain syscall, so it's also safe off the main thread.

### 4. LMDB map size on iOS
- Measure on device: open the env with the 64 GB map on the oldest supported iPhone (iOS 17), on both a fresh and a full UTXO set.
- If it fails or is marginal, either add the `extended-virtual-addressing` entitlement (verify it needs no special Apple approval) or use a smaller initial map (e.g. 16 GB) and grow-and-reopen when `MDB_MAP_FULL` occurs.
- Record the result in ticket 005 and check off its action items.

> **As implemented:** the map grows in place (`Env::resize`) instead of grow-and-reopen. Every txn holds a per-env gate shared and a resize takes it exclusively, so no txn in the process is open during the remap; address space is probed with a `PROT_NONE` mmap first, because LMDB drops the old map before mapping the new one. `apply_block`/`rollback_block` retry after `MDB_MAP_FULL`; the snapshot import grows between batches. The map size is pinned per env path within a process, because heed's global env cache rejects a second open of a live path with different options. Before the snapshot download, `check_snapshot_capacity` fails fast if the map can't reach `SNAPSHOT_MAP_REQUIRED_BYTES` (16 GiB).

### 5. Mempool memory
- Lower the foreground cap to about 50 MB on iOS, or make it device-memory-aware. Fix the stale doc comments.
- Background wakes don't build a mempool (028), but confirm nothing keeps a large mempool alive in a suspended process. Jetsam kills suspended apps by memory footprint first.

### 6. Disk space guard
- **Before the snapshot download:** require snapshot size + imported LMDB + headroom (about 25 GB free). Show a clear blocking message if there isn't room.
- **Ongoing:** check `volumeAvailableCapacityForImportantUsage` at launch and every N blocks. Below a threshold (e.g. 2 GB), pause validation and show a banner rather than letting LMDB/SQLite fail mid-transaction.
- Show "Storage used" in Settings (004 acceptance criterion).

## Files touched

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/StoragePaths.swift` | **New** — paths, backup exclusion, protection classes, migration |
| `HerculesApp/HerculesApp/NotificationManager.swift`, `ContentView.swift` | Use `StoragePaths`; locked-since-reboot handling |
| `HerculesApp/HerculesApp/SnapshotDownloader.swift` | Free-space preflight |
| `HerculesApp/HerculesApp/SettingsView.swift` | Storage used; low-disk banner |
| `HerculesApp/HerculesApp/HerculesApp.entitlements` | Possibly `extended-virtual-addressing` |
| `hercules-core/src/utxo.rs` | Map-size strategy; grow on `MDB_MAP_FULL` |
| `hercules-core/src/mempool.rs` | iOS cap; fix doc comments |
| `hercules-core/src/lib.rs` | Wallet token to Keychain (via Swift) instead of file |

## Dependencies

- **028**: `NodeHost` uses `StoragePaths`.
- **036**: key custody defines the wallet-secret rows above.
- **039**: backup/restore defines what wallet metadata is backed up.

## Estimated effort

~3–4 days:
- paths and migration: 1 day
- protection classes and locked handling: 0.5 day
- LMDB on-device measurement and fix: 1 day
- disk guard and UI: 0.5–1 day
- mempool: 0.5 day

## Verification

- After migration, Settings → iCloud → Manage Storage → Backups shows Hercules at a few MB, not GB.
- Upgrading an existing install with a synced node: after migration the node resumes at the same height with no re-download.
- Kill the app mid-migration and relaunch: migration completes and nothing is lost.
- Reboot without unlocking and send a push: the wake records "locked since reboot" and completes in under 1 s.
- `FileManager.attributesOfItem` shows the expected protection class for every file in `Chain/` and `Wallet/`.
- LMDB opens on the oldest supported device. Map-size behavior is documented in 005.
- Fill the disk to below the threshold: validation pauses with a banner and nothing gets corrupted.

## Open questions

- **Minimum supported device and iOS version** for the LMDB VA test matrix.
- **Should watch-only descriptors be backed up** (privacy: xpubs reveal full history to anyone with the backup)? Decide in 039.
- **A "Free up space" action** that drops the block store down to the minimum prune window?

## Roadmap position

Tier 1. Do this before any public TestFlight: the backup quota problem and App Review risk both hit on day one. Also do it before 020 Phase 2, because wallet storage depends on the protection plan.
