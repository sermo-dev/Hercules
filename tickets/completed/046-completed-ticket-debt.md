# Ticket 046: Completed-Ticket Debt (Housekeeping)

## Status (2026-10-24): Docs pass done. Ready to move to `completed/`

Every completed ticket listed below now has a `## Status (2026-10-24)` section. Verified boxes are ticked with file:line evidence, and every remaining unchecked box carries a pointer (→ NNN, Won't do, Not done/superseded, or new work listed here). See **Outcomes** and **Remaining new work** below. Per convention, the move to `completed/` happens in a separate commit after merge. The small new-work items are not done in this PR.

## Summary

Several tickets in `tickets/completed/` still have unchecked acceptance boxes, open questions with no recorded answer, or items explicitly deferred to "later". Some of that is done in code but never recorded. Some has been absorbed by new tickets (022-045), and some is genuinely outstanding. This ticket walks each one and assigns a disposition, so `completed/` means what it says and nothing quietly falls through.

Dispositions used below: **Done** (verify, tick the box, add a Status line), **→ NNN** (folded into another ticket; add a pointer), **New work** (small; do under this ticket), **Won't do** (record why).

## Inventory (verified against ticket text and code, 2026-10-23)

### 001 Multi-peer eclipse protection

Status line at `001…md:3` says "Complete (parallel range download deferred)", but all six acceptance boxes at `001…md:63-68` are `[ ]`.

| Item | Disposition |
|---|---|
| Acceptance boxes (≥4 peers, 2+ peer header check, divergent peer handling, /16 limit, persistent bans, peer UI) | **Done** in code (`peer_pool.rs` MAX_OUTBOUND=12 at :15, `subnet_bucket` at :538, `peer_store.rs` bans; cross-check in `sync.rs:712`). Tick the boxes, but note the cross-check only compares the first header of each batch (→ 023) |
| Parallel range download (deferred) | **Won't do** for now. Single-peer header download is fast enough post-AssumeUTXO |
| Manual "add my own node" peer (`001…md:50`, "Optional") | **New work**, small. Settings field to pin a trusted peer. Also useful with 029 |

### 004 Phase 2 pruned validating node

No Status section; all eight acceptance boxes at `004…md:161-168` unchecked.

| Item | Disposition |
|---|---|
| Boxes for block download, scripts, LMDB UTXO, AssumeUTXO load, real-time validation, pruning, catch-up | **Done.** Tick and add a Status line |
| "UI shows… storage usage" (`:168`) | Verify. If missing, **→ 030** (storage hygiene adds disk usage and low-space handling) |
| Snapshot hosting decision (`:136`, CDN/BitTorrent/IPFS) | **→ 032** (snapshot publishing pipeline) |
| ETA when >~100 blocks behind (`:151`) | **New work**, small UI item |

### 005 LMDB UTXO backend

All seven action items at `005…md:54-60` unchecked. LMDB clearly shipped (`utxo.rs`, `INITIAL_MAP_SIZE` = 64 GB at `utxo.rs:30`).

| Item | Disposition |
|---|---|
| Trait, heed backend, undo port, SQLite deprecation | **Done.** Tick |
| Benchmark blocks/sec | **Won't do** as specified (IBD from genesis isn't our path). Replace with a per-block apply timing in 028 instrumentation |
| `max_map_size` strategy and on-device mmap test (`:58-59`, risk at `:64-65`) | **→ 030** (64 GB virtual map vs iOS address-space limits; extended-virtual-addressing entitlement) |

### 006 Reorg handling

No Status section. The ticket proposes max depth "e.g., 6 blocks" (`006…md:33`); the code uses `MAX_REORG_DEPTH = 288` (`sync.rs:46`). Tests listed at `:45-46` aren't confirmed to exist.

| Item | Disposition |
|---|---|
| Depth limit mismatch | **Done-ish.** Record 288 as the decision (it matches the prune window) |
| Unit/integration reorg tests | **→ 027** (harness) and **025** (reorg hardening) |
| UI `reorg_depth` surfacing (`:41`) | **→ 025** |

### 008 Fully participating node

| Item | Disposition |
|---|---|
| Mempool persistence (`mempool.dat`, `008…md:157`) | **Won't do** for v1. Block-based fee estimation (041) removes the main reason |
| Snapshot format: HUTX vs Core `dumptxoutset` (`:43`, `:155`) | **Done** (HUTX + `convert_snapshot`). Revisit in **032** |
| Mempool size 50 MB in ticket (`:58`, `:161`) vs 150 MB in code (`mempool.rs:21`) | **→ 030** (iOS memory cap). Record the final number |
| AssumeUTXO height 935,000 (`:36`, `:47`, `:163`) vs 943,500 in code | Add a superseded note pointing to 017/`assumeutxo.rs` (and 044) |

### 009 RBF / 010 CPFP

No Status sections. 009 Phase B (full descendant eviction, `009…md:33,46`) appears implemented: `mempool.rs` computes a descendant eviction set capped at `MAX_REPLACEMENT_EVICTIONS = 100` (`mempool.rs:63`, `:322`). **Done.** Add Status lines to both and confirm the existing tests cover Phase B.

### 013 Live Activity / cellular

| Item | Disposition |
|---|---|
| Widget reload budget "worth measuring early" (`013…md:225`) | **New work**: measure on device; log reloads per day |
| Live Activity config gaps (no `NSSupportsLiveActivities`) | **→ 031** |

### 014 Wallet Tor onion API

| Item | Disposition |
|---|---|
| `get_compact_filter` stub (`wallet_rpc.rs:545-550`) | **→ 035** phase 2 (BIP158) |
| Tor v3 client authorization (`014…md:96`), per-wallet tokens/revoke (`:107`) | **Won't do** in v1. Revisit if external-wallet use grows; the in-app wallet is now primary |
| Broadcast never relayed | **→ 033** |
| Subscriptions/SSE (`:77`) | **Won't do** in v1 |

### 015 Offline catch-up

| Item | Disposition |
|---|---|
| Phase 2 `BGProcessingTask` (`015…md:60-89`). Code registers `BGAppRefreshTask` only (`AppDelegate.swift:43-48`, `NotificationManager.swift:399-400`) | **→ 028** (wake budget); decide whether Phase 2 is still wanted |
| ">~288 blocks may fail" user-facing caveat (`:136`) | **New work**: one line of UI copy, or handle in 028 |

### 016 Header tip cross-check

| Item | Disposition |
|---|---|
| "Revisit MAX_OUTBOUND once measured" (`016…md:10,106`). Code is already 12 (`peer_pool.rs:15`) with no wake-timing instrumentation | **→ 028** (instrumentation, then confirm or revert) |
| "ASN-diverse" 3-peer sample (`:114-125`). Code buckets by /16 (`peer_pool.rs:529-538`), not ASN | **→ 023** (or record /16 as the accepted proxy) |

### 017 AssumeUTXO trust model

| Item | Disposition |
|---|---|
| Layer 2 multi-source attestations (`017…md:126+`), blocked on finding reviewers | **→ 032** (pipeline publishes reproducible artifacts reviewers can attest to) |
| On-device MuHash cost (`:77`, `:116`) | **New work**: measure on oldest supported iPhone; record |

## Outcomes (docs pass, 2026-10-24)

Verified against code on `main` at `72d9327`. Where the code disagreed with the inventory above, the outcome follows the code and the row says so.

| Ticket | Item | Outcome | Evidence / note |
|---|---|---|---|
| 001 | 6 acceptance boxes | **Done** (ticked) | `peer_pool.rs:15` (MAX_OUTBOUND=12), `:538,:799-812` (/16), `peer_store.rs:159,178` (bans), `sync.rs:784` (cross-check; inventory said `:712`), `ContentView.swift:1592` (PeersCard). A divergent peer is penalised 50 (`sync.rs:59`) and banned at ≤20 from 100, so it's dropped on the second divergence |
| 001 | First-hash-only cross-check | **Folded into 023** | `023…md:43,76` |
| 001 | Parallel range download | **Won't do** | Single-peer header download is fast enough after AssumeUTXO |
| 001 | Manual "add my own node" peer | **New work** | No code exists |
| 004 | 6 of 8 boxes (blocks, scripts, LMDB, AssumeUTXO, real-time, catch-up) | **Done** (ticked) | `block_validation.rs:83-95,195,226`, `sync.rs:533`, `sync.rs:2412` |
| 004 | Pruning / ~10-12 GB bound | **Partly done; bound folded into 030** | Pruning at `sync.rs:1219-1222`. Bound unverified on device |
| 004 | UI: storage usage | **Folded into 030** | Not shown. `030…md:100` |
| 004 | UI: UTXO set size | **New work** | `utxo_count` only in `SnapshotInfo` (`hercules.udl:39`), not displayed. Not in 030 |
| 004 | Snapshot hosting | **Folded into 032** | |
| 004 | ETA when >~100 behind | **New work** | No ETA in `ContentView.swift` |
| 005 | heed backend, undo sub-DB, drop SQLite UTXO | **Done** (ticked) | `Cargo.toml:19`, `utxo.rs:131-208`, `utxo.rs:112,187` |
| 005 | `UtxoBackend` trait | **Not done (superseded)**, left unticked | Inventory said Done. No trait exists; LMDB replaced SQLite directly |
| 005 | Benchmark 0-200K | **Won't do** | Per-block timing via 028 wake-phase instrumentation (`028…md:39-50`) |
| 005 | `max_map_size` + on-device mmap | **Folded into 030** | `utxo.rs:30` (64 GB), `030…md:27,79-81` |
| 006 | Depth limit | **Done** (decision recorded) | `MAX_REORG_DEPTH = 288` (`sync.rs:46`) = prune window (`sync.rs:1219-1222`) |
| 006 | Reorg tests | **Folded into 027 + 025** | Only unit pieces exist: `utxo.rs:1537`, `store.rs:615` |
| 006 | UI `reorg_depth` | **Folded into 025** | No field in UDL/Swift; `025…md:106` |
| 008 | Mempool persistence | **Won't do (v1)** | None exists. 041 removes the need |
| 008 | Snapshot format (HUTX) | **Done**, revisit in 032 | `bin/convert_snapshot.rs` |
| 008 | Mempool 50 vs 150 MB | **Folded into 030** | `mempool.rs:21` = 150 MB; comments `:82,:113` still say 50 MB |
| 008 | AssumeUTXO 935,000 | **Superseded note added** | `assumeutxo.rs:12` = 943,500. Also 017, 044 |
| 009 | Phase A + B RBF | **Done** | `mempool.rs:63,322,808`. Tests `:1961-2168`. Gap: no test for the 100-eviction cap |
| 010 | CPFP / ancestor tracking | **Done** | `mempool.rs:48,53,58,1126`. Tests `:1638-1916`. Gaps: no 101 kvB size-limit test; `select_for_block` not built (optional) |
| 013 | Widget reload budget | **New work** | `reloadAllTimelines` on every write (`SharedNodeState.swift:193`), not measured |
| 013 | Live Activity config | **Folded into 031** | `031…md:8,22,68` |
| 014 | `get_compact_filter` stub | **Dropped (decided in 035)** | Inventory said → 035 phase 2. 035 has since dropped BIP158 serving (`035…md:5`). Stub at `wallet_rpc.rs:545-551` |
| 014 | Tor client auth, per-wallet tokens | **Won't do (v1)** | |
| 014 | Broadcast never relayed | **Folded into 033** | `033…md:7` |
| 014 | Subscriptions/SSE | **Won't do (v1)** | |
| 015 | Phase 1 budgeted catch-up | **Done** | `sync.rs:2412`, `hercules.udl:54,119` |
| 015 | Phase 2 `BGProcessingTask` | **Folded into 028** | Only `BGAppRefreshTask` (`AppDelegate.swift:43-48`, `NotificationManager.swift:400,445`); `028…md:27,76` |
| 015 | ">~288 blocks may fail" copy | **New work** | No such copy in Swift |
| 016 | Part 1 tip cross-check | **Done (simplified)** | Wake path `catch_up_blocks` cross-checks once per wake (`sync.rs:2500-2526`). Single witness + tiebreaker, not parallel 3-peer |
| 016 | MAX_OUTBOUND revisit | **Folded into 028** | `peer_pool.rs:15` = 12, no instrumentation; `028…md:35,73` |
| 016 | ASN-diverse sample | **Decision recorded: /16 is the accepted proxy** | No ASN data anywhere, and 023 doesn't add any. Cross-check witness bucket-distinctness **unverified** |
| 017 | Layer 3 forward-validation counter | **Done** | `sync.rs:581-599`, `SettingsView.swift:100-105` |
| 017 | Layer 1 MuHash | **Partly done** | Computed/stored/displayed (`utxo.rs:820,884,396`, `SettingsView.swift:201`). No enforced `ASSUMEUTXO_MUHASH` constant |
| 017 | Layer 2 attestations | **Folded into 032** | `032…md:70,74` |
| 017 | On-device MuHash cost | **New work** | Not measured |

Verification: every box left unchecked in `tickets/completed/{004,005}` carries a pointer, and the other completed tickets in this list have no checkbox lists. 007, 011, 018 and 022 were outside this ticket's inventory and are untouched.

## Remaining new work

Small items not covered by any other ticket. Do each as its own small PR. No new tickets were created.

1. **Manual trusted peer** (001): Settings field to pin a user's own node. Also useful with 029.
2. **Catch-up ETA** (004): show an estimated time when more than ~100 blocks behind.
3. **UTXO set size in UI** (004): surface `utxo_count` (already in `SnapshotInfo`, `hercules.udl:39`) or a live count. Not covered by 030.
4. **Widget reload measurement** (013): log `reloadAllTimelines` calls per day on device against the ~40-70/day WidgetKit budget.
5. **Catch-up >288 caveat** (015): one line of UI copy, unless 028 handles it.
6. **On-device MuHash timing** (017): measure snapshot-load MuHash cost on the oldest supported iPhone and record it in 017.

Test gaps found during verification (optional, small): a test for the RBF 100-eviction cap (`TooManyReplacements`) and for the 101 kvB ancestor size limit.

## Proposed process

1. One PR: tick verified boxes, add `## Status (2026-10-23)` lines and pointers to new tickets. Docs only.
2. Do the small **New work** items (manual peer, ETA UI, widget reload measurement, MuHash timing, catch-up caveat) as individual small PRs.

## Files touched

`tickets/completed/001, 004, 005, 006, 008, 009, 010, 013, 014, 015, 016, 017` (status notes); small Swift/Rust changes for the New-work items.

## Dependencies

None for the docs pass. New-work items are independent.

## Estimated effort

Docs pass ~0.5 day. New-work items ~2-3 days total.

## Verification

`grep -c "\- \[ \]" tickets/completed/*.md` drops to zero or each remaining box has an explicit pointer; every completed ticket has a Status line.

## Open questions

- Keep `completed/` strictly "done", or allow "done with follow-ups"? Recommendation: the latter, as long as each follow-up points to a ticket number.

## Roadmap position

Anytime; good filler between larger tickets. Do the docs pass before starting 022 so the baseline is clean.
