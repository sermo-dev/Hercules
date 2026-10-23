# Ticket 046: Completed-Ticket Debt (Housekeeping)

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
