# Ticket 044: Docs and Positioning Rewrite

## Summary

The README and in-app About copy describe a different product from the one being built. They say Hercules "is not a wallet", list Lightning as a future phase, list BDK as the wallet stack, and promise that all traffic goes over Tor. The owner's vision (2026-10-20) is **one iOS app = a pruned, fully-validating node + its own wallet + a People tab for person-to-person payments**, with no Lightning. This ticket rewrites the docs to match, makes the roadmap point at real tickets, and makes the trust claims honest.

## Background: what's stale (verified)

| Location | Current text | Problem |
|---|---|---|
| `README.md:17` ("The Goal") | "Hercules is not a wallet. It is the verification layer underneath any wallet…" | Contradicts the vision (020, 037, 043) |
| `README.md:384` "What Hercules Is Not" section | Same stance | Same |
| `HerculesApp/HerculesApp/AboutView.swift:153` | Limitations card: "Not a wallet" | User-facing; must change before any wallet build ships |
| `README.md:128` | Stack: "Wallet API: BDK (future)…Electrum-compatible local server" | Wallet engine is undecided (034). 020 chose hand-rolled. Electrum protocol was rejected in 014 (`tickets/completed/014-wallet-tor-onion-api.md:54`) |
| `README.md:129`, Phase 8 (`:312-320`) | "Lightning: LDK (future)", Phase 8 Lightning incl. "Cooperative channel monitoring" | Owner decision: **no Lightning**. 020:273 already says so. Remove |
| `README.md:76` | "All network connections are routed through **Tor**… The user's IP address is never exposed" | Pending 029 (clearnet default, Tor opt-in). Becomes false if 029 ships |
| `README.md` Phases 2-6 | Only Phases 0-1 have ✅ | Phase 2, 3, 4, 5 work is completed per tickets 004-018 |
| `README.md:300+` Phase 7 | Electrum Personal Server + BIP157/158 serving | Re-scope: the external-wallet API exists (014); BIP158 is 035 phase 2 |
| `tickets/completed/008…md:36,47,163` vs `assumeutxo.rs:12` | 935,000 vs 943,500 | Snapshot height drifted; docs must reference one source of truth |
| README Security Model | "Trust assumption: the AssumeUTXO snapshot hash… cross-verifiable against Bitcoin Core v26+ source" | The snapshot is a custom HUTX format at a non-Core height; it isn't directly cross-verifiable against Core's chainparams (017). Historical validation (003) is deferred |
| Name | "Hercules" throughout | Rename pending (031). Docs should use a placeholder-friendly structure |

## Proposed design

### README.md, new structure

1. **One-paragraph pitch:** your phone is a Bitcoin node and a wallet. Trustless verification and peer-to-peer payments, with no dedicated hardware, no server, and no account.
2. **What it does:** Node (validates every block, relays, serves peers), Wallet (main, watch-only and passphrase wallets; Face ID), People (pay friends via silent payments).
3. **How it works:** pruned validation, AssumeUTXO bootstrap, push-wake validation, network transport (clearnet default / Tor optional per 029), storage footprint.
4. **Trust model, honestly stated:**
   - Every block after the snapshot height is fully validated on-device.
   - The snapshot is trusted on the basis of a hash committed in the open-source app and verifiable as described in 017/032. Until 003 ships, history before the snapshot is not independently re-validated by the phone.
   - No server ever learns wallet contents; the push relay only learns an APNs token and wake times (019).
5. **What it is not:** not Lightning; not custodial; no accounts, no KYC; not a block explorer for pre-snapshot history.
6. **Architecture** diagram updated: wallet module, People, no Lightning box.
7. **Roadmap:** replace the phase essay with a table of tiers → ticket numbers (022-046), linking to `tickets/`.
8. **Glossary:** UTXO, AssumeUTXO, pruning, reorg, mempool, relay policy, BIP158 compact filters, silent payments, passphrase (25th word), watch-only / xpub, PSBT.
9. **Building & contributing:** `build-ios.sh`, xcodegen, `cargo test`, the server deploy pointer.

### In-app copy

- `AboutView.swift`: replace the "Not a wallet" limitation with accurate limitations (pre-snapshot history unavailable; background validation depends on push; pending payments only visible while the app is open; see 040).
- Onboarding copy (037) reuses the README pitch and glossary phrasing so the app and docs say the same thing.

### Single source of truth for numbers

The snapshot height/hash, peer limits and storage footprint should be referenced from code, e.g. "see `ASSUMEUTXO_HEIGHT` in `hercules-core/src/assumeutxo.rs`", or generated, rather than copied into prose that drifts.

## Files touched

| File | Action |
|---|---|
| `README.md` | Rewrite per structure above |
| `HerculesApp/HerculesApp/AboutView.swift` | Update limitations and description copy |
| `server/README.md` | Align with 019 amendment (height enrichment claim at `server/README.md:51` is currently false) |
| `tickets/README.md` or index section in README | **New**: ticket index by tier |

## Dependencies

- Decisions from **029** (transport default), **034** (wallet engine), **031** (rename) should be reflected. Write with placeholders now and update when those land.

## Estimated effort

~1-2 days for README and About copy; small follow-ups as 029/034/031 resolve.

## Verification

- `grep -i "not a wallet\|lightning\|LDK"` across README and Swift returns nothing, or only a "no Lightning" statement.
- Every roadmap item in the README links to an existing ticket file.
- A Bitcoin-literate reader can state the trust model correctly after reading the Trust section once.

## Open questions

- **Final name.** Blocks the title and the bundle-facing copy (031).
- **Audience.** One README for developers and a separate user-facing site/FAQ later? Recommendation: README for developers and reviewers now; a user FAQ before App Store submission.

## Roadmap position

Can land any time. Do the README rewrite early, because new contributors and reviewers currently read a contradictory pitch. The About copy must change before any build with the wallet ships.
