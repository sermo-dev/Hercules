# Ticket 037: App Tabs and Multi-Wallet Model

## Summary

Restructure the app around three root tabs: **Wallet**, **Node**, **People** (tab name TBD, see Open questions). Define the multi-wallet data model v1 ships with: one main wallet, any number of watch-only wallets, and session-only passphrase wallets. This replaces 020's "v1 ships single-wallet for simplicity" (`020-in-app-wallet.md:285`). The owner's decision: v1 is multi-wallet. There's no reason not to ship a complete, simple product.

This ticket owns the app shell, the data model, storage layout, visibility rules, and scan scheduling across wallets. Feature content lives elsewhere: send/receive in 020, scanning in 035, custody in 036, passphrase wallets in 038, People-tab content in 043.

## Background

Today there are no tabs. `HerculesApp.swift` opens `ContentView`, a single scroll view of node cards (state pill, Tor, node status, sync, snapshot, validation, network participation, peers) with About and Settings as sheets from header buttons (`ContentView.swift:614-620`). `AboutView.swift:153` lists "Not a wallet" as a limitation. That copy must change when this ships.

## Proposed design

### Root structure

```
TabView
├── Wallet   (default tab once a wallet exists; Node is default before)
├── Node     (today's ContentView dashboard, unchanged; About + Settings stay as sheets)
└── People   (shell only here; content in 043)
```

First launch with no wallet: the Wallet tab shows onboarding (Create / Import seed / Import xpub), while the node syncs in the background. The node must keep syncing regardless of which tab is shown.

### Wallet tab

```
┌──────────────────────────────┐
│  Main wallet        🔒 FaceID │  ← auth gate (036) before balance shows
│  1,234,567 sats              │
│  [Receive]   [Send]          │
│  ── activity ──              │
│  +50,000  Alice   2 conf     │
│  ...                         │
│                              │
│  [👁 Watch-only wallets  ›]  │  ← second gate (036 open question)
│  [🔑 Passphrases        ›]   │  ← opens 038 entry sheet
└──────────────────────────────┘
```

- **Main wallet:** the SE-protected seed (036). Exactly one per install.
- **Watch-only wallets:** list behind a second gate. Each has a name, balance, receive addresses, and history. No send, unless paired for PSBT signing (020 Phase 3).
- **Passphrases:** a button, never a list (038). Typing a passphrase opens a derived wallet for the session in the same wallet UI, with a visible "passphrase wallet" indicator and fingerprint.

### Data model

```
Wallet {
    id: UUID,
    kind: Main | WatchOnly | Passphrase,   // Passphrase never persisted (038)
    name: String,
    descriptors: [Descriptor],             // receive + change, per 034
    birthday_height: u32,                  // creation or import height
    gap_limit: u32,                        // default 20
    last_scanned_height: u32,              // 035 checkpoint
    notify: Bool,                          // arrival notifications on/off
}
WalletCoin   { wallet_id, outpoint, value, script, height, coinbase, label?, frozen? }
WalletTx     { wallet_id, txid, height?, net, fee?, label? }
```

Labels and freeze flags are used by 042. Payee links are used by 043.

### Storage layout

- **Chain data** (headers, blocks, LMDB UTXO): unchanged; location and backup policy in 030
- **Wallet DB:** a new SQLite file `wallet.sqlite`, **separate from chain data**:
  - File protection `completeUntilFirstUserAuthentication`, so push wakes can update watch data while the phone is locked (036)
  - Holds descriptors (public data), coins, txs, labels. **Never** seeds or passphrases
  - Wiping chain data ("switch validation mode") must not delete the wallet DB. Wallet history is rebuilt by rescan if chain data is replaced
  - Backup policy: open question (descriptors and labels are small and useful in an iCloud backup, but they are privacy-sensitive)
- **Key material:** Keychain / SE only (036)

### Visibility rules

| Wallet | Listed in UI | Loaded into WatchSet (035) | Scanned in push wakes | Notifications |
|---|---|---|---|---|
| Main | After auth | Always | Yes | Yes (if enabled) |
| Watch-only | After second gate | Always | Yes | Per-wallet toggle, default off? |
| Passphrase | Never | Only while open | **No** | **Never** (038) |

### Scan scheduling across wallets

- Block hook (035): all loaded wallets in one pass, so cost is roughly independent of wallet count
- UTXO walks: queue them. If several wallets need a walk (e.g. restore + 3 watch-only imports), batch into **one** pass
- Push wake budget (028): the block hook is cheap. **Never** start a UTXO walk inside a wake; walks run in foreground or `BGProcessingTask`
- Notification content: "Received 50,000 sats" without the wallet name, unless the user opts in. Lock-screen previews are visible to anyone holding the phone

### Settings changes

- Settings stays a sheet from the Node tab, plus a gear on the Wallet tab for wallet settings (default address type, gap limit, notifications, units)
- Remove About's "Not a wallet" limitation and rewrite the About copy (with 044)

## Files touched

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/HerculesApp.swift` | Root `TabView` |
| `HerculesApp/HerculesApp/ContentView.swift` | Becomes `NodeTab` content (rename later; minimal diff now) |
| `HerculesApp/HerculesApp/Wallet/WalletTab.swift` | **New** |
| `HerculesApp/HerculesApp/Wallet/WatchOnlyListView.swift` | **New** |
| `HerculesApp/HerculesApp/Wallet/WalletOnboardingView.swift` | **New** |
| `HerculesApp/HerculesApp/People/PeopleTab.swift` | **New** (shell) |
| `HerculesApp/HerculesApp/AboutView.swift` | Remove "Not a wallet" (:153) |
| `hercules-core/src/wallet_store.rs` | **New**: SQLite schema above |
| `hercules.udl` / `lib.rs` | Wallet list/create/import/delete APIs |

## Dependencies

- **034** (engine), **035** (scanner), **036** (auth gates). The tab shell and data model can be built before 036 is final, with stubbed gates.
- **030** (storage locations / protection classes)

## Estimated effort

1.5–2 weeks: shell + onboarding 3–4 days, data model + store 3 days, watch-only list + gating 2 days, polish 2 days.

## Verification

- Fresh install: Node tab syncs, Wallet tab onboarding works, switching tabs doesn't interrupt sync
- Create main wallet + 2 watch-only → all three receive correctly in one regtest block; one hook pass
- Lock phone → push wake → watch-only and main coins updated, notifications show without wallet names
- Passphrase wallet open → appears nowhere in lists; after close, nothing in `wallet.sqlite` references it (grep the DB file)
- "Switch validation mode" wipe → wallet DB intact; balances repopulate after resync/rescan

## Open questions

- **Tab name.** The owner called it "Peers," but the Node tab already shows *P2P peers*. Two meanings of "peers" will confuse users. Alternatives: "People", "Contacts", "Friends", "Pay". Recommendation: **People**.
- Default tab when a wallet exists: Wallet (recommended) or Node?
- Watch-only gate: device auth or separate password (036 Q3)?
- Should watch-only wallets notify on arrival by default?
- Is the wallet DB included in iCloud device backup? Recommendation: exclude by default; offer export (039) instead.
- Future: "pin" a passphrase wallet into the list. **Out of scope** (deniability cost, see 038).

## Roadmap position

After 034/035, alongside 036 implementation. Must land before any wallet feature is user-visible.
