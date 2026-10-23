# Ticket 042: Coin Control, Freezing, and Labels

## Summary

Give users optional, advanced control over *which* coins a payment spends, plus the ability to freeze coins and attach labels. The automatic flow stays the default, and none of this appears unless the user opens **Advanced** in the send flow or a coin's detail view. Labels export and import in the BIP329 standard format so they move with the user between wallets (and between devices; see 039).

## Background: what this means, in plain terms

**Your balance is not one number on-chain. It's a pile of separate coins.** Every payment you've received is its own coin (a UTXO) with its own amount and history. A wallet showing "0.05 BTC" might really hold three coins: 0.03 from an exchange withdrawal, 0.015 from a friend, and 0.005 of change from an earlier payment.

**When you pay someone, the wallet picks which coins to spend.** It usually picks automatically, using coin selection (ticket 020 specifies Branch-and-Bound plus a fallback; the library choice is in 034). If the payment needs more than one coin, the wallet spends several together in one transaction.

**Spending coins together links them publicly.** Chain analysis treats every input of a transaction as belonging to the same owner (the common-input-ownership heuristic). If you spend your exchange-withdrawal coin, which the exchange has tied to your identity by KYC, together with a coin a friend paid you privately, anyone watching the chain can now tie the private coin to your identity too.

This ticket adds four tools:

| Tool | What it does | Why a user wants it |
|---|---|---|
| **Coin control** | Manually choose which coins a payment spends | Avoid merging KYC and non-KYC coins; pick the coin with the right history |
| **Freeze** | Mark a coin "never spend automatically" | Dust attacks (tiny unsolicited coins sent to track you), coins being saved for a specific purpose |
| **Labels** | Notes on coins, addresses, transactions and contacts | "Coinbase withdrawal", "rent from Alice". Memory for later privacy decisions and accounting |
| **Consolidate** | Merge many small coins into one when fees are low | Small coins cost more in fees to spend later than they're worth when fees are high |

### Link to ticket 021

021's quantum-exposure drawer lists coins whose public keys are visible on-chain (Taproot outputs, spent-from addresses). Coin control turns that list into an action: **"Move these coins"** pre-selects exactly those coins in a send-to-self consolidation to a fresh P2WPKH address.

## Proposed design

### Core (Rust)

- `Utxo` gains `frozen: bool` and `label: Option<String>`, persisted in the wallet store (034/035).
- Coin selection accepts `must_include: [OutPoint]`, `must_exclude: [OutPoint]` and `only_from: [OutPoint]`. Frozen coins are excluded unless explicitly included.
- Label store keyed by BIP329 reference types: `tx`, `addr`, `pubkey`, `input`, `output`, `xpub`. Import and export as BIP329 JSON Lines.
- A privacy hint helper: given a selected coin set, report "these coins have different labels/sources" so the UI can warn before merging.

### iOS

- **Send → Advanced → Choose coins:** list coins with amount, label, confirmations and a type badge (021 exposure badge). Running total and fee preview update live.
- **Coin detail:** label, freeze toggle, origin transaction, exposure status.
- **Merge warning:** a non-blocking sheet when a selection mixes labeled sources.
- **Consolidate:** offered as a suggestion only when the coin count is high *and* the block-based fee estimate (041) is low.
- **Labels on transactions** in history and per contact in People (043).

### Defaults (keep it simple)

- Automatic coin selection, with no coin list shown, unless the user opens Advanced.
- Nothing is frozen automatically. A later improvement could suggest freezing coins below a dust threshold received from unknown senders.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/wallet*.rs` | Frozen flag, label store, selection constraints, BIP329 import/export |
| `hercules.udl` | `UtxoInfo` with label/frozen; selection constraint params; label import/export |
| `HerculesApp/.../Wallet/CoinListView.swift` | **New**: coin picker |
| `HerculesApp/.../Wallet/CoinDetailView.swift` | **New** |
| `HerculesApp/.../Wallet/SendView.swift` (037) | Advanced section, merge warning |

## Dependencies

- **034** wallet engine (coin selection lives there). ❌
- **035** wallet chain scanner (the UTXO list). ❌
- **039** uses BIP329 export for migration and backup of labels.
- **021** "move exposed coins" action.

## Estimated effort

~5-7 days: selection constraints and freeze (1-1.5d), label store plus BIP329 (1.5d), coin picker and detail UI (2-3d), tests (1d).

## Verification

- Unit: frozen coin never selected automatically; selected when explicitly included.
- Unit: `only_from` with insufficient funds → clear error, no silent fallback to other coins.
- BIP329 round-trip: export → wipe labels → import → identical label set. Import a Sparrow BIP329 export and labels attach to matching txids/addresses.
- Manual: 021 "move exposed coins" pre-selects exactly the exposed set.

## Open questions

- **v1 or post-v1?** Labels plus BIP329 are cheap and help migration (039), so they're a candidate for v1. The full coin picker could be v1 "Advanced" or v1.1. Owner's call.
- **Labels for contacts.** Should payments to a People contact (043) auto-label the transaction with the contact's name? Recommendation: yes, locally only.
- **Hidden wallets.** Labels for passphrase wallets (038) must be stored so that they don't reveal the hidden wallet exists, e.g. encrypted under a key derived from that wallet's seed. Coordinate with 038.

## Roadmap position

Wallet tier, after the send flow exists. Labels and BIP329 can land earlier, alongside 039.
