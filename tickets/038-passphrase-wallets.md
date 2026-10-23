# Ticket 038: Passphrase (Hidden) Wallets

## Summary

Support BIP39 passphrase wallets, the "25th word": a user-typed passphrase combined with the main seed derives an entirely separate wallet. From the Wallet tab, a **Passphrases** button opens an entry sheet. The typed passphrase opens the derived wallet for the current session only. Nothing about it is ever stored. When the session ends, the app retains no evidence that the wallet exists.

Purpose: plausible deniability and compartmentalization. Under coercion the user can reveal the main wallet, and the passphrase wallets are undiscoverable from the device.

## Background

BIP39 derives the 512-bit seed as `PBKDF2(mnemonic, "mnemonic" + passphrase)`. Any passphrase, including empty, typos, and different capitalization, produces a valid but completely different wallet. There is no checksum on the passphrase, so the app cannot tell a "real" hidden wallet from a typo. That property is the source of the deniability, and also the source of the main UX risk (typos lead to "my coins are gone" panic).

The main seed lives SE-wrapped (036). A passphrase wallet needs the seed decrypted plus the passphrase, so opening one requires the same auth as revealing/spending the main wallet.

## Proposed design

### Entry flow

```
Wallet tab → [🔑 Passphrases] → auth (036) → passphrase sheet
  ┌──────────────────────────────┐
  │ Enter passphrase             │
  │ [••••••••••••]  👁            │
  │ Fingerprint:  🦊🌵🚲🎈 (a3f1) │  ← updates as you type
  │ [Open wallet]                │
  └──────────────────────────────┘
```

- Derive the BIP32 master and show a **fingerprint**: the 4-byte master key fingerprint as hex plus an emoji mapping. It's recomputed live as the user types. The user learns to recognize "🦊🌵🚲🎈 is my savings wallet." A typo shows a different fingerprint, which is caught before opening. **Nothing is stored for comparison.** Recognition happens in the user's head.
- Open → derive descriptors in memory → add scripts to the WatchSet (035) → run a UTXO-set walk (035) → show balance + post-snapshot history from the walk.

### Hard rules (no evidence on device)

- Never write the passphrase, derived xpubs, descriptors, fingerprints, balances, or txids of a passphrase wallet to disk, the wallet DB, logs, crash reports, analytics, the widget's App Group store, or notification history
- No list of "your hidden wallets"; no count; no "recently used"
- **No background scanning and no notifications.** A lock-screen "Received 0.1 BTC" for a wallet you claim doesn't exist defeats the purpose
- Clear on: explicit close, app background for > N seconds, device lock, memory warning
- Zeroize the passphrase and derived keys in memory (036 memory hygiene). Passphrase entry uses a secure text field, autocorrect off, no keyboard learning (`.textContentType(.oneTimeCode)` hack or a custom keyboard?). Third-party keyboards must be disallowed for this field.
- Exclude the passphrase screen from app-switcher snapshots and screen capture (036)
- SwiftUI view state may retain the string. Hold the passphrase in a Rust-side zeroizing buffer and pass bytes, not `String`, where feasible

### Receiving and sending

- Receive: next unused address from the in-memory descriptor. **Problem:** with nothing persisted, "next unused" must be derived from the walk results each session. Fine with gap-limit logic, but address reuse is possible if the user hands out an address, closes, and hasn't been paid yet. Mitigation: show a warning "this address is only remembered while this wallet is open" and the derivation index.
- Send: identical to the main wallet; requires 036 spend auth.
- Incoming payments while closed are found on the next open's walk. Unconfirmed incoming (040) can't be seen while closed.

### Cost of each open

Every open triggers a full UTXO-set walk (035). If 035's on-device measurement shows minutes, this UX is slow. Options: accept it with a progress bar (deniability-preserving), or the deferred "pin" feature below.

### Backup warnings

The passphrase is **not** recoverable from the seed backup. When the user first opens a passphrase wallet that has a non-zero balance, or before the first receive, show: "This wallet is protected by the passphrase you typed. It is not stored anywhere. If you forget it, these funds are gone. Write it down separately from your seed words." Device transfer (039) never includes passphrases.

### Deferred: pinning (explicitly out of scope)

The owner floated an optional "pin this hidden wallet" so it persists and is scanned and notified like a normal wallet. **Not in v1.** Pinning stores evidence on the device (encrypted descriptors at minimum), which ends deniability for that wallet against anyone who can unlock the phone. If revisited later, it should be an explicit, warned opt-in per wallet.

## Files touched

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/Wallet/PassphraseEntryView.swift` | **New** |
| `HerculesApp/HerculesApp/Wallet/FingerprintEmoji.swift` | **New**: 4-byte → emoji mapping (fixed wordlist) |
| `hercules-core/src/wallet.rs` | Ephemeral wallet type; no persistence path |
| `hercules-core/src/wallet_scan.rs` | Add/remove scripts from WatchSet at runtime (035) |
| `hercules.udl` | `open_passphrase_wallet(bytes)`, `close_passphrase_wallet()` |

## Dependencies

- **036** (seed unwrap, memory hygiene, secure views), **035** (walk + runtime WatchSet), **037** (tab + wallet UI reuse)

## Estimated effort

1–1.5 weeks.

## Verification

- Same seed, passphrases "a", "A", "" → three distinct fingerprints and addresses, matching an external reference (e.g. Sparrow/iancoleman with the same mnemonic + passphrase)
- Open, receive on regtest, close → grep the app container (wallet DB, logs, App Group, caches, `NotificationHistory`) for the passphrase, xpub, fingerprint, address, txid → **zero hits**
- Push wake while a passphrase wallet is open in the background → no notification for it
- Background the app past the timeout → wallet closed, WatchSet entries removed
- Device transfer (039) bundle contains no passphrase data

## Open questions

- Session timeout default (60 s background?)
- Emoji fingerprint vs. hex only (emoji is friendlier, but leaks nothing extra either way)
- Should "Passphrases" be visible at all, or behind a Settings toggle (so its presence doesn't prompt a coercer to ask)? Many users have no hidden wallet; a visible button invites the question "what's this?". Recommendation: off by default, enabled in wallet settings. Ironically, the toggle state itself is evidence the user enabled it. Discuss.
- Keyboard: allow the system keyboard only (block third-party keyboards via `UIApplicationDelegate.application(_:shouldAllowExtensionPointIdentifier:)`)

## Roadmap position

After 036/037. Ships in v1 (owner decision).
