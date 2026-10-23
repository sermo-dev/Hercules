# Ticket 039: Backup, Restore, and Device Migration

## Summary

Define how a user protects against losing their phone, restores a wallet from a seed, and moves to a new iPhone. Three mechanisms with distinct roles:

1. **Paper seed phrase:** the mandatory root backup. It's the only thing that survives losing the phone.
2. **Device-to-device transfer:** an end-to-end encrypted move from an old phone to a new phone, bound by a QR code. It's a convenience, **not a backup**.
3. **Restore from seed:** type the words on a new device and get the correct balance immediately via a UTXO-set walk.

Plus export/import of non-secret metadata (labels via BIP329, watch-only descriptors).

## Background: the owner's question

> "The secure enclave CAN be device-specific but doesn't HAVE to be right? … seed only on the device but approve another device via QR + secure airdrop?"

**Secure Enclave keys are always device-specific.** That's a hardware guarantee with no option to export, sync, or back them up (see 036). What can move between devices is the **seed itself**. The old phone's SE decrypts it, it travels encrypted to the new phone, and the new phone's SE wraps it again with its own key. The owner's instinct (seed only on devices you hold, with transfers approved by a QR) is a sound design. The protocol just needs to be precise.

020 states "no iCloud backup, ever" (`020-in-app-wallet.md:178`, `:274`). This ticket keeps that as the current position but records it as an open question (below).

## Proposed design

### 1. Paper backup (mandatory)

- Creation flow as in 020 Phase 2: warning, display 24 words, verification quiz
- **Verify later:** a reminder 7 and 30 days after creation, with a "check your backup" flow (re-enter 4 random words). Doesn't reveal the words
- **Re-display** the seed behind 036's strongest auth (spend-level), on a secure view (no capture, no switcher snapshot)
- Wallet health indicator: "Backup verified on <date>" / "Backup never verified" ⚠️

### 2. Device-to-device transfer

```
NEW phone                                    OLD phone
─────────                                    ─────────
"Transfer from another iPhone"
generate ephemeral keypair (X25519, CryptoKit)
show QR: {version, session_id, pubkey_new}
                                ──camera──▶  user taps "Transfer to new iPhone"
                                             036 spend-level auth
                                             scan QR
                                             ephemeral keypair_old
                                             shared = ECDH(old_priv, pubkey_new)
                                             key = HKDF-SHA256(shared, session_id ‖ both pubkeys)
                                             ct = ChaChaPoly.seal(bundle, key)
        ◀── local channel: {pubkey_old, ct} ──
derive same key, show 6-digit code            show 6-digit code (from key via HKDF)
user confirms codes match on both screens
decrypt bundle → wrap seed with NEW SE (036)
                                             offer "Remove wallet from this phone"
```

- **Why the QR matters:** the camera scan is an authenticated out-of-band channel. The old phone learns the new phone's public key directly from its screen, so nobody on the network can substitute their own key. The short code is a second check that the local channel wasn't redirected.
- **Local channel:** Multipeer Connectivity or `Network.framework` peer-to-peer (Bonjour + AWDL). That's the same radio technology family as AirDrop, but app-to-app and bound to this session. The payload is already end-to-end encrypted, so the channel only needs to deliver bytes.
- **Fallback channel:** the old phone displays the ciphertext as an animated QR and the new phone scans it. That's slower but needs no radio and no pairing permission.
- **Bundle contents:** seed entropy, main-wallet descriptors and metadata, watch-only wallets, labels (BIP329), People contacts (043), wallet settings. **Never:** passphrases or anything about passphrase wallets (038), chain data.
- **Chain data is not transferred.** The new phone downloads the AssumeUTXO snapshot and syncs normally. Moving 10+ GB phone-to-phone is possible but out of scope. **Open question:** offer it as an option later?
- Both ephemeral keys are discarded after the transfer, and the session expires after 5 minutes.

**Why not plain AirDrop of an encrypted file:**
- The file lands in Files/Downloads, outside our control, and can be picked up by backups.
- AirDrop recipient selection is by name, so the wrong-recipient risk is real.
- The file isn't bound to a specific receiving device.

The QR binding removes all three problems.

### 3. Restore from seed

- Enter 12/24 words (secure per-word fields, BIP39 wordlist autocomplete, checksum validation)
- Choose or auto-detect script types: walk the UTXO set (035) for BIP84 + BIP86 + BIP49 + BIP44 receive/change at once. One walk, four script families
- **Balance correct immediately** after the walk
- **History starts at the snapshot height.** Coins found are shown as "received before history start." UI copy explains why (pruned node + AssumeUTXO)
- Optional import of a BIP329 labels file (JSONL) afterwards

### 4. Export

- **Labels:** BIP329 JSONL via share sheet (works with Sparrow and others)
- **Watch-only descriptors / xpub:** QR + text, for viewing in Sparrow
- **Never** export the seed as a file

### 5. iOS behaviors to handle

- **Restore from iCloud/Finder backup onto a new phone:** `ThisDeviceOnly` Keychain items and SE keys do **not** come across. The app opens with an orphaned wallet DB but no key. Detect this case (wallet DB present, Keychain item missing) and show "Your wallet's key stays on your old iPhone. Transfer from it, or restore from your seed words." Don't show a zero balance as if it were real.
- **App deletion:** Keychain items may persist across reinstall on iOS. Decide whether to wipe on first launch (detect via a UserDefaults sentinel). Recommendation: wipe, so a reinstall gives a clean slate. Discuss, because of the loss risk.

## Files touched

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/Wallet/BackupVerifyView.swift` | **New** |
| `HerculesApp/HerculesApp/Wallet/DeviceTransfer/*.swift` | **New**: QR, CryptoKit session, Multipeer channel, SAS UI |
| `HerculesApp/HerculesApp/Wallet/RestoreView.swift` | **New** |
| `hercules-core/src/wallet_export.rs` | **New**: BIP329 import/export, bundle (de)serialization |
| `hercules-core/src/wallet_scan.rs` | Multi-script-family walk (035) |

## Dependencies

- **036** (auth levels, SE wrap on receive side), **035** (walk), **037** (wallet DB), **043** (contacts in bundle; can come later)

## Estimated effort

2–3 weeks: transfer protocol + UI ~1.5 weeks, restore + verify ~1 week, export ~2 days.

## Verification

- Transfer on two physical iPhones: balances, watch-only wallets, labels identical; old phone wipe works
- Swap the QR mid-transfer for an attacker's (test harness) → codes mismatch → transfer aborts
- Capture the local-channel traffic → ciphertext only
- Restore a mainnet wallet from seed → exact balance vs. external reference; history note shown
- BIP329 round-trip with Sparrow
- iCloud-restore orphan case → clear message, no fake zero balance

## Open questions

- **iCloud backup of an encrypted seed** (Bitkey/Proton-style recovery). Currently banned by 020. Tradeoff: many more users keep their funds after losing a phone, versus the privacy and compulsion risks 020 describes. Keep the ban for v1?
- Should transfer also be allowed *to* a phone that already has a wallet (merge)? Recommendation: no, the new phone must be empty.
- Offer chain-data transfer (skip the snapshot download)?
- Wipe the Keychain on reinstall?

## Roadmap position

After 036/037. Restore-from-seed is required for v1. Device transfer is strongly desired for v1. Export is a small add-on.
