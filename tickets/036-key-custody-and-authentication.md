# Ticket 036: Key Custody and Authentication

**Status: DRAFT. Needs a design review with the owner before implementation.** This is the highest-priority design item in the wallet track. Nothing here is decided. It records the facts, the options, and the questions to settle.

## Summary

Define how the wallet seed is generated, stored, unlocked, used for signing, and protected. That includes biometric policy, fallbacks, memory hygiene, UI leak surfaces (screenshots, pasteboard, app switcher), and what background push wakes may touch while the phone is locked. Ticket 020 Phase 2 (`020-in-app-wallet.md:138-178`) has a first-cut design. This ticket supersedes it once decided.

## Background: platform facts that constrain every option

- **Secure Enclave (SE) keys are always device-bound.** They're generated inside the SE chip and can never be exported, backed up, synced, or moved to another device. That's a hardware property, not a setting.
- **The SE only does P-256 (secp256r1).** Bitcoin uses secp256k1, so the SE can't hold or use a Bitcoin key directly. The standard pattern, which 020 already describes: an SE-resident P-256 key **wraps** (encrypts) the seed; the ciphertext lives in the Keychain; decrypting it requires SE authorization. The ciphertext is useless on any other device.
- **Signing happens in app memory.** To sign, the seed (or derived private keys) must be decrypted into the app's RAM for the duration of the signing. That's the residual gap versus a hardware wallet. Ticket 020 Phase 3 (PSBT + external signer) is the answer for users who want to close it.
- **Access-control flags on the SE key decide who can unlock:**

| Flag | Unlocks with | Survives Face ID re-enrollment? | Survives passcode change? |
|---|---|---|---|
| `.biometryCurrentSet` | Current enrolled face only | **No.** Key is invalidated, wallet locked until seed restore | Yes |
| `.biometryAny` | Any enrolled face (incl. newly added) | Yes | Yes |
| `.userPresence` | Face ID **or** device passcode | Yes | Yes |
| `.devicePasscode` | Passcode only | n/a | Yes |

  These can be combined with `.or` / `.and`.
- **Keychain accessibility classes:**
  - `WhenUnlockedThisDeviceOnly`: readable only while the phone is unlocked; never migrates.
  - `WhenPasscodeSetThisDeviceOnly`: same, but **the item is deleted if the user ever removes their device passcode**. That's a silent fund-loss risk if the user has no paper backup.
  - `AfterFirstUnlockThisDeviceOnly`: readable while locked, after the first unlock since boot. Needed for anything a push wake reads. **Never for key material.**

## 020's current choice and its problem

020 uses `kSecAccessControlBiometryCurrentSet` (line 149). Its own verification step says "Re-enroll FaceID, observe the wallet locks and refuses to unwrap (the user has to recover from seed phrase)" (line 196). In practice, a user whose face changes, or who resets Face ID after a repair, is locked out of a hot wallet until they find their paper seed. That's a high-severity UX trap for a "simple product."

## Options

### Option 1: Face ID only, invalidated on re-enrollment (020 as written)
- Strongest against someone who knows your passcode (they can't add their face and unlock)
- Worst lockout risk. Requires the paper backup for routine events

### Option 2: Face ID **or** device passcode (`.userPresence`)
- Matches how users think about "my phone." No lockout from biometric changes
- Anyone who knows (or shoulder-surfs) the device passcode can open the wallet. That's the classic iPhone-thief attack: watch the passcode, steal the phone
- Mitigation: an app-level spending PIN on send (see Option 3)

### Option 3: Two layers. Device auth to *view*, separate wallet PIN/password to *spend*
- View balance: Face ID or passcode
- Send / reveal seed: wallet PIN (Argon2/scrypt-stretched, rate-limited, with attempt counter in the Keychain) **and** Face ID
- The PIN defeats the "stolen phone + known passcode" attack. Adds friction to every send
- The owner's sketch ("Face ID + passcode") may mean this. **Confirm.**

### Option 4: Option 3 plus `.biometryCurrentSet` with a PIN recovery path
- If the biometric set changes, the SE key for Face ID is invalidated, but a second SE-wrapped copy gated by the wallet PIN still decrypts. Re-wraps under the new face after PIN entry
- Best of both, but more complexity and two wrapped copies

**Draft recommendation (for discussion): Option 3 or 4.** Device auth for viewing, plus a wallet PIN for spending and seed reveal.

## Other items to decide

- **Devices without biometrics / biometrics disabled.** Passcode + PIN only. Must work.
- **Memory hygiene.** Hold the mnemonic and seed as byte buffers, zeroized after use (`zeroize` crate on the Rust side). Never as Swift `String` (immutable, copied, not zeroizable). Seed entry UI uses custom per-word fields, not a single `TextField`.
- **Screenshot / screen recording.** On seed display and entry screens: detect `UIScreen.capturedDidChangeNotification` and blank the content; warn on `userDidTakeScreenshotNotification`. iOS can't block screenshots, but we can obscure the content.
- **App-switcher snapshot.** Blur or cover wallet views on `scenePhase == .inactive`, so balances and seeds don't appear in the multitasking switcher snapshot.
- **Pasteboard rules.** Current issue: `SettingsView.swift:391` copies the Wallet API connection string, which includes the auth token, to `UIPasteboard.general` with no `localOnly` and no expiry, so it syncs to the user's other devices via Universal Clipboard. Policy for all secrets and addresses: `setItems(_:options: [.localOnly: true, .expirationDate: now+60s])`. Never allow copying the seed at all.
- **Auth timeouts.** Re-lock wallet views after N seconds in background (default 60 s?) and on device lock.
- **Push wakes while locked.** Wakes may read: chain data, wallet *watch scripts* and outpoints (protection class `AfterFirstUnlock`, see 030/037). Wakes must **never** touch key material. This lets arrival notifications work on a locked phone.
- **Jailbreak stance.** Warn only (detection is unreliable and bypassable), or refuse hot-wallet creation? Recommendation: warn, don't block.
- **Watch-only gate.** Device auth, or a separate app password? It ties to 037. Watch-only data isn't key material, so device auth is probably enough. The owner floated a password.
- **Duress / deniability interplay with 038.** The main wallet is what you reveal under coercion. The passphrase wallets are what you don't. Nothing in custody design may leave evidence of passphrase use (no "last passphrase used" timestamps, no cached fingerprints).
- **Seed generation.** `SecRandomCopyBytes` → 256-bit entropy → BIP39 24 words. Option to import 12/24. Option to add dice entropy? (Advanced; probably later.)

## Threat model

| Adversary | Option 1 | Option 2 | Option 3/4 |
|---|---|---|---|
| Thief, locked phone, no passcode | Safe | Safe | Safe |
| Thief who saw passcode | Safe (can't enroll face… but can reset Face ID → locks *you* out) | **Funds lost** | Safe unless PIN also known |
| Malware on non-jailbroken iOS | Sandbox protects | Same | Same |
| Kernel exploit / jailbreak | Seed exposed during signing | Same | Same |
| Coerced unlock ($5 wrench) | Main wallet revealed; passphrase wallets deniable (038) | Same | Same |
| Apple / iCloud / subpoena | Nothing in iCloud (ThisDeviceOnly) | Same | Same |
| Our push relay | Sees nothing wallet-related | Same | Same |
| Lost phone, no paper backup | **Funds lost** | **Funds lost** | **Funds lost** (039 device transfer helps only if old phone still works) |

## Files touched (expected, once decided)

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/Wallet/KeyCustody.swift` | **New**: SE wrap/unwrap, Keychain items, LAContext policy |
| `HerculesApp/HerculesApp/Wallet/WalletPIN.swift` | **New** (if Option 3/4) |
| `HerculesApp/HerculesApp/Wallet/SecureViews.swift` | **New**: capture-blanking, switcher cover |
| `HerculesApp/HerculesApp/SettingsView.swift` | Pasteboard fix at :391 |
| `hercules-core/src/wallet_signing.rs` | Zeroizing key buffers; accept seed bytes, never strings |

## Dependencies

- **034** (engine), for where signing lives
- Informs **037**, **038**, **039**, **043**

## Estimated effort

Design review: 1–2 sessions. Implementation: 1.5–2.5 weeks depending on option (Option 4 is the upper end).

## Verification (once decided)

- Re-enroll Face ID → behavior matches the chosen option (no silent lockout unless Option 1 was chosen deliberately)
- Remove device passcode → wallet behavior documented and tested; no silent deletion without warning
- Memory: after a send, scan process memory (debug build) for seed bytes → none
- Screen recording active → seed screen blanked; app switcher → wallet covered
- Copy address → `localOnly` + expiry set; seed copy impossible
- Push wake on locked phone → arrival detected, no Keychain key-material read attempted (log audit)

## Open questions for the owner

1. Which option: 2, 3, or 4? And does "Face ID + passcode" mean device passcode or a wallet PIN?
2. Is a send-time PIN acceptable friction for v1?
3. Watch-only gate: device auth or separate password?
4. Jailbreak: warn or block?
5. Timeout defaults.
6. Is `.biometryCurrentSet`'s lockout ever acceptable, e.g. as an opt-in "paranoid mode"?

## Roadmap position

Design discussion now, in parallel with Tier 0. Implementation after 034/035, before any hot-wallet UI ships.
