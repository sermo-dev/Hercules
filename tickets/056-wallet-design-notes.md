# Ticket 056: Wallet Design Notes — Owner Discussions (ON HOLD)

**Status: on hold (2026-10-31).** These notes capture the owner discussions of 2026-10-30/31, so nothing is lost while the node hardening (049–055, 025, 029) finishes. Nothing here is final. When wallet work resumes, these feed tickets 036 (custody), 037 (tabs and wallets), 038 (passphrases), 039 (backup and transfer), 035 (scanner) and 020.

## Product shape (owner leaning, agreed in principle)

- **Simple self-custody for normal people, not a Sparrow-style power tool.**
- **One signing wallet** (the main wallet), plus optional **BIP39 passphrase wallets** on top of it.
- **A separate Watch-only tab:** any number of xpub/descriptor imports that can never sign.
- **Creation: 24 words only.**
- **Restore: agreed.** The main wallet can be restored from any standard BIP39 seed (12 or 24 words), not only Hercules-made ones. Hercules words must work in any standard wallet, in both directions. Show a one-time note: if the seed came from a device with a known entropy bug (e.g. 2026 Coldcard), create a new one.
- **External hardware wallets / PSBT signing:** parked as a possible future option, not launch work (owner: feels power-user).

## Seed entropy (owner wants user entropy; to be discussed further)

**Context: the 2026 Coldcard incident.** A build error made seed generation fall back silently to a software PRNG. Mk3 seeds had about 40 bits of entropy; Mk4/Mk5/Q about 72 bits (Coinkite). Users who added 50 or more dice rolls stayed above 128 bits. Lessons:

1. Never fall back silently: refuse to create a seed if the expected source isn't available.
2. Statistical output tests can't detect a deterministic PRNG. Verify which source is used, at build time and at runtime.
3. Mixing in independent user entropy saved users.
4. A commit-reveal (Trezor-style entropy check) makes generation auditable.

**Sources, all mixed through a domain-separated hash** (the result is strong if any one source is):
- iOS `SecRandomCopyBytes`.
- Secure Enclave–derived randomness (e.g. hash the output of an ephemeral enclave key).
- **Default independent source: camera sensor noise plus motion sensors.** The camera is needed for QR scanning anyway; the motion sensors need no permission. The microphone is optional, since a mic prompt in a wallet may alarm users.
- **Advanced, quantifiable sources:**
  - **Dice:** 99 rolls of a d6 ≈ 256 bits. Verifiable offline, like Coldcard's.
  - **Playing cards:** a full 52-card deck entered as rank + suit, after about 7 riffle shuffles, ≈ 226 bits. Suit only ≈ 95 bits; colour only ≈ 49 bits.
- **Rejected ideas, and why:**
  - Shuffled unlabeled buttons, or picking among random on-screen words: the options come from the app's own RNG, so if that RNG is broken only the user's choice pattern is left (≤ log2(k) bits per pick, less with human bias).
  - "Pretend" dice typed from imagination: human sequences are about 1–2 bits per entry and can't be quantified per person.
- **Commit before reveal:** the app shows a fingerprint of its internal entropy before the user adds theirs.
- **Guardrails:** published test vectors, a Rust-only generation path, health checks (all-zero, repeats), and a hard failure if the source check fails.

## Secrets and storage

- **Store the BIP39 entropy (= the words), encrypted. Never store the PBKDF2 seed.** The words → seed step is one-way and depends on the passphrase, so storing only the empty-passphrase seed would make passphrase wallets impossible and the words unrecoverable.
- **The Secure Enclave wraps the entropy.** The enclave holds a P-256 key that never leaves the chip. The ciphertext sits in the Keychain (`ThisDeviceOnly`).
- **The enclave can't sign Bitcoin transactions.** It only does P-256, Bitcoin needs secp256k1, and no third-party code can run inside it. Signing happens in app memory: decrypt, sign in Rust, zeroize within milliseconds, and never put secrets in Swift `String`s.
- **Curves in the app:**
  - secp256k1: Bitcoin keys and signatures.
  - Ed25519 / Curve25519: Tor (our onion address, circuits).
  - P-256: the enclave wrap key.

## Authentication (recommendation, not yet decided)

**Two separate enclave keys with different rules,** so opening the app never unlocks signing:

| Action | Requires |
|---|---|
| Open / view | Face ID **or** device passcode (view key) |
| Sign / send | Face ID **and** a Hercules PIN, every time, with no reuse window (spend key; the enclave combines biometry with an app password, plus our own attempt limits) |
| Reveal seed | Same as send, plus a ~30 s confirmation delay, and only after the backup check |
| Passphrase wallet | The passphrase itself is the second factor |

- **Why the PIN:** it defends against the passcode thief (someone who shoulder-surfs the device passcode, then steals the phone).
- **Re-enrolling Face ID:** recommendation is that it doesn't destroy the key; the PIN is what protects it.
- **Backup check:** after showing the words, ask for a few random positions. Until it passes, cap the balance or show a persistent warning.
- **Seed viewable later** behind the strongest gate (rather than "only once"); losing the paper is the more common way to lose funds.
- **Screenshots:** detect and warn; hide the words in the app switcher.

## Moving to a new phone (039)

1. Paper words → restore.
2. Direct transfer:
   - the new phone shows a QR code with an ephemeral key;
   - the old phone unlocks at spend level and encrypts the entropy, wallet metadata **and history** to it;
   - both phones show a 6-digit code to confirm.
3. No iCloud copy of the seed, ever. SLIP-39 (Shamir) shares are a possible later option.

## History on a pruned node (035)

- **Automatic backfill on Wi-Fi only (owner agreed):** walk backwards from the tip until the wallet's balance was last zero.
  - Keep a set of coins that must have existed earlier: a spend of ours adds the coin, a creation of ours removes it.
  - When the set is empty, history is complete.
- **Use BIP157/158 filters when peers serve them, full blocks otherwise.** The filters include spent scripts, which is what makes Taproot spends visible.
- **The floor** is the oldest current coin's creation height (recorded in the UTXO set). Show "history complete back to block X". Quick partial win: "received" rows for every current coin first.
- Fetch over Tor from varied peers.

## Getting slightly closer to a hardware wallet (owner question, 2026-10-31)

See the answer recorded with this ticket's discussion; candidates to evaluate:
- inputs and amounts verified by our own node;
- what-you-see-is-what-you-sign, decoded from the signed bytes in Rust;
- hedged/deterministic nonces (RFC 6979, BIP 340 aux) so a bad RNG can't leak keys;
- the enclave-enforced PIN;
- jailbreak warning;
- optional delay on large sends;
- reproducible builds.

## Open decisions (when resumed)

1. Default entropy flow: camera + motion as the required step, with dice or cards as advanced — or require dice/cards?
2. Send gate: Face ID + PIN (recommended), a longer password, or user choice?
3. Seed reveal later: allowed behind the strongest gate (recommended), or never?
4. Face ID re-enrollment: keep the key (recommended), or invalidate?
5. Default address type: BIP84 (recommended) vs Taproot; silent-payment scan key policy; wallet data in iCloud backup (recommended: exclude); first TestFlight scope; Apple Developer account type (an organization account is required for wallet apps).
