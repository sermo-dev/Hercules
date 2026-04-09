# Ticket 020: In-App Wallet — Self-Contained Node + Wallet

## Summary

Embed a full Bitcoin wallet inside the Hercules iOS app so the same process that validates blocks also lets users hold, receive, and send Bitcoin. No external wallet, no IPC, no network round-trip — the wallet calls into the node via direct Rust function calls (or the existing UniFFI bridge for Swift-side state). The result is the **first and only iOS Bitcoin wallet where every UTXO displayed has been personally validated against consensus by the device in the user's hand**, with **arrival notifications that land within seconds of a block**, and where **no wallet operation ever leaks information to a third party**.

This ticket is **complementary** to ticket 014, not a replacement. Ticket 014 makes Hercules a backend for *external* wallets (Sparrow on a desktop, etc.) over a Tor onion JSON-RPC. Ticket 020 makes Hercules a *self-contained* wallet for users who want one app that does everything. Different audiences, different reachability constraints (014 is foreground-only because of iOS; 020 is foreground-and-push-wake), both legitimate.

## Background

The architectural insight underneath this ticket is that **bringing the wallet inside the same process as the node sidesteps every iOS background-execution problem**. iOS will not let a suspended app accept inbound TCP connections, so a Tor-onion-fronted wallet API (ticket 014) is only reachable when the user has Hercules in the foreground. But an in-app wallet doesn't need inbound connectivity at all — its "client" (the Hercules UI) is the same process. Whenever the user opens the wallet tab, both the wallet code and the node code are by definition running, because they're literally the same binary.

This unlocks three things that no other iOS Bitcoin wallet currently delivers, and that fall out of Hercules's existing architecture without significant new infrastructure.

## The three killer wins (load-bearing for the product story)

These are not "nice to have." They are the entire justification for this ticket. Each one is a feature people will switch wallets over.

### 1. Zero-hop validation provenance

Every UTXO the wallet displays was validated against consensus by *this exact device*, against *this exact UTXO set*, with *this exact AssumeUTXO trust anchor*. No other iOS wallet can claim this:

- **Sparrow + public Electrum server**: trusts a third party for chain state
- **BlueWallet / Muun / Phoenix / Wasabi / Samourai / etc.**: SPV or LSP-backed, trusts external chain data
- **Sparrow + your own home node** (the desktop gold standard): equivalent trust, but requires a separate machine running 24/7 + a Wi-Fi or Tor link back home

Hercules-as-wallet collapses the desktop "Sparrow + home Bitcoin Core" two-machine setup into a single phone process. The trust chain is `wallet → node → consensus rules`, all within one app on hardware in the user's pocket.

This is the strongest custodial trust model that has ever existed on iOS. The product line becomes: *"every satoshi you see has been validated by you, on the device in your hand, against the same rules every other Bitcoin Core node enforces."*

### 2. Instant arrival notifications via the push-wake architecture

When a new block lands and Hercules wakes for validation (per the relay deployment in ticket 019), it already has the BIP158 filter for that block in hand because it just computed it during validation. Checking the filter against the wallet's address set takes microseconds. If there's a match, fetch the relevant transactions from the just-validated block, extract the wallet-relevant outputs, and post a local notification — all within the same ~25-second push-wake window.

The end-to-end latency from "miner finds the block" to "your phone shows '+0.0042 BTC received'" is on the order of **5-15 seconds**: Bitcoin Core relay → blocknotify hook → SQS → Lambda → APNs → phone wakes → header fetch → block fetch → validation + filter check → local notification.

Compare to other wallets:
- **BlueWallet** polls its Electrum server every ~60s when in foreground, less often when backgrounded
- **Phoenix / Muun** poll their LSP backends with similar cadence
- **Sparrow on desktop** receives a `blockchain.scripthash.subscribe` push when its electrs notices the change (which is fast), but only if Sparrow is open
- **Most wallets show received funds within 1-10 minutes of the block** because they're all polling something on a timer

Hercules-as-wallet would notice new payments within seconds of the block landing, *whether or not the user has the app open*, because the block-validation wake cycle handles it. This is genuinely a killer feature and probably the single most marketable thing in the entire product.

### 3. Privacy by default and by construction

Every wallet operation is local. No xpub leaking to an Electrum server. No "what's my balance?" query that telegraphs your addresses to a third party. No leak of which addresses you watch. Address scanning happens against filters Hercules computed itself. Transaction broadcast happens through Hercules's own peers over its own Tor circuits. Even Wasabi (the privacy gold standard) leaks per-coin metadata to its CoinJoin coordinator; Hercules's in-app wallet leaks **nothing to anybody**.

The threat model: a global passive adversary watching all internet traffic learns nothing about which addresses belong to a Hercules user, because no observable network operation is correlated with any specific address. Outbound P2P (block fetch, tx broadcast) goes over Tor. Inbound P2P (other Bitcoin nodes pinging us) goes over Tor. The only network surface is the Hercules push-notification relay, which sees only "this device wants block notifications" — no address data, no balance data, no wallet correlation. The push relay can be compromised entirely without leaking anything wallet-relevant.

This is a meaningful privacy improvement over every other iOS wallet, and it costs nothing to deliver because Hercules is already routing everything over Tor for the node use case.

## Why we don't need an external indexer (electrs)

Most Bitcoin wallets that aren't directly tied to a Bitcoin Core wallet rely on an external indexer (electrs, ElectrumX, Fulcrum) to answer "what UTXOs belong to this script" and "what's the transaction history of this address." Hercules doesn't need one. This is the load-bearing technical insight underneath the ticket.

|  | Bitcoin Core alone | Bitcoin Core + electrs | **Hercules in-app wallet** |
|---|---|---|---|
| Find unspent outputs paying script X | `scantxoutset` (slow, not exposed to standard wallet RPCs) | Constant-time via script-keyed index | **One-time UTXO walk at import (~90s), then cached** |
| Track new activity going forward | Only descriptors registered before they receive funds | Index updates on each block | BIP158 filter check on each validated block |
| Historical history for already-spent outputs | Requires `txindex=1` + full chain (impossible on pruned) | Yes, full from genesis | Pre-import: not available. Post-import: yes |
| Subscribe / push on script activity | None | Yes, via Electrum protocol | Yes — and within seconds of block, via the push-wake architecture |
| Storage cost of the indexing layer | ~30 GB for `txindex` | Additional ~30 GB | **Zero — uses existing UTXO set** |

The single capability we give up — "historical transaction history for outputs spent before the wallet was imported" — affects only imported old wallets, and only for line items whose outputs are now fully consumed. Current balance is correct. Send capability is correct. All post-import activity is perfectly tracked. The missing case is "show me that I received 1 BTC in 2019 and spent it in 2020" when the resulting UTXOs no longer exist anywhere in the current chain state. For the vast majority of users, this is invisible.

Bitcoin Core could in principle take this same approach but doesn't because Core is built around the "register descriptors first, track forward" model. Hercules can take it because (a) the LMDB UTXO set is local and walks fast, (b) BIP158 filter computation is already happening for SPV serving, and (c) the wallet shares a process with the node so there's no IPC.

## Phasing

Three phases, each independently shippable. Phase 1 proves the architecture without committing to key custody. Phase 2 ships the main hot-wallet experience. Phase 3 supports cold storage via PSBT.

---

### Phase 1 — Watch-only wallet

Read-only wallet that imports an xpub, scans the UTXO set for current balances, and tracks new activity going forward. No private keys. No signing. No key custody decisions. This phase exists to prove the scanning architecture and ship a usable receive-side wallet quickly.

**Functionality:**
- Import an xpub (via paste, QR scan, or from another Hercules wallet)
- Derivation path selection: BIP44 (legacy), BIP49 (nested-segwit), BIP84 (native-segwit), BIP86 (taproot). Default to BIP84.
- Address derivation: receive chain (`m/.../0/i`) and change chain (`m/.../1/i`), gap limit configurable (default 20)
- One-time UTXO set scan at import: walk LMDB `utxos` table, check each entry's `scriptPubKey` against the wallet's derived script set, populate the wallet's known-outpoint cache. Show a progress bar. Expected duration: 30-120 seconds depending on UTXO set size and device.
- Ongoing block tracking: hook into the existing `apply_block` path. After each block is validated, compute its BIP158 filter (if not already), check the filter against the wallet's address set. If hit, fetch the block from `BlockStore`, extract relevant txs, update the wallet's known-outpoint cache (add new UTXOs, remove spent ones).
- Receive screen: generate next unused address, render as QR code, copy button, BIP21 URI support
- Balance display: confirmed / unconfirmed / total, in sats and (optional) fiat
- Transaction history view: list of txs touching the wallet's addresses, sorted by height (with mempool entries on top), per-tx details (txid, fee, confirmations, amounts, addresses)

**New Rust modules:**
- `hercules-core/src/wallet.rs` — wallet state (xpub, derivation path, known outpoints, scan progress), import scan, ongoing scan hook
- `hercules-core/src/wallet_store.rs` — LMDB or SQLite persistence for the wallet's known outpoints, observed transactions, and scan checkpoint

**New Swift surfaces:**
- `WalletView` — main wallet tab with balance + history + receive + send buttons (send disabled in Phase 1)
- `WalletImportView` — paste xpub, select derivation path, kick off scan
- `ReceiveView` — QR code + address + copy + share
- `TransactionDetailView` — per-tx view

**UDL exports:**
```
dictionary WalletBalance {
    u64 confirmed_sats;
    u64 unconfirmed_sats;
};

dictionary WalletTx {
    string txid;
    i64 net_amount_sats;
    u32 height;
    u32 confirmations;
    u64 fee_sats;
    sequence<string> addresses;
    u64 timestamp;
};

interface HerculesWallet {
    [Throws=WalletError]
    constructor(string xpub, DerivationPath path);
    
    [Throws=WalletError]
    void rescan();
    
    WalletBalance get_balance();
    sequence<WalletTx> get_transactions(u32 limit);
    string next_receive_address();
};
```

**Verification:**
- Import a known xpub from a wallet with known-current balance, observe correct balance after scan
- Send to a derived address from another wallet, observe arrival notification within seconds (during a push-wake) and the new tx in history
- Restart Hercules, observe the wallet state persists and no rescan is needed
- Force-quit during scan, observe scan resumes from checkpoint on next launch
- Import a wallet with > 1000 historical addresses, observe correct gap-limit handling (don't stop at 20 if there are funds beyond)

---

### Phase 2 — Hot wallet with Secure Enclave custody

Adds key custody, seed management, and signing. After this phase, Hercules is a full wallet capable of holding and spending Bitcoin without an external signer.

**Key custody — the Secure Enclave wrapping pattern:**

iOS Secure Enclave only supports P-256 (NIST `secp256r1`), not Bitcoin's `secp256k1`. The seed cannot live "in the SE" natively. Standard pattern (used by every serious iOS Bitcoin wallet):

1. **Seed generation**: BIP39 mnemonic (24 words) generated using `SecRandomCopyBytes`, derived secp256k1 master key in app memory using the bundled `secp256k1` C library
2. **SE wrapping key creation**: P-256 private key generated inside the Secure Enclave with:
   - `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave` (binds to the SE chip)
   - `kSecAttrAccessControl` with `kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet` (FaceID gate, invalidates if biometrics change)
   - `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (no iCloud sync, no transfer, no backup)
3. **Seed encryption**: ECIES encrypt the BIP39 seed bytes with the SE-resident wrapping key. The ciphertext is stored in regular Keychain (also `WhenUnlockedThisDeviceOnly`, `Synchronizable = false`)
4. **Signing flow**: User taps "Send" → FaceID prompt → SE decrypts the wrapped seed → seed is briefly in app RAM → secp256k1 signing happens in app RAM → seed is wiped from RAM → PSBT is finalized → broadcast via the existing peer pool

**Security properties of this design:**
- ✅ Seed never leaves the device (no iCloud, no backup outside the encrypted blob)
- ✅ Decryption requires biometric or passcode auth via the SE wrapping key
- ✅ Re-enrolling FaceID invalidates the wrapping key (`BiometryCurrentSet`)
- ✅ The encrypted blob is useless without the specific Secure Enclave it was wrapped against
- ⚠️ Seed is briefly in plain app RAM during signing — the residual gap vs. a hardware wallet, gated by FaceID and bounded in time. iOS sandboxing prevents cross-app reads; a kernel-level exploit could in principle observe it. This is exactly the threat model that justifies hardware wallets, which Phase 3 supports for users who want stronger guarantees.

**Wallet creation flow (Swift):**
1. New wallet onboarding screen with three options: "Create new wallet" / "Import seed phrase" / "Import xpub (watch-only)" — the last reuses Phase 1
2. For "Create new":
   1. **Pre-creation warning screen** (full-screen modal, must scroll + tap "I understand"):
      > **Your seed phrase is the only backup of this wallet.**
      > 
      > Hercules will never upload your seed phrase to iCloud, our servers, or any cloud backup — by design. This is what makes your wallet truly yours.
      > 
      > **If you lose this phone and have not written down your seed phrase, your funds are gone forever. We cannot recover them. Nobody can.**
      > 
      > Before continuing, get a pen and paper (or a metal backup plate). You will need to write down 24 words and store them somewhere safe and offline.
   2. Generate 24-word BIP39 mnemonic, display once with a "I have written this down" confirmation
   3. Verification quiz (re-enter 4 random words) — refuses to complete creation if the user can't reproduce the words. This is the only chance to verify the backup.
   4. SE wrapping + Keychain storage. Mnemonic is wiped from RAM after the user confirms.
3. For "Import seed phrase": paste / type 12 or 24 words, validate checksum, derive, SE wrap. Same warning as above is shown post-import as a "your backup is the seed phrase you just typed — make sure you have it stored safely" reminder.
4. After either path: same UTXO scan + ongoing tracking as Phase 1.

**Hard design decision (no iCloud backup, ever):** Hercules will not offer cloud-backed seed storage in any form. Not iCloud Keychain. Not iCloud Drive. Not encrypted-with-user-passphrase-uploaded-to-our-relay. Not any third-party backup service. The seed exists exactly two places: encrypted in this device's local Keychain (SE-wrapped), and on whatever physical medium the user wrote it down on. Users will lose funds because of this. We accept that trade-off because the alternative — any cloud backup path, no matter how encrypted — creates a class of user who *thinks* their wallet is privacy-pure when it isn't, and creates a target for legal compulsion or account compromise that we can't defend against. The pre-creation warning is the mitigation; user education is the strategy; lost funds from lost phones with no backup are the acceptable cost of the privacy property.

**Send flow (Swift + Rust):**
1. Send screen: paste address (or scan QR), enter amount (sats or fiat), or "send max"
2. Fee selection slider showing real fee rates from the local mempool (using ticket 008's mempool module): 1-block / 6-block / 24-block / custom. Each option shows the estimated total fee and confirmation time.
3. RBF flag (default ON) — sets the BIP125 sequence number
4. Coin selection: branch-and-bound from the wallet's known-outpoint set, with a fallback to knapsack
5. Change address: derived from the change chain, BIP84 by default
6. Review screen: from address(es), to address, amount, fee, total, change address, RBF flag, raw PSBT preview (collapsed by default)
7. Confirm → FaceID prompt → seed unwrap → sign in RAM → seed wipe → final tx → push to local mempool → relay to peers via existing peer pool's tx-relay path
8. Status screen: "Broadcasting..." → "Sent (in mempool)" → "Confirmed (1/6/...)" tracked via ongoing scan

**RBF / CPFP integration:**
- Replace-by-fee: from the transaction detail view, "Bump fee" button. Reuses ticket 009's RBF logic on the receiving side; constructs a replacement tx with higher fee, signs, broadcasts.
- Child-pays-for-parent: from the same view, "Bump received tx" for unconfirmed incoming txs whose parents are stuck. Reuses ticket 010's CPFP ancestor tracking.

**Verification:**
- Create a new wallet, write down the seed, restart the app, observe FaceID prompt unlocks the wallet
- Re-enroll FaceID, observe the wallet locks and refuses to unwrap (the user has to recover from seed phrase)
- Send a small amount to another wallet, observe correct fee, RBF flag set, broadcast confirmed via external block explorer
- Bump fee on an unconfirmed tx via RBF, observe the replacement appears and the original is evicted
- Receive a tx, observe the arrival notification within seconds during the next push-wake
- Force-restart during a send (between sign and broadcast), observe no double-spend / no funds loss
- Memory-dump test: verify the seed is actually wiped from RAM after signing (use `OSAllocatedUnfairLock` or equivalent zeroing pattern)

---

### Phase 3 — Cold wallet via PSBT-QR

Adds support for keeping the seed entirely off the iPhone, by exchanging PSBTs with an external signing device (ColdCard, SeedSigner, Foundation Passport, Keystone, Jade, or another phone running an air-gapped signer).

**Functionality:**
- Wallet creation flow gains a fourth option: "Pair with hardware wallet" — imports the hardware wallet's xpub via QR scan, registers it as a watch-only wallet from Hercules's perspective, but with PSBT-signing UX in the send flow
- Send flow becomes: construct PSBT → display as animated QR code (BBQr or UR2 encoding for large PSBTs) → user scans with hardware wallet → hardware wallet signs → user scans the signed PSBT back into Hercules via the iPhone camera → Hercules finalizes and broadcasts
- Multi-sig support: register multiple xpubs (via QR), specify quorum (m-of-n), construct multi-sig descriptors, send flow constructs multi-sig PSBTs that round-trip through multiple signers

**Animated QR considerations:**
- Use BBQr or UR2 (both are well-supported by major hardware wallets) for chunked PSBT encoding
- Receive side uses `AVCaptureSession` with frame-by-frame parsing
- Configurable density (frames per second) so users with older hardware wallets can slow it down

**Verification:**
- Pair a ColdCard, send a tx via PSBT-QR round-trip, observe successful broadcast
- Pair a SeedSigner, same test
- 2-of-3 multi-sig with two ColdCards and one Hercules-as-signer: send a tx requiring two signatures, observe the round-trip
- Test PSBTs with many inputs / outputs (large PSBT, multi-frame QR): observe correct chunking and reassembly

---

## Files modified / created

| File | Action | Phase |
|---|---|---|
| `hercules-core/src/wallet.rs` | **New** (wallet state, scanning, balance, history) | 1 |
| `hercules-core/src/wallet_store.rs` | **New** (LMDB persistence for wallet state) | 1 |
| `hercules-core/src/wallet_signing.rs` | **New** (PSBT construction, secp256k1 signing, coin selection) | 2 |
| `hercules-core/src/wallet_psbt_qr.rs` | **New** (BBQr/UR2 encoding) | 3 |
| `hercules-core/src/sync.rs` | Modify (hook wallet scan into apply_block path) | 1 |
| `hercules-core/src/lib.rs` | Modify (export new wallet types via UniFFI) | 1, 2, 3 |
| `hercules.udl` | Modify (new wallet types and methods) | 1, 2, 3 |
| `HerculesApp/HerculesApp/Wallet/WalletView.swift` | **New** | 1 |
| `HerculesApp/HerculesApp/Wallet/WalletImportView.swift` | **New** | 1 |
| `HerculesApp/HerculesApp/Wallet/ReceiveView.swift` | **New** | 1 |
| `HerculesApp/HerculesApp/Wallet/TransactionDetailView.swift` | **New** | 1 |
| `HerculesApp/HerculesApp/Wallet/SendView.swift` | **New** | 2 |
| `HerculesApp/HerculesApp/Wallet/SeedManagement.swift` | **New** (SE wrapping, FaceID, Keychain) | 2 |
| `HerculesApp/HerculesApp/Wallet/HardwareWalletPairing.swift` | **New** | 3 |
| `HerculesApp/HerculesApp/Wallet/PsbtQrScanner.swift` | **New** | 3 |
| `HerculesApp/HerculesApp.entitlements` | Audit (Keychain Sharing not needed; no iCloud Keychain) | 2 |

## Dependencies

- **Phase 5 / ticket 008** (mempool) — required for fee estimation in the send flow. ✅ Already complete.
- **Phase 5 / ticket 008** (BlockStore for the 288-block window) — required for fetching matched blocks during ongoing scan. ✅ Already complete.
- **Ticket 009** (RBF) and **ticket 010** (CPFP) — required for fee-bumping in the send flow. ✅ Already complete.
- **Ticket 019** (relay deployment) — strongly recommended before Phase 2 ships, because the "instant arrival notifications" killer win depends on the push-wake architecture being live.
- **Ticket 014** (external wallet onion API) — **not** a dependency. Tickets 014 and 020 are independent and complementary.
- **`secp256k1` crate** — already in `Cargo.toml` via `bitcoin 0.32`
- **`miniscript` crate** — for output descriptor parsing and address derivation. This is the canonical Rust descriptor library; BDK uses it internally. We use it directly. **Decision: hand-rolled wallet built on `bitcoin` + `miniscript` + `bip39`, not BDK.** Reasoning: BDK is designed for the wallet-talks-to-remote-backend model; our wallet shares a process with the node, so BDK's `ChainSource` abstraction is fighting our actual architecture. We get the *useful* parts of BDK (descriptor parsing via `miniscript`, PSBT via `bitcoin::psbt`) without the dep weight or the integration friction. Coin selection (~400 lines BnB+knapsack) we write ourselves. Wallet state lives in the same LMDB environment as the rest of Hercules's state for transactional consistency.
- **`bip39` crate** — small, single-purpose, well-maintained. For mnemonic generation and validation.
- **BIP39 word list** — bundled with the `bip39` crate, ~30 KB
- **BBQr / UR2 encoding library** — Phase 3 only. Likely a small Rust port; both formats are simple

## Estimated effort

- **Phase 1 (watch-only)**: ~2-3 weeks. The UTXO scan + filter-based ongoing tracking is the most novel piece; everything else is straightforward.
- **Phase 2 (hot wallet)**: ~4-6 weeks. Bulk of the UX work. Send flow with fee selection, seed management, SE integration, RBF/CPFP UX.
- **Phase 3 (PSBT)**: ~2-3 weeks. Mostly QR plumbing and testing against real hardware wallets.

Total: ~2-3 months of focused work, depending on UX polish.

## Out of scope (permanent product decisions, not deferred features)

These are not "we'll get to it later." They are deliberate exclusions from the Hercules product, period.

- **Lightning Network.** Hercules is a native Bitcoin product. No embedded LDK, no LND, no channel state management, no watchtowers, no LSP integration. Lightning is a different product with different threat models, different lifecycle requirements, and a different user. Users who want Lightning should use a Lightning-specific wallet (Phoenix, Mutiny, Zeus). Hercules will not bridge to Lightning at any layer.
- **iCloud or any cloud-based seed backup.** See the Phase 2 design decision above. The seed lives in two places: encrypted in this device's local Keychain, and on the user's physical backup. No third place. Ever.
- **Custodial fallback.** No "if you lose your phone we can recover" path. There is nothing to recover from on our end because we never have anything to recover.
- **KYC, identity verification, address screening, blacklists.** Hercules has no concept of who its users are and never will. We do not screen addresses against any list. We do not refuse to broadcast transactions based on their content. The mempool policy in ticket 018 (Knots-aligned filtering of data-payload protocols) is the *only* policy choice Hercules makes about transaction content, and it's a relay-policy decision, not a censorship one — filtered txs are still valid Bitcoin and will confirm if a miner mines them.

## Open questions

- **Default derivation path**: BIP84 (native segwit) is the safe modern default. BIP86 (taproot) is increasingly correct for new wallets but has slightly worse compatibility with older receivers. Recommendation: BIP84 default, BIP86 as a one-tap upgrade in Settings.
- **Gap limit**: BIP44 says 20. Some power users want higher (100+) for heavy reuse scenarios. Recommendation: 20 default, configurable in Settings, increased automatically during import scan if hits are found beyond the current limit.
- **Coin selection algorithm**: branch-and-bound is the modern standard (used by Bitcoin Core 0.17+). Knapsack is the fallback. Recommendation: BnB primary, knapsack fallback, consistent with Core.
- **Change address rotation**: each send generates a new change address by default. Settings option to reuse a single change address for users who prefer fewer addresses. Recommendation: rotate by default.
- **BIP47 / BIP352 (Silent Payments) support**: would dramatically improve receive privacy by not requiring address reuse. Out of scope for v1; track as a follow-up. BIP352 is the more interesting one because it doesn't require sender cooperation.
- **Multi-wallet support**: one Hercules instance, multiple named wallets? Probably yes eventually, but v1 ships single-wallet for simplicity.
- **Fiat display**: requires a price source. Recommendation: optional, off by default, fetched over Tor from a configurable price feed (or aggregated from several). Not critical for v1.
- **Address book / labels**: nice-to-have. Track separately.
- **Wallet export**: should the user be able to export an xpub to use with another wallet (e.g., to view in Sparrow)? Yes — share button on the wallet detail screen. Read-only export, no seed.
- **Phasing relative to ticket 003** (cooperative historical validation): ticket 020 phases can land around / interleaved with ticket 003. They don't share files. Recommendation: 020 Phase 1 → 020 Phase 2 → ticket 003 → 020 Phase 3, so the wallet ships sooner and PSBT support comes after the cooperative validation experiment.

## Roadmap position

The locked-in roadmap was **14 → 15 → 16 → 17 → 12 → 18 → 19 → 3** (skipping 02, post-launch). With ticket 020 added:

**14 → 15 → 16 → 17 → 12 → 18 → 19 → 20 (Phase 1) → 20 (Phase 2) → 3 → 20 (Phase 3) → 02 (post-launch)**

Reasoning:
- 020 Phase 1 lands after 019 because by then the relay is live and the "instant arrival notifications" killer win can ship in Phase 2 immediately afterward
- 020 Phase 2 follows immediately because Phase 1 is the architecture proof and Phase 2 is where the real product lands
- Ticket 003 (cooperative historical validation, the experimental piece) slots in between 020 Phase 2 and Phase 3 — by then the wallet's main hot path is shipped, the node is rock solid, and 003 is research work that benefits from the operational maturity
- 020 Phase 3 (PSBT for cold wallet) is last because it's a power-user feature and the hot wallet covers the median user

After **020 Phase 3** lands, Hercules is a complete self-sovereign Bitcoin product: validating node, full mempool participant, hot and cold wallet, push-wake notifications, all-Tor network surface, in a single iOS app. The only remaining ticket would be 02 (utreexo / compact UTXO), which is an optional optimization, not a missing capability.
