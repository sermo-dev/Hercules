# Ticket 043: People Tab — Contacts and Person-to-Person Payments

## Summary

Add the third top-level tab, **People** (name TBD; see Open questions): the people you transact with. It works like a built-in Venmo, except every payment is an ordinary on-chain Bitcoin transaction routed through the P2P network, with no server, account, or intermediary. You add a friend once, by scanning their QR or opening a link they sent. After that, paying them is: pick person → amount → Face ID.

The payee primitive is **Silent Payments (BIP352)**. Each user has one static, reusable code (`sp1…`). Anyone holding it can derive a **fresh, unique address for every payment**, so there's no address reuse, no notification transaction, and no server to look up addresses. The receiver finds payments by scanning blocks. Light wallets find that scanning expensive. For Hercules it's nearly free, because the node already validates every block and resolves every input's prevout.

## Background

- **No identity concept exists today.** The only identifier anywhere is the APNs device token used for push registration (`HerculesApp/HerculesApp/NotificationManager.swift:70-91`, `server/register/index.js:22`). The P2P layer has a persistent onion key (`hercules-core/src/tor.rs`), which is public by design.
- **020 deferred this.** `tickets/020-in-app-wallet.md:284` lists BIP47 / BIP352 as out of scope for v1. `:287` lists address book / labels as "track separately". This ticket is that follow-up, promoted into v1 scope by the owner's vision.
- **Why not BIP47 (PayNyms)?** BIP47 requires the sender to publish an on-chain *notification transaction* to each new recipient before the first payment. That costs a fee, is visible on-chain, and links the two parties' payment codes for anyone watching. BIP352 needs no notification transaction and no sender–receiver interaction beyond knowing the code.

### Identity question (owner asked)

> "This likely involves some sort of unique_hash to represent the device/user — also likely relevant for the relay push notification."

**Recommendation: no shared identifier. Keep them strictly separate.**

| Identifier | Purpose | Who sees it | Must never be linked to |
|---|---|---|---|
| APNs device token | Waking the phone on new blocks (019) | Apple, our push relay | Contacts, payment codes, wallet |
| P2P onion address | Inbound Bitcoin P2P peers | The whole P2P network | Contacts, wallet. Linking it would de-anonymize the user's node |
| **Silent payment code** | Being paid by contacts | People you share it with | Push registration, P2P identity |

The **contact identity is the silent payment code itself.** It's derived from the wallet seed (BIP352 scan and spend keys), so it survives device migration (039) with no server-side account. If the relay never sees anything wallet-related, a breach or subpoena of the relay reveals no social graph.

## Proposed design

### Data model (local only, in the app's wallet store)

```
Contact {
  id: UUID (local),
  display_name: String,
  avatar: local image (never uploaded),
  sp_code: String,              // sp1q…, validated on import
  note: Option<String>,
  created_at, last_paid_at,
}
```

Per-contact history = transactions whose outputs we created to that contact's derived addresses, plus incoming payments we can attribute (see Open questions).

### Flows

1. **My code:** People tab header shows "Your payment code" as a QR, a share sheet and a copy action. Sharing sends a link (custom URL scheme / universal link) carrying the `sp1…` code and an optional display name. This is static data and needs no server.
2. **Add person:** scan QR, open a shared link, or paste. Validate the BIP352 encoding, then prompt for a name.
3. **Pay person:** pick contact → amount (sats/BTC/fiat) → fee tier (041) → review → Face ID (036) → derive the BIP352 output from our selected inputs and their code → sign → broadcast (033). The tx is labeled with the contact's name locally (042).
4. **Request:** "Request 50,000 sats from Alice" produces a shareable BIP21 payment request (`bitcoin:?sp=…&amount=…`, per BIP21/BIP321 conventions; verify exact `sp` parameter support in BIP321) that the user sends however they like (Messages, Signal). There's no server and no inbox.
5. **History per person** and a combined feed.

### Receiving (scanning)

- BIP352 receiving: for each eligible transaction (taproot outputs, eligible input types), compute a shared secret from the sum of input pubkeys and our scan key, then check derived outputs. That's roughly one EC multiplication per eligible tx per block.
- Hercules resolves every prevout during validation (`validate_block_scripts`, `hercules-core/src/block_validation.rs:221`), so the input pubkeys are already in hand. Hook into the same per-block scan as ticket 035.
- **Cost check required:** measure the per-block scan time on an iPhone during a ~25 s wake (028 budget). If it's too slow, defer scanning to foreground or catch-up runs, and keep block validation in the wake.
- Coins found go into the wallet like any other UTXO. Labels distinguish "received via silent payment".

### Multi-wallet interplay

- The main wallet has one sp code. Each passphrase wallet (038) naturally derives its own. Those are only shown and scanned while that hidden wallet is unlocked, and they never appear in People otherwise.
- Watch-only wallets (037) can't scan silent payments without the scan *private* key. Out of scope unless a scan-key import is added later.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/silent_payments.rs` | **New**: BIP352 send derivation, receive scanning, code encode/decode |
| `hercules-core/src/wallet*.rs` | Contacts store, attribution, labels |
| `hercules-core/src/sync.rs` (035 hook) | Per-block SP scan alongside the WatchSet scan |
| `hercules.udl` | Contact CRUD, my-code, pay-contact, request-link |
| `HerculesApp/.../People/*` | **New** tab: list, detail, add (scan/link), pay, request |
| `HerculesApp/HerculesApp.swift` / Info.plist | URL scheme or universal link for contact and request links |

## Dependencies

- **037** tab structure. **036** key custody (scan/spend keys). **034** library choice (BIP352 support in BDK or a dedicated crate; evaluate maturity). **035** per-block scanner. **033** broadcast. **041** fees. ❌ all.

## Estimated effort

~2-3 weeks: BIP352 implementation or integration plus test vectors (4-6d), scanner hook and wake benchmarking (2-3d), contacts store and links (2d), UI (4-5d).

## Verification

- BIP352 official test vectors pass, for both send and receive.
- Two devices: A adds B by QR, pays B; B detects the payment within one block wake; the address differs on every payment.
- Wake budget: SP scan of a full mainnet block measured on the oldest supported iPhone.
- Privacy check: relay logs and push payloads contain nothing contact-related.

## Open questions

- **Tab name.** "Peers" clashes with Bitcoin P2P peers shown in the Node tab. Candidates: People, Contacts, Friends, Pay. Recommendation: **People**.
- **Incoming attribution.** BIP352 doesn't tell the receiver *who* paid. Options: BIP352 labels (a distinct sub-code per contact, so payments to Alice's label are attributed to Alice), or no attribution. Recommendation: per-contact labels. Check how that affects scanning cost.
- **Directory or discovery?** None in v1. All exchange is in person or by link. A future optional, privacy-preserving directory is out of scope.
- **Encrypted contact-to-contact messages / "payment sent" notifications.** Out of scope. Any carrier would learn the social graph.

## Roadmap position

Vision tier. After the wallet foundations (033-039) and the tab scaffold (037). The flagship user-facing feature of v1.
