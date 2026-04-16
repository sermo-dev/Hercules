# Ticket 021: Quantum-Safe Pubkey Exposure Indicator

## Summary

Add a small visual indicator to the wallet (from ticket 020) that tells the user whether any of their current UTXOs have had their public keys exposed on-chain. If every UTXO the wallet currently holds is sitting in an output type that hides its pubkey until spend, *and* none of the addresses holding those UTXOs have been spent from before, the wallet shows a **quantum-safe checkmark**. If any UTXO is held under an output type that reveals a pubkey (e.g. P2TR, P2PK) or under an address that has already been spent from (pubkey leaked on-chain in the spending input), the indicator shows a **warning** and explains which specific UTXOs are exposed.

This is a small feature — probably under a week of work once ticket 020 Phase 1 ships — but it makes a meaningful educational and product statement. Hercules is the only iOS wallet positioned to do this correctly, because it's the only one that has the full UTXO set and full chain access locally.

## Why this is interesting

Grover's algorithm halves the effective bit-security of SHA-256 and RIPEMD-160 — meaningful but not catastrophic on Bitcoin's time horizon. Shor's algorithm, on a sufficiently large quantum computer, breaks ECDSA and Schnorr outright: given an exposed secp256k1 pubkey, Shor recovers the private key. **This is the real quantum threat to Bitcoin.**

The defense Bitcoin already has is that most modern output types *hash* the pubkey rather than encoding it directly:

| Output type | Pubkey on-chain in the output? | Pubkey exposed when spent? |
|---|---|---|
| **P2PK** (ancient, Satoshi-era) | Yes, raw pubkey | Already exposed |
| **P2PKH** (legacy 1-addresses) | No, hashed (RIPEMD160(SHA256(pk))) | Yes, revealed in the scriptSig |
| **P2SH-P2WPKH** (nested segwit, 3-addresses) | No, hashed twice | Yes, revealed in the witness |
| **P2WPKH** (native segwit, bc1q…) | No, hashed | Yes, revealed in the witness |
| **P2TR** (taproot, bc1p…) | **Yes, x-only pubkey in the output** | Already exposed |

So a P2WPKH address that has never been spent from is — as far as anyone outside the wallet knows — just a 160-bit hash. A future quantum attacker with Shor would have to break SHA-256 + RIPEMD160 *first* to recover a pubkey to attack, which is a much harder problem than attacking the ECDSA once the pubkey is known.

**This means: a wallet that uses only P2WPKH, never reuses addresses, and has never spent from any of its addresses holds its coins in a post-quantum-resistant state today.** This isn't a theoretical future capability, it's the property Bitcoin already has for addresses that have never been touched on the spend side.

The twist is that **P2TR outputs actively give up this property** in exchange for smaller witness sizes, MAST, and Schnorr aggregation. For most users this tradeoff is invisible and probably fine — the quantum threat is decades out. But some users would meaningfully prefer to know which of their coins are in the strong-hygiene state vs. which are sitting out in the open.

## The indicator

Small, glanceable, never shaming. Two states:

**🛡️ Quantum-safe**
> All of your current coins are held under addresses whose public keys have never appeared on-chain. A future quantum attacker would need to break the address hash before they could even attempt to forge a signature.

**⚠️ Partial exposure**
> 2 of your 7 coins are held under addresses whose public keys are visible on-chain (Taproot outputs or previously-spent-from addresses). These specific coins are weaker against a hypothetical future quantum attacker. [Show details] [Learn more]

A third state, "No coins yet," is just a null indicator — the user hasn't received anything yet.

The "Show details" drawer lists the individual UTXOs in the exposed state with a short reason per entry ("Taproot output," "Spent-from address" with a tx link). The "Learn more" sheet is a short explainer: what a quantum computer is, why pubkey-exposure matters, what P2WPKH vs. P2TR do differently, and the fact that this isn't an imminent threat — it's a hygiene posture.

## The check

Two sub-checks, both fast given the wallet's existing data:

### Check 1: output-type exposure

For every UTXO in the wallet, look at its `scriptPubKey`:

- `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` → P2PKH → pubkey hidden
- `OP_0 <20>` → P2WPKH → pubkey hidden
- `OP_HASH160 <20> OP_EQUAL` → P2SH → pubkey hidden (assuming nested segwit)
- `OP_1 <32>` → **P2TR → x-only pubkey revealed**
- `<pk> OP_CHECKSIG` or `<pk33|65> OP_CHECKSIG` → **P2PK → pubkey revealed**
- bare multisig → **pubkeys revealed**

This is a one-tap classification; no chain data needed beyond the output itself.

### Check 2: spent-from exposure

For every UTXO held under a hashed-pubkey output type (P2PKH/P2SH-P2WPKH/P2WPKH), check whether any *previous* UTXO at the same scriptPubKey has ever been spent. If yes, the pubkey for that address is already on-chain in the spending input, so the *current* UTXO at that address is also weak (because the attacker already has the pubkey).

Implementation: when the wallet scans its address set during import (ticket 020 Phase 1), it's already walking the UTXO set. At the same time, we need to know whether each derived address has ever appeared as a spent input in history. Options:

1. **Bloom filter built from spent-input scriptPubKeys during post-AssumeUTXO sync.** We already ingest every block from the snapshot forward; for each block, hash the scriptPubKey of every spent input into a persistent Bloom filter, keyed by address. Wallet check: `filter.contains(address) → possibly spent from`. False positives are fine here because they're fail-safe (we'd just warn when there's no actual leak, which is conservative). ~10-50 MB filter size for the entire post-snapshot history.
2. **BIP158 block filter lookup in the reverse direction.** The BIP158 filters we're already computing for SPV serving include every scriptPubKey touched in the block on both sides. Scanning a wallet's address set against all post-snapshot filters answers "has this address ever been touched." This is slower per-scan but requires no new storage.
3. **Pre-snapshot history is opaque.** Anything the wallet owned before the AssumeUTXO snapshot is a known blind spot (the same blind spot ticket 020 already accepts for full history). Pragmatic answer: for pre-snapshot exposure, ask the user "was this address ever used before you imported the wallet?" during import, or just show a disclaimer on the indicator that the check only covers post-snapshot activity.

Recommendation: option 1 (Bloom filter) because it's fast at query time and the storage is small. Build the filter during initial post-snapshot sync, update it on each validated block going forward.

## What this ticket is *not*

- **Not a quantum-safe signature scheme.** Bitcoin doesn't have one yet, and this ticket doesn't pretend to deliver one. This is purely an *indicator* that surfaces the hygiene Bitcoin already provides.
- **Not a nag.** The goal is educational, not alarmist. Default design: small unobtrusive badge, opt-in drawer for details. No modal popups, no red screens, no forced user action.
- **Not a P2TR blocker.** Users who want Taproot can have Taproot. The indicator just tells them honestly that those specific coins are weaker in this specific way. Tradeoff, not prohibition.
- **Not a judgment on other wallets.** The indicator speaks only about *this* wallet's coins. We don't claim to see other wallets' exposure.

## The design tension worth calling out

Ticket 020 leans toward BIP84 as the default (native segwit, pubkey hidden). That's the conservative, quantum-friendly choice. BIP86 (taproot) is the modern choice and will probably become the industry default, but it *actively gives up* the pubkey-hiding property that gives P2WPKH its quantum-safety story.

If we ship the indicator, we should hold the BIP84 default and offer BIP86 as a deliberate choice with a line of copy ("Taproot outputs are smaller and cheaper to spend but reveal their public key on-chain — this means the coin's quantum-safety posture is weaker"). This lets users choose honestly.

There's an argument for making BIP86 the default anyway, because the quantum threat is probably 10-20+ years out and the fee savings are real today. That's a reasonable position. But given that Hercules's whole product story is "highest integrity Bitcoin experience possible on a phone," BIP84 + quantum-safe indicator is the on-brand choice.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/wallet.rs` | Add `UtxoExposure` enum and `wallet.exposure_summary()` method |
| `hercules-core/src/wallet_store.rs` | Add Bloom filter table for spent-scriptPubKey tracking |
| `hercules-core/src/sync.rs` | Update spent-scriptPubKey filter on each validated block |
| `HerculesApp/HerculesApp/Wallet/WalletView.swift` | Add indicator badge in the balance header |
| `HerculesApp/HerculesApp/Wallet/QuantumSafetyDetailView.swift` | **New** — per-UTXO breakdown + explainer |
| `hercules.udl` | Expose `UtxoExposure` + summary query |

## Dependencies

- **Ticket 020 Phase 1** — the wallet must exist before this indicator can mean anything. ❌ Not yet started.

## Phasing

Single phase, ships with or shortly after ticket 020 Phase 1. The check logic is small enough that there's no reason to split it.

## Estimated effort

~3-5 days of work, split roughly:
- Bloom filter infrastructure for spent-scriptPubKey tracking: ~1 day
- Output-type classification and exposure query: ~0.5 day
- Indicator UI + detail drawer: ~1.5 days
- Explainer copy + learn-more sheet: ~0.5 day
- Testing against wallets with known mixed exposure: ~0.5-1 day

## Verification

- Import a wallet with only unspent P2WPKH UTXOs at never-spent-from addresses → indicator shows quantum-safe
- Import a wallet with a mix of P2WPKH and P2TR → indicator shows partial exposure, drawer lists the P2TR UTXOs with reason "Taproot output"
- Import a wallet with a P2WPKH UTXO at an address that has a prior spent output → indicator shows partial exposure, reason "Spent-from address"
- Receive a new P2TR payment in a previously all-P2WPKH wallet → indicator transitions from quantum-safe to partial exposure within the arrival-notification window
- Spend the last P2TR UTXO out of a mixed wallet → indicator returns to quantum-safe

## Open questions

- **How strongly to surface the indicator.** Subtle badge in the balance header vs. prominent row under the balance vs. full-screen callout. Recommendation: small badge, tappable, drawer for detail. Don't be alarmist.
- **Whether to warn during send.** If a send would leave the wallet with new P2TR change, should we show a subtle note? Probably yes, but only if the user is currently in quantum-safe state and the send would move them out of it. Otherwise silent.
- **Pre-snapshot exposure handling.** How to communicate the blind spot for addresses used before AssumeUTXO. Recommendation: small footnote in the detail drawer, not a blocking warning.
- **Cross-wallet correlation warning.** If the user imports multiple wallets and one has exposed pubkeys that could be mathematically related to another (unlikely in practice, but…), do we say anything? Probably no — too niche.
- **Marketing copy.** "Quantum-safe" is technically a stretch (Grover still halves SHA-256 effective bits). Alternatives: "Quantum-resistant," "Post-quantum hygiene," "Pubkey-private." Recommendation: ship with "Quantum-safe" because it's the term users will search for, with a footnote explaining precisely what it means.

## Roadmap position

Slots in as **020 Phase 1 → 021 → 020 Phase 2**, because it's cheap enough to bundle into the Phase 1 wallet release and the indicator is a nice bit of differentiation that makes the watch-only wallet more compelling as a standalone product beat before the hot wallet lands.
