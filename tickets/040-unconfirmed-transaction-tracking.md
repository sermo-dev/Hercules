# Ticket 040: Unconfirmed (Mempool) Transaction Tracking

## Summary

Show incoming and outgoing payments the moment they reach the mempool, marked **pending**, instead of waiting up to ~10 minutes (or longer) for a block. This is what Sparrow does. It's also what essentially every mainstream wallet does: BlueWallet, Blockstream's app, Nunchuk, Phoenix's on-chain side. Sparrow gets mempool events from its Electrum server or from Bitcoin Core's wallet. Hercules already *has* a mempool on-device, so this needs no server: match every transaction we accept into the mempool against the wallet's watched scripts.

The catch is iOS-specific. The phone only has a live mempool while the node is running: when the app is in the foreground, or during a future relay shift (045). While backgrounded, an incoming payment first becomes visible at the next block wake, after it has confirmed. The UI has to say so honestly.

## Background

- **Mempool accept path exists.** `Mempool::accept_tx` (`hercules-core/src/mempool.rs:171`) is the single entry point for both peer-relayed transactions (`HeaderSync::handle_tx`, `hercules-core/src/sync.rs:2005`) and locally broadcast ones (`rpc_broadcast_tx`, `sync.rs:654`). Nothing downstream of it knows about wallets today.
- **Full RBF is the mempool's replacement rule.** `mempool.rs:833` documents that BIP125 rule 1 (signalling) is intentionally omitted ("we follow Bitcoin Core v28+ full RBF semantics"). So *any* unconfirmed transaction can be replaced by a higher-fee conflicting one. That is exactly why unconfirmed incoming payments must never be presented as final.
- **The wallet design already expects this.** Ticket 020's UDL sketch has `WalletBalance { confirmed_sats, unconfirmed_sats }` (`tickets/020-in-app-wallet.md:101-104`), but nothing specifies how `unconfirmed_sats` is computed. 020 only covers block-driven tracking.
- **Relay policy filters some txs.** `relay_policy.rs` (ticket 018) rejects inscriptions, Runes and similar before they reach the mempool. A payment *to* the user inside a filtered tx (rare: e.g. a payment transaction that also carries an inscription) would not show as pending. It would still show when confirmed, because blocks are fully validated regardless of policy.

## Proposed design

### 1. Mempool → wallet hook

After `accept_tx` succeeds, test the transaction against the WatchSet from ticket 035:
- **Incoming:** any output whose `scriptPubKey` is in the WatchSet.
- **Outgoing:** any input spending an outpoint the wallet owns. That covers our own sends from 033, and also spends of our coins made by another device holding the same seed.

On a match, insert a `PendingTx { txid, first_seen, fee_rate, net_amount, conflicts_with: [] }` into an in-memory pending table owned by the wallet. Don't persist it across launches as authoritative. On launch, rebuild from the mempool as it refills, and seed it with our own broadcast-tracker entries (033), which *are* persisted.

### 2. Lifecycle events

| Event | Source | Wallet action |
|---|---|---|
| Tx accepted | `accept_tx` | add pending entry, post "Payment incoming (pending)" notification if foregrounded |
| Tx replaced (RBF) | eviction in `accept_tx` replacement path | mark old entry **replaced**; if the replacement still pays us, swap txid; if not → **"Payment cancelled by sender"** warning |
| Tx confirmed | `remove_confirmed` after block apply | promote to confirmed history (035 block scanner owns this) |
| Tx evicted (size cap / expiry) | mempool eviction | mark **dropped from mempool**; for outgoing, 033 rebroadcast logic decides |
| Conflicting block spend | block scanner sees our input spent by a different tx | mark **double-spent**, loud warning |
| Reorg | ticket 025 re-adds disconnected txs | entries move back from confirmed → pending |

The mempool needs a small eviction/replacement callback (or an event queue drained by the wallet) so these transitions aren't inferred by polling.

### 3. UX rules

- Pending amounts are shown separately ("+50,000 sats pending"), never folded into the spendable balance.
- Spending unconfirmed *incoming* coins is disabled by default. Spending our own unconfirmed change is allowed (CPFP-friendly), behind coin selection rules in 034/042.
- Copy explains: "Pending payments can still be replaced or cancelled by the sender until they're in a block."
- Background limitation surfaced once, in an explainer: "While the app is closed, payments appear when they confirm (usually within ~10 minutes)."

### 4. Hidden and watch-only wallets

Watch-only wallets (037) participate fully. Passphrase wallets (038) only match while unlocked in the current session. A locked hidden wallet never appears in the pending table or in notifications.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/mempool.rs` | Emit accept / replace / evict events (callback or event queue) |
| `hercules-core/src/sync.rs` | Wire mempool events and `remove_confirmed` to the wallet |
| `hercules-core/src/wallet*.rs` (from 034/035) | Pending table, WatchSet matching, state transitions |
| `hercules.udl` | `unconfirmed_sats`, `PendingTx` list, pending-state enum |
| `HerculesApp/.../Wallet/*` (from 037) | Pending row styling, replaced/double-spent warnings |

## Dependencies

- **035** wallet chain scanner and WatchSet. ❌
- **033** own-transaction tracking for outgoing pending entries. ❌
- **025** reorg handling must put disconnected transactions back into the mempool. ❌
- **037** wallet UI. ❌

## Estimated effort

~4-6 days: mempool event plumbing (1-1.5d), wallet pending table and transitions (1.5-2d), UI states (1-1.5d), tests (1d).

## Verification

- Unit: tx paying a watched script → pending entry; replacement paying us less → entry updated; replacement paying someone else → "cancelled" state.
- Unit: block containing a conflicting spend of our input → double-spent state.
- Integration (027 harness): mock peer relays a tx to a watched address → pending within one relay cycle; mock peer mines it → promoted to confirmed exactly once.
- Manual: send from Sparrow on testnet/signet (or mainnet small amount) while app is foregrounded → pending row appears within seconds.

## Open questions

- **Notifications while foregrounded only?** An in-app banner is fine. A system notification for pending payments is probably noise. Recommendation: banner only, and keep system notifications for confirmed payments (block wakes).
- **Payments inside policy-filtered txs.** Accept the gap, or match against filtered txs before rejecting them, without admitting them to the mempool? Recommendation: match-before-reject is cheap, so do it, and mark those "pending (not relayed by your node)".
- **Sender-side notification.** A contact's app (043) could notify the recipient directly that a payment was sent. That needs a messaging channel and leaks the social graph to whatever carries it. Out of scope here; revisit with 043.

## Roadmap position

Ships with the first wallet release (037), right after 035 and 033. Without it, the wallet feels broken next to Sparrow and BlueWallet whenever the app is open.
