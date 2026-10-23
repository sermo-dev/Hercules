# Ticket 033: Own-Transaction Broadcast, Relay, and Rebroadcast

## Summary

**This is a bug in a shipped feature, not only unbuilt wallet work.**

Ticket 014 (completed) exposes `broadcast_transaction` on the wallet onion API so an external wallet such as Sparrow can send through Hercules. That call validates the transaction and adds it to the local mempool, and then **never announces it to any peer**. A transaction "broadcast" through Hercules today never leaves the phone.

This ticket fixes that and makes the code path the one the in-app wallet (020) will use to send:
- immediate announcement to peers
- tracking of the user's own transactions
- rebroadcast until confirmed
- clear error reporting
- integration with 029's private broadcast

## Background (verified)

**API entry.** `wallet_rpc.rs:327` routes `"broadcast_transaction"` to `handle_broadcast_transaction` (`:526`), which calls `syncer.rpc_broadcast_tx(&raw)` (`:539`).

**No relay.** `rpc_broadcast_tx` (`sync.rs:651-669`) deserializes the transaction, takes `current_height` from `self.store.tip()` (the **header** tip), calls `pool.accept_tx(...)`, and returns the txid. Its doc comment says "Relay to peers happens on the next monitor-loop tick", but nothing enqueues it.
- The only producer for `relay_queue` is `handle_tx` (`sync.rs:2006-2026`), which handles transactions *received from peers*. It schedules each with a Poisson delay (`poisson_delay_secs(2.0)`) and a `from_peer` so it isn't echoed back.
- `drain_relay_queue` (`sync.rs:2060+`, called from the monitor loop at `:1239`) only sends what is in that queue.

**Wrong height.** `handle_tx` uses `validated_height` (`sync.rs:2007`). `rpc_broadcast_tx` uses the header tip. While the UTXO set lags the headers (catch-up, background validation), coinbase-maturity and locktime checks run against a height the UTXO set hasn't reached.

**Policy applies to own transactions.** `accept_tx_internal` runs `check_relay_policy(&tx)` (`mempool.rs:300-301`) and returns `MempoolError::PolicyRejection`. If a user's wallet makes a transaction our Knots-style filters reject (a large OP_RETURN, for example), it fails with a generic `"mempool reject: …"` string (`sync.rs:666`). The user can't tell a consensus problem (bad signature, missing input) from a local policy choice.

**Nothing is persisted.** The mempool lives in memory. If iOS kills the app before peers pick up the transaction, it's gone, and the wallet has no record that it should resend.

## Proposed fix

### 1. Separate own-transaction submission path
Add `submit_own_tx(raw) -> Result<OwnTxReceipt, SubmitError>`, shared by the 014 RPC and the in-app wallet.
- Validate against `validated_height` and the UTXO set (consensus checks unchanged).
- **Local relay-policy filters (018) don't block own transactions.** Our filters say what *we* choose to relay for others, not what the user may send. Still require consensus validity, standardness that would stop peers relaying it (dust, non-standard scripts), and the absurd-fee guard.
- If the transaction would fail *other nodes'* standardness rules, warn the user instead of silently sending something that won't propagate.
- Return typed errors: `Consensus(..)`, `NonStandard(..)`, `FeeTooLow{min}`, `AbsurdFee`, `Conflict{txid}` (RBF context), `NotSynced`.

### 2. Immediate announcement
- Own transactions skip the Poisson trickle used for relayed transactions.
- In **Tor mode** (029), announce an `inv` to all outbound peers right away.
- In **Standard (clearnet) mode**, hand the transaction to the **private broadcast** path from 029: short-lived Tor connections to 2–3 peers, send the transaction, then disconnect. Don't announce it on our clearnet connections until it comes back from the network (an `inv` from an unrelated peer), so our clearnet IP is never the first to relay it.
- **Never** relay it with `from_peer` set to ourselves.

### 3. Own-transaction tracker (persisted)
- Add an `own_txs` table (SQLite next to the block store; later the wallet DB): `txid`, `raw`, `first_sent_at`, `last_sent_at`, `seen_from_peers` (count), `status ∈ {pending, propagated, confirmed(height), replaced(by), dropped}`.
- On each block (`apply_block`), mark confirmed.
- On reorg (025), demote back to pending.
- **Rebroadcast** pending transactions at each foreground session and on every Nth wake (cheap: one `inv`), with backoff. Stop on confirmation, on replacement (RBF), or when inputs are spent by a different transaction (conflict → `dropped`, surfaced to the user).
- Re-add pending own transactions to the mempool at startup.

### 4. FFI and RPC surface
- `hercules.udl`: `submit_own_tx`, `own_tx_status(txid)`, `list_own_txs()`.
- 014 RPC: `broadcast_transaction` returns the typed error and the txid; add `get_broadcast_status`.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/sync.rs` | `submit_own_tx`; use `validated_height`; immediate announcement; confirmation and reorg hooks; rebroadcast scheduler |
| `hercules-core/src/own_tx_store.rs` | **New** — persisted tracker |
| `hercules-core/src/mempool.rs` | `accept_own_tx` variant that skips `check_relay_policy` but keeps consensus, standardness, and fee checks |
| `hercules-core/src/wallet_rpc.rs` | Typed errors; `get_broadcast_status` |
| `hercules-core/src/lib.rs`, `hercules.udl` | FFI surface |
| `hercules-core/src/p2p.rs` | Short-lived private-broadcast connection helper (with 029) |

## Dependencies

- **029**: private broadcast transport. Until it lands, Tor mode (today's only mode) uses immediate `inv` announcement.
- **027**: mock peer harness for tests.
- **025**: reorg hooks for demoting confirmed own transactions.
- **020**: the in-app wallet is the main consumer.

## Estimated effort

~3–4 days:
- relay fix plus `validated_height`: 0.5 day. **Ship this alone first: it fixes the 014 bug.**
- typed errors and policy bypass: 1 day
- tracker and rebroadcast: 1.5 days
- tests: 1 day

## Verification

- **Regression for the bug.** Mock peer (027) connected; call `broadcast_transaction` → within 1 s the mock peer receives `inv(tx)` and then `getdata`/`tx`.
- A transaction with a large OP_RETURN submitted as an own transaction is accepted locally and announced. The same transaction arriving from a peer is still rejected by policy.
- A transaction spending an immature coinbase is rejected with `Consensus`, evaluated at `validated_height` rather than the header tip.
- Kill the app after submitting and relaunch: the transaction is back in the mempool and re-announced.
- A block confirms it: status goes to `confirmed(h)` and rebroadcast stops. Reorg it out (025 harness): back to `pending`.
- A conflicting spend confirms: status `dropped` and the user is notified.

## Open questions

- **How many private-broadcast peers, and how to confirm propagation?** Follow Bitcoin Core's private-broadcast design once its status is verified (029).
- **Rebroadcast cadence** given iOS wakes: every wake, or only every Nth?
- **Expose "send" in the 014 API to clearnet-mode users at all**, given 014 is Tor-only?

## Roadmap position

Ship the one-line relay fix (enqueue plus `validated_height`) as a bug fix right away, since it breaks a completed ticket's feature. The tracker and private broadcast land before 020's hot-wallet phase (sending).
