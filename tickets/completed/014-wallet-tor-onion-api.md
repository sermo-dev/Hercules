# Ticket 014: Wallet-Facing Tor Onion API

## Summary

Expose Hercules to external Bitcoin wallets over a dedicated Tor hidden service so the user's wallet — Sparrow on a paired desktop, a hardware-wallet companion app, a separate phone — can use *their own* Hercules node as its backend instead of trusting a public Electrum server or block explorer. The user gets meaningful node privacy without running a separate machine.

This is the missing piece that makes Hercules useful as a wallet backend, not just a "watching" node.

## Background

Hercules already runs an onion service for **Bitcoin P2P** protocol. `tor.rs::start_onion_service` listens for inbound peers that speak `version`/`verack`/`getheaders`/`addr`/etc. Other Bitcoin nodes can find and peer with it (see ticket 011 for self-advertisement).

External wallets, however, don't speak P2P. They speak one of:

- **Bitcoin Core JSON-RPC** (HTTP, basic auth, JSON bodies)
- **Electrum protocol** (TCP, line-delimited JSON, address-history queries)
- **Esplora REST** (HTTPS+JSON, address-history queries)
- **Nostr Wallet Connect** (encrypted, newer)

None of these are exposed today. The UDL (`hercules.udl`) only exposes node-internal operations to the iOS Swift layer — there's no HTTP server, no JSON-RPC server, no Electrum protocol implementation. There is no inbound surface for wallets at all.

### What Hercules CAN serve (pruned reality)

Pruned + AssumeUTXO fundamentally limits the queries a wallet can make:

| Query | Available? | Notes |
|---|---|---|
| Broadcast a signed transaction | **Yes** | Has peer connections, can push txs into mempool relay |
| Get current mempool state | **Yes** | Full local mempool |
| Get fee estimates | **Yes** | Real mempool → real fee data |
| Get block headers (any height) | **Yes** | Full header chain stored |
| Get a recent block by hash | **Yes** | Within prune window only |
| Get a historical block | **No** | Pruned away |
| Get UTXO for `(txid, vout)` | **Yes** | Full UTXO set in LMDB |
| Get balance / history for an **address** | **No** | No address index — would require unpruned chain or external indexer |
| Get BIP158 compact filter for a block | **Maybe** | Pruned nodes can compute and serve filters for blocks since the node was installed; older filters need a separate store |
| Subscribe to new blocks | **Yes** | Already wired internally |
| Subscribe to mempool events | **Yes** | Already wired internally |

So Hercules can be a *broadcast + headers + UTXO + mempool + filters* server — exactly enough for **client-side wallet scanning**. Compact-filter SPV wallets (Sparrow's filter mode, custom mobile wallets, BDK-based wallets) work perfectly with this. It is **not** enough to be a drop-in Electrum server replacement, because Electrum protocol assumes address-history queries.

## Design

### Part 1 — Protocol surface

**Recommendation: minimal JSON-RPC 2.0 over HTTP/1.1, served on a new Tor onion address that is unlinkable from the existing P2P onion address.**

Reasoning:
- **JSON-RPC 2.0**: well-known, hand-rollable in a few hundred lines, matches Bitcoin Core's interface enough that wallet authors find it familiar. No streaming, no subscriptions in v1 — clients poll.
- **HTTP/1.1**: trivial to implement over Arti's `DataStream` (status line + headers + content-length body). Code can be shared with the HTTP-over-Arti client proposed in ticket 012's snapshot Tor download.
- **Separate onion address**: the existing P2P onion identifies Hercules as a Bitcoin gossip participant; the wallet onion identifies it as someone's personal backend. A network observer who learns one should not be able to correlate it with the other. Run two distinct hidden services with two distinct keypairs.

Alternatives considered and rejected:
- **Electrum protocol** — wide wallet support but the address-history API is a non-starter for a pruned node. We'd be a "broken" Electrum server. Reject.
- **Esplora REST** — same address-history problem. No wallet currently expects "Esplora minus address history." Reject for v1.
- **Bitcoin Core RPC compatibility shim** — tempting (drop-in for many tools) but Core RPC is enormous and most endpoints don't apply to a pruned node. Could be a future compatibility layer over the v1 JSON-RPC. Reject for v1.
- **gRPC** — nice tooling but heavyweight for Hercules's deployment. Reject.
- **Custom binary protocol** — bandwidth-efficient but no existing wallet support. Reject.

### Part 2 — RPC method surface (v1)

```
broadcast_transaction(hex: string) -> { txid: string }
get_mempool_entry(txid: string) -> { fee, vsize, ancestors, descendants, ... } | null
get_fee_estimates() -> { 1: sat/vb, 6: sat/vb, 144: sat/vb, ... }
get_tip() -> { height, hash, time, validated_at, is_stale: bool }
get_block_header(hash_or_height) -> { ... }
get_block_hash(height) -> string
get_block(hash) -> { hex } | { error: "pruned" }
get_compact_filter(hash_or_height) -> { hex } | null
get_utxo(txid, vout) -> { value, script_pubkey, height } | null
get_node_info() -> { version, prune_height, tip_height, mempool_size, peer_count, last_validation_at }
```

Notably absent:
- `get_address_*` — pruned, no index
- `subscribe`/streaming endpoints — v1 is request/response. Clients poll `get_tip` for new blocks.
- Wallet-side state (`listunspent`, `getbalance`) — Hercules holds no wallet state, that's the wallet's job.

`get_tip` returns an `is_stale` flag if the last validation was more than ~30 min ago — wallets need to know not to trust the state if Hercules has been suspended too long.

Methods that mirror `bitcoind` should match its semantics so wallet authors can reuse existing client code paths.

### Part 3 — Tor surface

- New function `TorManager::start_wallet_api_onion_service(port) -> String` in `tor.rs`, structured the same way as the existing `start_onion_service` but with a different Arti `nickname` (`hercules-wallet`) so Arti generates and persists a separate keypair under a different state directory.
- The two onion addresses are unlinkable. Tor circuit isolation across the two services is automatic via Arti.
- Default port: arbitrary, doesn't matter (only reachable via the `.onion:port` URL).

### Part 4 — Authentication

Onion services already provide network-level authentication (only people who know the .onion URL can connect), but that is **not enough** — anyone who learns the URL (screenshot leak, shoulder surf, accidental copy/paste) gets full RPC access.

**Layer 1 — HTTP Basic auth** with a randomly-generated secret persisted alongside the wallet onion keypair. Pairing UX (Part 5) shows the user a single string combining the onion address + port + secret. Wallet authors implement standard HTTP Basic.

**Layer 2 (stretch) — Tor v3 client authorization.** Arti supports authorized clients on hidden services; only clients with a pre-shared keypair can even resolve the onion descriptor. This is meaningfully stronger than HTTP Basic because it prevents an attacker from even reaching the HTTP layer. Defer to a follow-up — wallet UX support is currently weak.

### Part 5 — Pairing UX (Swift)

- New "Wallet Connection" card in `SettingsView`
- Toggle: "Allow external wallet connections"
- When enabled for the first time:
  1. Hercules calls `start_wallet_api_onion_service` (~30 s for Arti to publish the descriptor)
  2. Generates and stores a random secret
  3. Shows a QR code + "Copy connection string" button + "Show as text" toggle for users without QR-capable wallets
- Connection string format (proposed): `bitcoin-rpc-tor://<onion>:<port>?token=<base64_secret>`. If a standard emerges, switch to it.
- "Revoke all wallets" button regenerates the secret (invalidates existing pairings) without changing the onion address
- "Reset onion address" button regenerates the keypair (for paranoia or compromise recovery)
- Status line: "Reachable now" / "Asleep — wallet will retry on next push wake" depending on app state, so the user understands the iOS background-execution constraint (see open questions)

### Part 6 — Server implementation

- New Rust module: `hercules-core/src/wallet_rpc.rs`
- Owns the second onion service handle and the inbound stream channel
- For each inbound `TorStream` from the wallet onion, spawn a handler that:
  1. Parses an HTTP/1.1 request (status line, headers, content-length body)
  2. Verifies HTTP Basic auth against the stored secret (constant-time comparison)
  3. Parses JSON body as JSON-RPC 2.0
  4. Dispatches to the matching read-only handler (or `broadcast_transaction`, the only writer)
  5. Serializes JSON-RPC 2.0 response, writes it back, closes the stream
- All handlers are read-only against the existing node state (UTXO set, mempool, headers, peer pool for tx broadcast). No new mutable state.
- Per-circuit rate limit (e.g., 100 req/min) to prevent abuse
- Bounded request body (e.g., 1 MB — comfortably above max signed tx size)
- All responses: `Content-Type: application/json`, no caching headers, no CORS (this is not a web API)

## Verification

- Start the wallet onion service, observe a `.onion:port` distinct from the P2P onion
- `curl --socks5-hostname 127.0.0.1:9050 -u user:secret http://<onion>:<port>/ -d '{"jsonrpc":"2.0","method":"get_tip","id":1}'` returns the current tip
- Pair Sparrow Wallet (or a custom test client) to the onion address, scan a few addresses via compact filters, observe correct UTXO returns
- Sign and broadcast a tx through the API, observe it in `get_mempool_entry`, observe it appears in mempool of an external block explorer
- Wrong/missing token returns 401
- 1000 rapid requests get throttled after 100
- Restart Hercules, observe the same wallet onion address (keypair persisted)
- Toggle "Allow external wallet connections" off, observe the onion service tears down and the URL becomes unreachable

## Dependencies

- Existing Tor infrastructure (`tor.rs::TorManager`, the `OnionServiceHandle` pattern)
- Existing UTXO/mempool/header/peer subsystems (read-only access)
- New UDL methods to start/stop the wallet API and return the connection string to Swift
- HTTP/1.1 server code (small) — could share request/response parsing with the future HTTP-over-Arti client from ticket 012

## Estimated effort

- **Tor wiring** (second onion service, separate keypair): ~80 lines Rust
- **HTTP/1.1 server**: ~250 lines Rust (request parser, response writer, content-length handling, basic auth)
- **JSON-RPC dispatch + 10 handlers**: ~400 lines Rust, mostly serde wiring against existing internal state
- **UDL + Swift bridge**: ~50 lines
- **Pairing UX**: ~200 lines Swift (Settings card, QR generation via `CIQRCodeGenerator`, copy/share)

Roughly a week of focused work.

## Open questions

- **iOS background reachability**. Hercules is suspended most of the time. The wallet API onion service is *announced* to the Tor network whenever Arti is running, but inbound connections will fail when Hercules itself isn't executing. Wallet UX must warn users that the node may be unreachable until they open the Hercules app. There is no way to wake the app on inbound onion traffic — iOS doesn't expose that hook. A real fix requires always-on Hercules, which iOS doesn't allow. **Mitigation**: pair the wallet during foreground use, do wallet operations during foreground sessions, accept that "background wallet backend" is a future-iOS-only feature.
- **Compact filter storage**. To serve `get_compact_filter` for arbitrary heights, we need a filter store. Cleaner scope: only serve filters for blocks since Hercules was installed (computed during validation, persisted forward). Wallets that need older filters fall back to other sources for the historical scan and use Hercules for the ongoing scan.
- **Multi-wallet pairing**. Should each paired wallet get its own secret/token so individual revocation works? Probably yes — the small extra complexity buys real value.
- **Subscriptions in v1?** A long-poll or SSE endpoint for "new block" / "tx confirmed" would be much nicer than polling. Defer to v2; document the polling pattern in v1.
- **Standardized connection string format**. The `bitcoin-rpc-tor://` scheme is invented for this ticket. Worth checking whether the Bitcoin community has converged on something. Probably not yet.
- **Trust model for `is_stale` on tip**. What threshold makes `get_tip` report stale? 30 min is two missed blocks expected; 60 min is one σ above the mean. Wallets should not auto-trust a Hercules tip that's been quiet for that long.
