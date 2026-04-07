# Ticket 008: Fully Participating Node (Phase 5)

## Summary

Transform Hercules from a validating observer into a full network participant. Today we download and validate but never give anything back. A real pruned node relays blocks and transactions, responds to peer requests, and accepts inbound connections. This ticket covers the full gap.

## Background

After Phase 4, Hercules validates every block in real-time via push notifications. But our P2P behavior is one-directional: we request `getheaders` and `getdata`, validate locally, and never send anything outbound. We don't relay block announcements, don't relay transactions, don't respond to peer requests, and don't accept inbound connections. Bitcoin Core's pruned mode (`-prune=550`) does all of these — it just doesn't serve historical blocks beyond its pruning window. We need to close this gap.

### What Bitcoin Core's pruned node does that we don't:

1. **Relays block announcements** (`inv`/`headers`) to peers after validation
2. **Relays transactions** from mempool to peers
3. **Responds to `getheaders`** — serves header chain to syncing peers
4. **Responds to `getdata`** — serves recent blocks within pruning window
5. **Responds to `mempool`/`getdata`** — serves transactions from mempool
6. **Accepts inbound connections** — listens on port 8333 (or .onion)
7. **Advertises `NODE_NETWORK_LIMITED`** (BIP 159) — signals it has recent blocks

### Dependencies:

- **AssumeUTXO snapshot** — Transaction validation requires a current UTXO set. We have snapshot *loading* (Phase 2d) but no automatic *downloading*. Without a synced UTXO set, we cannot validate or relay transactions.
- **Mempool** — Does not exist. Need transaction acceptance, validation, storage, eviction, and relay policy.
- **Bidirectional P2P** — `p2p.rs` only sends requests and reads responses. It doesn't handle incoming requests from peers or send unsolicited messages.

## Design

### Sub-phase 5a: AssumeUTXO Download & Bootstrap

**Goal:** One-tap onboarding to a synced UTXO set.

- Hardcode a download URL for the current AssumeUTXO snapshot
  - Temporary: host on a known mirror or CDN (the snapshot hash is verified regardless of source)
  - The snapshot hash is hardcoded in our code, same as Bitcoin Core — the download source is untrusted, the hash commitment is trusted
  - Use Bitcoin Core master's AssumeUTXO height: **935,000** (UTXO hash: `e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050`, block hash: `0000000000000000000147034958af1652b2b91bba607beacc5e72a56f0fb5ee`, from `chainparams.cpp` targeting v31)
  - History: Core v28 added 840,000, v30 added 880,000 and 910,000
- Download over WiFi with progress UI (snapshot is ~7GB compressed)
- After download, call existing `load_snapshot()` infrastructure
- Delete the downloaded file after successful load (UTXO set is now in SQLite)
- Background historical validation from genesis is optional/deferred (covered by Phase 6 cooperative spot-checking)

**Snapshot format compatibility:** We use our own snapshot format (custom binary, see `utxo.rs`). We'll need a converter that reads Bitcoin Core's `dumptxoutset` format (serialized UTXO entries) and writes our format, OR we generate and host a snapshot in our format. The latter is simpler for v1.

**Hardcoded snapshot config:**
```rust
const ASSUMEUTXO_HEIGHT: u32 = 935_000;
const ASSUMEUTXO_HASH: &str = "e4b90ef9eae834f56c4b64d2d50143cee10ad87994c614d7d04125e2a6025050";
const SNAPSHOT_DOWNLOAD_URL: &str = "https://..."; // temporary CDN
```

### Sub-phase 5b: Mempool

**Goal:** Accept, validate, store, and evict unconfirmed transactions.

**Storage:**
- In-memory HashMap: `txid -> Transaction` + fee metadata
- Size cap: 50MB (Core default: 300MB, Core `-blocksonly` mode: 5MB). 50MB handles normal mempool load; during severe fee spikes, low-fee txs get evicted earlier than 300MB peers. Configurable via settings. Revisit if testing shows 100MB is worth the RAM trade-off.
- Fee-rate index for eviction (lowest fee-rate evicted first)

**Validation (full, matching Bitcoin Core's `AcceptToMemoryPool`):**
- All inputs must exist in the UTXO set and not be spent by another mempool tx (or handle chains of unconfirmed)
- Script validation via `libbitcoinconsensus`
- Standard relay policy checks:
  - Standard script types only (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
  - Dust threshold (546 sats for most output types)
  - Max transaction weight (400,000 WU)
  - Min fee rate (1 sat/vB default)
  - BIP 125 RBF rules for replacement
  - Max ancestor/descendant chain limits

**Eviction:**
- When pool exceeds 50MB, evict lowest-fee-rate transactions
- Remove transactions that conflict with newly confirmed blocks
- Expire transactions older than 14 days (336 hours, matches Core default)

**New module:** `mempool.rs`

### Sub-phase 5c: Outbound Relay

**Goal:** Forward validated blocks and transactions to connected peers.

**Block relay:**
- After validating a new block, send `inv` (block hash) to all connected peers
- If a peer requests the block via `getdata`, serve it (if we still have it)
- Send `headers` messages for validated headers (BIP 130 `sendheaders` support)

**Transaction relay:**
- After accepting a transaction to mempool, send `inv` (txid) to peers
- On `getdata` for a tx, serve from mempool
- Respect `feefilter` (BIP 133) — don't send txs below peer's declared minimum fee rate
- Privacy: random delay before relay (Poisson distribution, ~2 seconds avg, matches Core)

**Responding to peer requests:**
- `getheaders` — serve from our header chain (already in SQLite)
- `getdata` (block) — serve recent blocks within pruning window, or `notfound`
- `getdata` (tx) — serve from mempool, or `notfound`
- `mempool` — send `inv` for all mempool transactions

**P2P protocol additions in `p2p.rs`:**
- `send_inv(items: Vec<Inventory>)`
- `send_headers(headers: Vec<Header>)`
- `send_tx(tx: Transaction)`
- `send_block(block: Block)`
- `send_not_found(items: Vec<Inventory>)`
- Handle incoming `getdata`, `getheaders`, `mempool`, `feefilter` messages
- Event-driven message handling (currently we only send-then-receive)

**Service flags:**
- Advertise `NODE_NETWORK_LIMITED` (BIP 159) in version message — signals we serve the last 288 blocks
- Do NOT advertise `NODE_NETWORK` (we don't have the full chain)

### Sub-phase 5d: Inbound Connections

**Goal:** Accept peer connections via the .onion hidden service.

- Activate the onion service in `tor.rs` (code exists but isn't wired up)
- Listen for inbound connections on the hidden service port
- Handle the version/verack handshake for inbound peers
- Service inbound requests using the same handlers as 5c
- Separate inbound slot limit (Bitcoin Core default: 114 inbound, 125 total - 11 outbound; Knots identical)
  - Default 16 inbound (idle TCP connections have negligible battery cost — the real drain is per-message I/O from relay, which scales with network activity not connection count)
  - BIP 159 has no minimum connection requirement — only requires serving last 288 blocks
  - User-configurable
- Inbound peers count toward reputation scoring (ticket 007)

## Integration Points

- **`p2p.rs`:** Bidirectional message handling, new send methods, incoming request dispatch
- **`peer_pool.rs`:** Inbound connection slots, service flag advertisement
- **`sync.rs`:** After block validation, trigger relay to peers
- **`mempool.rs`:** New module — tx acceptance, validation, storage, eviction, relay
- **`utxo.rs`:** Mempool tx validation queries (check input existence without modifying set)
- **`tor.rs`:** Activate onion service, accept inbound streams
- **`lib.rs`/UDL:** Expose mempool stats, inbound peer count, relay status to UI

## Testing Strategy

- **Mempool:** Unit tests for acceptance, eviction, RBF replacement, conflict removal on block
- **Relay:** Integration tests — mock peer receives `inv` after we validate a block
- **Inbound:** Connection handshake test with mock inbound peer
- **AssumeUTXO:** Snapshot download, hash verification, load, validate-forward

## Estimated Effort

Large. This is comparable to Phase 2 in scope. Suggested order:
1. 5a (AssumeUTXO download) — unblocks everything else
2. 5b (Mempool) — required for tx relay
3. 5c (Outbound relay) — blocks and headers first, then transactions
4. 5d (Inbound) — last, builds on everything above

## Open Questions

- **Snapshot hosting:** Where to host the Hercules-format snapshot for v1? Options: GitHub Releases, IPFS, BitTorrent, CDN. The hash is verified regardless of source.
- **Snapshot format:** Generate in our custom format (simpler) vs. read Bitcoin Core's `dumptxoutset` format directly (more interoperable)? Core's format is a flat serialization of CCoins entries.
- **Block storage for serving:** Currently we discard blocks after validation. To serve recent blocks (BIP 159 requires last 288), we need to persist them. Storage impact: ~288 * ~1.5MB = ~430MB. Store as raw bytes in SQLite or flat files?
- **Mempool on-disk persistence:** Core persists mempool to `mempool.dat` on shutdown and reloads on startup. Worth doing on mobile, or just start fresh each launch?

## Resolved Decisions

- **Mempool size:** 50MB default (Core: 300MB, Core blocksonly: 5MB). Configurable. Handles normal load; during fee spikes evicts low-fee txs earlier. Can revisit to 100MB after real-world testing.
- **Inbound limit:** 16 default (Core: 114). Idle connections have negligible battery cost. BIP 159 has no minimum connection count. User-configurable.
- **AssumeUTXO height:** 935,000 (Bitcoin Core master, targeting v31). UTXO hash: `e4b90ef9...025050`. Block hash: `00000000...0fb5ee`.
