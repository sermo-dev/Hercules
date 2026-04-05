# Hercules

**Turn your iPhone into a fully-validating Bitcoin node.**

Hercules is a native iOS application that runs a pruned Bitcoin full node directly on your phone. It validates every block against consensus rules, verifies your own transactions without trusting any third party, and participates in a novel cooperative relay protocol that allows a network of phones to collectively provide continuous mempool coverage — even though no single phone is always on.

## The Problem

Today, running a Bitcoin full node requires dedicated hardware (Raspberry Pi, old laptop, or server), a 600GB+ SSD, 24/7 power and internet, and significant technical setup. The result: **fewer than 1% of Bitcoin users validate their own transactions.** The rest trust exchanges, SPV wallets, or third-party servers — undermining the trustless model that makes Bitcoin valuable.

Meanwhile, every Bitcoin user already carries a device in their pocket with more processing power than the computers that ran Bitcoin for its first decade.

## The Goal

**Allow any Bitcoin user to validate their own transactions against their own node, on the phone they already own.**

Hercules is not a wallet. It is the verification layer underneath any wallet. Users keep their preferred wallet app (BlueWallet, Muun, or anything that supports Electrum or BIP 157/158) and point it at their local Hercules node. Every transaction is verified against the user's own copy of Bitcoin's rules — no trusted third parties, no remote servers, no extra hardware.

## How It Works

### Pruned Validation (Personal Security)

Hercules runs a pruned Bitcoin full node on-device:

- Downloads and validates every block header since genesis (~60MB)
- Bootstraps via AssumeUTXO — a cryptographically committed snapshot of the current UTXO set, enabling immediate validation of new blocks while historical verification proceeds in the background
- Validates every new block in full: transaction scripts, double-spend checks against the UTXO set, proof of work, merkle roots, block rewards
- Prunes old block data after validation, keeping storage to ~2-4GB
- Maintains the complete UTXO set — the authoritative record of who owns what

A pruned node has **identical security** to a full archival node. Every block is validated. The raw block data is simply discarded after its contents have been verified and applied to the UTXO set. Nothing is skipped.

### Push-Triggered Block Enforcement (Network Participation)

iOS aggressively limits background execution, but Bitcoin's consensus enforcement is naturally compatible with these constraints. New blocks arrive approximately every 10 minutes, and validating a block takes less than a second on modern hardware.

When a new block is mined:
1. A lightweight relay sends a silent push notification to the device
2. iOS wakes the app for ~30 seconds
3. Hercules downloads the block (~1-2MB), validates it, and relays or rejects it to connected peers
4. The app returns to sleep

This provides **real-time consensus enforcement** — the phone validates and relays its opinion on every new block as it arrives, matching the behavior of a 24/7 home node for the function that matters most.

### Cooperative Mempool Relay (Novel Protocol)

Beyond block validation, full nodes also relay unconfirmed transactions through the mempool. This is continuous, low-intensity work that iOS background limits cannot accommodate for a single device. Hercules solves this with a cooperative relay protocol.

**The concept:** Individual phones cannot maintain 24/7 mempool coverage. A group of phones can. By scheduling relay shifts across a user pool, the collective behaves like a single always-on node — even though each individual phone contributes only minutes per hour.

**How it works:**

- Users opt into a named **policy profile** that defines their mempool relay rules (e.g., "Core Standard," "Knots Conservative," or custom profiles)
- Users running the same policy are grouped into **relay cooperatives**
- Each phone is assigned a deterministic time slot: `slot = hash(node_id + current_hour) mod slots_per_hour`
- During its slot, the phone receives a push notification, wakes up, connects to peers, and relays mempool transactions according to the group's policy
- When the slot ends, the next phone in the cooperative takes over

**Scaling properties:**

| Users in cooperative | Duty per phone | Coverage |
|---|---|---|
| 60 | 1 min/hour | 24/7 continuous |
| 600 | 1 min/10 hours | 24/7 with 10x redundancy |
| 6,000 | 1 min/100 hours | 24/7 with 100x redundancy |
| 60,000 | ~1 min/week | 24/7, near-zero individual cost |

At scale, each phone does almost nothing while the cooperative provides robust, continuous relay coverage.

**Shared policy profiles** are a feature, not a limitation. They make mempool policy an explicit, visible choice rather than a hidden per-node configuration. Users understand what rules their cooperative enforces and actively opt into them.

**No central coordinator.** Slot assignment is deterministic — every node can independently compute its schedule. The push notification server only knows device tokens and wake times, not identities or policies. Users can choose from multiple independent push relays, or run their own.

### Privacy

All network connections are routed through **Tor** (via Arti, the Tor Project's Rust implementation). The user's IP address is never exposed to the Bitcoin P2P network. Peers see only onion addresses. ISPs see only Tor traffic, not Bitcoin traffic.

## Technical Architecture

```
┌─────────────────────────────────────────────────────┐
│  iOS (Swift / SwiftUI)                              │
│  ┌────────────────────────────────────────────────┐ │
│  │  UI Layer                                      │ │
│  │  - Sync status, block explorer, node dashboard │ │
│  │  - Cooperative status and scheduling           │ │
│  │  - Wallet integration settings                 │ │
│  └──────────────────┬─────────────────────────────┘ │
│                     │ UniFFI                         │
│  ┌──────────────────▼─────────────────────────────┐ │
│  │  Rust Core                                     │ │
│  │  ┌──────────────┐  ┌────────────────────────┐  │ │
│  │  │ rust-bitcoin  │  │ libbitcoinconsensus    │  │ │
│  │  │ Block parsing │  │ Script validation (C)  │  │ │
│  │  │ Serialization │  │ Consensus rules        │  │ │
│  │  └──────────────┘  └────────────────────────┘  │ │
│  │  ┌──────────────┐  ┌────────────────────────┐  │ │
│  │  │ P2P Protocol  │  │ UTXO Set Manager       │  │ │
│  │  │ Peer mgmt     │  │ Database (SQLite/LMDB) │  │ │
│  │  │ Block relay   │  │ Pruning engine         │  │ │
│  │  │ Mempool       │  │ AssumeUTXO bootstrap   │  │ │
│  │  └──────────────┘  └────────────────────────┘  │ │
│  │  ┌──────────────┐  ┌────────────────────────┐  │ │
│  │  │ Arti (Tor)    │  │ Cooperative Protocol   │  │ │
│  │  │ All traffic   │  │ Slot scheduling        │  │ │
│  │  │ via onion     │  │ Policy profiles        │  │ │
│  │  └──────────────┘  └────────────────────────┘  │ │
│  └────────────────────────────────────────────────┘ │
│                                                     │
│  iOS Lifecycle                                      │
│  - BGProcessingTask: historical block validation    │
│  - Silent push: new block validation + relay        │
│  - Silent push: cooperative mempool relay shifts     │
└─────────────────────────────────────────────────────┘
```

### Stack

| Component | Technology | Role |
|---|---|---|
| UI | Swift / SwiftUI | iOS app, lifecycle management |
| Bridge | UniFFI | Swift ↔ Rust interop |
| Block parsing | rust-bitcoin | Deserialization, script types, addresses |
| Consensus | libbitcoinconsensus (C FFI) | Script validation — battle-tested, from Bitcoin Core |
| Networking | Custom Rust | Bitcoin P2P protocol (version, verack, inv, getdata, block, tx) |
| Tor | Arti (Rust) | Onion routing for all connections |
| Storage | SQLite or LMDB | UTXO set, headers, pruned blocks |
| Wallet API | BDK (future) | Descriptor wallet, Electrum-compatible local server |
| Lightning | LDK (future) | Lightning Network integration |

### Why Rust

The core is written in Rust for several reasons:
- Cross-compiles cleanly to iOS ARM64
- Memory safety without garbage collection — critical for a long-running node
- The Bitcoin Rust ecosystem (rust-bitcoin, BDK, LDK, Arti) is mature and well-maintained
- UniFFI provides clean Swift bindings with minimal overhead
- A single Rust codebase could later target Android, desktop, and WASM

### Why libbitcoinconsensus

Consensus validation is the one place where "don't reinvent it" is an absolute rule. A single bug in consensus code means your node forks off the network — it accepts blocks the rest of the network rejects, or vice versa. `libbitcoinconsensus` is extracted directly from Bitcoin Core and has 15 years of battle-testing. We use it via C FFI for script validation and implement the remaining consensus checks (PoW, merkle root, block reward, UTXO updates) in Rust with extensive testing against Bitcoin Core's test vectors.

## Implementation Phases

### Phase 0: Toolchain & Proof of Life ✅
**Goal:** Rust code running on an iPhone, parsing real Bitcoin data.

- Set up Xcode project with Rust integration via UniFFI
- Cross-compile rust-bitcoin for `aarch64-apple-ios`
- Build a minimal app that fetches a block, deserializes it, and displays header information in SwiftUI

**Deliverable:** An app that displays block header information parsed by Rust on iOS.

### Phase 1: Header Sync & P2P Networking ✅
**Goal:** Connect to the real Bitcoin network and sync the full header chain.

- Bitcoin P2P protocol: version/verack handshake, getheaders/headers messages
- Full header chain download in 2,000-block batches from live peers
- Header validation: proof of work, difficulty retarget (every 2,016 blocks with U256 arithmetic), median-time-past timestamps, hash chain linkage
- SQLite header storage with WAL mode
- DNS seed peer discovery across 8 seeds
- Dark navy iOS UI with sync progress, peer info, and status cards
- 35-test suite covering validation, storage, and public API

**Deliverable:** App that syncs and validates all ~860,000+ block headers from live peers.

### Phase 2: Pruned Validating Node
**Goal:** A real, fully-validating pruned Bitcoin node on iPhone.

This is the core of the project and the largest phase, broken into four sub-phases.

**Phase 2a — Block Download & Structural Validation (3-4 weeks)**
- Add `getdata`/`block` messages to P2P layer
- Download full blocks from peers
- Validate block structure: merkle root, coinbase, block weight/size, witness commitments
- Transaction format validation

**Phase 2b — Script Validation via libbitcoinconsensus (2-3 weeks)**
- Integrate `bitcoinconsensus` crate (bundles the C library from Bitcoin Core)
- Validate transaction scripts for all input types (P2SH, SegWit, Taproot)
- Handle BIP activation heights (BIP 16, 34, 65, 66, 68/112/113, 141/143, 341/342)
- Test against Bitcoin Core's script test vectors

**Phase 2c — UTXO Set Management (4-6 weeks)**
- UTXO database using LMDB (~8GB, ~100M entries) — benchmark vs SQLite first
- Apply/rollback blocks against UTXO set (spend inputs, create outputs)
- Full validation: verify inputs exist, no double-spends, no inflation, correct fees
- Memory-conscious design for iOS (LMDB memory-mapping, no full set in RAM)

**Phase 2d — AssumeUTXO & Pruning (3-4 weeks)**
- Bootstrap from a committed UTXO snapshot (~8GB download, WiFi only)
- Verify snapshot hash against hardcoded value, load into LMDB
- Validate new blocks forward from snapshot height
- Pruning engine: retain last 288 blocks (~2 days), delete older block data
- Catch-up logic when app returns to foreground after being offline

**Design decisions:**
- ~10-12GB storage (UTXO set + pruned blocks) — accepted, target users are power users
- AssumeUTXO for onboarding — no full historical sync required on device
- Foreground validation only in Phase 2 — background/push deferred to Phase 4
- Historical validation handled cooperatively (see Phase 6)
- UTXO set must be complete (consensus requires it — relay policy is separate from validation)

**Deliverable:** iPhone app that validates every new block in real-time and maintains a complete, verified UTXO set.

**Milestone: 12-17 weeks after Phase 1**

### Phase 3: Tor Integration
**Goal:** All network traffic routed through Tor. Can begin in parallel with Phase 2.

- Integrate Arti as a Rust library dependency
- Route all P2P connections through Tor
- Tor-safe DNS resolution (no clearnet leaks)
- Optional: accept inbound connections via .onion hidden service
- Tor circuit management optimized for Bitcoin's connection patterns

**Deliverable:** Node that is invisible to ISPs. Peers see only a .onion address.

**Milestone: 3-4 weeks (can overlap with Phase 2)**

### Phase 4: Push-Triggered Block Validation
**Goal:** Real-time consensus enforcement even while the app is backgrounded.

- Build or integrate a lightweight block notification relay
- Implement silent push notification handling in iOS
- On push: wake app, download block from peers, validate, relay/reject, return to sleep
- Monitoring: track how many blocks were validated via push vs. foreground catch-up
- Ensure reliable peer connections can be re-established within the ~30 second push window

**Deliverable:** Phone validates and relays every new block within seconds of it being mined, 24/7, whether the app is open or not.

**Milestone: 3-4 weeks after Phase 2**

### Phase 5: Fully Participating Node
**Goal:** Transform Hercules from a validating observer into a full network participant — relay blocks, relay transactions, serve peers, accept inbound connections.

Through Phase 4, Hercules downloads and validates but never gives anything back to the network. A real pruned node (Bitcoin Core with `-prune`) still relays blocks and transactions, responds to peer requests, and accepts inbound connections. Phase 5 closes this gap.

**Phase 5a — AssumeUTXO Download & Bootstrap**
- Automatic download of an AssumeUTXO snapshot over WiFi (~7GB compressed)
- Hardcoded snapshot hash (matches Bitcoin Core v26+ `chainparams.cpp`) — download source is untrusted, hash commitment is trusted
- One-tap onboarding: download, verify, load into UTXO set, begin validating forward
- Temporary: host Hercules-format snapshot on CDN; long-term: BitTorrent/IPFS distribution

**Phase 5b — Mempool**
- In-memory transaction pool (50MB cap, appropriate for mobile)
- Full transaction validation against UTXO set (inputs exist, scripts valid, no double-spends)
- Standard relay policy: dust threshold, max weight, min fee rate, BIP 125 RBF
- Fee-rate-based eviction when pool is full
- Conflict removal when new blocks confirm transactions

**Phase 5c — Outbound Relay & Peer Serving**
- Relay validated block announcements (`inv`/`headers`) to all connected peers
- Relay validated mempool transactions (`inv`/`tx`) with privacy delay (Poisson, ~2s avg)
- Respond to `getheaders` — serve our header chain to syncing peers
- Respond to `getdata` — serve recent blocks (last 288, within pruning window) and mempool transactions
- Respect `feefilter` (BIP 133) — don't send transactions below peer's minimum fee rate
- Advertise `NODE_NETWORK_LIMITED` (BIP 159) service flag
- Bidirectional P2P message handling in `p2p.rs` (currently send-only)

**Phase 5d — Inbound Connections**
- Activate the .onion hidden service (groundwork exists in `tor.rs`)
- Accept inbound peer connections via onion address
- Handle inbound version/verack handshake and service requests
- Inbound peer limit: 4 (conservative for mobile battery)
- Inbound peers participate in reputation scoring (Ticket 007)

**Design decisions:**
- Persist last 288 full blocks for serving (~430MB) — required for `NODE_NETWORK_LIMITED`
- Mempool size 50MB (vs Core's 300MB) — configurable, balances utility vs mobile constraints
- Block relay is immediate; transaction relay uses random delay for privacy
- AssumeUTXO snapshot hash is the same trust model as Bitcoin Core — open-source, cross-verifiable

**Deliverable:** Hercules is a real, fully-participating pruned Bitcoin node — validates, relays, serves peers, and accepts inbound connections over Tor.

**Milestone: 8-12 weeks after Phase 4**

### Phase 6: Cooperative Mempool Relay & Historical Validation
**Goal:** The novel contribution — phones collectively provide continuous mempool relay and distributed chain verification.

**Cooperative Mempool Relay:**
- Design and implement the cooperative relay protocol
- Policy profile system: define, distribute, and enforce named mempool policies
- Deterministic slot scheduling algorithm
- Push notification integration for relay shift wake-ups
- Peer connection warm-up optimization (minimize time from wake to active relay)
- Shift overlap and handoff protocol for continuity
- Protocol specification document (potential BIP candidate)

**Cooperative Historical Validation:**
- Structural spot-checking: cooperative randomly audits historical blocks (merkle roots, coinbase rewards, transaction format) — works immediately, no utreexo required
- Full cooperative validation (future): with utreexo, phones validate assigned epoch ranges (~2,016 blocks each) and produce accumulator hashes that prove correct validation
- Multiple phones independently validate the same range — agreement proves correctness

**Deliverable:** A network of phones that collectively relays mempool transactions 24/7 and cooperatively verifies the full historical chain.

**Milestone: 2-3 months after Phase 5**

### Phase 7: Wallet Integration API
**Goal:** Let any wallet verify transactions against the local Hercules node.

- Implement local Electrum Personal Server protocol (so existing wallets can connect)
- Implement BIP 157/158 compact block filter serving
- Local HTTP/RPC interface for on-device wallet apps
- Documentation and integration guides for wallet developers

**Deliverable:** Any Electrum-compatible or BIP 157/158 wallet on the same device can use Hercules as its backend.

**Milestone: 4-6 weeks after Phase 5**

### Phase 8: Lightning (Future)
**Goal:** Full Lightning Network node backed by the on-device validating node.

- Integrate LDK (Lightning Dev Kit)
- Channel management and payment routing
- On-chain ↔ Lightning submarine swaps
- Cooperative channel monitoring (extension of the relay cooperative concept — phones watch each other's channels for fraud while owners are offline)

**Milestone: TBD — depends on LDK mobile maturity and Phase 2-7 stability**

## Security Model — Progressive Trust Reduction

Hercules progressively reduces trust assumptions as each phase ships. At every stage, the node is useful — later phases add resilience, not core functionality.

### Phase 2: Sovereign Validation (app open)

While the app is foregrounded, Hercules validates every new block: transaction scripts (via libbitcoinconsensus), UTXO spends, merkle roots, proof of work, coinbase rewards. Verifies your own transactions against your own UTXO set — zero reliance on third parties. Prunes old block data, keeping storage at ~10-12GB.

**Trust assumption:** The AssumeUTXO snapshot hash, hardcoded in open-source code and cross-verifiable against Bitcoin Core v26+ source. This is the same trust model every Bitcoin Core user operates under by default.

**Limitation:** App must be open. If backgrounded or killed, validation pauses until reopened. Does not relay or serve peers.

### Phase 4: Always-On Validation (push notifications)

Silent push notifications wake the app every ~10 minutes when a new block is mined. Hercules validates the block in 2-5 seconds within the 30-second iOS push window, then goes back to sleep.

Your phone validates every block 24/7, whether you're using the app or not — matching a dedicated home node for the function that matters most (consensus enforcement).

**Limitation:** Validates but does not yet relay blocks, serve peers, or maintain a mempool.

### Phase 5: Full Network Participation

Hercules becomes a real network participant: relays blocks and transactions, responds to peer requests, accepts inbound connections via Tor, and maintains a mempool. Advertises `NODE_NETWORK_LIMITED` (BIP 159). Functionally equivalent to Bitcoin Core in pruned mode.

**Limitation:** Individual phone mempool relay is intermittent (only while app is active or during push windows).

### Phase 6: Cooperative Verification

Two cooperative features eliminate remaining limitations:

**Mempool relay shifts:** Phones take scheduled turns relaying mempool transactions. With 60 users, each contributes 1 minute per hour for 24/7 continuous coverage. Solves the intermittent relay constraint.

**Historical spot-checking:** The cooperative randomly audits historical blocks across the full chain, verifying merkle roots, coinbase rewards, and transaction structure. Reduces reliance on the AssumeUTXO trust assumption through distributed probabilistic verification.

### Future: Utreexo

Replace the ~8GB UTXO database with a ~1KB cryptographic accumulator (see Ticket 002). This:

- Drops storage from ~10-12GB to ~2-3GB
- Enables full cooperative historical validation — phones validate assigned 2,016-block epoch ranges with compact proofs, proving correct validation via accumulator hash agreement
- The endgame: every historical block fully validated by the cooperative, every new block validated by your phone, ~2GB footprint, zero trust assumptions beyond the open-source code

### Risk Summary

| Stage | Trust assumption | Practical risk |
|---|---|---|
| Phase 2 | AssumeUTXO hash (in open-source code, matches Bitcoin Core) | Same as default Bitcoin Core |
| Phase 4 | Same, but no validation gaps from app closure | Full real-time validation |
| Phase 5 | Same, but now a full network participant (relay + serve) | Equivalent to pruned Bitcoin Core |
| Phase 6 spot-checking | Cooperative audits reduce snapshot reliance | Lower than Bitcoin Core default |
| Utreexo cooperative | Full chain verified, zero trust assumptions | Equivalent to full archival node |

## Resource Requirements (On-Device)

| Resource | Steady State | During Initial Sync |
|---|---|---|
| Storage | ~10-12 GB (UTXO set + pruned blocks) | ~5 GB download (compressed AssumeUTXO snapshot) |
| RAM | ~100-200 MB | ~200-300 MB |
| CPU | Burst every ~10 min (block validation) | Moderate (snapshot loading + catch-up) |
| Network | ~150-300 MB/day | ~5 GB (AssumeUTXO snapshot over WiFi) |
| Battery | Comparable to a messaging app | Noticeable during initial setup |

## What Hercules Is Not

- **Not a wallet.** It is the trust layer underneath your wallet. In Phase 7, existing wallets (BlueWallet, Sparrow, any Electrum-compatible wallet) can point at Hercules to verify transactions against your own node, on your own device.
- **Not a mining node.** It validates, it does not produce blocks.
- **Not a 24/7 server replacement.** Individual phones are intermittent. The cooperative protocol provides collective continuity, but a single Hercules node does not replace a dedicated always-on node for network infrastructure purposes.

## Why "Hercules"

The mythological figure who carried the weight of the world on his shoulders. Hercules puts the weight of validating your own transactions on the device you already carry — and shares the burden of supporting the network across everyone who participates.

## License

MIT

## Contributing

This project is in early development. See the implementation phases above for current status and priorities.
