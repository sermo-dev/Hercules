# Ticket 029: Clearnet by Default, Tor as an Opt-In Setting

## Decisions (2026-10-23)

- **Decided:** clearnet is the default for sync and relay. Tor is an opt-in setting.
- **Decided:** the user's own transactions always go out via short-lived Tor connections ("private broadcast"), even in clearnet mode.

## Summary

Proposal: make **clearnet** the default P2P transport and make **Tor an opt-in setting**. The user's own transactions should still leave the phone privately through a "private broadcast" path, so the main privacy cost of clearnet (linking a transaction to the IP that first sent it) is mitigated even in the default mode.

The Rust core already supports both transports, so this is mostly a settings, onboarding, and lifecycle change, plus a new private-broadcast path.

**Status: proposal for owner review.** The owner is strongly considering this. Decide before 028 is finalized and before the README rewrite (044).

## Background

**Both transports already exist in the core.**
- `HerculesNode::new(db_path, tor_data_dir: Option<String>)` (`hercules-core/src/lib.rs:308`) bootstraps Tor only when a directory is passed. Otherwise `tor` is `None`.
- `PeerPool` picks the transport per connection: `Peer::connect_tor` when Tor exists, `Peer::connect` otherwise (`peer_pool.rs:868-872`).
- Discovery also switches: `Peer::discover_peers_tor` resolves DNS seeds **through Tor** and adds onion seeds, while `Peer::discover_peers` resolves them over clearnet (`peer_pool.rs:647-649`, `p2p.rs:117-160`). So DNS seed lookups already avoid leaking in Tor mode.
- Note `p2p.rs:46`: the onion seed list carries "TODO: verify these against Bitcoin Core's current seed list."

**Swift hardcodes Tor on.** `torDataDir()` always returns `Documents/tor` (`NotificationManager.swift:461-464`, `ContentView.swift:529-532`), so every node is a Tor node. The README promises "All network connections are routed through Tor".

**Ticket 014's wallet API is Tor-only by design.** It is served on a second onion service, "hercules-wallet".

**Push relay registration (019) is clearnet already.** `registerWithRelay` uses `URLSession.shared` (`NotificationManager.swift` ~70-91). The relay therefore sees the phone's IP whatever this setting is.

## Tradeoffs

| | Clearnet (proposed default) | Tor (opt-in) |
|---|---|---|
| Wake latency | No bootstrap; peers in about 1 s. Makes 028's budget easy | 5–15 s bootstrap per cold wake (`lib.rs:306-307`); the biggest threat to the 30 s window |
| Reliability | Direct TCP; failures are rare and fast | Circuit build failures; slow or partitioned onion peers |
| Battery and data | Lower | Higher (circuit maintenance, cell overhead) |
| Peer supply | Tens of thousands of reachable IPv4/IPv6 nodes | A few thousand onion nodes |
| Eclipse resistance | `/16` bucketing (ticket 001/016) is meaningful | Onion addresses have no network topology, so `/16` diversity means nothing; diversity has to come from other signals |
| ISP visibility | ISP sees Bitcoin P2P traffic (port 8333, a recognizable protocol) | ISP sees only Tor |
| Peer visibility | Peers see the phone's IP (carrier CGNAT IP on cellular) | Peers see a Tor exit or onion |
| Own-tx origin | **Main risk:** the first relayer of a transaction is a strong origin signal, and spy nodes connect widely to catch it | Origin hidden |
| Inbound | Phones are almost always behind NAT/CGNAT; no clearnet inbound in practice | Inbound via onion service (`lib.rs:318`) |
| App Store / jurisdiction | No issue | Fine, but some networks block Tor |

The power users this product targets mostly care about **validation sovereignty** (clearnet is fine for that) and **payment privacy** (only the own-transaction broadcast really matters). Clearnet plus private broadcast covers both, and makes wakes fast and dependable.

## Proposed design

### 1. Settings
- New "Network privacy" card in Settings, with **Standard (clearnet)** as the default and **Tor** as the alternative.
- Persist the choice in `UserDefaults` (App Group, so the widget can show it).
- `NodeHost` (028) passes `torDataDir: nil` in Standard mode.

### 2. Private broadcast of own transactions, in both modes
Transactions from the in-app wallet (020) or the 014 wallet API go through a **separate path** (see 033):
- Open short-lived Tor connections to 2–3 random peers.
- Send only the transaction.
- Wait for a relay echo (`inv` back from other peers) or a timeout.
- Then tear the connections down.

In Standard mode this means bootstrapping Tor on demand, only when sending. That happens in the foreground, where the 5–15 s cost is acceptable and can be shown as "Broadcasting privately…".
- **Fallback** if Tor is unavailable: ask the user before broadcasting over clearnet, never silently.
- Bitcoin Core has been adding a comparable "private broadcast" feature (sending own transactions over short-lived Tor/I2P connections). **Verify its current status** and copy its peer-selection and confirmation rules rather than inventing our own.

### 3. Inbound and the onion service
Start the P2P onion service and the 014 wallet onion only in Tor mode. In Standard mode the 014 wallet API is unavailable (or Tor is bootstrapped just for it while it's open). Say so in Settings.

### 4. Switching modes at runtime
Changing modes means `NodeHost` tears the node down and rebuilds it. Address manager entries are kept, but tag peers by network so clearnet mode doesn't dial onion addresses and Tor mode can dial both. Nothing on disk needs wiping.

### 5. DNS
- Standard mode: clearnet DNS seeds (current `discover_peers`) are fine.
- Tor mode: keep the existing Tor-resolved seeds. Audit that nothing else (snapshot download, relay registration, any `URLSession`) runs over clearnet while Tor mode is on, or document each exception in the UI. That audit closes the README Phase 3 "Tor-safe DNS" item. Ticket 012 covers the snapshot download.

### 6. Onboarding copy (draft)
> **Standard** — Connects directly to the Bitcoin network. Fast and battery-friendly. Your internet provider can see that you run Bitcoin. Your own payments are still sent privately over Tor.
> **Tor** — Routes everything through Tor. Slower wake-ups and more battery use, but nobody on the network learns your IP.

## Files touched

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/SettingsView.swift` | Network privacy card |
| `HerculesApp/HerculesApp/NodeHost.swift` (from 028) | Pass `torDataDir` per setting; rebuild on change |
| `HerculesApp/HerculesApp/NotificationManager.swift`, `ContentView.swift` | Stop hardcoding `torDataDir()` |
| `HerculesApp/HerculesApp/AboutView.swift` | Copy update |
| `hercules-core/src/lib.rs` | Start onion services only in Tor mode; on-demand Tor for private broadcast |
| `hercules-core/src/peer_pool.rs`, `peer_store.rs` | Network tag on addresses; filter dialing by mode |
| `hercules-core/src/sync.rs` | Private-broadcast entry point (shared with 033) |
| `hercules-core/src/p2p.rs` | Resolve the onion seed TODO (`:46`) |

## Dependencies

- **028**: `NodeHost` owns node construction.
- **033**: private broadcast is the transport for own transactions.
- **044**: the README's "All traffic over Tor" claim must change.
- **014**: document that the wallet onion API needs Tor.

## Estimated effort

~4–5 days:
- settings and plumbing: 1 day
- address network tagging: 1 day
- private broadcast: 2 days, shared with 033
- copy and testing: 1 day

## Verification

- Fresh install defaults to Standard. The first wake reaches "transport ready" in under 2 s (028 instrumentation).
- Toggle to Tor: the node rebuilds, connects only through Tor, and the onion services start. Toggle back: the onion services stop.
- In Standard mode, broadcasting an own transaction opens Tor connections only for the broadcast; a packet capture shows no clearnet `tx` message from the phone.
- In Tor mode, a packet capture shows no clearnet DNS or TCP to Bitcoin peers.

## Open questions

- **Default.** The owner leans toward clearnet default. Confirm.
- **Is private broadcast mandatory in Standard mode, or a toggle?** Recommendation: on by default, with the confirm-before-clearnet fallback.
- **Push relay over Tor in Tor mode?** Registration currently leaks IP to the relay. It's probably worth routing it over Tor in Tor mode; track in 019.
- **I2P / CJDNS?** Out of scope.

## Roadmap position

Tier 1. Decide alongside 028, since the default transport largely determines whether wakes fit in budget. Implementation of private broadcast lands with 033.
