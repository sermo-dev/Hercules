# Ticket 052: Network Hygiene — Own-Tx Privacy, Address Book, Fair Penalties

## Summary

Five network problems that don't freeze the node (that's 049) but leak privacy, weaken eclipse protection, or punish honest peers:

1. **Own-tx linkability in Tor mode.** Our own transactions are announced to every peer, including peers that dialed our permanent .onion address. Every wallet send can be linked to one long-lived identity.
2. **Address book poisoning.** Any peer can fill the 10k-entry address book, push out the DNS seeds, and make maintenance dial dead entries for 30 s each.
3. **Honest peers banned for our own problems.** A header that is merely "too far in the future" (because the phone's clock is behind) costs the peer 50 points; two offenses mean a 24 h ban. A local error looking up the retarget epoch start is also blamed on the peer.
4. **Wasted downloads.** There is no recently-rejected filter and no in-flight dedup, so every Knots-filtered transaction is downloaded again from every peer that announces it.
5. **Small correctness gaps:**
   - an invalid onion seed;
   - LAN and CGNAT addresses accepted from gossip;
   - a peer can mark our own transaction "propagated" by echoing it back;
   - no pings, so dead inbound peers hold their slot forever.

**Severity: High** for items 1 and 2, **Medium** for item 3, **Low** for items 4 and 5.

Found by the P2P, consensus and mempool reviewers (2026-10-28 team review of main @ 7732755). The earlier whole-repo review reserved this ticket number for "network hygiene".

## Background

Line numbers are at main 7732755.

### 1. Own transactions in Tor mode

`announce_own_tx` (`sync.rs:1416-1446`) runs when no private-broadcast transport is installed, which is always: `set_private_broadcast` is dead code (`sync.rs:1446-1447`). Behavior by mode:

- **Tor mode:** it queues an `inv`, and `drain_relay_queue` sends it with no delay to every peer, inbound included. Inbound peers dialed our onion. Outbound peers received our onion in the self-advertisement on connect (`peer_pool.rs:993`). Our `getdata` gate then serves those peers the tx. A spy that connects to our onion and records which transactions we announce first clusters every wallet send under one identity. Production runs Tor on (`NodeHost` always passes `torDataDir`).
- **Clearnet mode** (the default chosen in 029): own transactions are never announced at all (`sync.rs:1425-1431`), so sends never leave the phone.

The real fix is ticket 029's private broadcast (short-lived isolated Tor connections, no self-advertisement). That is needed before the wallet can send. This ticket covers the stopgap and the rules the private path must follow.

### 2. Address book poisoning

`sync.rs:3872-3915` and `peer_pool.rs:298-405`, `558-563`, `603-615`:

- `addr`/`addrv2` is accepted from inbound peers with no rate limit and no source bucketing.
- Ten 1000-entry messages fill the 10k table. Eviction then removes every never-connected entry, oldest first, including the DNS seeds.
- Never-tried entries rank above retried ones, and the flood keeps `candidate_count ≥ 50`, so the DNS fallback never fires.
- Dead entries cost up to 30 s each (Tor connect) inside `maintain`, on the sync thread. All of this is persisted.
- **Eclipse risk:** onion addresses have no netgroup limit, and `cross_check_group` treats each onion as its own group. One operator's onions could fill all 12 outbound slots and act as "independent" witnesses.

### 3. Penalties for things that aren't the peer's fault

- **Future timestamps:** `validation.rs:106-117` returns `FutureTimestamp`, and every caller applies `INVALID_HEADERS_PENALTY` (50): `sync.rs:3658-3660` (tip extension), `3589-3593` (reorg), `1958-1961` (`fork_reaches`), `2504-2507` (witnesses), `4408` (wake) and `4759-4760` (catch-up). Peers start at 100 and are banned at ≤20. Core's `time-too-new` is `BLOCK_TIME_FUTURE`, which `MaybePunishNodeForBlock` does not punish.
  **Scenario:** the phone's clock is ~2 h behind. The node bans most of its honest peers within seconds, and the persisted bans outlast fixing the clock.
- **Epoch-start lookup:** `validation.rs:45-51`. If `epoch_start_time` fails at a retarget boundary (e.g. a SQLite error), it is reported as `BadDifficulty`, and callers penalize the peer. This breaks 024's rule that local faults are never the peer's fault.

### 4. Repeated downloads

`handle_inv` (`sync.rs:4079-4082`) requests any txid not in our mempool. Rejected transactions (often large inscriptions under Knots policy) are fetched again from each announcing peer, and accepted ones are often fetched from several peers at once.

### 5. Small gaps

- **All four** `ONION_SEEDS` entries (`p2p.rs:61-63`) fail v3 checksum validation, so none can be dialed (the 4th is also 55 characters). Found by the PR #30 test pass, which has an ignored reproducer.
- `is_routable` (`sync.rs:393`) accepts RFC1918, CGNAT, IPv4-mapped, ULA and link-local addresses on any port. In clearnet mode a peer can make us dial hosts on the user's LAN.
- An `inv` echoed back by the peer we sent our tx to marks it "propagated" (`sync.rs:4044`). A censoring peer can fake delivery.
- We never send pings, so dead inbound connections keep their slot; there is no inbound eviction.

## Proposed fix

### 1. Own transactions (stopgap now; 029 for the real path)

- **Tor mode stopgap:** never announce or serve own transactions to inbound peers, or to outbound peers we self-advertised to on that connection. Announce only to outbound peers that never received our onion, after a random delay (Poisson, like Core's trickle).
- **Self-advertisement:** decide whether outbound peers should ever receive our onion. Recommendation: advertise it only from connections that carry no own transactions, or stop advertising it until there's a reason to accept inbound.
- **Clearnet mode:** nothing until 029; a clear "not sent" state is covered by 053's delivery signal.
- **029 must follow these rules:** isolated circuit per broadcast, no self-ad, never the same identity as relay traffic, confirmation by seeing the tx come back from an unrelated peer.

### 2. Address book

- Per-peer token bucket for `addr` (Core: about 0.1 addresses/s, burst 1000). Ignore or heavily cap addr from inbound peers.
- Bucket new entries by source, so one source can fill only a bounded share of the table.
- Keep a protected set (DNS seeds, known-good) that eviction can't remove, and reserve some outbound slots for it.
- Group onion addresses for diversity: treat all onions as one netgroup for outbound and cross-check purposes, unless they were tried and good.
- Connect in parallel with a total deadline (overlaps 049's maintenance timer).

### 3. Fair penalties

- New `ValidationError` class for "not yet valid" (`FutureTimestamp`): no penalty. Store the valid prefix of the batch and retry later.
- New variant for missing local context (epoch start lookup): no penalty, local error.
- Audit every `misbehaving(...)` call site against 024's three classes, and record the class in the log line.
- Lift bans caused by `FutureTimestamp` on upgrade (one-time cleanup).

- **MTP for early heights:** `validation.rs:96` skips the median-time-past check for heights 1..=10. Core's `GetMedianTimePast` uses however many ancestors exist. This is low impact on mainnet (the anchor is far above), but it's a consensus divergence that regtest and the harness hit. Port it exactly. A reproducer test is in PR #29, ignored.

### 4. Recently-rejected filter and in-flight map

- Rolling filter of rejected txids (and wtxids), reset each block, as Core's `m_recent_rejects`.
- Map of in-flight tx requests with a timeout; ask another announcer only after the timeout.

### 5. Small gaps

- Fix or remove the bad onion seed. Add a test that every seed parses as v3 with a valid checksum.
- `is_routable`: reject RFC1918, CGNAT, mapped, ULA and link-local addresses, as Core's `IsRoutable`.
- Count "propagated" only from a peer we didn't send the tx to.
- Ping every peer; drop non-responders; add simple inbound eviction (oldest idle) when inbound slots are full.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/sync.rs` | Own-tx announce rules; addr rate limit; penalty classes; reject filter and in-flight map; propagation rule; pings |
| `hercules-core/src/peer_pool.rs` | Source bucketing, protected set, onion grouping, inbound eviction |
| `hercules-core/src/validation.rs` | `FutureTimestamp` and missing-context classes |
| `hercules-core/src/p2p.rs` | Onion seed fix; `is_routable` |
| `hercules-core/src/peer_store.rs` | Persist protected entries; one-time ban cleanup |

## Dependencies

- **049**: maintenance timer and parallel connects.
- **024**: penalty classes.
- **029**: private broadcast replaces the stopgap; required before the wallet can send.

## Estimated effort

3–4 days:
- own-tx stopgap: 0.5 day
- address book: 1.5 days
- penalties: 0.5 day
- reject filter and small gaps: 1 day

## Verification

- **Tor mode:** an inbound mock never sees our own tx; an outbound mock that received our self-ad never sees it.
- **Addr flood:** 10×1000 IPv4 and TorV3 entries from one inbound peer. DNS and known-good entries survive, and one source can't win more than its share of outbound slots.
- **Clock behind:** a header timestamp more than 2 h ahead of our clock leaves the sending peer's score unchanged; the batch is retried after the clock catches up.
- **Epoch lookup failure:** injected store error at a retarget boundary; no penalty, local error.
- **Rejects:** a rejected txid announced by three peers is downloaded once; an accepted tx announced by three peers is downloaded once.
- **Seeds:** every `ONION_SEEDS` entry parses as v3.
- **`is_routable`:** table test of the address classes.

## Open questions

- **Accept inbound at all in Tor mode?** It serves the network but is what makes the onion identity linkable. Recommendation: keep accepting, but never mix own-tx traffic with it (the rule above).
- **Addr from inbound:** ignore entirely, or accept at a low rate? Recommendation: accept at a low rate into a separate "unverified" bucket.

## Roadmap position

Fifth in the pre-wallet hardening block: **049 → 050 → 053 → 054 → 052 → 025**. The own-tx stopgap can land early if Tor-mode sends happen before 029.
