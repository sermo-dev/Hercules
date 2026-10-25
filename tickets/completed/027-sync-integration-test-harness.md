# Ticket 027: Sync Integration Test Harness — Mock Peers on a Regtest Chain

## Summary

Unit-test coverage of the parts that don't touch the network is good: 305 unit tests pass, covering header math, block structure, the UTXO set, the mempool graph and peer scoring. The parts that do touch the network have **no tests at all**:

- the `sync()` loop
- reorg execution
- `cross_check_headers`
- `validate_latest_block`
- `catch_up_blocks`
- `rpc_broadcast_tx` relay

Those are exactly where tickets 022–025 make changes, and where peers can attack us.

This ticket builds a harness that runs the real `HeaderSync` code against **mock peers**: fake Bitcoin nodes running inside the test process. They serve a regtest chain mined on the fly and can be told to misbehave on cue.

**Severity: Medium (infrastructure).** Without it, 022–026 can't really be verified, so it should land early.

## What a "mock peer" is

A mock peer is a small fake Bitcoin node that runs on a thread inside `cargo test`:

- It listens on a loopback TCP port (`127.0.0.1:0`) and speaks the **real Bitcoin P2P wire protocol** (version/verack, `getheaders`→`headers`, `getdata`→`block`, `ping`/`pong`, `inv`, `tx`).
- Hercules connects to it exactly as it would to a real peer, using the same `Peer::connect` / `PeerStream::Direct` code path. So everything above the socket is the production code.
- The mock follows a **script** that decides how it answers: honestly, or with a chosen misbehavior.

Example script entries:

- serve chain X
- serve a different block when asked for height 5
- never answer `getdata`
- answer after 40 seconds
- send garbage bytes
- announce a fork with more work

The pieces already partly exist. `p2p.rs` tests have a `loopback_peer_pair()` helper (`hercules-core/src/p2p.rs:814`) that opens a loopback TCP pair, wraps one end in a `Peer`, and lets the test read and write raw P2P messages on the other end. The mock peer generalizes that into a reusable, scriptable server.

## Background: why this needs more than a test file

### Chain parameters are hardcoded to mainnet

To serve blocks Hercules will accept, the mock needs valid proof-of-work. Mining a mainnet-difficulty block in a test is impossible. Bitcoin solves this with **regtest**, whose minimum difficulty (`bits = 0x207fffff`) means any nonce has a ~50% chance of working, so blocks are mined in microseconds. Hercules can't speak regtest today:

- **Network magic:** `RawNetworkMessage::new(Magic::BITCOIN, msg)` at `p2p.rs:422`.
- **PoW limit:** `MAX_TARGET_BITS = 0x1d00ffff` at `validation.rs:9`, plus mainnet retargeting every 2016 blocks (`validation.rs:41`). Regtest never retargets.
- **Activation heights:** `BIP34_HEIGHT = 227_931` and `SEGWIT_HEIGHT = 481_824` (`block_validation.rs:14,17`). Script flags come from `bitcoinconsensus::height_to_flags(height)` (`block_validation.rs:226`), which uses mainnet heights. On regtest everything is active from height 1.
- **Genesis:** the header store is seeded from the mainnet genesis.
- **Seeds:** `DNS_SEEDS` / `ONION_SEEDS` (`p2p.rs:33,47`) are always used by `discover_peers`. `HeaderSync::new(db_path, tor)` (`sync.rs:367`) has no way to inject peer addresses.
- **Netgroup diversity:** `peer_pool.rs:531` limits outbound peers per /16. Every mock peer is on 127.0.0.1, so they all fall into one bucket and only one would be allowed.
- **Anchors:** the AssumeUTXO constants and ticket 023's `MIN_CHAIN_WORK` are mainnet values.

## Proposed design

### 1. `ChainParams`

A new module, `hercules-core/src/chain_params.rs`:

```rust
pub struct ChainParams {
    pub magic: Magic,
    pub genesis: Header,
    pub pow_limit_bits: u32,
    pub no_retargeting: bool,
    pub bip34_height: u32,
    pub segwit_height: u32,
    pub script_flags: fn(u32) -> u32, // mainnet: height_to_flags; regtest: all
    pub min_chain_work: [u8; 32],      // regtest: zero
    pub snapshot_anchor: Option<SnapshotAnchor>,
    pub enforce_netgroup_diversity: bool,
}
impl ChainParams { pub fn mainnet() -> Self; pub fn regtest() -> Self; }
```

Thread `&'static ChainParams` (or an `Arc`) through `validation.rs`, `block_validation.rs`, `p2p.rs`, `peer_pool.rs` and `sync.rs`. Production code always uses `mainnet()`. Regtest is test-only, behind `#[cfg(any(test, feature = "regtest"))]`, so it can never be selected in the shipped app.

### 2. `FixtureChain` builder (test support)

A new file, `hercules-core/tests/support/fixture_chain.rs`:

- `FixtureChain::new()` starts at regtest genesis. `.mine(n)` appends blocks with real coinbases paying a test key.
- `.spend(outpoint, outputs)` builds and signs real P2WPKH and P2TR spends with rust-bitcoin + secp256k1, so script validation is exercised for real.
- `.fork_at(height)` returns a sibling chain for reorg tests. `.with_more_work()` adds blocks.
- Variants for building invalid blocks:
  - `.invalid_coinbase_overpay()`
  - `.strip_witness(block)`
  - `.wrong_merkle()`
  - `.spend_missing_input()`
  - `.csv_early_spend()` (for 026)
- `.utxo_snapshot_at(height)` writes a HUTX file for the snapshot-load path (for 023).

### 3. `MockPeer` (test support)

A new file, `hercules-core/tests/support/mock_peer.rs`:

- `MockPeer::spawn(chain: FixtureChain, script: Vec<Behavior>) -> MockPeerHandle { addr, log }`
- `Behavior` covers: `Honest`, `WrongBlockAt(h, Block)`, `WithholdBlock(h)`, `DelayResponses(Duration)`, `SendGarbage`, `UnsolicitedBlockBefore(h, Block)` (the 022 scenario), `AnnounceFork(FixtureChain)`, `ServeMutated(h)`, `Disconnect`.
- `log` records every message received, so tests can assert things like "Hercules relayed tx X to this peer" (033) or "Hercules never re-requested failed block Y" (024).

### 4. Constructing `HeaderSync` against mock peers

- `HeaderSync::with_config(SyncConfig { params, db_dir: tempdir, tor: None, peers: PeerSource::Static(vec![addr...]) })`
- `PeerSource::Static` bypasses `discover_peers()` and the DNS/onion seeds.
- Production `HeaderSync::new` becomes a thin wrapper using `PeerSource::Discover`.

### 5. Test matrix (in `hercules-core/tests/sync_integration.rs`)

| Scenario | Exercises |
|---|---|
| Initial sync from genesis, 3 honest peers, 300 blocks with spends | baseline `sync()`, pruning at 288 |
| Unsolicited block arrives before the requested one | 022 |
| Peer serves the wrong block / withholds it | 022, 024 |
| Mutated (witness-stripped) block, then an honest peer | 024 Delivery |
| Consensus-invalid block with valid PoW | 024 Consensus, failed-block cache |
| Invalid extending headers | 024 |
| Two peers disagree on headers; tiebreaker | `cross_check_headers` |
| Low-work chain from a single eclipsing peer | 023 Part B (regtest `min_chain_work` > fixture work) |
| 1-block and 2-block reorgs; reorg at depth 288 and 289 | 025 |
| New branch withheld after reorg headers | 025 revert |
| `validate_latest_block` after a new block | push-wake path |
| `validate_latest_block` across a 1-block reorg | 025 background |
| `catch_up_blocks` with 10 blocks behind and a 2-second budget | budget handling |
| `rpc_broadcast_tx` → appears in a mock peer's `inv` log | 033 |
| Snapshot load at height 100, then sync forward | 023 Part A |

## Alternative considered: real `bitcoind -regtest` in CI

Run Bitcoin Core in regtest mode as the peer, driven over RPC.

**Pros:**
- Tests against the reference implementation: a *differential* test that catches cases where we accept something Core rejects. That pairs well with 026.

**Cons:**
- Needs a bitcoind binary in CI.
- Each test is slower (seconds instead of milliseconds).
- Misbehavior can't be scripted, because Core is honest by design.

Recommendation: build the mock-peer harness now for adversarial cases. Add a small, optional bitcoind-differential suite later (`#[ignore]` by default) that replays Core-mined regtest chains with edge-case transactions through Hercules.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/chain_params.rs` | **New**: `ChainParams::{mainnet, regtest}` |
| `hercules-core/src/validation.rs` | Use `params.pow_limit_bits` and `no_retargeting` |
| `hercules-core/src/block_validation.rs` | Use `params` activation heights and `script_flags` |
| `hercules-core/src/p2p.rs` | Magic from `params`; seeds only for `PeerSource::Discover` |
| `hercules-core/src/peer_pool.rs` | Netgroup diversity gated by `params` |
| `hercules-core/src/store.rs` | Genesis from `params` |
| `hercules-core/src/sync.rs` | `SyncConfig`, `HeaderSync::with_config`, `PeerSource` |
| `hercules-core/tests/support/{fixture_chain,mock_peer}.rs` | **New** |
| `hercules-core/tests/sync_integration.rs` | **New**: the matrix above |
| `hercules-core/Cargo.toml` | `regtest` feature (`tempfile` is already a dependency) |

## Dependencies

- None to start.
- 022 can land before this with unit tests only. 023–026 should add their scenarios here as they land.

## Estimated effort

About 4–6 days:

- `ChainParams` threading: about 1.5 days (mechanical but touches many signatures)
- `FixtureChain` with signed spends: about 1.5 days
- `MockPeer` and behaviors: about 1 day
- First 6–8 scenarios: about 1–2 days

The remaining scenarios arrive with their own tickets.

## Verification

- `cargo test` runs the integration suite in under 30 seconds on a laptop, with no network access needed (works with `--offline`).
- The existing 305 unit tests still pass unchanged. Mainnet params produce the same behavior, checked by the mainnet header and Taproot fixtures already in `validation.rs` / `block_validation.rs`.
- A deliberately re-introduced 022 bug (remove the hash check) makes the "unsolicited block" scenario fail. This proves the harness catches the class of bug it was built for.

## Open questions

- **Threading params: `&'static` vs `Arc`.** Recommendation: `&'static ChainParams`, since there are only two static instances. That gives zero-cost access and simpler signatures.
- **Should regtest be shippable for developer builds** (for example, pointing the app at a local regtest bitcoind for UI work)? Useful, but it widens the attack surface if misconfigured. Recommendation: keep it test-only for now and revisit if UI development needs it.

## Roadmap position

Safety tier step 4: **022 → 023 → 024 → 027 → 025/026**. Ideally it starts in parallel with 022/023 so 024 lands with tests.
