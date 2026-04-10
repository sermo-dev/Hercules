# Ticket 012: Tor-Routed Snapshot Download

## Summary

The AssumeUTXO snapshot bootstrap (Phase 5a) downloads ~8.2 GB from a Cloudflare R2 bucket over plain HTTPS. All Bitcoin P2P traffic after bootstrap is routed through Tor, but this one-time download leaks the user's IP address to Cloudflare and reveals "this person uses Hercules" to any network observer. Close that gap.

## Background

Hercules is a privacy-preserving Bitcoin node — Arti routes every P2P connection through Tor by default. Phase 5a added one-tap bootstrap by downloading a hash-anchored UTXO snapshot from R2:

- URL: `https://pub-341db11a2808417d91d4fcabc62a2260.r2.dev/hercules-utxo.hutx.gz`
- Size: ~8.2 GB compressed
- Trust model: hash baked into `assumeutxo.rs::ASSUMEUTXO_HASH`, verified by `utxo.rs::load_snapshot` before any data touches the database. The hoster cannot tamper with the bytes undetected.

The snapshot trust model is solid, but the **delivery channel** leaks metadata that the rest of the node carefully hides.

### What leaks today

1. **Cloudflare logs** see the user's home IP tagged with the unique R2 bucket URL → "this IP bootstrapped a Hercules node at time T"
2. **ISP / on-path observers** see SNI = `pub-341db11a2808417d91d4fcabc62a2260.r2.dev` and an 8.2 GB transfer — a strong fingerprint
3. **DNS resolver** sees the R2 hostname (unless the user has DoH/DoT enabled)
4. **Temporal correlation**: bootstrap traffic followed by Tor circuits from the same IP gives a strong signal that this user runs Hercules, even though P2P content is hidden

### What does NOT leak

- Wallet, keys, addresses, transactions
- Anything about the user's Bitcoin activity post-bootstrap

The leak is "this person uses Hercules" — bounded but real, and inconsistent with the project's threat model.

### Why we shipped without Tor in v1

- **Speed.** Arti circuits typically deliver 100–500 KB/s end-to-end. 8.2 GB over Tor is 4–22 hours of waiting before the node can do anything useful. Adoption killer.
- **No onion mirror infrastructure.** R2 isn't directly reachable via Tor; we'd need to host the snapshot on a Hercules-controlled onion service.

## Design

Two layers, ship in order.

### Layer 1: User-facing disclosure (smallest, ship first)

Add a one-time disclosure dialog before the download starts:

> "Bootstrap downloads 8.2 GB from Cloudflare. This reveals to your ISP and Cloudflare that you use Hercules. All Bitcoin traffic after bootstrap is routed through Tor."

- Buttons: **Download** (proceeds) / **Cancel** (returns to idle)
- Persist a "user has acknowledged" flag so we don't nag on retries
- Add the same disclosure to onboarding / Settings → About

This is honest, takes ~30 lines of SwiftUI, and doesn't require any infrastructure changes. Lets users make an informed call today.

### Layer 2: Tor-routed download (real fix)

**a. Onion mirror infrastructure**

- Run a Hercules-operated onion service that serves the snapshot
- Host can be the same machine that publishes to R2 — just expose it on a `.onion` URL too
- Hardcode the onion URL alongside the R2 URL in `assumeutxo.rs`
- Same hash anchor verifies both sources

**b. HTTP-over-Arti client in `hercules-core`**

- Bridge `arti-client::DataStream` to a minimal HTTP/1.1 client (status line + headers + chunked or content-length body)
- Support HTTP Range requests for resume (R2 already does this; the onion mirror needs to as well)
- Expose a function: `download_snapshot_via_tor(onion_url, dest_path, on_progress) -> Result<...>`
- Reuses the existing `TorManager` instance — Tor is already bootstrapped by the time the user starts the download

**c. Swift integration**

- Add a Settings toggle: "Use Tor for snapshot download (slow, ~4–22 hours)"
- Default OFF for v1 of the toggle (don't surprise existing users)
- When enabled, Swift calls into Rust's `download_snapshot_via_tor` instead of using `URLSessionDownloadTask`
- Progress callback wires through the existing `SnapshotDownloader` `@Published` state — UI is unchanged
- The existing `SnapshotDownloadCard` already shows "Wi-Fi only • one-time" — extend to show "via Tor • slow" when the toggle is on

**d. Future: default-on for privacy-critical builds**

- Once the onion mirror is stable and the HTTP-over-Arti client is battle-tested, flip the default
- Direct R2 becomes the opt-in fallback for users who care more about speed than metadata

### Trust model unchanged

The `ASSUMEUTXO_HASH` constant remains the only trust anchor regardless of delivery channel. Tor routing improves privacy of *who* downloads, not *what* they download. R2 and the onion mirror serve the same bytes; corruption from either is caught before commit by `utxo.rs::load_snapshot`.

## Dependencies

- **Layer 1**: none — ship anytime
- **Layer 2a**: requires running an onion service (operational, not code)
- **Layer 2b**: depends on Arti's `DataStream` API, which is already in use by `peer_pool.rs` for P2P connections — no new crate needed
- **Layer 2c**: depends on the existing `SnapshotDownloader` Swift class

## Estimated Effort

- **Layer 1 (disclosure dialog)**: ~1 hour. Pure SwiftUI + UserDefaults.
- **Layer 2a (onion mirror)**: ops work, hours not days. Single static file served by an onion-side HTTP server.
- **Layer 2b (HTTP-over-Arti)**: ~300–500 lines of Rust. Manual HTTP/1.1 is small; Range support adds a bit. Tests can mock the onion stream.
- **Layer 2c (Swift integration)**: ~100 lines. Mostly wiring the new Rust function and toggle into the existing UI.

Total: roughly a week of focused work for Layer 2, minus the operational time for the mirror.

## Open questions

- **Mirror operator trust.** Running a single onion mirror creates a target. Multiple geographically-distributed mirrors with the same hash anchor would be more robust. Worth deciding up-front.
- **Resume across retries.** The Layer 2b HTTP client should support `Range: bytes=N-` so a Tor-side failure doesn't lose hours of progress, mirroring the URLSession resume behavior we just added in Phase 5a.
- **Bandwidth budget.** A popular onion mirror serving 8 GB to many users will be bandwidth-heavy. May want to rate-limit or shard across mirrors.
