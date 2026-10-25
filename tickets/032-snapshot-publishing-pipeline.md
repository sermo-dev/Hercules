# Ticket 032: AssumeUTXO Snapshot Publishing Pipeline

## Decisions (2026-10-23)

- **Decided: Option A only.** The snapshot hash is baked into the app binary Apple signs. There is no runtime-fetched manifest, so Option B (signed manifests) is dropped.
- Freshness comes from release cadence. The pipeline automates everything up to a PR that bumps the `assumeutxo.rs` constants; a human reviews, builds and submits.
- Cadence is still open (weekly vs bi-weekly vs monthly). Only *new installs* use the snapshot, and they always get the latest App Store version, so cadence only sets how many blocks a new user must catch up.
- Every snapshot file referenced by a shipped app version must stay hosted while that version can still be installed.

## Summary

Today's AssumeUTXO snapshot was made by hand:
1. Bitcoin Core `dumptxoutset`
2. `convert_snapshot` → HUTX
3. Hash pasted into `assumeutxo.rs`
4. File uploaded to a Cloudflare R2 dev URL

That works for development, but it doesn't scale to the App Store. The snapshot gets older every day, so new users download and validate an ever-larger backlog of blocks. The dev URL isn't meant for production traffic either.

This ticket builds a server-side pipeline that regularly produces, verifies, and publishes fresh snapshots. It also settles the **trust question** that comes with that.

## Background (verified)

**Pinned anchor.** `hercules-core/src/assumeutxo.rs` pins:
- `ASSUMEUTXO_HEIGHT = 943_500` (`:16`)
- `ASSUMEUTXO_HASH`, the SHA256 over the HUTX entries (`:27`): `a65fdd39…1bf734` since PR #27
- `RETRACTED_SNAPSHOT_HASHES` (`:42`): `705528fe…2d133e`, the first 943,500 file. Its converter wrote 34,336 uncompressed-P2PK coins as compressed-key scripts; sets imported from it are wiped on open
- `ASSUMEUTXO_UTXO_COUNT = 165_208_261` (`:57`), checked exactly against the header
- `ASSUMEUTXO_BLOCK_HASH` (`:61`)
- `SNAPSHOT_DOWNLOAD_URL` (`:115`)
- `SNAPSHOT_DOWNLOAD_SIZE` = 8,781,448,895 bytes compressed (`:119`)

The file was committed 2026-04-06. Around 28,000 blocks have been mined since, so a new user today downloads roughly 40+ GB of blocks after the snapshot and validates them before reaching the tip. That's the opposite of "install and go".

**Hosting.**
- `SnapshotDownloader.swift:20-22` hardcodes `https://pub-341db…r2.dev/hercules-943500-utxo-v2.hutx.gz` (was `hercules-utxo.hutx.gz`, the retracted file). Local download/resume file names derive from that object name.
- `r2.dev` public URLs are rate-limited and Cloudflare documents them as not for production.

**Conversion.**
- `hercules-core/src/bin/convert_snapshot.rs` converts a Core `dumptxoutset` file to HUTX.
- The HUTX header includes `version`, `height`, `block_hash`, `utxo_count`, `file_hash` (`utxo.rs:720-745`).
- Only the entries are covered by the hash. Binding height and block hash is ticket 023.

**MuHash.**
- The core computes a Core-compatible MuHash3072 over the set (`utxo.rs:11`, via `blvm_muhash`) and shows it in TrustInfo (`lib.rs:255`).
- Anyone running Core can compare it with `gettxoutsetinfo muhash` at the same height. This is the cross-implementation check that ticket 017 wanted.

**Infrastructure.** Ticket 019 already plans a Bitcoin Core node running `blocknotify` for the push relay. The pipeline can live on the same box.

## The trust question

**A hash compiled into the app adds no new trust.**
- The user already trusts the binary, which Apple signs and distributes. Bitcoin Core works the same way: `assumeutxo` parameters ship in each release and are reviewed like code.
- An attacker would need to compromise the source repo or the release process.

**A hash fetched from a server at runtime is a new trust point.**
- Whoever controls that server (or its TLS, or DNS) could serve a fake UTXO set together with a matching fake hash.
- The node would then accept coins that don't exist. The fake would only be caught when a later block spends a non-existent coin, if that ever happens.
- A fully automated "dump daily and publish the hash" pipeline therefore makes the server a single point of failure for every new user's ledger.

### Options

**A. Core model: pin per app release.**
- Each App Store release embeds a fresh height and hash, and the pipeline produces the candidate for the release.
- New-user backlog = time since the last release. At a monthly cadence that's ≤ ~4,400 blocks (~6–7 GB of blocks to validate).
- No new trust. Simple.
- Freshness is tied to release cadence, and App Review adds lag.

**B. Signed manifests with offline keys.**
- The app pins one or more Ed25519 public keys and a minimum height floor (the release's embedded snapshot height).
- The pipeline produces candidate snapshots and an unsigned manifest automatically.
- A human verifies the manifest (MuHash against an independent Core node) and signs it with a key that **never touches the server** (hardware key or air-gapped machine).
- The app accepts a manifest only if the signature checks, the height is ≥ the floor, and the header chain contains `block_hash` at that height (023).
- Trust grows only to "the holder of the signing key", which is the same party that ships the binary.

**C. Multi-party attestations (017 Layer 2).**
- k-of-n independent signers.
- Strongest, but blocked on recruiting signers.
- Design B's manifest format so it can carry several signatures later.

### Recommendation: A + B, designed for C
- Every release embeds a fallback anchor (A).
- Between releases, offline-signed manifests at a **weekly** cadence (B).
- Publish MuHash in every manifest so anyone running Core can independently check.

**Daily snapshots?** Possible, but each one needs a human signature, and going from weekly to daily cuts the new-user backlog from at most ~1,000 blocks to at most ~144. That's minutes of validation on a modern iPhone. Weekly is the better tradeoff. If more freshness is wanted later, make the cadence configurable.

## Release gate (required before publishing any snapshot)

The snapshot's MuHash, as Hercules computes it (the value `load_snapshot` stores and TrustInfo shows), **must equal** Bitcoin Core's `bitcoin-cli gettxoutsetinfo muhash <height>` on an independent, fully validating Core node, and the UTXO count must equal Core's `txouts`. No snapshot hash is baked into a release, and no file is uploaded, until this holds. The entries SHA256 only proves the file is the one we converted, not that the conversion was right: the 943,500 file shipped with a converter bug (uncompressed P2PK) that a MuHash comparison would have caught.

Current 943,500 file: Hercules MuHash `73877c075918cdf010b181b7cedb99715df424f70d52d412b0c8d78175d2de4c`. **Not yet compared with Core.**

## Pipeline design

1. **Trigger:** a cron job (weekly) or manual run on the Core box.
2. **Dump:** `bitcoin-cli dumptxoutset <path> latest`. Recent Core versions take a type or height argument; verify the exact syntax for the deployed version.
3. **Convert:** `convert_snapshot <dump> <out.hutx>`, built from the same commit as the app release it targets.
4. **Verify:**
   - Recompute the entries hash and MuHash.
   - Compare MuHash against `gettxoutsetinfo muhash` on the same node at that height.
   - Check the UTXO count and total amount against `gettxoutsetinfo`.
5. **Compress:** gzip (the format the app expects today). Measure zstd separately.
6. **Upload:** to an R2 bucket behind a **custom domain** (e.g. `snapshots.<product>.app`; R2 has zero egress fees). Use content-addressed object names: `utxo-<height>-<hash8>.hutx.gz`.
7. **Manifest:** `manifest-<height>.json` containing `{format_version, height, block_hash, hutx_hash, muhash, utxo_count, compressed_size, url, created_at}`. The `signatures[]` field is added by the offline signing step, which then uploads `manifest-latest.json`.
8. **Retention:** keep the last 3 snapshots (about 9 GB each, roughly 27 GB, which is cheap on R2) plus every snapshot that some still-supported app release embeds.
9. **Monitoring:**
   - Alert if no signed manifest in 10 days.
   - Alert if the dump or verification fails.
   - Alert if R2 download errors spike.

### App side
- Fetch `manifest-latest.json`, verify the signature(s), the height floor, and the `block_hash` against the header chain (headers sync first, then snapshot).
- Download the referenced file and verify `hutx_hash` while streaming (existing code).
- Fall back to the embedded release anchor on any failure.
- TrustInfo shows which anchor was used: "release-pinned" or "signed manifest (key X)".
- The download host moves from a hardcoded constant to the manifest. Tor-routed download remains ticket 012.

## Files touched

| File | Action |
|---|---|
| `server/snapshot/` | **New** — pipeline scripts (dump, convert, verify, upload), README, cron/systemd unit |
| `server/snapshot/sign-manifest` | **New** — offline signing tool, never deployed to the server |
| `hercules-core/src/assumeutxo.rs` | Pinned pubkeys, height floor, embedded fallback anchor |
| `hercules-core/src/snapshot_manifest.rs` | **New** — manifest parsing and signature verification |
| `hercules-core/src/bin/convert_snapshot.rs` | Emit manifest JSON; HUTX format v2 (with 023) |
| `HerculesApp/HerculesApp/SnapshotDownloader.swift` | Manifest-driven URL; drop the hardcoded `r2.dev` |
| `HerculesApp/HerculesApp/SettingsView.swift` | Show anchor source in the trust card |

## Dependencies

- **023**: bind snapshot height and block hash, and check them against the header chain. Required before any runtime manifest is accepted.
- **019**: shares the Core node and AWS/R2 accounts.
- **017**: Layer 2 multi-signer, as a future extension.
- **012**: Tor-routed download.

## Estimated effort

~5–7 days:
- pipeline scripts and verification: 2 days
- R2 custom domain and retention: 0.5 day
- manifest format and signing tool: 1 day
- app-side manifest verification and fallback: 2 days
- monitoring: 0.5 day

## Verification

- The pipeline produces a snapshot whose MuHash equals Core's `gettxoutsetinfo muhash` at the same height, and refuses to publish (see Release gate) when it doesn't.
- The app rejects a manifest with a bad signature, with height below the floor, with `block_hash` not in the header chain, or with a file whose hash doesn't match. In each case it falls back to the embedded anchor.
- A fresh install, with a manifest one week old, reaches the tip with ≤ ~1,008 blocks to validate.
- Deleting the custom-domain object makes the app fall back cleanly to the previous manifest or embedded anchor.

## Open questions

- **Who holds the signing key(s)** and on what hardware? Is a second signer available from day one?
- **Cadence:** weekly (recommended) or something else.
- **HUTX vs. Core's native snapshot format:** adopting Core's format would let users verify the file hash directly. Revisit with 017.
- **Snapshot size growth:** at what UTXO-set size do compression or Utreexo (002) become necessary?

## Roadmap position

Tier 1 infrastructure. Part A (per-release refresh) is needed for TestFlight. Part B (signed manifests) should land before App Store launch. 023 is a hard prerequisite for B.
