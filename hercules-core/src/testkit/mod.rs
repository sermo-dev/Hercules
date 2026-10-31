//! Test support for the sync integration harness (ticket 027): a regtest
//! chain builder and scripted loopback mock peers. Compiled for tests only.
//! The scenarios themselves live in `sync_integration.rs`, mounted inside
//! `sync` so they can reach `HeaderSync` internals (store, UTXO set, anchor).

pub mod fixture_chain;
pub mod mock_peer;

/// Block-level tests of the ticket-026 contextual rules on fixture chains.
#[cfg(test)]
mod consensus_rules;

/// Both sides of every block-level consensus limit (data-path test pass).
#[cfg(test)]
mod consensus_boundaries;

pub use fixture_chain::{FixtureChain, Invalid};
pub use mock_peer::{Behavior, MockPeer};

/// Address test listeners bind to: `HERCULES_TEST_LOOPBACK` (e.g. `::1`
/// when a host has run out of IPv4 loopback ports), default 127.0.0.1.
/// Returns a `host:0` string for `TcpListener::bind`.
pub fn loopback_bind() -> String {
    let host = std::env::var("HERCULES_TEST_LOOPBACK").unwrap_or_else(|_| "127.0.0.1".into());
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:0", host)
    } else {
        format!("{}:0", host)
    }
}
