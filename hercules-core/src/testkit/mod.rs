//! Test support for the sync integration harness (ticket 027): a regtest
//! chain builder and scripted loopback mock peers. Compiled for tests only.
//! The scenarios themselves live in `sync_integration.rs`, mounted inside
//! `sync` so they can reach `HeaderSync` internals (store, UTXO set, anchor).

pub mod fixture_chain;
pub mod mock_peer;

/// Block-level tests of the ticket-026 contextual rules on fixture chains.
#[cfg(test)]
mod consensus_rules;

pub use fixture_chain::{FixtureChain, Invalid};
pub use mock_peer::{Behavior, MockPeer};
