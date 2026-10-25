//! Test support for the sync integration harness (ticket 027): a regtest
//! chain builder and scripted loopback mock peers. Compiled for tests only.
//! The scenarios themselves live in `sync_integration.rs`, mounted inside
//! `sync` so they can reach `HeaderSync` internals (store, UTXO set, anchor).

pub mod fixture_chain;
pub mod mock_peer;

pub use fixture_chain::{FixtureChain, Invalid};
pub use mock_peer::{Behavior, MockPeer};

/// Address (`ip:0`) that loopback test listeners bind to: mock peers and
/// the p2p unit tests' socket pairs. `127.0.0.1` unless the
/// `HERCULES_TEST_LOOPBACK` env var names another loopback IP, e.g.
/// `HERCULES_TEST_LOOPBACK=::1` on a host whose IPv4 ephemeral ports are
/// exhausted (long-uptime macOS can stop expiring TIME_WAIT sockets, after
/// which every connect to 127.0.0.1 fails with EADDRNOTAVAIL).
pub fn loopback_bind_addr() -> std::net::SocketAddr {
    let ip: std::net::IpAddr = std::env::var("HERCULES_TEST_LOOPBACK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    std::net::SocketAddr::new(ip, 0)
}
