use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use bitcoin::block::Block;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::BlockHash;

use log::{debug, info, warn};

use crate::tor::{TorManager, TorStream};

const PROTOCOL_VERSION: u32 = 70016;
const USER_AGENT: &str = "/Hercules:0.1.0/";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(test))]
const READ_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
/// Test builds shrink the direct-TCP timeouts so mock-peer scenarios that
/// withhold or delay data (ticket 027) resolve in seconds, not minutes.
#[cfg(test)]
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(test)]
pub(crate) const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(3);

/// Timeouts used when connecting through Tor (higher latency).
const TOR_READ_TIMEOUT: Duration = Duration::from_secs(60);
const TOR_BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// The whole version handshake, however the bytes arrive (ticket 049): a
/// peer dribbling its `version` one byte per read timeout can't hold a
/// connection attempt (or the inbound accept) for longer.
#[cfg(not(test))]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(test)]
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long one write may wait for the peer to take any bytes (ticket
/// 049). Without it a peer that stops reading blocks `send`, and the sync
/// thread with it, forever. A message as a whole also gets
/// `MIN_TRANSFER_RATE`.
#[cfg(not(test))]
const WRITE_TIMEOUT: Duration = Duration::from_secs(20);
#[cfg(test)]
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const TOR_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Slowest a peer may move one message's bytes, either way, once the
/// message has started (ticket 049): it gets the base read or write
/// timeout plus its length at this rate (a 4 MB block: 160 s on top). A
/// peer trickling bytes just inside every per-read timeout is dropped
/// rather than holding the connection for hours.
const MIN_TRANSFER_RATE: u64 = 25_000;

/// Most bytes one `read` asks for: payloads are read in pieces of this
/// size, so a frame header claiming 4 MB costs nothing until the bytes
/// actually arrive.
const READ_CHUNK: usize = 64 * 1024;

/// Time allowed for a message of `len` bytes beyond `base`, at
/// `MIN_TRANSFER_RATE`.
fn transfer_allowance(len: usize) -> Duration {
    Duration::from_millis(len as u64 * 1000 / MIN_TRANSFER_RATE)
}

/// Maximum P2P message payload size (4 MB, matches Bitcoin Core's MAX_SIZE).
/// Prevents OOM from malicious peers sending crafted headers claiming huge payloads.
const MAX_P2P_PAYLOAD: u32 = 4_000_000;

/// How many non-requested `block` messages `receive_block` will skip before
/// giving up. Honest peers announce via inv/headers/cmpctblock rather than
/// pushing full blocks, so one or two is already generous; without a cap a
/// peer could make us download ~20 × 4 MB of junk per request (on cellular).
const MAX_UNREQUESTED_BLOCKS: usize = 2;

/// DNS seeds for discovering Bitcoin mainnet peers.
const DNS_SEEDS: &[&str] = &[
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.net",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
];

/// Bitcoin v3 .onion seed nodes: eight entries spread across Bitcoin
/// Core's `contrib/seeds/nodes_main.txt` (master, 2026-10-31). Ticket 052:
/// every earlier entry failed the v3 checksum, so none was ever dialed;
/// `onion_seeds_are_valid_v3_addresses` now checks each one. Seeds go
/// stale: refresh them from Core's list when it is regenerated.
const ONION_SEEDS: &[&str] = &[
    "24yjwaf2ni6wz44pmqpw3jyjhksoko7wxzelp6uyep2pdlgb5epbnoqd.onion:8333",
    "5mbrhlddl2zgwbmgrtnz2uk6icrr7dtybagtz3afk7axszdssz2gdxad.onion:8333",
    "czfu73oyemygxnooumke2wlajj52lphvpjwrnv6ys363lvitba7rmzqd.onion:8333",
    "gh5nop77tdu72smpeswoayaesr7ghbesfg3jnxvneg76gwsxm7h5g7qd.onion:8333",
    "k4vadrbdwgh5gbxqurkfhi5ab72xthkzkrz24xgbpk4ts3k4ybk4v3yd.onion:8333",
    "n7ofwmu7rcqg55pxv6catz4ey4lzuxz5kofuu5yuomlr3fkxhbvadeid.onion:8333",
    "qvl4hqoooka3jogtit34t7g6ru443xaf5g4ld47i6j3tc7nsomsu3fad.onion:8333",
    "uvb7zm5buued5j4mn2fjwsjmnhyqwpultidczfvqq4laosojhytdiqqd.onion:8333",
];

// ── PeerStream ────────────────────────────────────────────────────────

/// Abstraction over TCP and Tor streams for Bitcoin P2P connections.
pub enum PeerStream {
    Direct(TcpStream),
    Tor(TorStream),
    /// Scripted in-memory stream for tests (`tests::MemStream`).
    #[cfg(test)]
    Mem(tests::MemStream),
}

impl PeerStream {
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            PeerStream::Direct(tcp) => tcp.set_read_timeout(timeout),
            PeerStream::Tor(tor) => {
                tor.set_read_timeout(timeout);
                Ok(())
            }
            #[cfg(test)]
            PeerStream::Mem(_) => Ok(()),
        }
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            PeerStream::Direct(tcp) => tcp.set_write_timeout(timeout),
            PeerStream::Tor(tor) => {
                tor.set_write_timeout(timeout);
                Ok(())
            }
            #[cfg(test)]
            PeerStream::Mem(_) => Ok(()),
        }
    }

    /// The standing per-read timeout for this transport.
    fn read_timeout(&self) -> Duration {
        match self {
            PeerStream::Direct(_) => READ_TIMEOUT,
            PeerStream::Tor(_) => TOR_READ_TIMEOUT,
            #[cfg(test)]
            PeerStream::Mem(_) => READ_TIMEOUT,
        }
    }

    /// The overall deadline for one block download on this transport.
    fn block_download_timeout(&self) -> Duration {
        match self {
            PeerStream::Direct(_) => BLOCK_DOWNLOAD_TIMEOUT,
            PeerStream::Tor(_) => TOR_BLOCK_DOWNLOAD_TIMEOUT,
            #[cfg(test)]
            PeerStream::Mem(_) => BLOCK_DOWNLOAD_TIMEOUT,
        }
    }

    fn write_timeout(&self) -> Duration {
        match self {
            PeerStream::Direct(_) => WRITE_TIMEOUT,
            PeerStream::Tor(_) => TOR_WRITE_TIMEOUT,
            #[cfg(test)]
            PeerStream::Mem(_) => WRITE_TIMEOUT,
        }
    }
}

impl Read for PeerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            PeerStream::Direct(tcp) => tcp.read(buf),
            PeerStream::Tor(tor) => tor.read(buf),
            #[cfg(test)]
            PeerStream::Mem(m) => m.read(buf),
        }
    }
}

/// An absolute read deadline (ticket 028): every `read` gets the time left
/// until `at`, capped at `cap`, so a peer trickling bytes can't stretch one
/// message (or a run of them) past the deadline.
#[derive(Clone, Copy)]
struct ReadDeadline {
    at: Instant,
    cap: Duration,
    /// `at` is the caller's own budget (a wake's), so running into it is
    /// `DeadlineReached`, never the peer's fault. Otherwise it is a request
    /// timeout (ticket 049), and running into it is the peer's `Timeout`.
    budget: bool,
}

impl ReadDeadline {
    /// A request's own timeout `own`, tightened to the caller's `limit` if
    /// that is sooner. `None` for a zero limit: no time to even ask.
    fn request(own: Duration, limit: Option<Duration>, cap: Duration) -> Option<ReadDeadline> {
        let now = Instant::now();
        match limit {
            Some(l) if l.is_zero() => None,
            Some(l) if l < own => Some(ReadDeadline { at: now + l, cap, budget: true }),
            _ => Some(ReadDeadline { at: now + own, cap, budget: false }),
        }
    }

    fn passed(&self) -> bool {
        Instant::now() >= self.at
    }
}

/// `PeerStream` reads bounded by a `ReadDeadline`.
struct DeadlineReader<'a> {
    stream: &'a mut PeerStream,
    deadline: ReadDeadline,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.deadline.at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "read deadline passed"));
        }
        // A zero timeout means "block forever" to the socket API.
        let timeout = left.min(self.deadline.cap).max(Duration::from_millis(1));
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.read(buf)
    }
}

impl Write for PeerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            PeerStream::Direct(tcp) => tcp.write(buf),
            PeerStream::Tor(tor) => tor.write(buf),
            #[cfg(test)]
            PeerStream::Mem(m) => m.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            PeerStream::Direct(tcp) => tcp.flush(),
            PeerStream::Tor(tor) => tor.flush(),
            #[cfg(test)]
            PeerStream::Mem(_) => Ok(()),
        }
    }
}

// ── Peer ──────────────────────────────────────────────────────────────

/// A connection to a single Bitcoin peer.
pub struct Peer {
    stream: PeerStream,
    addr: String,
    /// Network magic for every message we send (`ChainParams::magic`).
    magic: Magic,
    their_version: Option<VersionMessage>,
    /// True if this peer connected to us (inbound), false if we connected to them.
    pub inbound: bool,
    /// True if this peer sent us a `sendaddrv2` during the handshake (BIP 155),
    /// meaning we should send them BIP 155 `addrv2` messages instead of legacy
    /// v1 `addr`. Required for advertising our own .onion address — TorV3
    /// can't be encoded in the v1 form.
    wants_addrv2: bool,
    /// The bytes of a message still arriving (ticket 049), kept across
    /// reads: a read that times out mid-message (common over Tor and
    /// cellular) never loses the framing. Never holds more than one frame.
    partial: Vec<u8>,
    /// When the first byte in `partial` arrived: the message must be
    /// complete within `message_allowance` of it.
    partial_since: Option<Instant>,
    /// When the last complete message arrived (or the connection opened):
    /// inbound eviction drops the idlest peer (ticket 052).
    last_recv: Instant,
    /// Our outstanding `ping` (nonce, sent at), cleared by the matching
    /// `pong` wherever it is read (`read_message`), and when we last sent
    /// one: see `keep_alive` (ticket 052).
    ping_sent: Option<(u64, Instant)>,
    last_ping: Instant,
}

/// Core's keep-alive (net_processing `PING_INTERVAL`, net.h
/// `TIMEOUT_INTERVAL`): a ping every 2 minutes, and a peer that hasn't
/// answered one in 20 is dropped (ticket 052: a dead inbound connection
/// otherwise holds its slot for good).
pub const PING_INTERVAL: Duration = Duration::from_secs(2 * 60);
pub const PING_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Source of inbound peers' pool addresses (`inbound#N`), unique for the
/// process lifetime.
static NEXT_INBOUND_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Peer {
    fn new(stream: PeerStream, addr: String, magic: Magic, inbound: bool) -> Peer {
        Peer {
            stream,
            addr,
            magic,
            their_version: None,
            inbound,
            wants_addrv2: false,
            partial: Vec::new(),
            partial_since: None,
            last_recv: Instant::now(),
            ping_sent: None,
            last_ping: Instant::now(),
        }
    }

    /// How long since this peer last sent us a complete message.
    pub fn idle_for(&self) -> Duration {
        self.last_recv.elapsed()
    }

    /// Core's keep-alive (ticket 052): send a `ping` once `interval` has
    /// passed since the last one was answered (or sent), and fail once one
    /// has gone unanswered for `timeout`; the caller drops the peer. The
    /// `pong` is matched in `read_message`, so any reader clears it.
    pub fn keep_alive(&mut self, interval: Duration, timeout: Duration) -> Result<(), PeerError> {
        let now = Instant::now();
        match self.ping_sent {
            Some((_, sent)) if now.duration_since(sent) >= timeout => {
                Err(PeerError::Receive(format!("ping timeout: no pong in {}s", timeout.as_secs())))
            }
            Some(_) => Ok(()),
            None if now.duration_since(self.last_ping) >= interval => {
                use std::collections::hash_map::RandomState;
                use std::hash::{BuildHasher, Hasher};
                let nonce = RandomState::new().build_hasher().finish();
                self.send(NetworkMessage::Ping(nonce))?;
                self.ping_sent = Some((nonce, now));
                self.last_ping = now;
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Pretend the last message arrived `ago` (eviction tests).
    #[cfg(test)]
    pub(crate) fn set_idle_for_test(&mut self, ago: Duration) {
        self.last_recv = Instant::now() - ago;
    }

    /// Discover peer addresses from DNS seeds (clearnet).
    pub fn discover_peers() -> Vec<String> {
        let mut addrs = Vec::new();
        for seed in DNS_SEEDS {
            let seed_with_port = format!("{}:8333", seed);
            match seed_with_port.to_socket_addrs() {
                Ok(resolved) => {
                    let new_addrs: Vec<String> = resolved.map(|a| a.to_string()).collect();
                    info!("DNS seed {} returned {} peers", seed, new_addrs.len());
                    addrs.extend(new_addrs);
                }
                Err(e) => {
                    warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }
        info!("Discovered {} total peer addresses", addrs.len());
        addrs
    }

    /// Discover peer addresses through Tor (no clearnet DNS leak).
    /// Resolves DNS seeds via Tor and adds well-known .onion seed nodes.
    pub fn discover_peers_tor(tor: &TorManager) -> Vec<String> {
        let mut addrs = Vec::new();

        // Resolve DNS seeds through Tor
        for seed in DNS_SEEDS {
            match tor.resolve(seed) {
                Ok(resolved) => {
                    let new_addrs: Vec<String> = resolved.iter().map(|a| a.to_string()).collect();
                    info!("DNS seed {} (via Tor) returned {} peers", seed, new_addrs.len());
                    addrs.extend(new_addrs);
                }
                Err(e) => {
                    warn!("Failed to resolve DNS seed {} via Tor: {}", seed, e);
                }
            }
        }

        // Add well-known .onion seed nodes
        for onion in ONION_SEEDS {
            addrs.push(onion.to_string());
        }
        info!("Discovered {} total peer addresses via Tor ({} onion seeds)", addrs.len(), ONION_SEEDS.len());

        addrs
    }

    /// Connect to a peer over direct TCP and complete the version handshake.
    pub fn connect(addr: &str, our_height: i32, magic: Magic) -> Result<Peer, PeerError> {
        info!("Connecting to peer {}", addr);

        let sock_addr: SocketAddr = addr
            .parse()
            .map_err(|e| PeerError::Connection(format!("invalid address {}: {}", addr, e)))?;

        let stream = TcpStream::connect_timeout(&sock_addr, CONNECT_TIMEOUT)
            .map_err(|e| PeerError::Connection(format!("{}: {}", addr, e)))?;

        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))?;

        let mut peer = Peer::new(PeerStream::Direct(stream), addr.to_string(), magic, false);

        peer.handshake(our_height)?;
        info!("Handshake complete with {}", addr);
        // Ask the peer for their address book so we can keep our AddrManager
        // populated. Non-fatal — peers that ignore us are still usable.
        if let Err(e) = peer.send_getaddr() {
            debug!("send_getaddr to {} failed: {}", addr, e);
        }
        Ok(peer)
    }

    /// Connect to a peer through Tor and complete the version handshake.
    /// The address can be an IP:port, hostname:port, or .onion:port.
    pub fn connect_tor(
        tor: &TorManager,
        addr: &str,
        our_height: i32,
        magic: Magic,
    ) -> Result<Peer, PeerError> {
        info!("Connecting to peer {} via Tor", addr);

        let tor_stream = tor
            .connect(addr)
            .map_err(|e| PeerError::Connection(format!("{}: {}", addr, e)))?;

        let mut peer = Peer::new(PeerStream::Tor(tor_stream), addr.to_string(), magic, false);

        peer.handshake(our_height)?;
        info!("Handshake complete with {} via Tor", addr);
        if let Err(e) = peer.send_getaddr() {
            debug!("send_getaddr to {} via Tor failed: {}", addr, e);
        }
        Ok(peer)
    }

    /// Re-label a test peer, so a pool slot can pose as any address.
    #[cfg(test)]
    pub(crate) fn set_addr_for_test(&mut self, addr: &str, inbound: bool) {
        self.addr = addr.to_string();
        self.inbound = inbound;
    }

    /// Accept an inbound connection: run the version handshake as responder.
    /// (Wait for their version first, then send ours + verack.) The whole
    /// exchange is bounded by `HANDSHAKE_TIMEOUT` (ticket 049); production
    /// runs it off the sync thread (`InboundHandshakes`).
    pub fn accept(stream: PeerStream, our_height: i32, magic: Magic) -> Result<Peer, PeerError> {
        // Filled after receiving their version.
        let mut peer = Peer::new(stream, String::new(), magic, true);
        let deadline = peer.handshake_deadline();
        let result = peer.accept_within(our_height, deadline);
        peer.restore_read_timeout()?;
        result.map_err(Peer::handshake_timeout)?;
        let user_agent = peer.peer_user_agent().unwrap_or_default();
        info!("Accepted inbound peer: {} ({})", peer.addr, user_agent);
        Ok(peer)
    }

    fn accept_within(&mut self, our_height: i32, deadline: ReadDeadline) -> Result<(), PeerError> {
        // Receive their version first
        let mut got_version = false;
        for _ in 0..10 {
            let msg = self.receive_until(Some(deadline))?;
            match msg {
                NetworkMessage::Version(v) => {
                    if v.version < 70015 {
                        return Err(PeerError::Handshake(format!(
                            "inbound peer version {} too old (min 70015)", v.version
                        )));
                    }
                    // Keyed by a connection id, not anything the peer
                    // chose (its version nonce): a peer must not be able
                    // to pick, collide with, or reuse a pool identity.
                    self.addr = format!(
                        "inbound#{}",
                        NEXT_INBOUND_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    );
                    self.their_version = Some(v);
                    got_version = true;
                    break;
                }
                _ => {} // ignore pre-version messages
            }
        }

        if !got_version {
            return Err(PeerError::Handshake("inbound peer did not send version".into()));
        }

        // Send our version
        let our_services = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
        let our_version = VersionMessage {
            version: PROTOCOL_VERSION,
            services: our_services,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs() as i64,
            receiver: Address::new(
                &SocketAddr::from(([0, 0, 0, 0], 8333)),
                ServiceFlags::NETWORK,
            ),
            sender: Address::new(
                &SocketAddr::from(([0, 0, 0, 0], 0)),
                our_services,
            ),
            nonce: rand_nonce(),
            user_agent: USER_AGENT.to_string(),
            start_height: our_height,
            relay: true,
        };
        self.send(NetworkMessage::Version(our_version))?;
        // BIP 155: announce addrv2 support before our verack. Same rationale
        // as the outbound path — without this, peers strip our TorV3 self-ad
        // from gossip and inbound discovery never bootstraps.
        self.send(NetworkMessage::SendAddrV2)?;
        self.send(NetworkMessage::Verack)?;

        // Wait for their verack. Track sendaddrv2 here too — the inbound
        // peer may send it in the same window.
        for _ in 0..10 {
            let msg = self.receive_until(Some(deadline))?;
            match msg {
                NetworkMessage::Verack => return Ok(()),
                NetworkMessage::SendAddrV2 => {
                    self.wants_addrv2 = true;
                }
                NetworkMessage::Ping(nonce) => {
                    self.send(NetworkMessage::Pong(nonce))?;
                }
                _ => {}
            }
        }

        Err(PeerError::Handshake("inbound peer did not send verack".into()))
    }

    /// The overall handshake deadline, starting now. Running into it is
    /// the peer's fault (`budget: false`).
    fn handshake_deadline(&self) -> ReadDeadline {
        ReadDeadline {
            at: Instant::now() + HANDSHAKE_TIMEOUT,
            cap: self.stream.read_timeout(),
            budget: false,
        }
    }

    /// A handshake that ran out of time says so.
    fn handshake_timeout(e: PeerError) -> PeerError {
        match e {
            PeerError::Timeout => PeerError::Handshake(format!(
                "no handshake within {}s",
                HANDSHAKE_TIMEOUT.as_secs_f32()
            )),
            other => other,
        }
    }

    /// Perform the version/verack handshake (outbound/initiator mode),
    /// within `HANDSHAKE_TIMEOUT` (ticket 049): a wake's connect deadline
    /// stops new connection attempts, so one in progress must end on its
    /// own.
    fn handshake(&mut self, our_height: i32) -> Result<(), PeerError> {
        let deadline = self.handshake_deadline();
        let result = self.handshake_within(our_height, deadline);
        self.restore_read_timeout()?;
        result.map_err(Peer::handshake_timeout)
    }

    fn handshake_within(&mut self, our_height: i32, deadline: ReadDeadline) -> Result<(), PeerError> {
        // For the version message, use a dummy address if we can't parse
        // (e.g., .onion addresses don't map to SocketAddr).
        let receiver_addr = self
            .addr
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 8333)));

        // Send our version
        // Advertise NODE_NETWORK_LIMITED (BIP 159) + NODE_WITNESS (BIP 144)
        let our_services = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;

        let our_version = VersionMessage {
            version: PROTOCOL_VERSION,
            services: our_services,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs() as i64,
            receiver: Address::new(&receiver_addr, ServiceFlags::NETWORK),
            sender: Address::new(
                &SocketAddr::from(([0, 0, 0, 0], 0)),
                our_services,
            ),
            nonce: rand_nonce(),
            user_agent: USER_AGENT.to_string(),
            start_height: our_height,
            relay: true,
        };

        self.send(NetworkMessage::Version(our_version))?;
        debug!("Sent version to {}", self.addr);

        // BIP 155: announce that we accept addrv2. MUST be sent after our
        // version and before our verack. Sending it immediately after the
        // version keeps the handshake one round-trip — without it, peers
        // fall back to legacy v1 `addr` and silently strip our TorV3
        // self-advertisement out of the gossip mesh.
        self.send(NetworkMessage::SendAddrV2)?;
        debug!("Sent sendaddrv2 to {}", self.addr);

        // Receive their version and verack (order can vary)
        let mut got_version = false;
        let mut got_verack = false;

        for _ in 0..10 {
            let msg = self.receive_until(Some(deadline))?;
            match msg {
                NetworkMessage::Version(v) => {
                    // Reject peers running protocol versions too old to
                    // support compact blocks and segwit (min 70015, same
                    // as Bitcoin Core's MIN_PEER_PROTO_VERSION).
                    if v.version < 70015 {
                        return Err(PeerError::Handshake(format!(
                            "peer {} version {} too old (min 70015)",
                            self.addr, v.version
                        )));
                    }
                    info!(
                        "Peer {} running {} at height {}",
                        self.addr, v.user_agent, v.start_height
                    );
                    self.their_version = Some(v);
                    got_version = true;
                    // Send verack in response
                    self.send(NetworkMessage::Verack)?;
                    debug!("Sent verack to {}", self.addr);
                }
                NetworkMessage::Verack => {
                    got_verack = true;
                    debug!("Received verack from {}", self.addr);
                }
                NetworkMessage::SendHeaders => {
                    debug!("Peer {} requested SendHeaders mode", self.addr);
                }
                NetworkMessage::SendAddrV2 => {
                    debug!("Peer {} requested SendAddrV2", self.addr);
                    self.wants_addrv2 = true;
                }
                NetworkMessage::WtxidRelay => {
                    debug!("Peer {} requested WtxidRelay", self.addr);
                }
                other => {
                    debug!(
                        "Ignoring {} message during handshake from {}",
                        msg_name(&other),
                        self.addr
                    );
                }
            }
            if got_version && got_verack {
                return Ok(());
            }
        }

        if !got_version {
            return Err(PeerError::Handshake("never received version".into()));
        }
        if !got_verack {
            return Err(PeerError::Handshake("never received verack".into()));
        }
        Ok(())
    }

    /// Send a Bitcoin P2P message, within `WRITE_TIMEOUT` per write and
    /// `MIN_TRANSFER_RATE` overall (ticket 049). Running out of either is
    /// an error, and the caller drops the peer.
    pub fn send(&mut self, msg: NetworkMessage) -> Result<(), PeerError> {
        let mut bytes = Vec::new();
        RawNetworkMessage::new(self.magic, msg)
            .consensus_encode(&mut bytes)
            .map_err(|e| PeerError::Send(format!("{}", e)))?;
        let cap = self.stream.write_timeout();
        let at = Instant::now() + cap + transfer_allowance(bytes.len());
        let mut sent = 0;
        while sent < bytes.len() {
            let left = at.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(PeerError::Send(format!(
                    "write deadline passed ({} of {} bytes taken)",
                    sent,
                    bytes.len()
                )));
            }
            // A zero timeout means "block forever" to the socket API.
            self.stream
                .set_write_timeout(Some(left.min(cap).max(Duration::from_millis(1))))
                .map_err(|e| PeerError::Send(format!("set write timeout: {}", e)))?;
            match self.stream.write(&bytes[sent..]) {
                Ok(0) => return Err(PeerError::Send("connection closed".into())),
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                    return Err(PeerError::Send(format!(
                        "write timed out ({} of {} bytes taken)",
                        sent,
                        bytes.len()
                    )));
                }
                Err(e) => return Err(PeerError::Send(format!("{}", e))),
            }
        }
        self.stream
            .flush()
            .map_err(|e| PeerError::Send(format!("flush: {}", e)))
    }

    /// Receive a Bitcoin P2P message.
    ///
    /// Reads the 24-byte P2P header first to validate payload size before
    /// allocation, preventing OOM from crafted headers (MAX_SIZE = 4 MB,
    /// matching Bitcoin Core). Returns `PeerError::Timeout` on read timeout
    /// for reliable detection by `poll_message()`. A message already under
    /// way must finish within `message_allowance`.
    #[cfg(test)]
    pub fn receive(&mut self) -> Result<NetworkMessage, PeerError> {
        self.receive_until(None)
    }

    /// `receive` with every read bounded by `deadline`, if set.
    fn receive_until(&mut self, deadline: Option<ReadDeadline>) -> Result<NetworkMessage, PeerError> {
        match self.read_message(deadline)? {
            Some(msg) => Ok(msg),
            // A timeout at our own deadline is ours, not the peer's fault.
            None => match deadline {
                Some(d) if d.budget && d.passed() => Err(PeerError::DeadlineReached),
                _ => Err(PeerError::Timeout),
            },
        }
    }

    /// How long a message of `payload_len` bytes may take from its first
    /// byte: the standing read timeout plus `MIN_TRANSFER_RATE`.
    fn message_allowance(&self, payload_len: usize) -> Duration {
        self.stream.read_timeout() + transfer_allowance(24 + payload_len)
    }

    /// Read until a whole message is buffered (`Some`) or a read times out
    /// (`None`; the bytes so far stay in `partial`, ticket 049). Every read
    /// is bounded by `deadline`, if set (else by the standing read
    /// timeout), and once a message has started it must finish within
    /// `message_allowance`: running out of that is an error.
    fn read_message(&mut self, deadline: Option<ReadDeadline>) -> Result<Option<NetworkMessage>, PeerError> {
        loop {
            // Bytes 0..4 are the network magic. A peer on another network
            // (or one desynchronized from the message framing) is useless
            // to us; fail before reading its payload so the caller drops it.
            let mut want = 24;
            if self.partial.len() >= 24 {
                if self.partial[..4] != self.magic.to_bytes() {
                    let got = self.partial[..4].try_into().unwrap();
                    self.clear_partial();
                    return Err(PeerError::WrongMagic { got, expected: self.magic });
                }
                // Payload length is at bytes 16..20 (little-endian u32)
                let payload_len = u32::from_le_bytes(self.partial[16..20].try_into().unwrap());
                if payload_len > MAX_P2P_PAYLOAD {
                    self.clear_partial();
                    return Err(PeerError::Receive(format!(
                        "message payload {} bytes exceeds limit {}",
                        payload_len, MAX_P2P_PAYLOAD
                    )));
                }
                want = 24 + payload_len as usize;
            }
            if self.partial.len() >= 24 && self.partial.len() == want {
                // Decode from the complete message buffer
                let frame = std::mem::take(&mut self.partial);
                self.partial_since = None;
                let raw = RawNetworkMessage::consensus_decode(&mut frame.as_slice())
                    .map_err(|e| PeerError::Receive(format!("{}", e)))?;
                self.last_recv = Instant::now();
                if let NetworkMessage::Pong(nonce) = raw.payload() {
                    if self.ping_sent.is_some_and(|(n, _)| n == *nonce) {
                        self.ping_sent = None;
                        self.last_ping = self.last_recv;
                    }
                }
                return Ok(Some(raw.payload().clone()));
            }

            // The message deadline, once its first byte is in.
            let payload_len = want - 24;
            let message_at = self.partial_since.map(|since| since + self.message_allowance(payload_len));
            if message_at.is_some_and(|at| Instant::now() >= at) {
                let have = self.partial.len();
                self.clear_partial();
                return Err(PeerError::Receive(format!(
                    "message too slow: {} of {} bytes in {}s",
                    have,
                    want.max(24),
                    self.message_allowance(payload_len).as_secs()
                )));
            }
            // Without a deadline of the caller's the standing read timeout
            // bounds each read, so the message deadline is overrun by at
            // most one of those.
            let bound = match (deadline, message_at) {
                (Some(d), Some(at)) => Some(ReadDeadline { at: d.at.min(at), ..d }),
                (d, _) => d,
            };

            let have = self.partial.len();
            let n = (want - have).min(READ_CHUNK);
            self.partial.resize(have + n, 0);
            let result = match bound {
                Some(deadline) => DeadlineReader { stream: &mut self.stream, deadline }
                    .read(&mut self.partial[have..]),
                None => self.stream.read(&mut self.partial[have..]),
            };
            self.partial.truncate(have + *result.as_ref().unwrap_or(&0));
            match result {
                Ok(0) => {
                    self.clear_partial();
                    return Err(PeerError::Receive("connection closed by peer".into()));
                }
                Ok(_) => {
                    if have == 0 {
                        self.partial_since = Some(Instant::now());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {
                    // Loop once more if it was the message deadline, which
                    // is reported above.
                    if message_at.is_some_and(|at| Instant::now() >= at) {
                        continue;
                    }
                    return Ok(None);
                }
                Err(e) => {
                    self.clear_partial();
                    return Err(PeerError::Receive(format!("{}", e)));
                }
            }
        }
    }

    fn clear_partial(&mut self) {
        self.partial.clear();
        self.partial_since = None;
    }

    /// Put the standing per-read timeout back after a call that bounded
    /// reads differently.
    fn restore_read_timeout(&mut self) -> Result<(), PeerError> {
        let normal = self.stream.read_timeout();
        self.stream
            .set_read_timeout(Some(normal))
            .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))
    }

    /// Request block headers starting from the given locator hashes.
    /// Returns the headers received from the peer.
    pub fn get_headers(
        &mut self,
        locator_hashes: Vec<BlockHash>,
        stop_hash: BlockHash,
    ) -> Result<Vec<bitcoin::block::Header>, PeerError> {
        self.get_headers_within(locator_hashes, stop_hash, None)
    }

    /// `get_headers` bounded by `limit` across every read of the exchange
    /// (ticket 028), like `get_block_within`. Without a limit (or with a
    /// longer one) the exchange still ends after the standing read timeout
    /// (ticket 049: the main loop's requests get a deadline too); running
    /// into that is the peer's `Timeout`, not `DeadlineReached`.
    pub fn get_headers_within(
        &mut self,
        locator_hashes: Vec<BlockHash>,
        stop_hash: BlockHash,
        limit: Option<Duration>,
    ) -> Result<Vec<bitcoin::block::Header>, PeerError> {
        let normal_timeout = self.stream.read_timeout();
        let Some(deadline) = ReadDeadline::request(normal_timeout, limit, normal_timeout) else {
            return Err(PeerError::DeadlineReached);
        };
        let result = self.exchange_headers(locator_hashes, stop_hash, deadline);
        // The deadline reader changed the socket timeout per read.
        self.restore_read_timeout()?;
        result
    }

    fn exchange_headers(
        &mut self,
        locator_hashes: Vec<BlockHash>,
        stop_hash: BlockHash,
        deadline: ReadDeadline,
    ) -> Result<Vec<bitcoin::block::Header>, PeerError> {
        let get_headers = GetHeadersMessage {
            version: PROTOCOL_VERSION,
            locator_hashes,
            stop_hash,
        };

        self.send(NetworkMessage::GetHeaders(get_headers))?;

        // Read messages until we get Headers
        for _ in 0..10 {
            let msg = self.receive_until(Some(deadline))?;
            match msg {
                NetworkMessage::Headers(headers) => {
                    return Ok(headers);
                }
                NetworkMessage::Ping(nonce) => {
                    self.send(NetworkMessage::Pong(nonce))?;
                }
                other => {
                    debug!(
                        "Ignoring {} message while waiting for headers",
                        msg_name(&other)
                    );
                }
            }
        }

        Err(PeerError::Receive(
            "did not receive headers response".into(),
        ))
    }

    /// Request a full block by hash. Uses WitnessBlock inventory type
    /// to ensure segwit witness data is included.
    pub fn get_block(&mut self, block_hash: BlockHash) -> Result<Block, PeerError> {
        self.get_block_within(block_hash, None)
    }

    /// `get_block` bounded by `limit` (ticket 028): a wake passes the time
    /// left in its budget so one slow peer can't hold the request past the
    /// iOS window. The limit is an absolute deadline across every read of
    /// the request, not a per-read timeout. Running into it is
    /// `DeadlineReached` (not the peer's fault); a zero limit sends nothing.
    /// Without a limit the block download timeout is the absolute deadline
    /// (ticket 049), and running into it is `BlockNotReceived`.
    pub fn get_block_within(
        &mut self,
        block_hash: BlockHash,
        limit: Option<Duration>,
    ) -> Result<Block, PeerError> {
        // Use longer timeout for block downloads (blocks can be up to ~4MB)
        let download_timeout = self.stream.block_download_timeout();
        let Some(deadline) = ReadDeadline::request(download_timeout, limit, download_timeout) else {
            return Err(PeerError::DeadlineReached);
        };

        let inv = vec![Inventory::WitnessBlock(block_hash)];
        let result = match self.send(NetworkMessage::GetData(inv)) {
            Ok(()) => self.receive_block(block_hash, Some(deadline)),
            Err(e) => Err(e),
        };

        // Restore normal read timeout
        self.restore_read_timeout()?;

        result
    }

    /// Read messages until we receive the Block we asked for.
    ///
    /// A `block` whose hash doesn't match `expected` is skipped rather than
    /// returned: it may be an unsolicited announcement racing our getdata,
    /// or a peer trying to substitute a different block. Either way it must
    /// never be mistaken for the requested one. Running out of the message
    /// bound, skipping more than `MAX_UNREQUESTED_BLOCKS`, or hitting the
    /// read timeout yields `BlockNotReceived`.
    fn receive_block(
        &mut self,
        expected: BlockHash,
        deadline: Option<ReadDeadline>,
    ) -> Result<Block, PeerError> {
        let mut skipped_blocks = 0;
        for _ in 0..20 {
            let msg = match self.receive_until(deadline) {
                Ok(m) => m,
                Err(PeerError::Timeout) => {
                    return Err(PeerError::BlockNotReceived { expected });
                }
                Err(e) => return Err(e),
            };
            match msg {
                NetworkMessage::Block(block) => {
                    let got = block.block_hash();
                    if got == expected {
                        return Ok(block);
                    }
                    skipped_blocks += 1;
                    if skipped_blocks > MAX_UNREQUESTED_BLOCKS {
                        return Err(PeerError::BlockNotReceived { expected });
                    }
                    debug!(
                        "Skipping block {} while waiting for {}",
                        got, expected
                    );
                }
                NetworkMessage::Ping(nonce) => {
                    self.send(NetworkMessage::Pong(nonce))?;
                }
                NetworkMessage::NotFound(_) => {
                    return Err(PeerError::Receive("block not found by peer".into()));
                }
                other => {
                    debug!(
                        "Ignoring {} message while waiting for block",
                        msg_name(&other)
                    );
                }
            }
        }

        Err(PeerError::BlockNotReceived { expected })
    }

    pub fn peer_height(&self) -> Option<i32> {
        self.their_version.as_ref().map(|v| v.start_height)
    }

    pub fn peer_user_agent(&self) -> Option<String> {
        self.their_version.as_ref().map(|v| v.user_agent.clone())
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Whether this peer announced BIP 155 `sendaddrv2` during the
    /// handshake. Required to know whether `addr` or `addrv2` is the
    /// correct gossip envelope when sending peer addresses (in particular,
    /// our own .onion can only be encoded in `addrv2`).
    pub fn wants_addrv2(&self) -> bool {
        self.wants_addrv2
    }

    /// Poll for a single incoming message, reading for at most `timeout`.
    /// Returns `Ok(Some(msg))` if a whole message is in, `Ok(None)` if not
    /// (yet: a message still arriving stays buffered for the next poll,
    /// ticket 049), or `Err` on connection failure or a message that
    /// overran its deadline. Unlike `idle_wait`, this returns the message
    /// to the caller for dispatch rather than handling it internally.
    pub fn poll_message(&mut self, timeout: Duration) -> Result<Option<NetworkMessage>, PeerError> {
        let deadline = ReadDeadline { at: Instant::now() + timeout, cap: timeout, budget: true };
        let result = self.read_message(Some(deadline));

        // Restore normal timeout
        let _ = self.restore_read_timeout();

        result
    }

    // ── Sending helpers for serving and relay ─────────────────────────

    /// Send a batch of headers to the peer (response to getheaders or unsolicited announcement).
    pub fn send_headers(&mut self, headers: Vec<bitcoin::block::Header>) -> Result<(), PeerError> {
        self.send(NetworkMessage::Headers(headers))
    }

    /// Send a full block to the peer (response to getdata).
    pub fn send_block(&mut self, block: Block) -> Result<(), PeerError> {
        self.send(NetworkMessage::Block(block))
    }

    /// Send a transaction to the peer (response to getdata).
    pub fn send_tx(&mut self, tx: bitcoin::Transaction) -> Result<(), PeerError> {
        self.send(NetworkMessage::Tx(tx))
    }

    /// Send inventory announcements to the peer (for relay).
    pub fn send_inv(&mut self, items: Vec<Inventory>) -> Result<(), PeerError> {
        self.send(NetworkMessage::Inv(items))
    }

    /// Send a not-found response for requested items we don't have.
    pub fn send_not_found(&mut self, items: Vec<Inventory>) -> Result<(), PeerError> {
        self.send(NetworkMessage::NotFound(items))
    }

    /// Ask the peer to send us their address book. Used immediately after
    /// handshake on outbound connections so we can populate our AddrManager
    /// with gossip-discovered peers (instead of relying solely on DNS).
    /// Bitcoin Core sends one getaddr per outbound peer per connection
    /// lifetime; we follow the same pattern.
    pub fn send_getaddr(&mut self) -> Result<(), PeerError> {
        self.send(NetworkMessage::GetAddr)
    }

    /// Send an unsolicited `addrv2` carrying our own .onion address so this
    /// peer can relay it onward (and dial us back). This is the smoking-gun
    /// fix for `inbound_peers = 0` — without it, no other node ever learns
    /// where to find us. Silently no-ops on peers that didn't negotiate
    /// addrv2 (BIP 155): the legacy `addr` encoding has no slot for a 32-byte
    /// pubkey, and silently dropping our self-ad is preferable to advertising
    /// a fake clearnet address that won't actually accept connections.
    pub fn send_self_advertisement(
        &mut self,
        pubkey: [u8; 32],
        port: u16,
    ) -> Result<(), PeerError> {
        if !self.wants_addrv2 {
            return Ok(());
        }
        let entry = bitcoin::p2p::address::AddrV2Message {
            time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .min(u32::MAX as u64) as u32,
            services: ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS,
            addr: bitcoin::p2p::address::AddrV2::TorV3(pubkey),
            port,
        };
        self.send(NetworkMessage::AddrV2(vec![entry]))
    }

    /// Wait for a duration while responding to pings to keep the connection alive.
    /// Returns Ok on timeout (normal), Err if the peer disconnects.
    pub fn idle_wait(&mut self, duration: std::time::Duration) -> Result<(), PeerError> {
        let deadline = ReadDeadline {
            at: Instant::now() + duration,
            cap: duration,
            budget: true,
        };
        loop {
            match self.read_message(Some(deadline)) {
                Ok(Some(NetworkMessage::Ping(nonce))) => {
                    self.send(NetworkMessage::Pong(nonce))?;
                }
                Ok(Some(_)) => {} // ignore other messages during idle
                Ok(None) | Err(_) => break, // timeout or disconnect
            }
        }

        // Restore standard read timeout
        self.restore_read_timeout()
    }
}

// ── Inbound handshakes off the sync thread (ticket 049) ───────────────

/// At most this many inbound handshakes run at once; connections beyond it
/// are dropped (the pool takes `MAX_INBOUND` anyway).
const MAX_INBOUND_HANDSHAKES: usize = 8;

/// Finished inbound peers waiting for the sync loop to pick them up.
const INBOUND_READY_QUEUE: usize = 16;

/// Inbound connections are handshaken here, each on a thread of its own
/// (the Tor accept task's blocking pool), never on the sync thread: a
/// silent or trickling inbound peer costs one of `MAX_INBOUND_HANDSHAKES`
/// slots for at most `HANDSHAKE_TIMEOUT`, and the sync loop only ever sees
/// finished, version-checked peers (`next_peer`).
pub struct InboundHandshakes {
    magic: Magic,
    /// Our tip, for the `version` we answer with.
    our_height: std::sync::atomic::AtomicI32,
    in_flight: std::sync::atomic::AtomicUsize,
    ready_tx: std::sync::mpsc::SyncSender<Peer>,
    ready_rx: std::sync::Mutex<std::sync::mpsc::Receiver<Peer>>,
}

impl InboundHandshakes {
    pub fn new(magic: Magic) -> InboundHandshakes {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(INBOUND_READY_QUEUE);
        InboundHandshakes {
            magic,
            our_height: std::sync::atomic::AtomicI32::new(0),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            ready_tx,
            ready_rx: std::sync::Mutex::new(ready_rx),
        }
    }

    pub fn set_our_height(&self, height: u32) {
        self.our_height
            .store(height.min(i32::MAX as u32) as i32, std::sync::atomic::Ordering::Relaxed);
    }

    /// Claim a handshake slot before handing a connection to `run`; false
    /// when `MAX_INBOUND_HANDSHAKES` are already running (drop it).
    pub fn try_begin(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_INBOUND_HANDSHAKES).then_some(n + 1)
            })
            .is_ok()
    }

    /// Give back a slot claimed by `try_begin` without running a handshake
    /// (the connection failed first).
    pub fn abandon(&self) {
        self.in_flight.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Run the handshake on `stream` (blocking, within `HANDSHAKE_TIMEOUT`)
    /// in a slot claimed by `try_begin`, and queue the peer if it succeeds.
    pub fn run(&self, stream: PeerStream) {
        struct Slot<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Slot<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
        }
        let _slot = Slot(&self.in_flight);
        let height = self.our_height.load(std::sync::atomic::Ordering::Relaxed);
        match Peer::accept(stream, height, self.magic) {
            Ok(peer) => {
                if self.ready_tx.try_send(peer).is_err() {
                    info!("Inbound peer dropped: too many waiting for the sync loop");
                }
            }
            Err(e) => info!("Inbound handshake failed: {}", e),
        }
    }

    /// A finished inbound peer, if one is waiting (non-blocking).
    pub fn next_peer(&self) -> Option<Peer> {
        self.ready_rx.lock().unwrap().try_recv().ok()
    }

    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::Acquire)
    }
}

pub(crate) fn msg_name(msg: &NetworkMessage) -> &'static str {
    match msg {
        NetworkMessage::Version(_) => "version",
        NetworkMessage::Verack => "verack",
        NetworkMessage::Ping(_) => "ping",
        NetworkMessage::Pong(_) => "pong",
        NetworkMessage::SendHeaders => "sendheaders",
        NetworkMessage::GetHeaders(_) => "getheaders",
        NetworkMessage::Headers(_) => "headers",
        NetworkMessage::Inv(_) => "inv",
        NetworkMessage::GetData(_) => "getdata",
        NetworkMessage::Block(_) => "block",
        NetworkMessage::Tx(_) => "tx",
        NetworkMessage::NotFound(_) => "notfound",
        NetworkMessage::Addr(_) => "addr",
        NetworkMessage::AddrV2(_) => "addrv2",
        NetworkMessage::Alert(_) => "alert",
        NetworkMessage::FeeFilter(_) => "feefilter",
        NetworkMessage::MemPool => "mempool",
        NetworkMessage::GetAddr => "getaddr",
        NetworkMessage::SendAddrV2 => "sendaddrv2",
        NetworkMessage::WtxidRelay => "wtxidrelay",
        _ => "unknown",
    }
}

#[derive(Debug)]
pub enum PeerError {
    Connection(String),
    Handshake(String),
    Send(String),
    Receive(String),
    /// Read timed out (no data available within the timeout period).
    /// Distinct from `Receive` to allow reliable detection without string matching.
    Timeout,
    /// The peer never delivered the block we requested — the message bound
    /// or download timeout ran out (possibly after sending other blocks).
    /// Distinct from transport errors so callers can penalize and retry.
    BlockNotReceived { expected: BlockHash },
    /// A message arrived with another network's magic (ticket 024). Never
    /// honest after a successful handshake; callers drop and ban the peer.
    WrongMagic { got: [u8; 4], expected: Magic },
    /// The caller's own deadline (a wake budget) ran out mid-exchange. Not
    /// evidence against the peer: callers don't penalize it.
    DeadlineReached,
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Connection(s) => write!(f, "connection error: {}", s),
            PeerError::Handshake(s) => write!(f, "handshake error: {}", s),
            PeerError::Send(s) => write!(f, "send error: {}", s),
            PeerError::Receive(s) => write!(f, "receive error: {}", s),
            PeerError::Timeout => write!(f, "read timed out"),
            PeerError::DeadlineReached => write!(f, "deadline reached"),
            PeerError::BlockNotReceived { expected } => {
                write!(f, "requested block {} not received", expected)
            }
            PeerError::WrongMagic { got, expected } => {
                write!(f, "wrong network magic {:02x?} (expected {})", got, expected)
            }
        }
    }
}

impl std::error::Error for PeerError {}

fn rand_nonce() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}

#[cfg(test)]
pub(crate) mod tests {
    //! Send-helper serialization round-trips.
    //!
    //! These tests cover the thin `send_*` wrappers (`send_headers`,
    //! `send_block`, `send_tx`, `send_inv`, `send_not_found`) by attaching
    //! a `Peer` to one half of a TCP loopback pair, calling the helper,
    //! and decoding the bytes that arrived on the other end with the same
    //! `RawNetworkMessage` codec the receive path uses.
    //!
    //! We deliberately don't run the version handshake here — these are
    //! unit tests for the framing/serialization wrappers, not integration
    //! tests for the protocol. Constructing a Peer in-place is the cheapest
    //! way to exercise the send code without standing up a full responder.
    use super::*;
    use bitcoin::block::Header as BlockHeader;
    use bitcoin::consensus::{deserialize, Decodable};
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::message::RawNetworkMessage;
    use std::net::{TcpListener, TcpStream};

    /// Open a loopback TCP pair and wrap one half in a `Peer` so the
    /// `send_*` helpers can write into it. The returned listener-side
    /// `TcpStream` is what the test reads to decode the wire bytes.
    pub(crate) fn loopback_peer_pair() -> (Peer, TcpStream) {
        let listener = TcpListener::bind(crate::testkit::loopback_bind()).expect("bind loopback");
        let addr = listener.local_addr().expect("local_addr");

        // Connect side runs in the test thread; accept side runs in a
        // worker so we can join after the send completes.
        let accept_handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream
        });

        let client = TcpStream::connect(addr).expect("connect loopback");
        let server_side = accept_handle.join().expect("accept thread joined");

        // Generous read timeout for the server side: tests on a busy CI
        // machine occasionally need a few hundred ms to deliver. The send
        // side never needs a timeout because it's writing into a kernel
        // buffer, not waiting on the peer.
        server_side
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set server read timeout");

        let peer = Peer::new(PeerStream::Direct(client), addr.to_string(), Magic::BITCOIN, false);
        (peer, server_side)
    }

    /// Read one full P2P message off `stream` and parse it via the same
    /// `RawNetworkMessage` codec the production receive path uses, so the
    /// tests catch any framing drift between sender and receiver.
    pub(crate) fn read_one_message(stream: &mut TcpStream) -> NetworkMessage {
        let mut header = [0u8; 24];
        stream.read_exact(&mut header).expect("read header");
        let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload).expect("read payload");
        }
        let mut buf = Vec::with_capacity(24 + payload_len);
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&payload);
        let mut slice = buf.as_slice();
        let raw = RawNetworkMessage::consensus_decode(&mut slice).expect("decode raw");
        raw.payload().clone()
    }

    /// Write one P2P message onto `stream` using the same codec as
    /// `Peer::send`, so a test can play the remote side of the connection.
    pub(crate) fn write_message(stream: &mut TcpStream, msg: NetworkMessage) {
        let raw = RawNetworkMessage::new(Magic::BITCOIN, msg);
        raw.consensus_encode(stream).expect("encode message");
        stream.flush().expect("flush");
    }

    /// Coinbase-only block whose hash is distinguished by `nonce`. Not
    /// consensus-valid; only the hash matters for the get_block tests.
    pub(crate) fn synthetic_block(nonce: u32) -> Block {
        use bitcoin::blockdata::block::{Header, Version};
        use bitcoin::blockdata::transaction::{
            OutPoint, Sequence, TxIn, TxOut, Version as TxVersion,
        };
        use bitcoin::{absolute::LockTime, Amount, CompactTarget, ScriptBuf, TxMerkleNode, Witness};
        let coinbase = bitcoin::Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
            }],
        };
        Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce,
            },
            txdata: vec![coinbase],
        }
    }

    /// Assert the server side received our `getdata` for `hash`.
    fn expect_getdata(server: &mut TcpStream, hash: BlockHash) {
        match read_one_message(server) {
            NetworkMessage::GetData(inv) => match inv.as_slice() {
                [Inventory::WitnessBlock(h)] => assert_eq!(*h, hash),
                _ => panic!("unexpected getdata inventory: {:?}", inv),
            },
            other => panic!("expected GetData, got {}", msg_name(&other)),
        }
    }

    /// A minimal real block header — using the genesis header here so we
    /// don't have to hand-roll a `Header` literal in every test that needs
    /// to send headers.
    fn sample_header() -> BlockHeader {
        // Mainnet genesis block header (80 bytes).
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c",
        )
        .unwrap();
        deserialize(&raw).expect("genesis header")
    }

    #[test]
    fn send_headers_writes_headers_message() {
        let (mut peer, mut server) = loopback_peer_pair();
        let h = sample_header();
        peer.send_headers(vec![h, h]).expect("send_headers");

        match read_one_message(&mut server) {
            NetworkMessage::Headers(hdrs) => {
                assert_eq!(hdrs.len(), 2);
                assert_eq!(hdrs[0].block_hash(), h.block_hash());
                assert_eq!(hdrs[1].block_hash(), h.block_hash());
            }
            other => panic!("expected Headers, got {}", msg_name(&other)),
        }
    }

    #[test]
    fn send_inv_writes_inv_message_with_items_in_order() {
        let (mut peer, mut server) = loopback_peer_pair();
        let h1 = BlockHash::from_byte_array([0x01; 32]);
        let h2 = BlockHash::from_byte_array([0x02; 32]);
        let h3 = BlockHash::from_byte_array([0x03; 32]);
        let items = vec![
            Inventory::Block(h1),
            Inventory::WitnessBlock(h2),
            Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array([0x09; 32])),
            Inventory::Block(h3),
        ];
        peer.send_inv(items.clone()).expect("send_inv");

        match read_one_message(&mut server) {
            NetworkMessage::Inv(received) => {
                // We don't compare with `==` because Inventory's equality
                // covers the variants we care about; iterating is clearer.
                assert_eq!(received.len(), items.len());
                for (sent, got) in items.iter().zip(received.iter()) {
                    match (sent, got) {
                        (Inventory::Block(a), Inventory::Block(b)) => assert_eq!(a, b),
                        (Inventory::WitnessBlock(a), Inventory::WitnessBlock(b)) => {
                            assert_eq!(a, b)
                        }
                        (
                            Inventory::WitnessTransaction(a),
                            Inventory::WitnessTransaction(b),
                        ) => assert_eq!(a, b),
                        _ => panic!("inventory variant mismatch: {:?} vs {:?}", sent, got),
                    }
                }
            }
            other => panic!("expected Inv, got {}", msg_name(&other)),
        }
    }

    #[test]
    fn send_not_found_writes_notfound_with_inventory() {
        let (mut peer, mut server) = loopback_peer_pair();
        let missing = vec![Inventory::WitnessBlock(BlockHash::from_byte_array(
            [0xfe; 32],
        ))];
        peer.send_not_found(missing.clone()).expect("send_not_found");

        match read_one_message(&mut server) {
            NetworkMessage::NotFound(items) => {
                assert_eq!(items.len(), 1);
                match (&items[0], &missing[0]) {
                    (Inventory::WitnessBlock(a), Inventory::WitnessBlock(b)) => {
                        assert_eq!(a, b)
                    }
                    _ => panic!("expected single WitnessBlock entry"),
                }
            }
            other => panic!("expected NotFound, got {}", msg_name(&other)),
        }
    }

    #[test]
    fn send_block_writes_block_message_preserving_txdata() {
        let (mut peer, mut server) = loopback_peer_pair();
        // Build a tiny synthetic block with a single coinbase. Header
        // checksum and merkle root don't matter — the wire codec only
        // cares about byte layout.
        use bitcoin::blockdata::block::{Header, Version};
        use bitcoin::blockdata::transaction::{
            OutPoint, Sequence, TxIn, TxOut, Version as TxVersion,
        };
        use bitcoin::{absolute::LockTime, Amount, CompactTarget, ScriptBuf, TxMerkleNode, Witness};
        let coinbase = bitcoin::Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
            }],
        };
        let block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![coinbase],
        };
        let expected_txid = block.txdata[0].compute_txid();

        peer.send_block(block.clone()).expect("send_block");

        match read_one_message(&mut server) {
            NetworkMessage::Block(received) => {
                assert_eq!(received.txdata.len(), 1);
                assert_eq!(received.txdata[0].compute_txid(), expected_txid);
                assert_eq!(received.header.time, 0);
            }
            other => panic!("expected Block, got {}", msg_name(&other)),
        }
    }

    #[test]
    fn send_tx_writes_tx_message_preserving_outpoints_and_amounts() {
        let (mut peer, mut server) = loopback_peer_pair();
        use bitcoin::blockdata::transaction::{
            OutPoint, Sequence, TxIn, TxOut, Version as TxVersion,
        };
        use bitcoin::{absolute::LockTime, Amount, ScriptBuf, Txid, Witness};
        let tx = bitcoin::Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x55; 32]),
                    vout: 7,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(123_456),
                script_pubkey: ScriptBuf::from_bytes(vec![0xac, 0xab]),
            }],
        };
        let expected_txid = tx.compute_txid();

        peer.send_tx(tx).expect("send_tx");

        match read_one_message(&mut server) {
            NetworkMessage::Tx(received) => {
                assert_eq!(received.compute_txid(), expected_txid);
                assert_eq!(received.input.len(), 1);
                assert_eq!(received.input[0].previous_output.vout, 7);
                assert_eq!(received.output.len(), 1);
                assert_eq!(received.output[0].value.to_sat(), 123_456);
            }
            other => panic!("expected Tx, got {}", msg_name(&other)),
        }
    }

    // ── Network magic (ticket 024) ───────────────────────────────────

    #[test]
    fn receive_rejects_wrong_network_magic() {
        let (mut peer, mut server) = loopback_peer_pair();
        let raw = RawNetworkMessage::new(Magic::REGTEST, NetworkMessage::Ping(7));
        raw.consensus_encode(&mut server).expect("encode message");
        server.flush().expect("flush");
        match peer.receive() {
            Err(PeerError::WrongMagic { got, expected }) => {
                assert_eq!(got, Magic::REGTEST.to_bytes());
                assert_eq!(expected, Magic::BITCOIN);
            }
            Ok(m) => panic!("accepted {} with regtest magic on mainnet", msg_name(&m)),
            Err(e) => panic!("expected magic error, got {}", e),
        }
    }

    #[test]
    fn receive_accepts_matching_network_magic() {
        let (mut peer, mut server) = loopback_peer_pair();
        write_message(&mut server, NetworkMessage::Ping(7));
        assert!(matches!(peer.receive(), Ok(NetworkMessage::Ping(7))));
    }

    // ── get_block hash binding (ticket 022) ──────────────────────────

    #[test]
    fn get_block_skips_unrequested_block_then_returns_requested() {
        let (mut peer, mut server) = loopback_peer_pair();
        let wanted = synthetic_block(1);
        let other = synthetic_block(2);
        let wanted_hash = wanted.block_hash();
        assert_ne!(wanted_hash, other.block_hash());

        write_message(&mut server, NetworkMessage::Block(other));
        write_message(&mut server, NetworkMessage::Block(wanted));

        let got = peer.get_block(wanted_hash).expect("get_block");
        assert_eq!(got.block_hash(), wanted_hash);
        expect_getdata(&mut server, wanted_hash);
    }

    #[test]
    fn get_block_never_returns_wrong_block_within_message_bound() {
        let (mut peer, mut server) = loopback_peer_pair();
        let wanted_hash = synthetic_block(1).block_hash();
        // Exhaust the 20-message bound with non-block noise.
        for _ in 0..20 {
            write_message(
                &mut server,
                NetworkMessage::Inv(vec![Inventory::Block(synthetic_block(3).block_hash())]),
            );
        }
        write_message(&mut server, NetworkMessage::Block(synthetic_block(2)));

        match peer.get_block(wanted_hash) {
            Err(PeerError::BlockNotReceived { expected }) => assert_eq!(expected, wanted_hash),
            Ok(b) => panic!("returned wrong block {}", b.block_hash()),
            Err(e) => panic!("expected BlockNotReceived, got {}", e),
        }
    }

    #[test]
    fn get_block_tolerates_unrequested_blocks_up_to_cap() {
        let (mut peer, mut server) = loopback_peer_pair();
        let wanted = synthetic_block(1);
        let wanted_hash = wanted.block_hash();
        for _ in 0..MAX_UNREQUESTED_BLOCKS {
            write_message(&mut server, NetworkMessage::Block(synthetic_block(2)));
        }
        write_message(&mut server, NetworkMessage::Block(wanted));

        let got = peer.get_block(wanted_hash).expect("get_block");
        assert_eq!(got.block_hash(), wanted_hash);
    }

    #[test]
    fn get_block_gives_up_after_too_many_unrequested_blocks() {
        // A peer streaming wrong blocks must not make us download ~20 × 4 MB:
        // we bail as soon as the cap is exceeded, even if the right block
        // would have followed.
        let (mut peer, mut server) = loopback_peer_pair();
        let wanted = synthetic_block(1);
        let wanted_hash = wanted.block_hash();
        for _ in 0..=MAX_UNREQUESTED_BLOCKS {
            write_message(&mut server, NetworkMessage::Block(synthetic_block(2)));
        }
        write_message(&mut server, NetworkMessage::Block(wanted));

        match peer.get_block(wanted_hash) {
            Err(PeerError::BlockNotReceived { expected }) => assert_eq!(expected, wanted_hash),
            Ok(b) => panic!("expected give-up, got block {}", b.block_hash()),
            Err(e) => panic!("expected BlockNotReceived, got {}", e),
        }
    }

    #[test]
    fn receive_block_times_out_as_block_not_received_after_wrong_block() {
        // get_block itself uses the 120s download timeout, so drive
        // receive_block directly with a short read timeout to cover the
        // timeout half of the "only wrong block" case.
        let (mut peer, mut server) = loopback_peer_pair();
        let wanted_hash = synthetic_block(1).block_hash();
        write_message(&mut server, NetworkMessage::Block(synthetic_block(2)));
        peer.stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set timeout");

        match peer.receive_block(wanted_hash, None) {
            Err(PeerError::BlockNotReceived { expected }) => assert_eq!(expected, wanted_hash),
            Ok(b) => panic!("returned wrong block {}", b.block_hash()),
            Err(e) => panic!("expected BlockNotReceived, got {}", e),
        }
    }

    #[test]
    fn get_block_within_bounds_a_trickling_peer() {
        // The peer drips the block a few bytes at a time, each chunk well
        // inside any per-read timeout. Only an absolute deadline stops it.
        let (mut peer, mut server) = loopback_peer_pair();
        let block = synthetic_block(1);
        let hash = block.block_hash();
        let mut bytes = Vec::new();
        RawNetworkMessage::new(Magic::BITCOIN, NetworkMessage::Block(block))
            .consensus_encode(&mut bytes)
            .unwrap();
        let dripper = std::thread::spawn(move || {
            for chunk in bytes.chunks(4) {
                if server.write_all(chunk).and_then(|_| server.flush()).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });

        let start = Instant::now();
        let result = peer.get_block_within(hash, Some(Duration::from_millis(300)));
        let took = start.elapsed();
        assert!(matches!(result, Err(PeerError::DeadlineReached)), "{:?}", result.map(|b| b.block_hash()));
        // Unbounded, this takes ~(bytes / 4) * 100 ms, several seconds. The
        // deadline is honored exactly (no 1 s minimum).
        assert!(took < Duration::from_millis(600), "took {:?}", took);
        drop(peer);
        dripper.join().unwrap();
    }

    #[test]
    fn get_headers_within_bounds_a_silent_peer() {
        let (mut peer, _server) = loopback_peer_pair();
        let start = Instant::now();
        let result = peer.get_headers_within(vec![], BlockHash::all_zeros(), Some(Duration::from_millis(200)));
        assert!(matches!(result, Err(PeerError::DeadlineReached)), "{:?}", result.map(|h| h.len()));
        assert!(start.elapsed() < Duration::from_millis(500), "{:?}", start.elapsed());
        // A zero limit doesn't even send.
        assert!(matches!(
            peer.get_headers_within(vec![], BlockHash::all_zeros(), Some(Duration::ZERO)),
            Err(PeerError::DeadlineReached)
        ));
    }

    #[test]
    fn get_block_returns_error_on_notfound() {
        let (mut peer, mut server) = loopback_peer_pair();
        let wanted_hash = synthetic_block(1).block_hash();
        write_message(
            &mut server,
            NetworkMessage::NotFound(vec![Inventory::WitnessBlock(wanted_hash)]),
        );

        match peer.get_block(wanted_hash) {
            Err(PeerError::Receive(msg)) => assert!(msg.contains("not found"), "{}", msg),
            Ok(b) => panic!("returned block {}", b.block_hash()),
            Err(e) => panic!("expected not-found Receive error, got {}", e),
        }
    }

    #[test]
    fn get_block_handles_interleaved_noise_and_answers_ping() {
        let (mut peer, mut server) = loopback_peer_pair();
        let wanted = synthetic_block(1);
        let wanted_hash = wanted.block_hash();

        write_message(&mut server, NetworkMessage::Ping(0xdead_beef));
        write_message(
            &mut server,
            NetworkMessage::Inv(vec![Inventory::Block(synthetic_block(3).block_hash())]),
        );
        write_message(&mut server, NetworkMessage::Block(synthetic_block(2)));
        write_message(&mut server, NetworkMessage::Block(wanted));

        let got = peer.get_block(wanted_hash).expect("get_block");
        assert_eq!(got.block_hash(), wanted_hash);

        expect_getdata(&mut server, wanted_hash);
        match read_one_message(&mut server) {
            NetworkMessage::Pong(nonce) => assert_eq!(nonce, 0xdead_beef),
            other => panic!("expected Pong, got {}", msg_name(&other)),
        }
    }

    // ══ Adversarial wire input (tests/network-app) ═══════════════════
    //
    // Most of these drive `Peer` over `MemStream`: a scripted, in-memory
    // `PeerStream` (test builds only). Reads come from a list of chunks,
    // `Chunk::Stall` makes one read time out, and the end of the script
    // reads as the peer hanging up. That makes framing, handshake and
    // exchange bounds deterministic, and cheap enough for property tests.

    use proptest::prelude::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// One step of a scripted inbound byte stream.
    #[derive(Clone, Debug)]
    pub(crate) enum Chunk {
        /// Bytes the peer sends, delivered over as many reads as needed.
        Data(Vec<u8>),
        /// One read times out here: the peer paused past our read timeout.
        Stall,
    }

    /// In-memory `PeerStream`: reads follow the script, writes are kept.
    pub(crate) struct MemStream {
        input: VecDeque<Chunk>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for MemStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                match self.input.pop_front() {
                    None => return Ok(0),
                    Some(Chunk::Stall) => {
                        return Err(io::Error::new(io::ErrorKind::WouldBlock, "scripted stall"))
                    }
                    Some(Chunk::Data(d)) if d.is_empty() => continue,
                    Some(Chunk::Data(d)) => {
                        let n = d.len().min(buf.len());
                        buf[..n].copy_from_slice(&d[..n]);
                        if n < d.len() {
                            self.input.push_front(Chunk::Data(d[n..].to_vec()));
                        }
                        return Ok(n);
                    }
                }
            }
        }
    }

    impl Write for MemStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A `Peer` (outbound, `magic`) reading `script`; the returned buffer
    /// collects everything it sends.
    pub(crate) fn mem_peer(script: Vec<Chunk>, magic: Magic) -> (Peer, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = MemStream { input: script.into(), written: written.clone() };
        let peer = Peer::new(PeerStream::Mem(stream), "198.51.100.7:8333".into(), magic, false);
        (peer, written)
    }

    /// `msg` framed for the wire with `magic`.
    pub(crate) fn encode(magic: Magic, msg: NetworkMessage) -> Vec<u8> {
        let mut out = Vec::new();
        RawNetworkMessage::new(magic, msg).consensus_encode(&mut out).unwrap();
        out
    }

    /// Script delivering `msgs` (mainnet magic) one message per chunk.
    pub(crate) fn script_of(msgs: Vec<NetworkMessage>) -> Vec<Chunk> {
        msgs.into_iter().map(|m| Chunk::Data(encode(Magic::BITCOIN, m))).collect()
    }

    /// Every message in `bytes`, in order.
    pub(crate) fn decode_all(bytes: &[u8]) -> Vec<NetworkMessage> {
        let mut slice = bytes;
        let mut out = Vec::new();
        while !slice.is_empty() {
            let raw = RawNetworkMessage::consensus_decode(&mut slice).expect("we sent a bad frame");
            out.push(raw.payload().clone());
        }
        out
    }

    /// A raw frame with an arbitrary command and payload. `checksum: None`
    /// computes the real one.
    pub(crate) fn frame(magic: Magic, command: &[u8], payload: &[u8], checksum: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + payload.len());
        out.extend_from_slice(&magic.to_bytes());
        let mut cmd = [0u8; 12];
        cmd[..command.len()].copy_from_slice(command);
        out.extend_from_slice(&cmd);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let sum = checksum.unwrap_or_else(|| {
            let h = bitcoin::hashes::sha256d::Hash::hash(payload).to_byte_array();
            [h[0], h[1], h[2], h[3]]
        });
        out.extend_from_slice(&sum);
        out.extend_from_slice(payload);
        out
    }

    pub(crate) fn their_version(version: u32) -> NetworkMessage {
        let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        NetworkMessage::Version(VersionMessage {
            version,
            services,
            timestamp: 1_700_000_000,
            receiver: Address::new(&SocketAddr::from(([0, 0, 0, 0], 0)), ServiceFlags::NONE),
            sender: Address::new(&SocketAddr::from(([0, 0, 0, 0], 0)), services),
            nonce: 42,
            user_agent: "/Satoshi:30.0.0/".into(),
            start_height: 900_000,
            relay: true,
        })
    }

    /// Every command name rust-bitcoin parses into a typed message (plus
    /// one it doesn't), for the malformed-payload sweeps.
    const COMMANDS: &[&str] = &[
        "version", "verack", "addr", "addrv2", "sendaddrv2", "inv", "getdata", "notfound",
        "getblocks", "getheaders", "mempool", "tx", "block", "headers", "sendheaders", "getaddr",
        "ping", "pong", "merkleblock", "filterload", "filteradd", "filterclear", "getcfilters",
        "cfilter", "getcfheaders", "cfheaders", "getcfcheckpt", "cfcheckpt", "sendcmpct",
        "cmpctblock", "getblocktxn", "blocktxn", "alert", "reject", "feefilter", "wtxidrelay",
        "hercjunk",
    ];

    /// Payload shapes that break decoders: empty, truncated varints, huge
    /// element counts with nothing behind them, junk.
    fn hostile_payloads() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x01],
            vec![0xfd],
            vec![0xfd, 0xff, 0xff],
            vec![0xfe, 0xff, 0xff, 0xff, 0xff],
            vec![0xff; 9],
            vec![0xff; 81],
            [&[0xfd, 0xd0, 0x07][..], &[0u8; 80][..]].concat(), // "2000 headers", one present
            vec![0x00; 200],
        ]
    }

    // ── Framing bounds ───────────────────────────────────────────────

    #[test]
    fn receive_rejects_lengths_over_the_limit_from_the_header_alone() {
        for len in [MAX_P2P_PAYLOAD + 1, 0x7fff_ffff, u32::MAX] {
            let mut hdr = frame(Magic::BITCOIN, b"block", &[], None);
            hdr[16..20].copy_from_slice(&len.to_le_bytes());
            // Only the header is scripted: a reader that tried to fetch
            // the payload would hit EOF and say so instead.
            let (mut peer, _) = mem_peer(vec![Chunk::Data(hdr)], Magic::BITCOIN);
            match peer.receive() {
                Err(PeerError::Receive(m)) => assert!(m.contains("exceeds limit"), "{}: {}", len, m),
                other => panic!("{}: {:?}", len, other.map(|m| msg_name(&m))),
            }
        }
    }

    #[test]
    fn receive_reads_a_payload_exactly_at_the_limit() {
        let payload = vec![0x5a; MAX_P2P_PAYLOAD as usize];
        let (mut peer, _) =
            mem_peer(vec![Chunk::Data(frame(Magic::BITCOIN, b"hercjunk", &payload, None))], Magic::BITCOIN);
        match peer.receive() {
            Ok(NetworkMessage::Unknown { command, payload: p }) => {
                assert_eq!(command.to_string(), "hercjunk");
                assert_eq!(p.len(), MAX_P2P_PAYLOAD as usize);
            }
            other => panic!("{:?}", other.map(|m| msg_name(&m))),
        }
    }

    #[test]
    fn receive_rejects_a_bad_checksum() {
        let payload = 7u64.to_le_bytes();
        let (mut peer, _) = mem_peer(
            vec![Chunk::Data(frame(Magic::BITCOIN, b"ping", &payload, Some([0, 0, 0, 0])))],
            Magic::BITCOIN,
        );
        assert!(matches!(peer.receive(), Err(PeerError::Receive(_))));
    }

    #[test]
    fn receive_reports_a_hangup_mid_header_or_mid_payload_as_an_error() {
        let ping = encode(Magic::BITCOIN, NetworkMessage::Ping(7));
        for cut in [1, 4, 10, 23, 24, ping.len() - 1] {
            let (mut peer, _) = mem_peer(vec![Chunk::Data(ping[..cut].to_vec())], Magic::BITCOIN);
            assert!(matches!(peer.receive(), Err(PeerError::Receive(_))), "cut at {}", cut);
        }
        // Nothing at all: a clean hangup is an error too, not a timeout.
        let (mut peer, _) = mem_peer(vec![], Magic::BITCOIN);
        assert!(matches!(peer.receive(), Err(PeerError::Receive(_))));
    }

    #[test]
    fn receive_returns_unknown_commands_without_error() {
        let (mut peer, _) =
            mem_peer(vec![Chunk::Data(frame(Magic::BITCOIN, b"hercjunk", &[1, 2, 3], None))], Magic::BITCOIN);
        assert!(matches!(peer.receive(), Ok(NetworkMessage::Unknown { .. })));
    }

    #[test]
    fn malformed_payloads_of_every_command_are_errors_and_keep_the_stream_aligned() {
        // A well-framed message whose payload doesn't parse is consumed in
        // full and reported (the caller drops the peer); it never panics,
        // and the next frame on the stream still parses.
        for cmd in COMMANDS {
            for payload in hostile_payloads() {
                let script = vec![
                    Chunk::Data(frame(Magic::BITCOIN, cmd.as_bytes(), &payload, None)),
                    Chunk::Data(encode(Magic::BITCOIN, NetworkMessage::Ping(99))),
                ];
                let (mut peer, _) = mem_peer(script, Magic::BITCOIN);
                let _ = peer.receive();
                assert!(
                    matches!(peer.receive(), Ok(NetworkMessage::Ping(99))),
                    "stream misaligned after {} with {:02x?}",
                    cmd,
                    &payload[..payload.len().min(8)]
                );
            }
        }
    }

    #[test]
    fn headers_carrying_transactions_are_rejected() {
        // Each header in a `headers` message is followed by a tx count that
        // must be zero.
        let mut payload = vec![0x01];
        payload.extend_from_slice(&bitcoin::consensus::serialize(&sample_header()));
        payload.push(0x01);
        let (mut peer, _) =
            mem_peer(vec![Chunk::Data(frame(Magic::BITCOIN, b"headers", &payload, None))], Magic::BITCOIN);
        assert!(matches!(peer.receive(), Err(PeerError::Receive(_))));
    }

    #[test]
    fn huge_element_counts_are_rejected_without_allocating_for_them() {
        // "4 billion inventory entries" in a 9-byte payload: refused from
        // the count, not by trying to read (or reserve) that many.
        for cmd in ["inv", "getdata", "notfound", "headers", "addr", "addrv2", "getheaders"] {
            let payload: Vec<u8> = if cmd == "getheaders" {
                [&70016u32.to_le_bytes()[..], &[0xfe, 0xff, 0xff, 0xff, 0xff][..]].concat()
            } else {
                vec![0xfe, 0xff, 0xff, 0xff, 0xff]
            };
            let (mut peer, _) =
                mem_peer(vec![Chunk::Data(frame(Magic::BITCOIN, cmd.as_bytes(), &payload, None))], Magic::BITCOIN);
            let start = Instant::now();
            assert!(peer.receive().is_err(), "{} accepted", cmd);
            assert!(start.elapsed() < Duration::from_secs(1), "{} took {:?}", cmd, start.elapsed());
        }
    }

    #[test]
    fn wrong_magic_after_good_messages_is_reported_as_wrong_magic() {
        let script = vec![
            Chunk::Data(encode(Magic::BITCOIN, NetworkMessage::Ping(1))),
            Chunk::Data(encode(Magic::TESTNET3, NetworkMessage::Ping(2))),
        ];
        let (mut peer, _) = mem_peer(script, Magic::BITCOIN);
        assert!(matches!(peer.receive(), Ok(NetworkMessage::Ping(1))));
        assert!(matches!(peer.receive(), Err(PeerError::WrongMagic { .. })));
    }

    // ── Outbound handshake ───────────────────────────────────────────

    #[test]
    fn handshake_sends_version_then_sendaddrv2_and_verack_only_after_theirs() {
        let (mut peer, written) =
            mem_peer(script_of(vec![their_version(70016), NetworkMessage::Verack]), Magic::BITCOIN);
        peer.handshake(123).unwrap();
        let sent = decode_all(&written.lock().unwrap());
        let names: Vec<&str> = sent.iter().map(msg_name).collect();
        assert_eq!(names, ["version", "sendaddrv2", "verack"]);
        match &sent[0] {
            NetworkMessage::Version(v) => {
                assert_eq!(v.start_height, 123);
                assert!(v.version >= 70016);
                // We never claim to serve full history (pruned node).
                assert!(!v.services.has(ServiceFlags::NETWORK));
                assert!(v.services.has(ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS));
            }
            other => panic!("first message {}", msg_name(other)),
        }
        assert_eq!(peer.peer_height(), Some(900_000));
    }

    #[test]
    fn handshake_accepts_verack_before_version() {
        let (mut peer, _) =
            mem_peer(script_of(vec![NetworkMessage::Verack, their_version(70016)]), Magic::BITCOIN);
        peer.handshake(0).unwrap();
        assert_eq!(peer.peer_user_agent().as_deref(), Some("/Satoshi:30.0.0/"));
    }

    #[test]
    fn handshake_records_sendaddrv2_and_tolerates_feature_negotiation() {
        // Core sends wtxidrelay and sendaddrv2 between version and verack,
        // and may send sendheaders, sendcmpct, ping or feefilter early.
        let (mut peer, _) = mem_peer(
            script_of(vec![
                their_version(70016),
                NetworkMessage::WtxidRelay,
                NetworkMessage::SendAddrV2,
                NetworkMessage::SendHeaders,
                NetworkMessage::FeeFilter(1000),
                NetworkMessage::Verack,
            ]),
            Magic::BITCOIN,
        );
        peer.handshake(0).unwrap();
        assert!(peer.wants_addrv2());

        let (mut peer, _) =
            mem_peer(script_of(vec![their_version(70016), NetworkMessage::Verack]), Magic::BITCOIN);
        peer.handshake(0).unwrap();
        assert!(!peer.wants_addrv2(), "addrv2 assumed without sendaddrv2");
    }

    #[test]
    fn handshake_enforces_minimum_protocol_version() {
        let (mut peer, _) =
            mem_peer(script_of(vec![their_version(70014), NetworkMessage::Verack]), Magic::BITCOIN);
        assert!(matches!(peer.handshake(0), Err(PeerError::Handshake(m)) if m.contains("too old")));
        let (mut peer, _) =
            mem_peer(script_of(vec![their_version(70015), NetworkMessage::Verack]), Magic::BITCOIN);
        assert!(peer.handshake(0).is_ok(), "70015 is the minimum, not below it");
    }

    #[test]
    fn handshake_gives_up_after_ten_messages_without_completing() {
        // Version but never verack, among chatter: bounded, not a hang.
        let mut msgs = vec![their_version(70016)];
        msgs.extend((0..20).map(NetworkMessage::Ping));
        let (mut peer, _) = mem_peer(script_of(msgs), Magic::BITCOIN);
        assert!(matches!(peer.handshake(0), Err(PeerError::Handshake(m)) if m.contains("verack")));
        // Never a version at all.
        let (mut peer, _) = mem_peer(script_of((0..20).map(NetworkMessage::Pong).collect()), Magic::BITCOIN);
        assert!(matches!(peer.handshake(0), Err(PeerError::Handshake(m)) if m.contains("version")));
    }

    #[test]
    fn handshake_fails_on_wrong_magic_hangup_or_garbage() {
        let (mut peer, _) = mem_peer(
            vec![Chunk::Data(encode(Magic::REGTEST, their_version(70016)))],
            Magic::BITCOIN,
        );
        assert!(matches!(peer.handshake(0), Err(PeerError::WrongMagic { .. })));
        let (mut peer, _) = mem_peer(vec![], Magic::BITCOIN);
        assert!(peer.handshake(0).is_err());
        let (mut peer, _) = mem_peer(vec![Chunk::Data(vec![0xab; 64])], Magic::BITCOIN);
        assert!(peer.handshake(0).is_err());
    }

    #[test]
    fn connect_rejects_addresses_it_cannot_dial_directly() {
        // An onion or a hostname over direct TCP, or junk: an error before
        // any network I/O, never a panic.
        for addr in ["", "not an address", "example.com:8333", "abc.onion:8333", "1.2.3.4", "[::1]", "1.2.3.4:99999"] {
            assert!(
                matches!(Peer::connect(addr, 0, Magic::BITCOIN), Err(PeerError::Connection(_))),
                "{:?}",
                addr
            );
        }
    }

    // ── Inbound handshake ────────────────────────────────────────────

    pub(crate) fn inbound(script: Vec<Chunk>) -> (Result<Peer, PeerError>, Arc<Mutex<Vec<u8>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = PeerStream::Mem(MemStream { input: script.into(), written: written.clone() });
        (Peer::accept(stream, 5, Magic::BITCOIN), written)
    }

    #[test]
    fn accept_answers_with_version_sendaddrv2_verack_and_pongs_before_verack() {
        let (peer, written) = inbound(script_of(vec![
            their_version(70016),
            NetworkMessage::SendAddrV2,
            NetworkMessage::Ping(5),
            NetworkMessage::Verack,
        ]));
        let peer = peer.unwrap();
        assert!(peer.inbound && peer.wants_addrv2());
        let names: Vec<&str> = decode_all(&written.lock().unwrap()).iter().map(msg_name).collect();
        assert_eq!(names, ["version", "sendaddrv2", "verack", "pong"]);
    }

    #[test]
    fn accept_ids_are_per_connection_not_peer_chosen() {
        // Two connections sending the identical version (same nonce,
        // agent, height) still get distinct pool identities.
        let msgs = || script_of(vec![their_version(70016), NetworkMessage::Verack]);
        let a = inbound(msgs()).0.unwrap();
        let b = inbound(msgs()).0.unwrap();
        assert!(a.addr().starts_with("inbound#") && b.addr().starts_with("inbound#"));
        assert_ne!(a.addr(), b.addr());
    }

    #[test]
    fn accept_rejects_old_versions_missing_version_or_missing_verack() {
        assert!(matches!(
            inbound(script_of(vec![their_version(70001), NetworkMessage::Verack])).0,
            Err(PeerError::Handshake(_))
        ));
        assert!(matches!(
            inbound(script_of((0..12).map(NetworkMessage::Ping).collect())).0,
            Err(PeerError::Handshake(m)) if m.contains("version")
        ));
        let mut msgs = vec![their_version(70016)];
        msgs.extend((0..12).map(NetworkMessage::Pong));
        assert!(matches!(inbound(script_of(msgs)).0, Err(PeerError::Handshake(m)) if m.contains("verack")));
        assert!(inbound(vec![]).0.is_err());
    }

    // ── Exchange bounds ──────────────────────────────────────────────

    #[test]
    fn get_headers_gives_up_after_ten_unrelated_messages() {
        let mut msgs: Vec<NetworkMessage> = (0..10).map(|_| NetworkMessage::Verack).collect();
        msgs.push(NetworkMessage::Headers(vec![sample_header()]));
        let (mut peer, _) = mem_peer(script_of(msgs), Magic::BITCOIN);
        assert!(matches!(
            peer.get_headers(vec![], BlockHash::all_zeros()),
            Err(PeerError::Receive(m)) if m.contains("did not receive headers")
        ));
    }

    #[test]
    fn get_headers_answers_pings_and_returns_the_batch() {
        let (mut peer, written) = mem_peer(
            script_of(vec![
                NetworkMessage::Ping(11),
                NetworkMessage::Inv(vec![]),
                NetworkMessage::Headers(vec![sample_header(); 3]),
            ]),
            Magic::BITCOIN,
        );
        let locator = vec![BlockHash::from_byte_array([7; 32])];
        let headers = peer.get_headers(locator.clone(), BlockHash::all_zeros()).unwrap();
        assert_eq!(headers.len(), 3);
        let sent = decode_all(&written.lock().unwrap());
        match &sent[0] {
            NetworkMessage::GetHeaders(gh) => assert_eq!(gh.locator_hashes, locator),
            other => panic!("{}", msg_name(other)),
        }
        assert!(matches!(sent[1], NetworkMessage::Pong(11)));
    }

    #[test]
    fn get_headers_passes_oversized_batches_up_for_the_caller_to_punish() {
        // The wire layer doesn't cap the count (sync does: > 2000 is
        // misbehavior), but it must deliver the batch intact, not truncate.
        let (mut peer, _) =
            mem_peer(script_of(vec![NetworkMessage::Headers(vec![sample_header(); 2001])]), Magic::BITCOIN);
        assert_eq!(peer.get_headers(vec![], BlockHash::all_zeros()).unwrap().len(), 2001);
    }

    #[test]
    fn get_block_stall_is_block_not_received_and_wrong_magic_is_wrong_magic() {
        let hash = synthetic_block(1).block_hash();
        let (mut peer, _) = mem_peer(vec![Chunk::Stall], Magic::BITCOIN);
        assert!(matches!(peer.get_block(hash), Err(PeerError::BlockNotReceived { .. })));
        let (mut peer, _) =
            mem_peer(vec![Chunk::Data(encode(Magic::REGTEST, NetworkMessage::Block(synthetic_block(1))))], Magic::BITCOIN);
        assert!(matches!(peer.get_block(hash), Err(PeerError::WrongMagic { .. })));
    }

    #[test]
    fn idle_wait_answers_pings_and_returns_ok_when_the_peer_hangs_up() {
        let (mut peer, written) =
            mem_peer(script_of(vec![NetworkMessage::Ping(3), NetworkMessage::Inv(vec![])]), Magic::BITCOIN);
        peer.idle_wait(Duration::from_millis(200)).unwrap();
        assert!(matches!(decode_all(&written.lock().unwrap())[..], [NetworkMessage::Pong(3)]));
    }

    #[test]
    fn poll_message_reports_idle_as_none_and_hangup_as_error() {
        let (mut peer, _) = mem_peer(vec![Chunk::Stall], Magic::BITCOIN);
        assert!(matches!(peer.poll_message(Duration::from_millis(10)), Ok(None)));
        assert!(peer.poll_message(Duration::from_millis(10)).is_err());
    }

    /// Reviewer finding: `poll_message` (100 ms per read in the monitor
    /// loop) gives up on a message whose bytes straddle the timeout, but
    /// the bytes already read are gone: the next read starts mid-frame and
    /// fails as wrong magic, and the peer is dropped. Over Tor a message
    /// split across cells routinely arrives like this.
    #[test]
    fn poll_message_keeps_framing_when_a_message_straddles_the_timeout() {
        let ping = encode(Magic::BITCOIN, NetworkMessage::Ping(77));
        for split in [10, 24, 26] {
            let (mut peer, _) = mem_peer(
                vec![
                    Chunk::Data(ping[..split].to_vec()),
                    Chunk::Stall,
                    Chunk::Data(ping[split..].to_vec()),
                ],
                Magic::BITCOIN,
            );
            let mut got = None;
            for _ in 0..3 {
                match peer.poll_message(Duration::from_millis(10)) {
                    Ok(Some(m)) => {
                        got = Some(m);
                        break;
                    }
                    Ok(None) => continue,
                    Err(e) => panic!("split at {}: peer dropped: {}", split, e),
                }
            }
            assert!(
                matches!(got, Some(NetworkMessage::Ping(77))),
                "split at {}: {:?}",
                split,
                got.map(|m| msg_name(&m))
            );
        }
    }

    // ── Write side ───────────────────────────────────────────────────

    #[test]
    fn send_after_the_peer_hangs_up_is_an_error_not_a_crash() {
        let (mut peer, server) = loopback_peer_pair();
        drop(server);
        // The first writes may land in the socket buffer; within a few the
        // reset surfaces as an error (EPIPE, not SIGPIPE).
        let failed = (0..50).any(|_| {
            std::thread::sleep(Duration::from_millis(5));
            peer.send(NetworkMessage::Ping(1)).is_err()
        });
        assert!(failed, "send to a closed socket never failed");
    }

    /// Reviewer finding: sockets have a read timeout but no write timeout,
    /// so a peer that requests data and never reads blocks `send` (and the
    /// thread running it, e.g. the sync loop serving `getdata`) forever.
    #[test]
    fn send_to_a_peer_that_never_reads_is_bounded() {
        let (mut peer, server) = loopback_peer_pair();
        let mut big = synthetic_block(1);
        // ~1 MB of padding in the coinbase output script.
        big.txdata[0].output[0].script_pubkey = bitcoin::ScriptBuf::from_bytes(vec![0x51; 1_000_000]);
        let sender = std::thread::spawn(move || {
            for _ in 0..64 {
                if peer.send_block(big.clone()).is_err() {
                    return;
                }
            }
        });
        let start = Instant::now();
        while !sender.is_finished() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let finished = sender.is_finished();
        drop(server);
        assert!(finished, "send still blocked after {:?} on a peer that never reads", start.elapsed());
    }

    /// Reviewer finding: `Peer::accept` (run on the sync thread for each
    /// inbound Tor connection) only has the per-read timeout, so an inbound
    /// peer dribbling its version one byte at a time, each inside the
    /// timeout, holds the handshake (and the sync loop) for as long as it
    /// likes: ~2 hours at one byte per 59 s against Tor's 60 s.
    #[test]
    fn accept_bounds_a_trickling_handshake() {
        let listener = TcpListener::bind(crate::testkit::loopback_bind()).unwrap();
        let addr = listener.local_addr().unwrap();
        let bytes = encode(Magic::BITCOIN, their_version(70016));
        let dripper = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            for b in bytes {
                if s.write_all(&[b]).is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let (server, _) = listener.accept().unwrap();
        server.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let start = Instant::now();
        let _ = Peer::accept(PeerStream::Direct(server), 0, Magic::BITCOIN);
        let took = start.elapsed();
        dripper.join().unwrap();
        assert!(took < Duration::from_secs(3), "accept held for {:?} by a trickling peer", took);
    }

    // ── Deadlines (ticket 049) ───────────────────────────────────────

    /// A listener whose one connection gets `bytes` written `every` apart
    /// (one write per chunk), then is held open until the test ends.
    fn dripping_listener(chunks: Vec<Vec<u8>>, every: Duration) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind(crate::testkit::loopback_bind()).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            for chunk in chunks {
                if s.write_all(&chunk).is_err() {
                    return;
                }
                std::thread::sleep(every);
            }
            // Hold the connection until the peer hangs up.
            let _ = s.read(&mut [0u8; 1]);
        });
        (addr, handle)
    }

    #[test]
    fn connect_bounds_a_trickling_handshake() {
        // A wake's connect deadline stops new attempts, not one under way:
        // the handshake must end by itself.
        let bytes = encode(Magic::BITCOIN, their_version(70016));
        let (addr, dripper) = dripping_listener(bytes.chunks(1).map(<[u8]>::to_vec).collect(), Duration::from_millis(100));
        let start = Instant::now();
        let result = Peer::connect(&addr, 0, Magic::BITCOIN);
        let took = start.elapsed();
        assert!(matches!(&result, Err(PeerError::Handshake(m)) if m.contains("no handshake")), "{:?}", result.err());
        assert!(took >= HANDSHAKE_TIMEOUT && took < HANDSHAKE_TIMEOUT + Duration::from_secs(3), "took {:?}", took);
        drop(result);
        dripper.join().unwrap();
    }

    #[test]
    fn get_headers_without_a_limit_ends_at_its_own_deadline_as_the_peers_timeout() {
        // The main loop's requests have no wake budget, but still end: a
        // silent peer gets `Timeout` (its fault), not `DeadlineReached`.
        let (mut peer, _server) = loopback_peer_pair();
        let start = Instant::now();
        let result = peer.get_headers(vec![], BlockHash::all_zeros());
        assert!(matches!(result, Err(PeerError::Timeout)), "{:?}", result.map(|h| h.len()));
        assert!(start.elapsed() < READ_TIMEOUT + Duration::from_secs(2), "{:?}", start.elapsed());
        // A budget shorter than the request timeout is the budget's.
        let result = peer.get_headers_within(vec![], BlockHash::all_zeros(), Some(Duration::from_millis(100)));
        assert!(matches!(result, Err(PeerError::DeadlineReached)));
    }

    #[test]
    fn a_message_split_by_a_pause_is_delivered_and_the_peer_kept() {
        // Header, a pause longer than the 100 ms poll, then the payload:
        // the monitor loop's polls see nothing until it is whole.
        let ping = encode(Magic::BITCOIN, NetworkMessage::Ping(9));
        let (mut peer, mut server) = loopback_peer_pair();
        let writer = std::thread::spawn(move || {
            server.write_all(&ping[..24]).unwrap();
            std::thread::sleep(Duration::from_millis(150));
            server.write_all(&ping[24..]).unwrap();
            server
        });
        let start = Instant::now();
        let got = loop {
            match peer.poll_message(Duration::from_millis(100)) {
                Ok(Some(m)) => break m,
                Ok(None) => assert!(start.elapsed() < Duration::from_secs(5), "never delivered"),
                Err(e) => panic!("peer dropped: {}", e),
            }
        };
        assert!(matches!(got, NetworkMessage::Ping(9)));
        let _server = writer.join().unwrap();
    }

    #[test]
    fn a_message_trickling_below_the_minimum_rate_drops_the_peer() {
        // A frame header claiming 1000 payload bytes, then a byte every
        // 100 ms: each poll returns nothing (never an error, never a
        // blocked loop) until the message is past its allowance.
        let mut frame_bytes = frame(Magic::BITCOIN, b"hercjunk", &[0u8; 1000], None);
        frame_bytes.truncate(600);
        let mut chunks = vec![frame_bytes[..24].to_vec()];
        chunks.extend(frame_bytes[24..].chunks(1).map(<[u8]>::to_vec));
        let (addr, dripper) = dripping_listener(chunks, Duration::from_millis(100));
        let stream = TcpStream::connect(&addr).unwrap();
        let mut peer = Peer::new(PeerStream::Direct(stream), addr, Magic::BITCOIN, false);
        let allowance = peer.message_allowance(1000);
        let start = Instant::now();
        let err = loop {
            let poll = Instant::now();
            match peer.poll_message(Duration::from_millis(100)) {
                Ok(Some(m)) => panic!("{} delivered", msg_name(&m)),
                Ok(None) => {
                    assert!(poll.elapsed() < Duration::from_secs(1), "a poll blocked for {:?}", poll.elapsed());
                    assert!(start.elapsed() < allowance + Duration::from_secs(3), "never dropped");
                }
                Err(e) => break e,
            }
        };
        assert!(matches!(&err, PeerError::Receive(m) if m.contains("too slow")), "{}", err);
        assert!(start.elapsed() >= allowance - Duration::from_millis(200), "dropped early: {:?}", start.elapsed());
        drop(peer);
        dripper.join().unwrap();
    }

    #[test]
    fn inbound_handshakes_finish_off_thread_within_a_bounded_number_of_slots() {
        let hs = Arc::new(InboundHandshakes::new(Magic::BITCOIN));
        hs.set_our_height(77);
        for _ in 0..MAX_INBOUND_HANDSHAKES {
            assert!(hs.try_begin());
        }
        assert!(!hs.try_begin(), "more handshakes than slots");
        hs.abandon();
        assert_eq!(hs.in_flight(), MAX_INBOUND_HANDSHAKES - 1);
        for _ in 0..MAX_INBOUND_HANDSHAKES - 1 {
            hs.abandon();
        }

        // A good handshake comes out as a peer that has had our height; a
        // bad one doesn't; either way the slot is given back.
        let good = PeerStream::Mem(MemStream {
            input: script_of(vec![their_version(70016), NetworkMessage::Verack]).into(),
            written: Arc::new(Mutex::new(Vec::new())),
        });
        let written = match &good {
            PeerStream::Mem(m) => m.written.clone(),
            _ => unreachable!(),
        };
        let bad = PeerStream::Mem(MemStream { input: script_of(vec![their_version(1)]).into(), written: Arc::default() });
        let threads: Vec<_> = [good, bad]
            .into_iter()
            .map(|stream| {
                assert!(hs.try_begin());
                let hs = Arc::clone(&hs);
                std::thread::spawn(move || hs.run(stream))
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let peer = hs.next_peer().expect("finished peer");
        assert!(peer.inbound && peer.addr().starts_with("inbound#"));
        assert!(hs.next_peer().is_none(), "the failed handshake produced a peer");
        assert_eq!(hs.in_flight(), 0);
        let sent = decode_all(&written.lock().unwrap());
        match &sent[0] {
            NetworkMessage::Version(v) => assert_eq!(v.start_height, 77),
            other => panic!("{}", msg_name(other)),
        }
    }

    // ── Keep-alive (ticket 052) ──────────────────────────────────────

    /// A ping once the interval has passed; the matching pong (read by any
    /// receive path) clears it; one left unanswered past the timeout fails
    /// the peer. A pong with the wrong nonce doesn't count.
    #[test]
    fn keep_alive_pings_and_times_out_a_silent_peer() {
        let (mut peer, mut server) = loopback_peer_pair();
        let long = Duration::from_secs(3600);
        peer.keep_alive(long, long).unwrap();
        server.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut b = [0u8; 1];
        assert!(server.peek(&mut b).is_err(), "pinged before the interval");
        server.set_read_timeout(None).unwrap();

        peer.keep_alive(Duration::ZERO, long).unwrap();
        let NetworkMessage::Ping(nonce) = read_one_message(&mut server) else { panic!("no ping") };
        write_message(&mut server, NetworkMessage::Pong(nonce.wrapping_add(1)));
        assert!(matches!(peer.poll_message(Duration::from_secs(2)), Ok(Some(NetworkMessage::Pong(_)))));
        assert!(peer.keep_alive(Duration::ZERO, Duration::ZERO).is_err(), "wrong nonce accepted");

        let (mut peer, mut server) = loopback_peer_pair();
        peer.keep_alive(Duration::ZERO, long).unwrap();
        let NetworkMessage::Ping(nonce) = read_one_message(&mut server) else { panic!("no ping") };
        write_message(&mut server, NetworkMessage::Pong(nonce));
        assert!(matches!(peer.poll_message(Duration::from_secs(2)), Ok(Some(NetworkMessage::Pong(_)))));
        assert!(peer.idle_for() < Duration::from_secs(2));
        peer.keep_alive(long, Duration::ZERO).expect("answered: nothing outstanding");
    }

    // ── Seeds and names ──────────────────────────────────────────────

    /// Every bundled onion seed must be a dialable v3 address: 56 base32
    /// chars whose embedded checksum and version byte verify
    /// (rend-spec-v3 §6, the same check `tor_v3` applies to gossip).
    #[test]
    fn onion_seeds_are_valid_v3_addresses() {
        let invalid: Vec<&str> = ONION_SEEDS
            .iter()
            .copied()
            .filter(|seed| match seed.rsplit_once(':') {
                Some((host, "8333")) => crate::tor_v3::hostname_to_pubkey(host).is_none(),
                _ => true,
            })
            .collect();
        assert!(invalid.is_empty(), "{} of {} onion seeds invalid: {:?}", invalid.len(), ONION_SEEDS.len(), invalid);
    }

    #[test]
    fn dns_seeds_are_unique_bare_hostnames() {
        let mut seen = std::collections::HashSet::new();
        for seed in DNS_SEEDS {
            assert!(seen.insert(*seed), "duplicate {}", seed);
            assert!(!seed.contains(':') && seed.contains('.'), "{}", seed);
            assert!(
                seed.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'),
                "{}",
                seed
            );
        }
    }

    #[test]
    fn msg_name_names_every_message_we_send_or_handle() {
        let header = sample_header();
        for (msg, name) in [
            (their_version(70016), "version"),
            (NetworkMessage::Verack, "verack"),
            (NetworkMessage::Ping(1), "ping"),
            (NetworkMessage::Pong(1), "pong"),
            (NetworkMessage::SendHeaders, "sendheaders"),
            (NetworkMessage::Headers(vec![header]), "headers"),
            (NetworkMessage::Inv(vec![]), "inv"),
            (NetworkMessage::GetData(vec![]), "getdata"),
            (NetworkMessage::NotFound(vec![]), "notfound"),
            (NetworkMessage::Addr(vec![]), "addr"),
            (NetworkMessage::AddrV2(vec![]), "addrv2"),
            (NetworkMessage::FeeFilter(1), "feefilter"),
            (NetworkMessage::MemPool, "mempool"),
            (NetworkMessage::GetAddr, "getaddr"),
            (NetworkMessage::SendAddrV2, "sendaddrv2"),
            (NetworkMessage::WtxidRelay, "wtxidrelay"),
        ] {
            assert_eq!(msg_name(&msg), name);
            // And the wire command agrees.
            assert_eq!(msg.cmd(), name);
        }
    }

    // ── Property tests ───────────────────────────────────────────────

    pub(crate) fn arb_inventory() -> impl Strategy<Value = Inventory> {
        (0u8..5, any::<[u8; 32]>()).prop_map(|(k, h)| match k {
            0 => Inventory::Block(BlockHash::from_byte_array(h)),
            1 => Inventory::WitnessBlock(BlockHash::from_byte_array(h)),
            2 => Inventory::Transaction(bitcoin::Txid::from_byte_array(h)),
            3 => Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(h)),
            _ => Inventory::WTx(bitcoin::Wtxid::from_byte_array(h)),
        })
    }

    pub(crate) fn arb_header() -> impl Strategy<Value = BlockHeader> {
        (any::<i32>(), any::<[u8; 32]>(), any::<[u8; 32]>(), any::<u32>(), any::<u32>(), any::<u32>()).prop_map(
            |(v, prev, root, time, bits, nonce)| BlockHeader {
                version: bitcoin::block::Version::from_consensus(v),
                prev_blockhash: BlockHash::from_byte_array(prev),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
                time,
                bits: bitcoin::CompactTarget::from_consensus(bits),
                nonce,
            },
        )
    }

    /// Messages Hercules sends or parses, with arbitrary contents.
    pub(crate) fn arb_message() -> impl Strategy<Value = NetworkMessage> {
        prop_oneof![
            any::<u64>().prop_map(NetworkMessage::Ping),
            any::<u64>().prop_map(NetworkMessage::Pong),
            any::<i64>().prop_map(NetworkMessage::FeeFilter),
            prop::collection::vec(arb_inventory(), 0..60).prop_map(NetworkMessage::Inv),
            prop::collection::vec(arb_inventory(), 0..60).prop_map(NetworkMessage::GetData),
            prop::collection::vec(arb_inventory(), 0..60).prop_map(NetworkMessage::NotFound),
            prop::collection::vec(arb_header(), 0..40).prop_map(NetworkMessage::Headers),
            (prop::collection::vec(any::<[u8; 32]>(), 0..40), any::<[u8; 32]>()).prop_map(|(loc, stop)| {
                NetworkMessage::GetHeaders(GetHeadersMessage {
                    version: PROTOCOL_VERSION,
                    locator_hashes: loc.into_iter().map(BlockHash::from_byte_array).collect(),
                    stop_hash: BlockHash::from_byte_array(stop),
                })
            }),
            prop::collection::vec((any::<u32>(), any::<[u8; 16]>(), any::<u16>()), 0..30).prop_map(|v| {
                NetworkMessage::Addr(
                    v.into_iter()
                        .map(|(t, ip, port)| {
                            let sa = SocketAddr::from((std::net::Ipv6Addr::from(ip), port));
                            (t, Address::new(&sa, ServiceFlags::NETWORK))
                        })
                        .collect(),
                )
            }),
            // No `Unknown`: we never send one, and rust-bitcoin encodes its
            // payload with a length prefix that decoding keeps (asymmetric).
            Just(NetworkMessage::Verack),
            Just(NetworkMessage::SendAddrV2),
            Just(NetworkMessage::WtxidRelay),
            Just(NetworkMessage::SendHeaders),
            Just(NetworkMessage::GetAddr),
            Just(NetworkMessage::MemPool),
        ]
    }

    proptest! {
        /// Whatever we send, a peer reading our bytes gets back exactly.
        #[test]
        fn prop_sent_messages_round_trip_through_receive(msgs in prop::collection::vec(arb_message(), 1..6)) {
            let (mut sender, written) = mem_peer(vec![], Magic::BITCOIN);
            for m in &msgs {
                sender.send(m.clone()).unwrap();
            }
            let bytes = written.lock().unwrap().clone();
            // Delivered in 7-byte pieces, so reads return less than asked.
            let script = bytes.chunks(7).map(|c| Chunk::Data(c.to_vec())).collect();
            let (mut receiver, _) = mem_peer(script, Magic::BITCOIN);
            for m in &msgs {
                prop_assert_eq!(&receiver.receive().unwrap(), m);
            }
            prop_assert!(receiver.receive().is_err(), "trailing bytes");
        }

        /// Arbitrary bytes on the wire: errors, never a panic, never more
        /// messages than the bytes could hold.
        #[test]
        fn prop_receive_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
            let (mut peer, _) = mem_peer(vec![Chunk::Data(bytes.clone())], Magic::BITCOIN);
            let mut n = 0;
            while peer.receive().is_ok() {
                n += 1;
                prop_assert!(n * 24 <= bytes.len());
            }
        }

        /// Well-framed (right magic, right checksum) frames with arbitrary
        /// commands and payloads reach every message decoder.
        #[test]
        fn prop_receive_never_panics_on_framed_garbage(
            cmd in prop::sample::select(COMMANDS),
            payload in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            let script = vec![
                Chunk::Data(frame(Magic::BITCOIN, cmd.as_bytes(), &payload, None)),
                Chunk::Data(encode(Magic::BITCOIN, NetworkMessage::Ping(5))),
            ];
            let (mut peer, _) = mem_peer(script, Magic::BITCOIN);
            let _ = peer.receive();
            prop_assert!(matches!(peer.receive(), Ok(NetworkMessage::Ping(5))));
        }

        /// Any other network's magic is refused before the payload is read.
        #[test]
        fn prop_foreign_magic_is_always_refused(magic in any::<[u8; 4]>(), payload in prop::collection::vec(any::<u8>(), 0..64)) {
            prop_assume!(magic != Magic::BITCOIN.to_bytes());
            let mut f = frame(Magic::BITCOIN, b"ping", &payload, None);
            f[..4].copy_from_slice(&magic);
            let (mut peer, _) = mem_peer(vec![Chunk::Data(f[..24].to_vec())], Magic::BITCOIN);
            prop_assert!(matches!(peer.receive(), Err(PeerError::WrongMagic { .. })), "magic {:02x?} accepted", magic);
        }

        /// Any handshake script ends in success or an error, never a panic
        /// or a hang (each script is finite).
        #[test]
        fn prop_handshake_terminates_on_any_message_sequence(
            msgs in prop::collection::vec(prop_oneof![
                arb_message(),
                (60000u32..80000).prop_map(their_version),
            ], 0..14),
        ) {
            let (mut peer, _) = mem_peer(script_of(msgs.clone()), Magic::BITCOIN);
            let _ = peer.handshake(0);
            let _ = inbound(script_of(msgs)).0;
        }
    }
}
