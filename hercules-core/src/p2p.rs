use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

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
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeouts used when connecting through Tor (higher latency).
const TOR_READ_TIMEOUT: Duration = Duration::from_secs(60);
const TOR_BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum P2P message payload size (4 MB, matches Bitcoin Core's MAX_SIZE).
/// Prevents OOM from malicious peers sending crafted headers claiming huge payloads.
const MAX_P2P_PAYLOAD: u32 = 4_000_000;

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

/// Well-known Bitcoin v3 .onion seed nodes.
/// These are 56-character base32-encoded v3 onion addresses.
/// TODO: verify these against Bitcoin Core's current seed list.
const ONION_SEEDS: &[&str] = &[
    "bsqbtcparrfihlwolt4xgjbf4cgqckvrvsfyvy6etgfnhongzoqxziad.onion:8333",
    "bnpczgbhoyoeg5nai4e4aw2kkxbda47gx2jrlansi6xxne5jrwxfauad.onion:8333",
    "wizbit5555bsslwv4cqlcc7zsahelqeyaa5kauwcy2b4fhbzab5pwdqd.onion:8333",
    "2dayzh7uruqtfflmhlt3r2pj2xygkdmcpbezfbml4nbnwrae7zn6eqd.onion:8333",
];

// ── PeerStream ────────────────────────────────────────────────────────

/// Abstraction over TCP and Tor streams for Bitcoin P2P connections.
pub enum PeerStream {
    Direct(TcpStream),
    Tor(TorStream),
}

impl PeerStream {
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            PeerStream::Direct(tcp) => tcp.set_read_timeout(timeout),
            PeerStream::Tor(tor) => {
                tor.set_read_timeout(timeout);
                Ok(())
            }
        }
    }
}

impl Read for PeerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            PeerStream::Direct(tcp) => tcp.read(buf),
            PeerStream::Tor(tor) => tor.read(buf),
        }
    }
}

impl Write for PeerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            PeerStream::Direct(tcp) => tcp.write(buf),
            PeerStream::Tor(tor) => tor.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            PeerStream::Direct(tcp) => tcp.flush(),
            PeerStream::Tor(tor) => tor.flush(),
        }
    }
}

// ── Peer ──────────────────────────────────────────────────────────────

/// A connection to a single Bitcoin peer.
pub struct Peer {
    stream: PeerStream,
    addr: String,
    their_version: Option<VersionMessage>,
    /// True if this peer connected to us (inbound), false if we connected to them.
    pub inbound: bool,
}

impl Peer {
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
    pub fn connect(addr: &str, our_height: i32) -> Result<Peer, PeerError> {
        info!("Connecting to peer {}", addr);

        let sock_addr: SocketAddr = addr
            .parse()
            .map_err(|e| PeerError::Connection(format!("invalid address {}: {}", addr, e)))?;

        let stream = TcpStream::connect_timeout(&sock_addr, CONNECT_TIMEOUT)
            .map_err(|e| PeerError::Connection(format!("{}: {}", addr, e)))?;

        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))?;

        let mut peer = Peer {
            stream: PeerStream::Direct(stream),
            addr: addr.to_string(),
            their_version: None,
            inbound: false,
        };

        peer.handshake(our_height)?;
        info!("Handshake complete with {}", addr);
        Ok(peer)
    }

    /// Connect to a peer through Tor and complete the version handshake.
    /// The address can be an IP:port, hostname:port, or .onion:port.
    pub fn connect_tor(tor: &TorManager, addr: &str, our_height: i32) -> Result<Peer, PeerError> {
        info!("Connecting to peer {} via Tor", addr);

        let tor_stream = tor
            .connect(addr)
            .map_err(|e| PeerError::Connection(format!("{}: {}", addr, e)))?;

        let mut peer = Peer {
            stream: PeerStream::Tor(tor_stream),
            addr: addr.to_string(),
            their_version: None,
            inbound: false,
        };

        peer.handshake(our_height)?;
        info!("Handshake complete with {} via Tor", addr);
        Ok(peer)
    }

    /// Accept an inbound connection: run the version handshake as responder.
    /// (Wait for their version first, then send ours + verack.)
    pub fn accept(stream: PeerStream, our_height: i32) -> Result<Peer, PeerError> {
        let mut peer = Peer {
            stream,
            addr: String::new(), // filled after receiving their version
            their_version: None,
            inbound: true,
        };

        // Receive their version first
        let mut got_version = false;
        for _ in 0..10 {
            let msg = peer.receive()?;
            match msg {
                NetworkMessage::Version(v) => {
                    if v.version < 70015 {
                        return Err(PeerError::Handshake(format!(
                            "inbound peer version {} too old (min 70015)", v.version
                        )));
                    }
                    peer.addr = format!("inbound-{}", v.nonce);
                    peer.their_version = Some(v);
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
        peer.send(NetworkMessage::Version(our_version))?;
        peer.send(NetworkMessage::Verack)?;

        // Wait for their verack
        let mut got_verack = false;
        for _ in 0..10 {
            let msg = peer.receive()?;
            match msg {
                NetworkMessage::Verack => {
                    got_verack = true;
                    break;
                }
                NetworkMessage::Ping(nonce) => {
                    peer.send(NetworkMessage::Pong(nonce))?;
                }
                _ => {}
            }
        }

        if !got_verack {
            return Err(PeerError::Handshake("inbound peer did not send verack".into()));
        }

        let user_agent = peer.peer_user_agent().unwrap_or_default();
        info!("Accepted inbound peer: {} ({})", peer.addr, user_agent);
        Ok(peer)
    }

    /// Perform the version/verack handshake (outbound/initiator mode).
    fn handshake(&mut self, our_height: i32) -> Result<(), PeerError> {
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

        // Receive their version and verack (order can vary)
        let mut got_version = false;
        let mut got_verack = false;

        for _ in 0..10 {
            let msg = self.receive()?;
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

    /// Send a Bitcoin P2P message.
    pub fn send(&mut self, msg: NetworkMessage) -> Result<(), PeerError> {
        let raw = RawNetworkMessage::new(Magic::BITCOIN, msg);
        // bitcoin's consensus_encode requires bitcoin::io::Write, not std::io::Write.
        // We match on the variant to get the concrete type which bitcoin_io knows about.
        match &mut self.stream {
            PeerStream::Direct(tcp) => {
                raw.consensus_encode(tcp)
                    .map_err(|e| PeerError::Send(format!("{}", e)))?;
                tcp.flush()
                    .map_err(|e| PeerError::Send(format!("flush: {}", e)))?;
            }
            PeerStream::Tor(tor) => {
                raw.consensus_encode(&mut bitcoin::io::FromStd::new(&mut *tor))
                    .map_err(|e| PeerError::Send(format!("{}", e)))?;
                tor.flush()
                    .map_err(|e| PeerError::Send(format!("flush: {}", e)))?;
            }
        }
        Ok(())
    }

    /// Receive a Bitcoin P2P message.
    ///
    /// Reads the 24-byte P2P header first to validate payload size before
    /// allocation, preventing OOM from crafted headers (MAX_SIZE = 4 MB,
    /// matching Bitcoin Core). Returns `PeerError::Timeout` on read timeout
    /// for reliable detection by `poll_message()`.
    pub fn receive(&mut self) -> Result<NetworkMessage, PeerError> {
        // Read the 24-byte P2P message header
        let mut header = [0u8; 24];
        self.stream.read_exact(&mut header).map_err(|e| {
            if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
                PeerError::Timeout
            } else {
                PeerError::Receive(format!("{}", e))
            }
        })?;

        // Payload length is at bytes 16..20 (little-endian u32)
        let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap());
        if payload_len > MAX_P2P_PAYLOAD {
            return Err(PeerError::Receive(format!(
                "message payload {} bytes exceeds limit {}",
                payload_len, MAX_P2P_PAYLOAD
            )));
        }

        // Read the payload
        let mut payload = vec![0u8; payload_len as usize];
        if payload_len > 0 {
            self.stream.read_exact(&mut payload).map_err(|e| {
                if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
                    PeerError::Timeout
                } else {
                    PeerError::Receive(format!("{}", e))
                }
            })?;
        }

        // Decode from the complete message buffer
        let mut buf = Vec::with_capacity(24 + payload_len as usize);
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&payload);

        let mut slice = buf.as_slice();
        let raw = RawNetworkMessage::consensus_decode(&mut slice)
            .map_err(|e| PeerError::Receive(format!("{}", e)))?;
        Ok(raw.payload().clone())
    }

    /// Request block headers starting from the given locator hashes.
    /// Returns the headers received from the peer.
    pub fn get_headers(
        &mut self,
        locator_hashes: Vec<BlockHash>,
        stop_hash: BlockHash,
    ) -> Result<Vec<bitcoin::block::Header>, PeerError> {
        let get_headers = GetHeadersMessage {
            version: PROTOCOL_VERSION,
            locator_hashes,
            stop_hash,
        };

        self.send(NetworkMessage::GetHeaders(get_headers))?;

        // Read messages until we get Headers
        for _ in 0..10 {
            let msg = self.receive()?;
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
        // Use longer timeout for block downloads (blocks can be up to ~4MB)
        let download_timeout = match &self.stream {
            PeerStream::Direct(_) => BLOCK_DOWNLOAD_TIMEOUT,
            PeerStream::Tor(_) => TOR_BLOCK_DOWNLOAD_TIMEOUT,
        };
        let normal_timeout = match &self.stream {
            PeerStream::Direct(_) => READ_TIMEOUT,
            PeerStream::Tor(_) => TOR_READ_TIMEOUT,
        };

        self.stream
            .set_read_timeout(Some(download_timeout))
            .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))?;

        let inv = vec![Inventory::WitnessBlock(block_hash)];
        self.send(NetworkMessage::GetData(inv))?;

        let result = self.receive_block();

        // Restore normal read timeout
        self.stream
            .set_read_timeout(Some(normal_timeout))
            .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))?;

        result
    }

    /// Read messages until we receive a Block response.
    fn receive_block(&mut self) -> Result<Block, PeerError> {
        for _ in 0..20 {
            let msg = self.receive()?;
            match msg {
                NetworkMessage::Block(block) => return Ok(block),
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

        Err(PeerError::Receive(
            "did not receive block response".into(),
        ))
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

    /// Poll for a single incoming message with the given timeout.
    /// Returns `Ok(Some(msg))` if a message was received, `Ok(None)` on timeout,
    /// or `Err` on connection failure. Unlike `idle_wait`, this returns the
    /// message to the caller for dispatch rather than handling it internally.
    pub fn poll_message(&mut self, timeout: Duration) -> Result<Option<NetworkMessage>, PeerError> {
        let normal_timeout = match &self.stream {
            PeerStream::Direct(_) => READ_TIMEOUT,
            PeerStream::Tor(_) => TOR_READ_TIMEOUT,
        };

        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))?;

        let result = self.receive();

        // Restore normal timeout
        let _ = self.stream.set_read_timeout(Some(normal_timeout));

        match result {
            Ok(msg) => Ok(Some(msg)),
            Err(PeerError::Timeout) => Ok(None), // no message available
            Err(e) => Err(e),
        }
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

    /// Wait for a duration while responding to pings to keep the connection alive.
    /// Returns Ok on timeout (normal), Err if the peer disconnects.
    pub fn idle_wait(&mut self, duration: std::time::Duration) -> Result<(), PeerError> {
        let start = std::time::Instant::now();
        let normal_timeout = match &self.stream {
            PeerStream::Direct(_) => READ_TIMEOUT,
            PeerStream::Tor(_) => TOR_READ_TIMEOUT,
        };

        while start.elapsed() < duration {
            let remaining = duration.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))?;

            match self.receive() {
                Ok(NetworkMessage::Ping(nonce)) => {
                    self.send(NetworkMessage::Pong(nonce))?;
                }
                Ok(_) => {} // ignore other messages during idle
                Err(_) => break, // timeout or disconnect
            }
        }

        // Restore standard read timeout
        self.stream
            .set_read_timeout(Some(normal_timeout))
            .map_err(|e| PeerError::Connection(format!("set timeout: {}", e)))?;

        Ok(())
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
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Connection(s) => write!(f, "connection error: {}", s),
            PeerError::Handshake(s) => write!(f, "handshake error: {}", s),
            PeerError::Send(s) => write!(f, "send error: {}", s),
            PeerError::Receive(s) => write!(f, "receive error: {}", s),
            PeerError::Timeout => write!(f, "read timed out"),
        }
    }
}

impl std::error::Error for PeerError {}

fn rand_nonce() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    RandomState::new().build_hasher().finish()
}
