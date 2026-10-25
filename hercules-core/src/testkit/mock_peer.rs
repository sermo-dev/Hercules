//! `MockPeer`: a scripted fake Bitcoin node on a loopback port (ticket 027).
//!
//! Each mock listens on `127.0.0.1:0` and speaks the real P2P wire protocol
//! (version/verack, `getheaders`→`headers`, `getdata`→`block`/`notfound`,
//! `ping`→`pong`). Hercules reaches it through the production
//! `Peer::connect` / `PeerStream::Direct` path, so everything above the
//! socket is the code that ships. By default a mock serves its
//! `FixtureChain` honestly; `Behavior`s make it misbehave on cue.
//!
//! Every message Hercules sends is recorded in `log()`, so tests can assert
//! on what was (or wasn't) requested.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::block::{Block, Header};
use bitcoin::consensus::{serialize, Decodable};
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::BlockHash;

use super::fixture_chain::FixtureChain;

/// How a mock deviates from honestly serving its chain.
#[derive(Clone, Debug)]
pub enum Behavior {
    /// Answer `getdata` for the block at this height with a different block
    /// (the ticket 022 substitution attack), then send nothing else.
    WrongBlockAt(u32, Block),
    /// Push this unrequested block before answering `getdata` for the block
    /// at this height (an announcement racing our request).
    UnsolicitedBlockBefore(u32, Block),
    /// Never answer `getdata` for the block at this height.
    WithholdBlock(u32),
    /// Serve the block at this height with its witnesses stripped: same hash,
    /// fails the witness commitment (ticket 024 "delivery" failure).
    ServeMutated(u32),
    /// Like `ServeMutated`, but strip the coinbase's witness reserved value
    /// too, so the block carries no witness data at all.
    ServeWitnessless(u32),
    /// Answer `getheaders` and `ping` with mainnet magic instead of regtest.
    WrongMagic,
    /// Sleep this long before every response after the handshake.
    DelayResponses(Duration),
    /// After the handshake, answer the first request with garbage bytes and
    /// hang up.
    SendGarbage,
    /// Hang up right after the handshake.
    Disconnect,
    /// Answer every `getheaders` with an empty `headers` message.
    WithholdHeaders,
}

/// The chain a mock serves, indexed by hash.
struct ChainView {
    blocks: Vec<Block>,
    index: HashMap<BlockHash, u32>,
}

impl ChainView {
    fn of(chain: &FixtureChain) -> ChainView {
        let blocks = chain.blocks().to_vec();
        let index = blocks
            .iter()
            .enumerate()
            .map(|(h, b)| (b.block_hash(), h as u32))
            .collect();
        ChainView { blocks, index }
    }

    fn tip_height(&self) -> u32 {
        (self.blocks.len() - 1) as u32
    }

    /// Core's `getheaders` semantics: start after the first locator hash we
    /// know (genesis if none), stop at `stop` or after 2000 headers.
    fn headers_after(&self, locator: &[BlockHash], stop: BlockHash) -> Vec<Header> {
        let start = locator
            .iter()
            .find_map(|h| self.index.get(h))
            .map(|h| h + 1)
            .unwrap_or(1) as usize;
        let mut out = Vec::new();
        for block in self.blocks.iter().skip(start).take(2000) {
            out.push(block.header);
            if block.block_hash() == stop {
                break;
            }
        }
        out
    }
}

struct Shared {
    magic: Magic,
    chain: Mutex<ChainView>,
    behaviors: Mutex<Vec<Behavior>>,
    log: Mutex<Vec<NetworkMessage>>,
    /// Write halves of live sessions, for `announce_tip` and shutdown.
    sessions: Mutex<Vec<Arc<Mutex<TcpStream>>>>,
    connections: AtomicUsize,
    shutdown: AtomicBool,
}

/// A running mock peer. Dropping it closes the listener and all sessions.
pub struct MockPeer {
    addr: SocketAddr,
    shared: Arc<Shared>,
}

impl MockPeer {
    /// Start serving `chain` (regtest magic) with the given behaviors.
    pub fn spawn(chain: &FixtureChain, behaviors: Vec<Behavior>) -> MockPeer {
        let listener = TcpListener::bind(super::loopback_bind_addr()).expect("bind mock peer");
        let addr = listener.local_addr().expect("mock peer addr");
        let shared = Arc::new(Shared {
            magic: FixtureChain::params().magic,
            chain: Mutex::new(ChainView::of(chain)),
            behaviors: Mutex::new(behaviors),
            log: Mutex::new(Vec::new()),
            sessions: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
        });
        let accept_shared = shared.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if accept_shared.shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                accept_shared.connections.fetch_add(1, Ordering::SeqCst);
                let session_shared = accept_shared.clone();
                std::thread::spawn(move || {
                    let _ = run_session(stream, &session_shared);
                });
            }
        });
        MockPeer { addr, shared }
    }

    /// `host:port` as Hercules' address book keys it.
    pub fn addr(&self) -> String {
        self.addr.to_string()
    }

    /// Serve a different chain from now on (e.g. a more-work fork).
    pub fn set_chain(&self, chain: &FixtureChain) {
        *self.shared.chain.lock().unwrap() = ChainView::of(chain);
    }

    pub fn set_behaviors(&self, behaviors: Vec<Behavior>) {
        *self.shared.behaviors.lock().unwrap() = behaviors;
    }

    /// Announce the current tip with an `inv` on every live session.
    pub fn announce_tip(&self) {
        let tip = {
            let chain = self.shared.chain.lock().unwrap();
            chain.blocks.last().unwrap().block_hash()
        };
        let sessions = self.shared.sessions.lock().unwrap().clone();
        for w in sessions {
            let _ = send(&w, self.shared.magic, NetworkMessage::Inv(vec![Inventory::Block(tip)]));
        }
    }

    /// Every message received from Hercules, across all sessions, in order.
    pub fn log(&self) -> Vec<NetworkMessage> {
        self.shared.log.lock().unwrap().clone()
    }

    /// Block hashes Hercules asked for via `getdata`.
    pub fn block_requests(&self) -> Vec<BlockHash> {
        self.log()
            .iter()
            .filter_map(|m| match m {
                NetworkMessage::GetData(inv) => Some(inv.clone()),
                _ => None,
            })
            .flatten()
            .filter_map(|i| match i {
                Inventory::Block(h) | Inventory::WitnessBlock(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    /// Number of TCP connections accepted so far.
    pub fn connections(&self) -> usize {
        self.shared.connections.load(Ordering::SeqCst)
    }
}

impl Drop for MockPeer {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        for w in self.shared.sessions.lock().unwrap().drain(..) {
            let _ = w.lock().unwrap().shutdown(Shutdown::Both);
        }
        // Unblock the accept loop so its thread exits.
        let _ = TcpStream::connect(self.addr);
    }
}

// ── Session ──────────────────────────────────────────────────────────

fn run_session(stream: TcpStream, shared: &Shared) -> io::Result<()> {
    let mut reader = stream.try_clone()?;
    let writer = Arc::new(Mutex::new(stream));
    shared.sessions.lock().unwrap().push(writer.clone());
    let magic = shared.magic;

    // Handshake: wait for their version, answer with ours + verack.
    loop {
        let msg = recv(&mut reader, shared)?;
        if let NetworkMessage::Version(_) = msg {
            break;
        }
    }
    let start_height = shared.chain.lock().unwrap().tip_height() as i32;
    send(&writer, magic, NetworkMessage::Version(version_message(start_height)))?;
    send(&writer, magic, NetworkMessage::Verack)?;

    let behaviors = shared.behaviors.lock().unwrap().clone();
    if behaviors.iter().any(|b| matches!(b, Behavior::Disconnect)) {
        let _ = writer.lock().unwrap().shutdown(Shutdown::Both);
        return Ok(());
    }

    loop {
        let msg = recv(&mut reader, shared)?;
        if shared.shutdown.load(Ordering::SeqCst) {
            return Ok(());
        }
        let behaviors = shared.behaviors.lock().unwrap().clone();
        let is_request = matches!(
            msg,
            NetworkMessage::GetHeaders(_) | NetworkMessage::GetData(_) | NetworkMessage::Ping(_)
        );
        if !is_request {
            continue;
        }
        for b in &behaviors {
            if let Behavior::DelayResponses(d) = b {
                std::thread::sleep(*d);
            }
        }
        if behaviors.iter().any(|b| matches!(b, Behavior::SendGarbage)) {
            let mut w = writer.lock().unwrap();
            let _ = w.write_all(&[0xab; 64]);
            let _ = w.shutdown(Shutdown::Both);
            return Ok(());
        }

        let magic = if behaviors.iter().any(|b| matches!(b, Behavior::WrongMagic)) {
            Magic::BITCOIN
        } else {
            magic
        };
        match msg {
            NetworkMessage::Ping(nonce) => send(&writer, magic, NetworkMessage::Pong(nonce))?,
            NetworkMessage::GetHeaders(gh) => {
                let headers = if behaviors.iter().any(|b| matches!(b, Behavior::WithholdHeaders)) {
                    Vec::new()
                } else {
                    shared
                        .chain
                        .lock()
                        .unwrap()
                        .headers_after(&gh.locator_hashes, gh.stop_hash)
                };
                send(&writer, magic, NetworkMessage::Headers(headers))?;
            }
            NetworkMessage::GetData(items) => {
                for item in items {
                    serve_item(&writer, shared, &behaviors, item)?;
                }
            }
            _ => {}
        }
    }
}

fn serve_item(
    writer: &Arc<Mutex<TcpStream>>,
    shared: &Shared,
    behaviors: &[Behavior],
    item: Inventory,
) -> io::Result<()> {
    let magic = shared.magic;
    let hash = match item {
        Inventory::Block(h) | Inventory::WitnessBlock(h) => h,
        other => return send(writer, magic, NetworkMessage::NotFound(vec![other])),
    };
    let found = {
        let chain = shared.chain.lock().unwrap();
        chain
            .index
            .get(&hash)
            .map(|h| (*h, chain.blocks[*h as usize].clone()))
    };
    let Some((height, block)) = found else {
        return send(writer, magic, NetworkMessage::NotFound(vec![item]));
    };

    let mut reply = block;
    for b in behaviors {
        match b {
            Behavior::WithholdBlock(h) if *h == height => return Ok(()),
            Behavior::WrongBlockAt(h, other) if *h == height => {
                return send(writer, magic, NetworkMessage::Block(other.clone()));
            }
            Behavior::UnsolicitedBlockBefore(h, other) if *h == height => {
                send(writer, magic, NetworkMessage::Block(other.clone()))?;
            }
            Behavior::ServeMutated(h) if *h == height => {
                reply = FixtureChain::strip_witness(&reply);
            }
            Behavior::ServeWitnessless(h) if *h == height => {
                reply = FixtureChain::strip_all_witness(&reply);
            }
            _ => {}
        }
    }
    send(writer, magic, NetworkMessage::Block(reply))
}

fn version_message(start_height: i32) -> VersionMessage {
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    VersionMessage {
        version: 70016,
        services,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        receiver: Address::new(&SocketAddr::from(([0, 0, 0, 0], 0)), ServiceFlags::NONE),
        sender: Address::new(&SocketAddr::from(([0, 0, 0, 0], 0)), services),
        nonce: 0x0027_0027,
        user_agent: "/HerculesMockPeer:0.27/".to_string(),
        start_height,
        relay: true,
    }
}

// ── Wire codec (non-panicking: Hercules may hang up at any time) ─────

fn send(writer: &Arc<Mutex<TcpStream>>, magic: Magic, msg: NetworkMessage) -> io::Result<()> {
    let bytes = serialize(&RawNetworkMessage::new(magic, msg));
    let mut w = writer.lock().unwrap();
    w.write_all(&bytes)?;
    w.flush()
}

fn recv(reader: &mut TcpStream, shared: &Shared) -> io::Result<NetworkMessage> {
    let mut header = [0u8; 24];
    reader.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    if len > 4_000_000 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "oversized payload"));
    }
    let mut buf = header.to_vec();
    buf.resize(24 + len, 0);
    reader.read_exact(&mut buf[24..])?;
    let raw = RawNetworkMessage::consensus_decode(&mut buf.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let msg = raw.payload().clone();
    shared.log.lock().unwrap().push(msg.clone());
    Ok(msg)
}
