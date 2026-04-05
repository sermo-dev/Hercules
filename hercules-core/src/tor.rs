use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tor_rtcompat::PreferredRuntime;

/// Timeout for Tor bootstrap (first connection to the Tor network).
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout for individual Tor connections to peers.
const TOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default read timeout for Tor streams.
const TOR_READ_TIMEOUT: Duration = Duration::from_secs(60);

// ── TorError ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum TorError {
    Bootstrap(String),
    Connection(String),
    Resolve(String),
    OnionService(String),
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorError::Bootstrap(s) => write!(f, "Tor bootstrap error: {}", s),
            TorError::Connection(s) => write!(f, "Tor connection error: {}", s),
            TorError::Resolve(s) => write!(f, "Tor DNS resolve error: {}", s),
            TorError::OnionService(s) => write!(f, "Tor onion service error: {}", s),
        }
    }
}

impl std::error::Error for TorError {}

// ── TorStatus ─────────────────────────────────────────────────────────

/// Tor connection status, exposed to the UI via UniFFI.
#[derive(Debug, Clone)]
pub struct TorStatus {
    pub is_bootstrapped: bool,
    pub bootstrap_progress: u8,
    pub onion_address: Option<String>,
}

// ── TorStream ─────────────────────────────────────────────────────────

/// A synchronous wrapper around Arti's async DataStream.
/// Implements `Read` and `Write` by blocking on the tokio runtime.
pub struct TorStream {
    handle: tokio::runtime::Handle,
    reader: tokio::io::ReadHalf<arti_client::DataStream>,
    writer: tokio::io::WriteHalf<arti_client::DataStream>,
    read_timeout: Duration,
}

impl TorStream {
    fn new(handle: tokio::runtime::Handle, stream: arti_client::DataStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        TorStream {
            handle,
            reader,
            writer,
            read_timeout: TOR_READ_TIMEOUT,
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout.unwrap_or(TOR_READ_TIMEOUT);
    }
}

impl Read for TorStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let timeout = self.read_timeout;
        let reader = &mut self.reader;
        self.handle.block_on(async {
            match tokio::time::timeout(timeout, reader.read(buf)).await {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Tor read timed out",
                )),
            }
        })
    }
}

impl Write for TorStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let writer = &mut self.writer;
        self.handle.block_on(async { writer.write(buf).await })
    }

    fn flush(&mut self) -> io::Result<()> {
        let writer = &mut self.writer;
        self.handle.block_on(async { writer.flush().await })
    }
}

// ── TorManager ────────────────────────────────────────────────────────

/// Manages the Tor client lifecycle. Owns a background tokio runtime
/// and an Arti TorClient. All public methods are synchronous (blocking).
pub struct TorManager {
    runtime: Runtime,
    client: TorClient<PreferredRuntime>,
    bootstrap_progress: Arc<AtomicU8>,
    onion_address: Option<String>,
}

impl TorManager {
    /// Bootstrap the Tor client. This blocks until connected to the Tor
    /// network (typically 5-15 seconds on a good connection).
    pub fn bootstrap(data_dir: &Path) -> Result<Self, TorError> {
        info!("Tor: bootstrapping from {}", data_dir.display());

        let runtime = Runtime::new()
            .map_err(|e| TorError::Bootstrap(format!("tokio runtime: {}", e)))?;

        let state_dir = data_dir.join("state");
        let cache_dir = data_dir.join("cache");

        std::fs::create_dir_all(&state_dir)
            .map_err(|e| TorError::Bootstrap(format!("create state dir: {}", e)))?;
        std::fs::create_dir_all(&cache_dir)
            .map_err(|e| TorError::Bootstrap(format!("create cache dir: {}", e)))?;

        let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()
            .map_err(|e| TorError::Bootstrap(format!("config: {}", e)))?;

        let bootstrap_progress = Arc::new(AtomicU8::new(0));

        let client = runtime.block_on(async {
            tokio::time::timeout(
                BOOTSTRAP_TIMEOUT,
                TorClient::create_bootstrapped(config),
            )
            .await
            .map_err(|_| TorError::Bootstrap("bootstrap timed out after 120s".into()))?
            .map_err(|e| TorError::Bootstrap(format!("{}", e)))
        })?;

        bootstrap_progress.store(100, Ordering::Relaxed);
        info!("Tor: bootstrap complete");

        Ok(TorManager {
            runtime,
            client,
            bootstrap_progress,
            onion_address: None,
        })
    }

    /// Connect to a peer through Tor. Returns a synchronous TorStream.
    /// The address can be an IP:port, hostname:port, or .onion:port.
    pub fn connect(&self, addr: &str) -> Result<TorStream, TorError> {
        let handle = self.runtime.handle().clone();
        let client = self.client.clone();

        let stream = self.runtime.block_on(async {
            tokio::time::timeout(TOR_CONNECT_TIMEOUT, client.connect(addr))
                .await
                .map_err(|_| {
                    TorError::Connection(format!("connection to {} timed out", addr))
                })?
                .map_err(|e| TorError::Connection(format!("{}: {}", addr, e)))
        })?;

        info!("Tor: connected to {}", addr);
        Ok(TorStream::new(handle, stream))
    }

    /// Resolve a hostname through Tor (no clearnet DNS leak).
    pub fn resolve(&self, hostname: &str) -> Result<Vec<SocketAddr>, TorError> {
        let client = self.client.clone();
        let host = hostname.to_string();

        self.runtime.block_on(async {
            let addrs = client
                .resolve(&host)
                .await
                .map_err(|e| TorError::Resolve(format!("{}: {}", hostname, e)))?;

            Ok(addrs
                .iter()
                .map(|ip| SocketAddr::new(*ip, 8333))
                .collect())
        })
    }

    /// Get an isolated Tor client handle. Connections made through this
    /// handle use separate circuits, preventing correlation between peers.
    pub fn isolated_connect(&self, addr: &str) -> Result<TorStream, TorError> {
        let handle = self.runtime.handle().clone();
        let isolated = self.client.isolated_client();

        let stream = self.runtime.block_on(async {
            tokio::time::timeout(TOR_CONNECT_TIMEOUT, isolated.connect(addr))
                .await
                .map_err(|_| {
                    TorError::Connection(format!(
                        "isolated connection to {} timed out",
                        addr
                    ))
                })?
                .map_err(|e| TorError::Connection(format!("{}: {}", addr, e)))
        })?;

        info!("Tor: isolated connection to {}", addr);
        Ok(TorStream::new(handle, stream))
    }

    /// Get current Tor status for UI display.
    pub fn status(&self) -> TorStatus {
        TorStatus {
            is_bootstrapped: self.bootstrap_progress.load(Ordering::Relaxed) == 100,
            bootstrap_progress: self.bootstrap_progress.load(Ordering::Relaxed),
            onion_address: self.onion_address.clone(),
        }
    }

    /// Get the tokio runtime handle (for internal use by PeerStream).
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

// ── OnionServiceHandle ────────────────────────────────────────────────

/// Handle for a running .onion hidden service.
pub struct OnionServiceHandle {
    pub address: String,
    // The onion service stays alive as long as this handle exists.
    // Arti manages the service internally via the TorClient.
    _service: Box<dyn std::any::Any + Send>,
}

impl TorManager {
    /// Start an onion hidden service that accepts inbound connections
    /// on the given port. Returns the .onion address.
    ///
    /// The persistent keypair is stored in the Tor data directory,
    /// giving the node a stable .onion address across restarts.
    pub fn start_onion_service(&mut self, port: u16) -> Result<OnionServiceHandle, TorError> {
        info!("Tor: starting onion service on port {}", port);

        let (service, address) = self.runtime.block_on(async {
            use arti_client::config::onion_service::OnionServiceConfigBuilder;

            let svc_config = OnionServiceConfigBuilder::default()
                .nickname("hercules".parse().map_err(|e| {
                    TorError::OnionService(format!("invalid nickname: {}", e))
                })?)
                .build()
                .map_err(|e| {
                    TorError::OnionService(format!("config: {}", e))
                })?;

            let (service, _request_stream) = self
                .client
                .launch_onion_service(svc_config)
                .map_err(|e| {
                    TorError::OnionService(format!("launch: {}", e))
                })?
                .ok_or_else(|| {
                    TorError::OnionService("onion service disabled in config".into())
                })?;

            // Get the onion address from the service
            use safelog::DisplayRedacted;
            let hs_id = service.onion_address().ok_or_else(|| {
                TorError::OnionService("no onion address assigned yet".into())
            })?;
            let address = format!("{}", hs_id.display_unredacted());

            Ok::<_, TorError>((service, address))
        })?;

        let onion_addr = format!("{}:{}", address, port);
        info!("Tor: onion service running at {}", onion_addr);
        self.onion_address = Some(onion_addr.clone());

        Ok(OnionServiceHandle {
            address: onion_addr,
            _service: Box::new(service),
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_status_default() {
        let status = TorStatus {
            is_bootstrapped: false,
            bootstrap_progress: 0,
            onion_address: None,
        };
        assert!(!status.is_bootstrapped);
        assert_eq!(status.bootstrap_progress, 0);
        assert!(status.onion_address.is_none());
    }

    #[test]
    fn tor_error_display() {
        let err = TorError::Bootstrap("test".into());
        assert!(format!("{}", err).contains("bootstrap"));

        let err = TorError::Connection("peer".into());
        assert!(format!("{}", err).contains("connection"));
    }
}
