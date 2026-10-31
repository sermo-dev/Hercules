use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard};

use bitcoin::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use heed::types::{Bytes, Unit};
use heed::{Database, Env, EnvFlags, EnvOpenOptions, FlagSetMode, MdbError, PutFlags};
use sha2::{Digest, Sha256};
use blvm_muhash::{MuHash3072, serialize_coin_for_muhash};

use log::{error, info, warn};

use crate::assumeutxo::SnapshotAnchor;

/// Snapshot file magic bytes: "HUTX"
const SNAPSHOT_MAGIC: [u8; 4] = [b'H', b'U', b'T', b'X'];

/// Current snapshot format version.
const SNAPSHOT_VERSION: u32 = 1;

/// Maximum allowed amount per UTXO (Bitcoin's MAX_MONEY in satoshis).
/// Used as a sanity bound on read so a corrupt value doesn't propagate
/// silently into fee math or hash inputs.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

const GIB: u64 = 1 << 30;

/// Minimum LMDB map size: 32 GiB. `map_size` is *virtual* address space, not
/// an on-disk reservation (file growth is lazy; we don't use `WRITEMAP`), but
/// it is not free on iOS: a process without the
/// `com.apple.developer.kernel.extended-virtual-addressing` entitlement gets
/// a per-process VA budget far below the hardware limit, and an mmap larger
/// than that fails at open (ticket 030). The app carries that entitlement;
/// this floor covers a fresh AssumeUTXO import (~12 GB UTXO set + undo) in a
/// single session.
const MIN_MAP_SIZE: u64 = 32 * GIB;

/// Upper bound for the preferred map: never reserve more than this.
const MAX_MAP_SIZE: u64 = 128 * GIB;

/// Headroom over the current data file kept by the *smallest* fallback map,
/// i.e. how much the env can grow in one session if VA is tight.
const MIN_MAP_HEADROOM: u64 = 4 * GIB;

/// Rough LMDB footprint per snapshot entry (key + value + B-tree overhead),
/// used to check before a load that the map can hold the set the header
/// announces. ~12 GB for the mainnet anchor's set, with margin.
const SNAPSHOT_EST_BYTES_PER_UTXO: u64 = 80;

/// During a snapshot load, grow the map at a batch boundary once less than
/// this much of it is left (a 1M-entry batch is ~100 MB, so this is many
/// batches of warning).
const SNAPSHOT_GROW_TRIGGER: u64 = 2 * GIB;

/// Times a write txn is retried after growing the map on `MDB_MAP_FULL`.
const MAP_FULL_RETRIES: usize = 3;

/// Map-sizing knobs, bundled so tests can shrink them (a real 32 GiB floor
/// can't be filled in a unit test). Production always uses `DEFAULT_SIZING`.
#[derive(Clone, Copy, Debug)]
struct MapSizing {
    min: u64,
    max: u64,
    headroom: u64,
    /// Every map size is a multiple of this (and so of the page size).
    granule: u64,
}

const DEFAULT_SIZING: MapSizing = MapSizing {
    min: MIN_MAP_SIZE,
    max: MAX_MAP_SIZE,
    headroom: MIN_MAP_HEADROOM,
    granule: GIB,
};

#[cfg(test)]
thread_local! {
    static TEST_SIZING: std::cell::Cell<Option<MapSizing>> = const { std::cell::Cell::new(None) };
}

fn sizing() -> MapSizing {
    #[cfg(test)]
    if let Some(s) = TEST_SIZING.with(|c| c.get()) {
        return s;
    }
    DEFAULT_SIZING
}

/// Process-wide bookkeeping per canonical env path (ticket 030).
///
/// heed 0.20 caches one `Env` per path in a process-global `OPENED_ENV`
/// map and returns `BadOpenOptions` if a later open of the same path passes
/// different options while that `Env` is alive. Our map size depends on
/// `data.mdb`'s size at open time, so a second `UtxoSet` on the same path
/// (a push-wake node while the foreground node is running) would otherwise
/// fail to open once the data file had grown. Every open while the env is
/// live therefore passes exactly the size it was first opened with, and a
/// reopen after a full close starts from the last size that worked.
///
/// It also counts users, so heed's cache entry is only torn down when the
/// *last* `UtxoSet` on the path drops (tearing it down earlier makes every
/// later open fail with `DatabaseClosing` while another set still holds the
/// env).
struct EnvSlot {
    /// Shared with every live `UtxoSet` on this env; `None` once all closed.
    shared: Option<Arc<EnvShared>>,
    users: usize,
    /// `map_size` the live heed `Env` was created with.
    opened_with: u64,
    /// Map size (including any growth) when the env was last fully closed.
    remembered: u64,
}

/// State every `UtxoSet` on one live env shares.
struct EnvShared {
    /// Held shared for the lifetime of every txn and exclusively to resize:
    /// `mdb_env_set_mapsize` remaps the file, so no txn in this process may
    /// be open (LMDB doesn't check; a reader would be left pointing at an
    /// unmapped region).
    gate: RwLock<()>,
    /// Current map size, including growth since open.
    map_size: AtomicU64,
    /// Set if a resize failed after LMDB had already dropped the old map:
    /// the env can't be used until it is closed and reopened.
    poisoned: AtomicBool,
}

fn env_registry() -> MutexGuard<'static, HashMap<PathBuf, EnvSlot>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, EnvSlot>>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Whether `size` bytes of address space can be reserved right now. Probed
/// with a `PROT_NONE` anonymous mapping before a resize, because once LMDB
/// has unmapped the old map a failed remap leaves the env unusable. The old
/// map is still in place during the probe, so this is conservative.
fn can_reserve_address_space(size: u64) -> bool {
    let Ok(len) = usize::try_from(size) else { return false };
    // SAFETY: an anonymous PROT_NONE mapping touches no memory and is
    // unmapped immediately; it only asks the kernel for address space.
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            return false;
        }
        libc::munmap(p, len);
    }
    true
}

/// A write-path error that remembers whether LMDB ran out of map space, so
/// the caller can grow the map and retry the (aborted, so side-effect-free)
/// txn.
enum WriteError {
    MapFull(String),
    Other(UtxoError),
}

impl From<UtxoError> for WriteError {
    fn from(e: UtxoError) -> Self {
        WriteError::Other(e)
    }
}

/// `map_err` adapter for heed calls on a write path.
fn lmdb(ctx: &'static str) -> impl FnOnce(heed::Error) -> WriteError {
    move |e| {
        let msg = format!("{}: {}", ctx, e);
        if matches!(e, heed::Error::Mdb(MdbError::MapFull)) {
            WriteError::MapFull(msg)
        } else {
            WriteError::Other(UtxoError(msg))
        }
    }
}

/// Why a snapshot load failed. The app keeps the downloaded file unless
/// the file itself is bad, so a retry after freeing space (or on a device
/// that can map the set) doesn't re-download ~9 GB.
#[derive(Debug)]
pub enum SnapshotLoadError {
    /// The snapshot is corrupt, truncated, unsorted, or doesn't match the
    /// anchor (header or content hash): delete it and download again.
    Invalid(String),
    /// The file may be fine but couldn't be stored: map or disk full, an
    /// LMDB error, a non-empty set, or the load was cancelled.
    Storage(String),
}

impl std::fmt::Display for SnapshotLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotLoadError::Invalid(m) => write!(f, "invalid snapshot: {}", m),
            SnapshotLoadError::Storage(m) => write!(f, "utxo error: {}", m),
        }
    }
}

impl std::error::Error for SnapshotLoadError {}

impl From<UtxoError> for SnapshotLoadError {
    fn from(e: UtxoError) -> Self {
        SnapshotLoadError::Storage(e.0)
    }
}

impl From<WriteError> for SnapshotLoadError {
    fn from(e: WriteError) -> Self {
        match e {
            WriteError::MapFull(m) => SnapshotLoadError::Storage(m),
            WriteError::Other(e) => SnapshotLoadError::Storage(e.0),
        }
    }
}

/// Number of named DBs we open inside the env. heed requires this up-front.
const MAX_DBS: u32 = 8;

/// LMDB key length for the `utxos` DB: txid (32) + vout (4 BE).
const UTXO_KEY_LEN: usize = 36;

/// Key inside the `meta` DB for the assume-valid floor: the highest block
/// height covered by the most-recently loaded UTXO snapshot. Stored as 4
/// little-endian bytes. Absent on a fresh-from-genesis install.
const META_KEY_ASSUME_VALID_FLOOR: &[u8] = b"assume_valid_floor";

/// Key inside the `meta` DB for the MuHash of the UTXO set at the snapshot
/// height. Stored as 32 bytes (SHA256 finalization of the MuHash3072
/// accumulator). Compatible with `bitcoin-cli gettxoutsetinfo muhash`.
const META_KEY_MUHASH: &[u8] = b"muhash";

/// Key inside the `meta` DB for the block hash the loaded snapshot commits
/// to (32 bytes, internal order). Written alongside the assume-valid floor
/// so a snapshot whose activation is deferred until headers reach it (see
/// `HeaderSync::load_snapshot`) still activates against the anchor it was
/// verified with, even if a later app release bumps the compiled anchor.
const META_KEY_SNAPSHOT_BLOCK_HASH: &[u8] = b"snapshot_block_hash";

/// Key inside the `meta` DB for the block the UTXO set is currently at:
/// height (4 LE) || block hash (32, internal order). Written in the same
/// txn as every `apply_block`, `rollback_block_to` and snapshot load, so it
/// can never disagree with the UTXO rows themselves (ticket 024). The sync
/// layer compares it with its header chain before trusting a validation
/// failure, and uses it to repair `validated_height` after a crash between
/// a UTXO write and the matching header-store update. Absent on databases
/// written before it existed, and after a test-only `rollback_block`.
const META_KEY_BEST_BLOCK: &[u8] = b"best_block";

/// `META_KEY_BEST_BLOCK` value: height (4 LE) || hash (32).
fn encode_best_block(height: u32, hash: &[u8; 32]) -> [u8; 36] {
    let mut v = [0u8; 36];
    v[..4].copy_from_slice(&height.to_le_bytes());
    v[4..].copy_from_slice(hash);
    v
}

/// LMDB key length for the `height_index` DB: height (4 BE) + txid (32) + vout (4 BE).
const HEIGHT_INDEX_KEY_LEN: usize = 40;

/// Header bytes in a serialized utxos value: amount(8) + height(4) + flags(1).
const UTXO_VALUE_HEADER_LEN: usize = 13;

/// `flags` bit indicating the UTXO came from a coinbase tx.
const FLAG_COINBASE: u8 = 1 << 0;

/// Header bytes in a serialized undo entry value: txid(32) + vout(4) + amount(8) + orig_height(4) + flags(1).
const UNDO_VALUE_HEADER_LEN: usize = 49;

/// Bulk-load batch size: commit and reopen the write txn every N entries
/// during snapshot load. Bounds dirty-page accumulation in LMDB's per-txn
/// dirty list so it doesn't grow past available RAM and trigger the mmap
/// eviction death spiral on iOS. APPEND ordering is preserved across
/// commits since the snapshot stream is monotonically sorted.
///
/// Lowered to a tiny value under `cfg(test)` so the test suite actually
/// exercises the periodic-commit code path with handfuls of entries instead
/// of needing a million-entry stream.
#[cfg(not(test))]
const SNAPSHOT_LOAD_BATCH: u64 = 1_000_000;
#[cfg(test)]
const SNAPSHOT_LOAD_BATCH: u64 = 4;

/// Buffered reader capacity for snapshot streams (256 KiB). Larger than the
/// default 8 KiB to reduce syscall + gzip-decoder overhead during the
/// hours-long iPhone import.
const SNAPSHOT_READ_BUF: usize = 256 * 1024;

/// Sentinel filename written next to the LMDB env directory while a
/// snapshot load is in progress. Its presence on `UtxoSet::open` means a
/// previous load was interrupted (process killed, OS reboot) and the
/// on-disk state is partial / unverified — we wipe and start fresh.
const SNAPSHOT_LOADING_MARKER_SUFFIX: &str = ".loading";

/// Metadata about a loaded or expected UTXO snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub utxo_count: u64,
    pub utxo_hash: [u8; 32],
}

/// A single unspent transaction output.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub height: u32,
    pub is_coinbase: bool,
}

/// Persistent UTXO set backed by LMDB (via the `heed` crate).
///
/// Three named databases live inside one env:
///
/// * `utxos` — `key = txid(32) || vout(4 BE)`, value = `amount(8 LE) || height(4 LE) || flags(1) || script`.
///   Big-endian vout makes the natural lex sort match `(txid, vout)`, so a
///   single cursor scan reproduces the snapshot iteration order without an
///   ORDER BY.
///
/// * `undo` — `key = block_height(4 BE) || idx(4 BE)`, value = the spent UTXO
///   we'll need to restore on rollback. Keying by height puts every block's
///   undo records together, so prune-below and rollback both range-scan a
///   contiguous chunk.
///
/// * `height_index` — `key = block_height(4 BE) || txid(32) || vout(4 BE)`,
///   value = empty. Lets us answer "which UTXOs were created at this height?"
///   in O(matches) instead of scanning the full set, which rollback needs.
///   Also gives `has_utxos_at_height` a single cursor seek.
///
/// * `meta` — `key = ascii name`, value = arbitrary bytes. Cross-restart
///   metadata that doesn't fit the per-UTXO or per-height schemas (currently
///   just the assume-valid floor written by `load_snapshot`).
///
/// All schema versioning is implicit in the snapshot format hash check —
/// loading a snapshot computed under different on-disk semantics will fail
/// the SHA256 verification before any data lands.
pub struct UtxoSet {
    /// `ManuallyDrop` so `Drop` can release it while holding the env
    /// registry lock (see `EnvSlot`).
    env: ManuallyDrop<Env>,
    shared: Arc<EnvShared>,
    /// Canonical env path: the registry key.
    canonical: PathBuf,
    utxos: Database<Bytes, Bytes>,
    undo: Database<Bytes, Bytes>,
    height_index: Database<Bytes, Unit>,
    meta: Database<Bytes, Bytes>,
    /// Test builds: a slot in the per-process LMDB lock budget, held for
    /// this handle's life (see `testkit::lmdb_gate`). Dropped after `Drop`
    /// has closed the env.
    #[cfg(test)]
    _lmdb_slot: crate::testkit::LmdbSlot,
}

impl UtxoSet {
    /// Open or create a UTXO LMDB env at `path`. `path` is treated as a
    /// directory — heed creates `data.mdb` and `lock.mdb` inside it.
    ///
    /// If a `<path>.loading` marker exists, a previous snapshot load was
    /// interrupted: the env on disk is partial and unverified. We wipe it
    /// before opening so the caller sees an empty set and can re-import.
    pub fn open(path: &str) -> Result<UtxoSet, UtxoError> {
        let path_buf = PathBuf::from(path);
        let marker = loading_marker_path(&path_buf);

        if marker.exists() {
            warn!(
                "Detected interrupted UTXO snapshot load at {} — wiping partial env",
                path_buf.display()
            );
            if path_buf.exists() {
                fs::remove_dir_all(&path_buf).map_err(|e| {
                    UtxoError(format!("wipe partial env {}: {}", path_buf.display(), e))
                })?;
            }
            fs::remove_file(&marker).map_err(|e| {
                UtxoError(format!("remove loading marker {}: {}", marker.display(), e))
            })?;
        }

        fs::create_dir_all(&path_buf)
            .map_err(|e| UtxoError(format!("create utxo dir {}: {}", path, e)))?;
        Self::open_at(&path_buf)
    }

    fn open_at(path: &Path) -> Result<UtxoSet, UtxoError> {
        // Before any LMDB call, so a throttled test waits here instead of
        // failing `mdb_txn_begin` with EINVAL.
        #[cfg(test)]
        let lmdb_slot = crate::testkit::lmdb_slot();
        // SAFETY: heed marks `open` unsafe because LMDB requires the same
        // mmap'd file isn't simultaneously opened with conflicting flags from
        // another process. We're a single-process iOS app and never share the
        // env directory across processes, so this contract holds.
        // Map sizing (ticket 030): prefer max(32 GiB, 2 x current data file)
        // for the first open in a process. If the mmap can't be reserved (iOS
        // VA limit), fall back to progressively smaller maps down to data +
        // 4 GiB so the node still opens instead of failing outright. Within
        // a process the size is pinned per path (see `EnvSlot`): later opens
        // while the env is live reuse it exactly, and a reopen after a full
        // close starts from the last size that worked. The map grows in
        // place on `MDB_MAP_FULL` (`grow_map`).
        let canonical = path
            .canonicalize()
            .map_err(|e| UtxoError(format!("canonicalize {}: {}", path.display(), e)))?;
        let data_len = fs::metadata(path.join("data.mdb")).map(|m| m.len()).unwrap_or(0);
        let sz = sizing();

        // Held across the heed open so two threads opening the same path
        // agree on the options, and so a concurrent last-user drop can't
        // tear heed's cache entry down in between.
        let mut registry = env_registry();
        let live = registry
            .get(&canonical)
            .and_then(|slot| slot.shared.clone().map(|sh| (sh, slot.opened_with)));
        let candidates = match &live {
            Some((_, opened_with)) => vec![*opened_with],
            None => {
                let mut c = map_size_candidates_with(data_len, &sz);
                let floor = round_up(data_len + sz.headroom, sz.granule);
                if let Some(r) = registry.get(&canonical).map(|slot| slot.remembered) {
                    if r >= floor {
                        c.retain(|size| *size < r);
                        c.insert(0, r);
                    }
                }
                c
            }
        };

        let mut last_err = None;
        let mut opened = None;
        for size in candidates {
            match unsafe {
                EnvOpenOptions::new()
                    .map_size(size as usize)
                    .max_dbs(MAX_DBS)
                    .open(path)
            } {
                Ok(env) => {
                    opened = Some((env, size));
                    break;
                }
                Err(e) => {
                    warn!(
                        "LMDB open at {} with map_size={} MiB failed: {}",
                        path.display(),
                        size >> 20,
                        e
                    );
                    last_err = Some(e);
                }
            }
        }
        let (env, opened_with) = opened.ok_or_else(|| {
            UtxoError(format!(
                "open env at {}: {}",
                path.display(),
                last_err.map(|e| e.to_string()).unwrap_or_default()
            ))
        })?;

        let shared = match live {
            Some((shared, _)) => shared,
            None => Arc::new(EnvShared {
                gate: RwLock::new(()),
                // LMDB may round a too-small request up to the data size.
                map_size: AtomicU64::new(env.info().map_size as u64),
                poisoned: AtomicBool::new(false),
            }),
        };
        let slot = registry.entry(canonical.clone()).or_insert(EnvSlot {
            shared: None,
            users: 0,
            opened_with,
            remembered: 0,
        });
        if slot.users == 0 {
            slot.opened_with = opened_with;
            slot.shared = Some(shared.clone());
        }
        slot.users += 1;
        drop(registry);

        // The slot now counts us: any error below must release it.
        let set_env = ManuallyDrop::new(env);
        let create = (|| {
            let _gate = shared.gate.read().unwrap_or_else(|e| e.into_inner());
            let mut wtxn = set_env
                .write_txn()
                .map_err(|e| UtxoError(format!("begin create-tx: {}", e)))?;
            let utxos: Database<Bytes, Bytes> = set_env
                .create_database(&mut wtxn, Some("utxos"))
                .map_err(|e| UtxoError(format!("create utxos db: {}", e)))?;
            let undo: Database<Bytes, Bytes> = set_env
                .create_database(&mut wtxn, Some("undo"))
                .map_err(|e| UtxoError(format!("create undo db: {}", e)))?;
            let height_index: Database<Bytes, Unit> = set_env
                .create_database(&mut wtxn, Some("height_index"))
                .map_err(|e| UtxoError(format!("create height_index db: {}", e)))?;
            let meta: Database<Bytes, Bytes> = set_env
                .create_database(&mut wtxn, Some("meta"))
                .map_err(|e| UtxoError(format!("create meta db: {}", e)))?;
            wtxn.commit()
                .map_err(|e| UtxoError(format!("commit create-tx: {}", e)))?;
            Ok::<_, UtxoError>((utxos, undo, height_index, meta))
        })();
        let (utxos, undo, height_index, meta) = match create {
            Ok(dbs) => dbs,
            Err(e) => {
                release_env(&canonical, ManuallyDrop::into_inner(set_env));
                return Err(e);
            }
        };

        info!(
            "UTXO LMDB env opened at {} (map_size={} MiB, data={} MiB)",
            path.display(),
            shared.map_size.load(Ordering::Acquire) >> 20,
            data_len >> 20
        );

        Ok(UtxoSet {
            env: set_env,
            shared,
            canonical,
            utxos,
            undo,
            height_index,
            meta,
            #[cfg(test)]
            _lmdb_slot: lmdb_slot,
        })
    }

    /// Shared hold on the resize gate, taken before every txn and kept for
    /// its whole lifetime (declare it *before* the txn so it drops after).
    fn read_gate(&self) -> Result<RwLockReadGuard<'_, ()>, UtxoError> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            return Err(UtxoError(
                "LMDB map resize failed; the UTXO env must be reopened (restart the node)".into(),
            ));
        }
        Ok(self.shared.gate.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Current LMDB map size in bytes (address space reserved, not disk).
    pub fn map_size(&self) -> u64 {
        self.shared.map_size.load(Ordering::Acquire)
    }

    /// Grow the map in place to at least `min_size` (ticket 030).
    ///
    /// Takes the gate exclusively, so it waits until no txn is open on this
    /// env anywhere in the process; callers must not hold a txn or a
    /// `read_gate` guard. Address space for the new size is probed first:
    /// LMDB unmaps the old map before mapping the new one, so a failed remap
    /// would leave the env unusable (it is then poisoned and must be
    /// reopened). A probe failure leaves the env untouched.
    fn grow_map(&self, min_size: u64) -> Result<(), UtxoError> {
        let _gate = self.shared.gate.write().unwrap_or_else(|e| e.into_inner());
        if self.shared.poisoned.load(Ordering::Acquire) {
            return Err(UtxoError("LMDB env poisoned by an earlier failed resize".into()));
        }
        let current = self.env.info().map_size as u64;
        if current >= min_size {
            // Another thread grew it while we waited for the gate.
            self.shared.map_size.store(current, Ordering::Release);
            return Ok(());
        }
        let sz = sizing();
        // Grow by at least half again so repeated MAP_FULLs don't resize per block.
        let target = round_up(min_size.max(current + current / 2), sz.granule);
        if !can_reserve_address_space(target) {
            return Err(UtxoError(format!(
                "can't grow LMDB map from {} MiB to {} MiB: not enough address space",
                current >> 20,
                target >> 20
            )));
        }
        // SAFETY: the exclusive gate guarantees no txn is active on this env
        // in this process (every txn holds the gate shared), which is
        // `mdb_env_set_mapsize`'s precondition. Single-process app.
        if let Err(e) = unsafe { self.env.resize(target as usize) } {
            self.shared.poisoned.store(true, Ordering::Release);
            return Err(UtxoError(format!("resize LMDB map to {} MiB: {}", target >> 20, e)));
        }
        let now = self.env.info().map_size as u64;
        self.shared.map_size.store(now, Ordering::Release);
        info!("UTXO LMDB map grown from {} MiB to {} MiB", current >> 20, now >> 20);
        Ok(())
    }

    /// Grow after `MDB_MAP_FULL`: to the next step above the current size.
    fn grow_after_map_full(&self, what: &str) -> Result<(), UtxoError> {
        let current = self.map_size();
        warn!("{}: LMDB map full at {} MiB, growing", what, current >> 20);
        self.grow_map(current + sizing().headroom)
    }

    /// Make sure the map can hold at least `bytes` (growing it if needed),
    /// or fail with a clear message. Used before an AssumeUTXO download so a
    /// device that can't map the set finds out before fetching ~9 GB.
    pub fn ensure_map_capacity(&self, bytes: u64) -> Result<(), UtxoError> {
        if self.map_size() >= bytes {
            return Ok(());
        }
        self.grow_map(bytes).map_err(|e| {
            UtxoError(format!(
                "this device can't map the UTXO set: it needs about {} GiB of address space \
                 and only {} GiB could be reserved ({})",
                bytes.div_ceil(GIB),
                self.map_size() / GIB,
                e.0
            ))
        })
    }

    /// Look up an unspent output by txid and output index.
    pub fn get(&self, txid: &Txid, vout: u32) -> Result<Option<UtxoEntry>, UtxoError> {
        let key = utxo_key(&txid.to_byte_array(), vout);
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let val = self
            .utxos
            .get(&rtxn, &key)
            .map_err(|e| UtxoError(format!("get utxo: {}", e)))?;
        match val {
            Some(bytes) => Ok(Some(decode_utxo_value(bytes)?)),
            None => Ok(None),
        }
    }

    /// Apply a validated block to the UTXO set.
    /// Removes spent outputs and adds new unspent outputs.
    /// Handles in-block spends correctly (outputs created and spent
    /// within the same block never touch the database).
    ///
    /// On `MDB_MAP_FULL` the txn is aborted (nothing written), the map is
    /// grown in place, and the block is applied again (ticket 030).
    pub fn apply_block(&self, block: &Block, height: u32) -> Result<(), UtxoError> {
        let mut attempt = 0;
        loop {
            match self.apply_block_txn(block, height) {
                Ok(()) => return Ok(()),
                Err(WriteError::Other(e)) => return Err(e),
                Err(WriteError::MapFull(msg)) => {
                    attempt += 1;
                    if attempt > MAP_FULL_RETRIES {
                        return Err(UtxoError(msg));
                    }
                    self.grow_after_map_full("apply_block")?;
                }
            }
        }
    }

    fn apply_block_txn(&self, block: &Block, height: u32) -> Result<(), WriteError> {
        // Phase 1: Analyze the block to find in-block spends so we can skip
        // writing then immediately deleting outputs that are spent in the
        // same block. (`HashSet` of (txid, vout) since we only need
        // membership checks.)
        let mut created: std::collections::HashSet<(Txid, u32)> =
            std::collections::HashSet::new();
        let mut in_block_spent: std::collections::HashSet<(Txid, u32)> =
            std::collections::HashSet::new();

        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                if !output.script_pubkey.is_op_return() {
                    created.insert((txid, vout as u32));
                }
            }
            if !tx.is_coinbase() {
                for input in &tx.input {
                    let key = (input.previous_output.txid, input.previous_output.vout);
                    if created.contains(&key) {
                        in_block_spent.insert(key);
                    }
                }
            }
        }

        let _gate = self.read_gate()?;
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(lmdb("begin tx"))?;

        // Index inside the block for the undo key — multiple inputs can be
        // recorded against the same height, so we tie-break with a counter.
        let mut undo_idx: u32 = 0;

        // Phase 2a: copy each spent UTXO into `undo` then delete it from `utxos`
        // (and from `height_index`, where it was registered when created).
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.input {
                let prev_txid = input.previous_output.txid;
                let prev_vout = input.previous_output.vout;
                let okey = (prev_txid, prev_vout);
                if in_block_spent.contains(&okey) {
                    continue;
                }
                let prev_txid_bytes = prev_txid.to_byte_array();
                let utxo_k = utxo_key(&prev_txid_bytes, prev_vout);
                let val = self
                    .utxos
                    .get(&wtxn, &utxo_k)
                    .map_err(lmdb("get for spend"))?
                    .ok_or_else(|| {
                        UtxoError(format!(
                            "apply_block: missing utxo {}:{}",
                            hex::encode(prev_txid_bytes),
                            prev_vout
                        ))
                    })?
                    .to_vec();
                let entry = decode_utxo_value(&val)?;

                let undo_k = undo_key(height, undo_idx);
                undo_idx = undo_idx
                    .checked_add(1)
                    .ok_or_else(|| UtxoError("undo idx overflow".into()))?;
                let undo_v = encode_undo_value(&prev_txid_bytes, prev_vout, &entry);
                self.undo
                    .put(&mut wtxn, &undo_k, &undo_v)
                    .map_err(lmdb("put undo"))?;

                self.utxos
                    .delete(&mut wtxn, &utxo_k)
                    .map_err(lmdb("delete utxo"))?;

                let hi_k = height_index_key(entry.height, &prev_txid_bytes, prev_vout);
                self.height_index
                    .delete(&mut wtxn, &hi_k)
                    .map_err(lmdb("delete height_index"))?;
            }
        }

        // Phase 2b: write the new outputs (skipping in-block-spent and
        // OP_RETURN) plus their `height_index` entries.
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let txid_bytes = txid.to_byte_array();
            let is_cb = tx.is_coinbase();

            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey.is_op_return() {
                    continue;
                }
                let vout = vout as u32;
                if in_block_spent.contains(&(txid, vout)) {
                    continue;
                }
                let entry = UtxoEntry {
                    amount: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                    height,
                    is_coinbase: is_cb,
                };
                let utxo_k = utxo_key(&txid_bytes, vout);
                let utxo_v = encode_utxo_value(&entry);
                // BIP 30 guard (ticket 026). An unspent output with this
                // txid:vout already existing would be a BIP 30 violation,
                // which BIP 34 rules out below BIP34_IMPLIES_BIP30_LIMIT
                // (Core skips the explicit check there too, and treats an
                // overwrite as a logic error in AddCoins). NO_OVERWRITE
                // costs nothing on the normal path; if it ever trips we
                // log, assert in debug builds, and keep the old overwrite
                // behavior so release builds don't wedge the chain.
                match self.utxos.put_with_flags(
                    &mut wtxn,
                    PutFlags::NO_OVERWRITE,
                    &utxo_k,
                    &utxo_v,
                ) {
                    Ok(()) => {}
                    Err(heed::Error::Mdb(MdbError::KeyExist)) => {
                        error!(
                            "apply_block {}: output {}:{} overwrites an unspent output (BIP 30)",
                            height, txid, vout
                        );
                        debug_assert!(
                            false,
                            "BIP 30: block {} overwrites unspent {}:{}",
                            height, txid, vout
                        );
                        self.utxos
                            .put(&mut wtxn, &utxo_k, &utxo_v)
                            .map_err(lmdb("put utxo"))?;
                    }
                    Err(e) => return Err(lmdb("put utxo")(e)),
                }

                let hi_k = height_index_key(height, &txid_bytes, vout);
                self.height_index
                    .put(&mut wtxn, &hi_k, &())
                    .map_err(lmdb("put height_index"))?;
            }
        }

        let best = encode_best_block(height, &block.block_hash().to_byte_array());
        self.meta
            .put(&mut wtxn, META_KEY_BEST_BLOCK, &best)
            .map_err(lmdb("put best_block"))?;

        wtxn.commit()
            .map_err(lmdb("commit"))?;
        Ok(())
    }

    /// The block the UTXO set is at, as `(height, block hash)`, or `None`
    /// if unknown (see `META_KEY_BEST_BLOCK`).
    pub fn best_block(&self) -> Result<Option<(u32, [u8; 32])>, UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let bytes = self
            .meta
            .get(&rtxn, META_KEY_BEST_BLOCK)
            .map_err(|e| UtxoError(format!("read best_block: {}", e)))?;
        match bytes {
            Some(b) if b.len() == 36 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&b[4..]);
                Ok(Some((u32::from_le_bytes(b[..4].try_into().unwrap()), hash)))
            }
            Some(b) => Err(UtxoError(format!("corrupt best_block: len {}", b.len()))),
            None => Ok(None),
        }
    }

    /// Highest block height covered by the most-recently loaded UTXO snapshot,
    /// or 0 on a fresh-from-genesis install. Persisted by `load_snapshot` and
    /// read out of the `meta` LMDB DB on every call so process restarts pick
    /// it up automatically.
    ///
    /// `rollback_block` uses this as a hard floor: snapshot rows have no
    /// `height_index` entries (see the comment in `load_snapshot`), so a
    /// rollback at or below the snapshot height would silently leave them in
    /// place — corrupting the UTXO set against any later re-application of a
    /// different chain. Today this is unreachable in practice because the
    /// snapshot floor sits well below `MAX_REORG_DEPTH` from tip, but it's
    /// the kind of guard we'd rather have explicit than implicit.
    pub fn assume_valid_floor(&self) -> Result<u32, UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let bytes = self
            .meta
            .get(&rtxn, META_KEY_ASSUME_VALID_FLOOR)
            .map_err(|e| UtxoError(format!("read assume_valid_floor: {}", e)))?;
        match bytes {
            Some(b) if b.len() == 4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(b);
                Ok(u32::from_le_bytes(buf))
            }
            Some(b) => Err(UtxoError(format!(
                "corrupt assume_valid_floor: len {}",
                b.len()
            ))),
            None => Ok(0),
        }
    }

    /// Block hash the loaded snapshot was taken at (internal byte order), or
    /// `None` on a fresh-from-genesis install or a snapshot loaded before
    /// this key existed.
    pub fn snapshot_block_hash(&self) -> Result<Option<[u8; 32]>, UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let bytes = self
            .meta
            .get(&rtxn, META_KEY_SNAPSHOT_BLOCK_HASH)
            .map_err(|e| UtxoError(format!("read snapshot_block_hash: {}", e)))?;
        match bytes {
            Some(b) if b.len() == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(b);
                Ok(Some(buf))
            }
            Some(b) => Err(UtxoError(format!(
                "corrupt snapshot_block_hash: len {}",
                b.len()
            ))),
            None => Ok(None),
        }
    }

    /// Read the stored MuHash from the meta database. Returns `None` if no
    /// snapshot has been loaded (genesis-mode sync).
    pub fn muhash(&self) -> Result<Option<[u8; 32]>, UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let bytes = self
            .meta
            .get(&rtxn, META_KEY_MUHASH)
            .map_err(|e| UtxoError(format!("read muhash: {}", e)))?;
        match bytes {
            Some(b) if b.len() == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(b);
                Ok(Some(buf))
            }
            Some(b) => Err(UtxoError(format!("corrupt muhash: len {}", b.len()))),
            None => Ok(None),
        }
    }

    /// Undo a block's UTXO changes. Must be called from the chain tip downward.
    ///
    /// 1. Removes all outputs created at this height (via `height_index`).
    /// 2. Restores all outputs that were spent at this height (from `undo`).
    /// 3. Deletes the undo data for this height.
    ///
    /// Rejects rollbacks at or below the assume-valid floor — see
    /// `assume_valid_floor` for the rationale.
    ///
    /// Retried after growing the map on `MDB_MAP_FULL`, like `apply_block`.
    ///
    /// Leaves the best-block marker unknown; production rollbacks use
    /// `rollback_block_to`, which knows the parent's hash. Test-only.
    #[cfg(test)]
    pub fn rollback_block(&self, height: u32) -> Result<(), UtxoError> {
        self.rollback_block_inner(height, None)
    }

    /// `rollback_block`, recording `parent_hash` (the block at `height - 1`)
    /// as the new best block in the same txn.
    pub fn rollback_block_to(&self, height: u32, parent_hash: [u8; 32]) -> Result<(), UtxoError> {
        self.rollback_block_inner(height, Some(parent_hash))
    }

    fn rollback_block_inner(
        &self,
        height: u32,
        parent_hash: Option<[u8; 32]>,
    ) -> Result<(), UtxoError> {
        let floor = self.assume_valid_floor()?;
        if height <= floor && floor > 0 {
            return Err(UtxoError(format!(
                "rollback_block: height {} is at or below assume-valid floor {} \
                 (snapshot rows have no height_index entries and cannot be rolled back)",
                height, floor
            )));
        }
        let mut attempt = 0;
        loop {
            match self.rollback_block_txn(height, parent_hash) {
                Ok(()) => return Ok(()),
                Err(WriteError::Other(e)) => return Err(e),
                Err(WriteError::MapFull(msg)) => {
                    attempt += 1;
                    if attempt > MAP_FULL_RETRIES {
                        return Err(UtxoError(msg));
                    }
                    self.grow_after_map_full("rollback_block")?;
                }
            }
        }
    }

    fn rollback_block_txn(
        &self,
        height: u32,
        parent_hash: Option<[u8; 32]>,
    ) -> Result<(), WriteError> {

        let _gate = self.read_gate()?;
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(lmdb("begin tx"))?;

        // Step 1: collect (txid, vout) pairs created at this height.
        // We can't delete during iteration in heed, so buffer first.
        let prefix = height.to_be_bytes();
        let mut to_delete: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        {
            let iter = self
                .height_index
                .prefix_iter(&wtxn, &prefix)
                .map_err(lmdb("prefix iter"))?;
            for r in iter {
                let (k, _) =
                    r.map_err(lmdb("height_index iter"))?;
                if k.len() != HEIGHT_INDEX_KEY_LEN {
                    return Err(UtxoError(format!(
                        "corrupt height_index key len {}",
                        k.len()
                    ))
                    .into());
                }
                // Extract the (txid, vout) suffix as the utxo key.
                let utxo_k = k[4..].to_vec();
                to_delete.push((k.to_vec(), utxo_k));
            }
        }
        for (hi_k, utxo_k) in &to_delete {
            self.utxos
                .delete(&mut wtxn, utxo_k.as_slice())
                .map_err(lmdb("delete utxo"))?;
            self.height_index
                .delete(&mut wtxn, hi_k.as_slice())
                .map_err(lmdb("delete height_index"))?;
        }

        // Step 2 & 3: walk undo entries for this height, then restore each
        // spent UTXO into `utxos` + `height_index` and delete the undo
        // record. heed's iterator borrows the txn immutably for as long as
        // it's alive, so we collect first then mutate.
        let mut restorations: Vec<(Vec<u8>, [u8; 32], u32, UtxoEntry)> = Vec::new();
        {
            let iter = self
                .undo
                .prefix_iter(&wtxn, &prefix)
                .map_err(lmdb("undo prefix iter"))?;
            for r in iter {
                let (k, v) = r.map_err(lmdb("undo iter"))?;
                let (txid, vout, entry) = decode_undo_value(v)?;
                restorations.push((k.to_vec(), txid, vout, entry));
            }
        }
        for (undo_k, txid, vout, entry) in restorations {
            let utxo_k = utxo_key(&txid, vout);
            let utxo_v = encode_utxo_value(&entry);
            self.utxos
                .put(&mut wtxn, &utxo_k, &utxo_v)
                .map_err(lmdb("restore utxo"))?;
            let hi_k = height_index_key(entry.height, &txid, vout);
            self.height_index
                .put(&mut wtxn, &hi_k, &())
                .map_err(lmdb("restore height_index"))?;
            self.undo
                .delete(&mut wtxn, undo_k.as_slice())
                .map_err(lmdb("delete undo"))?;
        }

        match parent_hash {
            Some(hash) => self
                .meta
                .put(&mut wtxn, META_KEY_BEST_BLOCK, &encode_best_block(height.saturating_sub(1), &hash))
                .map_err(lmdb("put best_block"))?,
            None => {
                self.meta
                    .delete(&mut wtxn, META_KEY_BEST_BLOCK)
                    .map_err(lmdb("delete best_block"))?;
            }
        }

        wtxn.commit()
            .map_err(lmdb("commit rollback"))?;
        Ok(())
    }

    /// Delete undo data for blocks below the given height.
    /// Call this to reclaim disk space for deeply-buried blocks
    /// that will never be rolled back.
    pub fn prune_undo_below(&self, height: u32) -> Result<(), UtxoError> {
        let _gate = self.read_gate()?;
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin tx: {}", e)))?;

        // Range delete: [0..height_be).
        let upper = height.to_be_bytes();
        let lower = [0u8; 4];
        let range = (
            std::ops::Bound::Included(&lower[..]),
            std::ops::Bound::Excluded(&upper[..]),
        );
        self.undo
            .delete_range(&mut wtxn, &range)
            .map_err(|e| UtxoError(format!("prune undo: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit prune: {}", e)))?;
        Ok(())
    }

    // ── Snapshot support ─────────────────────────────────────────────

    /// Compute a deterministic SHA256 hash over the entire UTXO set.
    /// Iterates all UTXOs in (txid, vout) order and hashes each entry.
    pub fn compute_hash(&self) -> Result<[u8; 32], UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let mut hasher = Sha256::new();
        let iter = self
            .utxos
            .iter(&rtxn)
            .map_err(|e| UtxoError(format!("iter: {}", e)))?;
        for r in iter {
            let (k, v) = r.map_err(|e| UtxoError(format!("hash iter: {}", e)))?;
            if k.len() != UTXO_KEY_LEN {
                return Err(UtxoError(format!("corrupt utxo key len {}", k.len())));
            }
            let entry = decode_utxo_value(v)?;
            if entry.script_pubkey.len() > u16::MAX as usize {
                return Err(UtxoError(format!(
                    "script too long for hash: {} bytes",
                    entry.script_pubkey.len()
                )));
            }
            // Same field order as the snapshot file's hash chain — see
            // `load_snapshot` for the matching feed sequence.
            let txid = &k[..32];
            let vout_be = &k[32..36];
            let vout = u32::from_be_bytes([vout_be[0], vout_be[1], vout_be[2], vout_be[3]]);
            hasher.update(txid);
            hasher.update(&vout.to_le_bytes());
            hasher.update(&entry.amount.to_le_bytes());
            hasher.update(&(entry.script_pubkey.len() as u16).to_le_bytes());
            hasher.update(&entry.script_pubkey);
            hasher.update(&entry.height.to_le_bytes());
            hasher.update(&[entry.is_coinbase as u8]);
        }
        Ok(hasher.finalize().into())
    }

    /// Write the entire UTXO set to a snapshot file.
    ///
    /// Format:
    /// - Header: magic (4) + version (4) + height (4) + block_hash (32) + utxo_count (8) + utxo_hash (32)
    /// - Entries: txid (32) + vout (4) + amount (8) + height (4) + is_coinbase (1) + script_len (2) + script
    pub fn write_snapshot<W: Write>(
        &self,
        writer: W,
        height: u32,
        block_hash: &[u8; 32],
    ) -> Result<SnapshotMeta, UtxoError> {
        let utxo_count = self.count()?;
        let utxo_hash = self.compute_hash()?;

        let mut w = BufWriter::new(writer);

        // Header
        w.write_all(&SNAPSHOT_MAGIC)
            .map_err(|e| UtxoError(format!("write magic: {}", e)))?;
        w.write_all(&SNAPSHOT_VERSION.to_le_bytes())
            .map_err(|e| UtxoError(format!("write version: {}", e)))?;
        w.write_all(&height.to_le_bytes())
            .map_err(|e| UtxoError(format!("write height: {}", e)))?;
        w.write_all(block_hash)
            .map_err(|e| UtxoError(format!("write block_hash: {}", e)))?;
        w.write_all(&utxo_count.to_le_bytes())
            .map_err(|e| UtxoError(format!("write count: {}", e)))?;
        w.write_all(&utxo_hash)
            .map_err(|e| UtxoError(format!("write hash: {}", e)))?;

        // Entries — natural cursor order is `(txid, vout)` because vout is BE
        // in the key.
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let iter = self
            .utxos
            .iter(&rtxn)
            .map_err(|e| UtxoError(format!("snapshot iter: {}", e)))?;
        for r in iter {
            let (k, v) = r.map_err(|e| UtxoError(format!("snapshot iter row: {}", e)))?;
            if k.len() != UTXO_KEY_LEN {
                return Err(UtxoError(format!("corrupt utxo key len {}", k.len())));
            }
            let entry = decode_utxo_value(v)?;
            let txid = &k[..32];
            let vout = u32::from_be_bytes([k[32], k[33], k[34], k[35]]);

            w.write_all(txid)
                .map_err(|e| UtxoError(format!("write txid: {}", e)))?;
            w.write_all(&vout.to_le_bytes())
                .map_err(|e| UtxoError(format!("write vout: {}", e)))?;
            w.write_all(&entry.amount.to_le_bytes())
                .map_err(|e| UtxoError(format!("write amount: {}", e)))?;
            w.write_all(&entry.height.to_le_bytes())
                .map_err(|e| UtxoError(format!("write entry height: {}", e)))?;
            w.write_all(&[entry.is_coinbase as u8])
                .map_err(|e| UtxoError(format!("write is_coinbase: {}", e)))?;
            if entry.script_pubkey.len() > u16::MAX as usize {
                return Err(UtxoError(format!(
                    "script too long for snapshot format: {} bytes (max {})",
                    entry.script_pubkey.len(),
                    u16::MAX
                )));
            }
            let script_len = entry.script_pubkey.len() as u16;
            w.write_all(&script_len.to_le_bytes())
                .map_err(|e| UtxoError(format!("write script_len: {}", e)))?;
            w.write_all(&entry.script_pubkey)
                .map_err(|e| UtxoError(format!("write script: {}", e)))?;
        }

        w.flush()
            .map_err(|e| UtxoError(format!("flush snapshot: {}", e)))?;

        let meta = SnapshotMeta {
            height,
            block_hash: *block_hash,
            utxo_count,
            utxo_hash,
        };

        info!(
            "Wrote UTXO snapshot: height={}, utxos={}, hash={}",
            height,
            utxo_count,
            hex::encode(utxo_hash)
        );

        Ok(meta)
    }

    /// Load a UTXO snapshot from a reader. Verifies the UTXO hash after loading.
    /// The UTXO set must be empty before calling this.
    ///
    /// When `expected` is given, the file header's `height` and `block_hash`
    /// must equal the anchor's and its stored hash must equal
    /// `expected.utxo_hash`; otherwise the file is rejected before anything
    /// (including the crash marker) is written. The content hash covers only
    /// the entries (HUTX v1), so these explicit header checks are what bind
    /// the snapshot to a position on the chain.
    ///
    /// `on_progress` is called periodically with (loaded_count, total_count);
    /// returning `false` cancels the load (cleaned up like any failure).
    ///
    /// Errors are `SnapshotLoadError::Invalid` when the file itself is bad
    /// and `Storage` otherwise (map/disk full, cancelled, LMDB failure), so
    /// the caller knows whether the file is worth keeping.
    ///
    /// ## Performance and crash safety
    ///
    /// The naive "single huge write txn" form of this loop took hours on
    /// iPhone because (a) every entry triggered a random `height_index.put`
    /// across an unsorted B+ tree, and (b) the per-txn dirty page list grew
    /// past available RAM, evicting the mmap and faulting cold pages back
    /// in on every subsequent put. Three changes fix it:
    ///
    /// 1. **Skip `height_index` for snapshot rows.** The index is only used
    ///    by rollback, and rollback past the snapshot height is forbidden by
    ///    design (the snapshot is the assume-valid floor). Halves the LMDB
    ///    write count and eliminates *all* of the random-write work.
    /// 2. **Periodic mid-stream commits.** Every `SNAPSHOT_LOAD_BATCH`
    ///    entries we commit and reopen the wtxn so dirty pages flush to the
    ///    OS page cache instead of accumulating in LMDB's per-txn list.
    ///    APPEND ordering survives across commits because each new key is
    ///    still strictly greater than the existing max.
    /// 3. **`NO_META_SYNC` for the load window.** Defers the meta-page
    ///    fsync between batches; data pages still fsync at each commit, so
    ///    a crash loses at most the last batch — never corrupts the env.
    ///    `NO_SYNC` was *not* used because it can leave LMDB structurally
    ///    broken on a process kill.
    ///
    /// Periodic commits introduce a new failure mode: if the process dies
    /// after batch N has committed but before verification finishes, the
    /// env contains unverified partial state. To prevent that from
    /// masquerading as a complete UTXO set, we write a `<env>.loading`
    /// marker file before the first batch and delete it only after a
    /// successful `force_sync`. `UtxoSet::open` checks for the marker on
    /// startup and wipes the env if found.
    pub fn load_snapshot<R: std::io::Read, F>(
        &self,
        reader: R,
        expected: Option<&SnapshotAnchor>,
        on_progress: F,
    ) -> Result<SnapshotMeta, SnapshotLoadError>
    where
        F: Fn(u64, u64) -> bool,
    {
        let mut r = BufReader::with_capacity(SNAPSHOT_READ_BUF, reader);

        // ── Header ─────────────────────────────────────────────────
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .map_err(|e| SnapshotLoadError::Invalid(format!("read magic: {}", e)))?;
        if magic != SNAPSHOT_MAGIC {
            return Err(SnapshotLoadError::Invalid("invalid snapshot magic".into()));
        }

        let mut buf4 = [0u8; 4];
        r.read_exact(&mut buf4)
            .map_err(|e| SnapshotLoadError::Invalid(format!("read version: {}", e)))?;
        let version = u32::from_le_bytes(buf4);
        if version != SNAPSHOT_VERSION {
            return Err(SnapshotLoadError::Invalid(format!(
                "unsupported snapshot version {}",
                version
            )));
        }

        r.read_exact(&mut buf4)
            .map_err(|e| SnapshotLoadError::Invalid(format!("read height: {}", e)))?;
        let height = u32::from_le_bytes(buf4);

        let mut block_hash = [0u8; 32];
        r.read_exact(&mut block_hash)
            .map_err(|e| SnapshotLoadError::Invalid(format!("read block_hash: {}", e)))?;

        let mut buf8 = [0u8; 8];
        r.read_exact(&mut buf8)
            .map_err(|e| SnapshotLoadError::Invalid(format!("read count: {}", e)))?;
        let utxo_count = u64::from_le_bytes(buf8);

        let mut file_hash = [0u8; 32];
        r.read_exact(&mut file_hash)
            .map_err(|e| SnapshotLoadError::Invalid(format!("read hash: {}", e)))?;

        if let Some(expected) = expected {
            if height != expected.height {
                return Err(SnapshotLoadError::Invalid(format!(
                    "snapshot height mismatch: file={}, expected={}",
                    height, expected.height
                )));
            }
            if block_hash != expected.block_hash {
                return Err(SnapshotLoadError::Invalid(format!(
                    "snapshot block hash mismatch: file={}, expected={}",
                    hex::encode(block_hash),
                    hex::encode(expected.block_hash)
                )));
            }
            if file_hash != expected.utxo_hash {
                return Err(SnapshotLoadError::Invalid(format!(
                    "snapshot hash mismatch: file={}, expected={}",
                    hex::encode(file_hash),
                    hex::encode(expected.utxo_hash)
                )));
            }
        }

        info!(
            "Loading UTXO snapshot: height={}, utxos={}, hash={}",
            height,
            utxo_count,
            hex::encode(file_hash)
        );

        // ── Map capacity (ticket 030) ─────────────────────────────
        // Fail before touching the env if the map can't be grown to hold
        // the set the header announces (an iOS VA limit). A storage error,
        // not a bad file: the caller keeps the download.
        let needed = utxo_count
            .saturating_mul(SNAPSHOT_EST_BYTES_PER_UTXO)
            .saturating_add(sizing().headroom);
        self.ensure_map_capacity(needed)?;

        // ── NO_META_SYNC for the load window ──────────────────────
        // SAFETY: NO_META_SYNC is documented as integrity-preserving (a
        // crash may undo the last committed transaction but cannot corrupt
        // the env). The FlagGuard's Drop unconditionally restores the
        // default sync mode for any subsequent operations on this env.
        //
        // Done *before* the marker write so a set_flags failure can't
        // orphan a marker file on an env that was never touched.
        let _flag_guard = unsafe {
            self.env
                .set_flags(EnvFlags::NO_META_SYNC, FlagSetMode::Enable)
                .map_err(|e| UtxoError(format!("enable NO_META_SYNC: {}", e)))?;
            FlagGuard {
                env: &self.env,
                flags_to_clear: EnvFlags::NO_META_SYNC,
            }
        };

        // ── Crash-recovery marker ─────────────────────────────────
        // Write the marker before touching the env so an interrupted load
        // is always detectable on next open. We won't delete it until the
        // final force_sync returns.
        let marker = loading_marker_path(self.env.path());
        fs::write(&marker, b"snapshot load in progress\n").map_err(|e| {
            UtxoError(format!(
                "write loading marker {}: {}",
                marker.display(),
                e
            ))
        })?;

        // ── Bulk-load loop (in a closure so error paths funnel through
        //     the cleanup block below) ──────────────────────────────
        let load_result: Result<(), SnapshotLoadError> = (|| {
            // Re-taken around each map growth below (growth needs every
            // txn in the process closed, ours included).
            let mut gate = self.read_gate()?;
            let mut wtxn = self
                .env
                .write_txn()
                .map_err(|e| UtxoError(format!("begin snapshot tx: {}", e)))?;

            // TOCTOU-safe emptiness check inside the (initial) write txn.
            if !self
                .utxos
                .is_empty(&wtxn)
                .map_err(|e| UtxoError(format!("is_empty check: {}", e)))?
            {
                return Err(SnapshotLoadError::Storage(
                    "UTXO set must be empty before loading snapshot".into(),
                ));
            }

            let mut txid = [0u8; 32];
            let mut buf2 = [0u8; 2];
            let mut buf4 = [0u8; 4];
            let mut buf8 = [0u8; 8];
            let mut hasher = Sha256::new();
            let mut muhash = MuHash3072::new();
            let mut prev_key: Option<[u8; UTXO_KEY_LEN]> = None;
            // Reuse a single allocation for the value buffer across the inner loop.
            let mut value_buf: Vec<u8> = Vec::with_capacity(UTXO_VALUE_HEADER_LEN + 64);

            for i in 0..utxo_count {
                r.read_exact(&mut txid)
                    .map_err(|e| SnapshotLoadError::Invalid(format!("read txid at {}: {}", i, e)))?;
                r.read_exact(&mut buf4)
                    .map_err(|e| SnapshotLoadError::Invalid(format!("read vout at {}: {}", i, e)))?;
                let vout = u32::from_le_bytes(buf4);

                r.read_exact(&mut buf8)
                    .map_err(|e| SnapshotLoadError::Invalid(format!("read amount at {}: {}", i, e)))?;
                let amount = u64::from_le_bytes(buf8);
                if amount > MAX_MONEY {
                    return Err(SnapshotLoadError::Invalid(format!(
                        "snapshot entry {}: amount {} exceeds MAX_MONEY",
                        i, amount
                    )));
                }

                r.read_exact(&mut buf4)
                    .map_err(|e| SnapshotLoadError::Invalid(format!("read entry height at {}: {}", i, e)))?;
                let entry_height = u32::from_le_bytes(buf4);

                let mut cb_byte = [0u8; 1];
                r.read_exact(&mut cb_byte)
                    .map_err(|e| SnapshotLoadError::Invalid(format!("read is_coinbase at {}: {}", i, e)))?;
                let is_coinbase = cb_byte[0] != 0;

                r.read_exact(&mut buf2)
                    .map_err(|e| SnapshotLoadError::Invalid(format!("read script_len at {}: {}", i, e)))?;
                let script_len = u16::from_le_bytes(buf2) as usize;

                let mut script = vec![0u8; script_len];
                r.read_exact(&mut script)
                    .map_err(|e| SnapshotLoadError::Invalid(format!("read script at {}: {}", i, e)))?;

                // Build the LMDB key and assert strictly-ascending order so the
                // APPEND optimization stays valid across commits. (LMDB's APPEND
                // would error out anyway, but our message is clearer.)
                let key = utxo_key(&txid, vout);
                if let Some(ref prev) = prev_key {
                    if key.as_slice() <= prev.as_slice() {
                        return Err(SnapshotLoadError::Invalid(
                            "snapshot entries not sorted by (txid, vout)".into(),
                        ));
                    }
                }
                prev_key = Some(key);

                // Feed the canonical hash format BEFORE writing — a stream
                // corruption detected on read aborts before the *current*
                // batch is committed. Earlier already-committed batches are
                // wiped by the cleanup block on the way out.
                hasher.update(&txid);
                hasher.update(&vout.to_le_bytes());
                hasher.update(&amount.to_le_bytes());
                hasher.update(&(script_len as u16).to_le_bytes());
                hasher.update(&script);
                hasher.update(&entry_height.to_le_bytes());
                hasher.update(&[is_coinbase as u8]);

                // MuHash accumulator — Core-compatible serialization
                let coin_ser = serialize_coin_for_muhash(
                    &txid,
                    vout,
                    entry_height,
                    is_coinbase,
                    amount as i64,
                    &script,
                );
                muhash = muhash.insert(&coin_ser);

                // Encode the value.
                value_buf.clear();
                value_buf.extend_from_slice(&amount.to_le_bytes());
                value_buf.extend_from_slice(&entry_height.to_le_bytes());
                value_buf.push(if is_coinbase { FLAG_COINBASE } else { 0 });
                value_buf.extend_from_slice(&script);

                self.utxos
                    .put_with_flags(&mut wtxn, PutFlags::APPEND, &key, &value_buf)
                    .map_err(|e| UtxoError(format!("append utxo {}: {}", i, e)))?;

                // Note: `height_index` is intentionally NOT populated for
                // snapshot rows — see the doc comment on this function.

                // Periodic commit + reopen so LMDB's per-txn dirty list
                // doesn't pile up. The next key in the stream is still
                // strictly greater than the new max key in the DB, so
                // APPEND keeps working in the new txn.
                let next_i = i + 1;
                if next_i < utxo_count && next_i % SNAPSHOT_LOAD_BATCH == 0 {
                    wtxn.commit().map_err(|e| {
                        UtxoError(format!("commit batch at {}: {}", next_i, e))
                    })?;
                    // Between batches no txn is open, so this is where the
                    // map can grow before it fills mid-batch (ticket 030).
                    if self.snapshot_map_low() {
                        drop(gate);
                        let used = self.env.real_disk_size().unwrap_or(0);
                        self.grow_map(used + sizing().headroom)?;
                        gate = self.read_gate()?;
                    }
                    wtxn = self.env.write_txn().map_err(|e| {
                        UtxoError(format!("reopen tx at {}: {}", next_i, e))
                    })?;
                }

                // `false` from the callback cancels (e.g. the app saw free
                // space drop below its threshold). The cleanup block below
                // wipes the committed batches; the file itself is fine.
                if i % 100_000 == 0 && !on_progress(i, utxo_count) {
                    return Err(SnapshotLoadError::Storage(format!(
                        "snapshot load cancelled at entry {} of {}",
                        i, utxo_count
                    )));
                }
            }

            // Verify hash BEFORE the final commit. If this fails, the
            // in-flight wtxn rolls back and the cleanup block wipes any
            // earlier batched commits.
            let loaded_hash: [u8; 32] = hasher.finalize().into();
            if loaded_hash != file_hash {
                return Err(SnapshotLoadError::Invalid(format!(
                    "snapshot verification failed: loaded={}, expected={}",
                    hex::encode(loaded_hash),
                    hex::encode(file_hash)
                )));
            }

            // Finalize the MuHash accumulator — produces a 32-byte hash
            // compatible with `bitcoin-cli gettxoutsetinfo muhash`.
            let muhash_result = muhash.finalize();

            // Record the assume-valid floor so `rollback_block` can refuse
            // to roll back into snapshot territory across process restarts.
            // Written in the same txn as the final batch so a commit failure
            // (or earlier hash failure causing rollback) leaves no orphan.
            self.meta
                .put(
                    &mut wtxn,
                    META_KEY_ASSUME_VALID_FLOOR,
                    &height.to_le_bytes(),
                )
                .map_err(|e| UtxoError(format!("put assume_valid_floor: {}", e)))?;
            self.meta
                .put(&mut wtxn, META_KEY_SNAPSHOT_BLOCK_HASH, &block_hash)
                .map_err(|e| UtxoError(format!("put snapshot_block_hash: {}", e)))?;
            self.meta
                .put(&mut wtxn, META_KEY_BEST_BLOCK, &encode_best_block(height, &block_hash))
                .map_err(|e| UtxoError(format!("put best_block: {}", e)))?;

            // Persist the MuHash for UI display and independent verification.
            self.meta
                .put(&mut wtxn, META_KEY_MUHASH, &muhash_result)
                .map_err(|e| UtxoError(format!("put muhash: {}", e)))?;

            wtxn.commit()
                .map_err(|e| UtxoError(format!("commit snapshot: {}", e)))?;
            Ok(())
        })();

        // ── Cleanup / commit ──────────────────────────────────────
        match load_result {
            Ok(()) => {
                // Force a synchronous flush of all data + meta pages so
                // the marker file can be removed safely. NO_META_SYNC
                // doesn't disable explicit force_sync.
                self.env
                    .force_sync()
                    .map_err(|e| UtxoError(format!("force_sync after load: {}", e)))?;
                // Marker removal proves the load completed end-to-end.
                fs::remove_file(&marker).map_err(|e| {
                    UtxoError(format!(
                        "remove loading marker {}: {}",
                        marker.display(),
                        e
                    ))
                })?;
            }
            Err(e) => {
                // Wipe any partial state so the next load can start from
                // empty. The marker is only removed if BOTH the wipe and
                // the sync succeed — otherwise we leave it on disk so
                // `open()` will wipe again on next start. Removing the
                // marker after a failed clear_all would strand partial
                // data with no recovery signal, which is unrecoverable
                // without manual intervention.
                let cleanup_ok =
                    self.clear_all().is_ok() && self.env.force_sync().is_ok();
                if cleanup_ok {
                    let _ = fs::remove_file(&marker);
                }
                return Err(e);
            }
        }

        let _ = on_progress(utxo_count, utxo_count);

        info!(
            "UTXO snapshot loaded and verified: {} utxos at height {}",
            utxo_count, height
        );

        Ok(SnapshotMeta {
            height,
            block_hash,
            utxo_count,
            utxo_hash: file_hash,
        })
    }

    /// True when less than `SNAPSHOT_GROW_TRIGGER` of the map is left
    /// beyond the data file (LMDB extends the file as pages are written,
    /// so its size tracks the highest page in use).
    fn snapshot_map_low(&self) -> bool {
        let used = self.env.real_disk_size().unwrap_or(0);
        let trigger = SNAPSHOT_GROW_TRIGGER.min(sizing().headroom);
        self.map_size().saturating_sub(used) < trigger
    }

    /// Wipe every named DB inside the env in a single transaction. Used by
    /// the snapshot-load error path to clear partial state from earlier
    /// batched commits before returning the error to the caller.
    fn clear_all(&self) -> Result<(), UtxoError> {
        let _gate = self.read_gate()?;
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("clear_all begin tx: {}", e)))?;
        self.utxos
            .clear(&mut wtxn)
            .map_err(|e| UtxoError(format!("clear_all utxos: {}", e)))?;
        self.undo
            .clear(&mut wtxn)
            .map_err(|e| UtxoError(format!("clear_all undo: {}", e)))?;
        self.height_index
            .clear(&mut wtxn)
            .map_err(|e| UtxoError(format!("clear_all height_index: {}", e)))?;
        self.meta
            .clear(&mut wtxn)
            .map_err(|e| UtxoError(format!("clear_all meta: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("clear_all commit: {}", e)))?;
        Ok(())
    }

    /// Check if any UTXOs exist at the given block height.
    /// Crash-recovery fallback for legacy databases only (no best-block
    /// marker, see `HeaderSync::utxo_has_block`): it can't tell two blocks
    /// at one height apart, and misses blocks whose outputs are all
    /// OP_RETURN or spent in-block.
    pub fn has_utxos_at_height(&self, height: u32) -> Result<bool, UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let prefix = height.to_be_bytes();
        let mut iter = self
            .height_index
            .prefix_iter(&rtxn, &prefix)
            .map_err(|e| UtxoError(format!("prefix iter: {}", e)))?;
        match iter.next() {
            Some(Ok(_)) => Ok(true),
            Some(Err(e)) => Err(UtxoError(format!("prefix iter row: {}", e))),
            None => Ok(false),
        }
    }

    /// Get the number of UTXOs in the set.
    pub fn count(&self) -> Result<u64, UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        self.utxos
            .len(&rtxn)
            .map_err(|e| UtxoError(format!("len: {}", e)))
    }
}

impl Drop for UtxoSet {
    /// Force heed to actually close the LMDB env when the last `UtxoSet`
    /// on this path goes away.
    ///
    /// Without this, heed's process-global `OPENED_ENV` cache holds an
    /// extra `Arc<EnvInner>` for every opened path, so the underlying env
    /// stays mapped for the lifetime of the process — even after every
    /// user-facing `Env` handle has been dropped. That's harmless for a
    /// long-running iOS node, but it breaks two important cases:
    ///
    /// 1. **Crash-recovery wipe in `open()`** — if a process restart
    ///    detects a stale `<env>.loading` marker, we `remove_dir_all` the
    ///    env directory and reopen. With heed's stale cache entry still
    ///    around, the reopen would return the *old* `Env` (still mmap'd to
    ///    the now-unlinked file) instead of a fresh empty one.
    /// 2. **Tests** that simulate restart by dropping a `UtxoSet` and
    ///    reopening the same path.
    ///
    /// Only the last user does this (see `EnvSlot`): `prepare_for_closing`
    /// marks heed's entry as closing, and every later open of the path
    /// fails with `DatabaseClosing` until the env is really gone, so doing
    /// it while another `UtxoSet` still holds the env would break it.
    fn drop(&mut self) {
        // SAFETY: `self.env` is not used again after this.
        let env = unsafe { ManuallyDrop::take(&mut self.env) };
        release_env(&self.canonical, env);
    }
}

/// Drop one user's handle on the env at `canonical`; the last user closes
/// it (synchronously, under the registry lock, so a concurrent open can't
/// see heed's entry half torn down) and remembers its map size.
fn release_env(canonical: &Path, env: Env) {
    let mut registry = env_registry();
    let last = match registry.get_mut(canonical) {
        Some(slot) => {
            slot.users = slot.users.saturating_sub(1);
            if slot.users == 0 {
                if let Some(shared) = slot.shared.take() {
                    slot.remembered = shared.map_size.load(Ordering::Acquire);
                }
                true
            } else {
                false
            }
        }
        None => true,
    };
    if last {
        // Takes heed's cached `Arc` out; with ours dropped at the end of the
        // call that was the last reference, so `mdb_env_close` runs here.
        let _ = env.prepare_for_closing();
    } else {
        drop(env);
    }
}

/// `n` rounded up to a multiple of `granule`, saturating at `u64::MAX`.
/// A corrupt snapshot header can announce ~2^64 entries; the plain
/// product overflowed there (a panic in debug builds, a map size wrapped
/// to 0 in release) instead of failing the capacity check.
fn round_up(n: u64, granule: u64) -> u64 {
    n.div_ceil(granule).saturating_mul(granule)
}

/// Map sizes to try, largest first, for an env whose `data.mdb` is
/// `data_len` bytes. All are whole GiB (a multiple of every page size).
/// The first is the preferred size; the rest are fallbacks for when the
/// address space can't be reserved, ending at data + `MIN_MAP_HEADROOM`.
/// (`_with` takes the sizing knobs so tests can shrink them.)
#[cfg(test)]
fn map_size_candidates(data_len: u64) -> Vec<u64> {
    map_size_candidates_with(data_len, &DEFAULT_SIZING)
}

fn map_size_candidates_with(data_len: u64, sz: &MapSizing) -> Vec<u64> {
    let round_up = |n: u64| round_up(n, sz.granule);
    let floor = round_up(data_len + sz.headroom);
    let preferred = round_up(data_len.saturating_mul(2))
        .clamp(sz.min, sz.max)
        .max(floor);
    let mut sizes = vec![preferred];
    let mut next = preferred / 2;
    while next > floor {
        sizes.push(round_up(next));
        next /= 2;
    }
    if *sizes.last().unwrap() != floor {
        sizes.push(floor);
    }
    sizes
}

// ── Encoding helpers ────────────────────────────────────────────────

/// Path of the "snapshot load in progress" sentinel for an LMDB env at
/// `env_dir`. Stored as a sibling file (`<env_dir><suffix>`) rather than
/// inside the env directory so it can't collide with LMDB's own files
/// and survives a `remove_dir_all(env_dir)` wipe.
fn loading_marker_path(env_dir: &Path) -> PathBuf {
    let mut p = env_dir.to_path_buf();
    let new_name = match env_dir.file_name() {
        Some(name) => {
            let mut s = name.to_os_string();
            s.push(SNAPSHOT_LOADING_MARKER_SUFFIX);
            s
        }
        None => std::ffi::OsString::from(SNAPSHOT_LOADING_MARKER_SUFFIX),
    };
    p.set_file_name(new_name);
    p
}

/// RAII guard that restores the env's default sync flags when dropped, no
/// matter how the snapshot-load function exits. Constructed only after the
/// caller has *enabled* one or more "unsafe" flags (e.g. `NO_META_SYNC`)
/// and trusts the guard to disable them again.
struct FlagGuard<'a> {
    env: &'a Env,
    flags_to_clear: EnvFlags,
}

impl Drop for FlagGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: Disabling NO_SYNC / NO_META_SYNC restores conservative
        // defaults — the unsafety in `set_flags` is on the *enable* side.
        // Errors here are ignored because Drop has nowhere to report them
        // and leaving a flag enabled is no worse than the current state.
        unsafe {
            let _ = self
                .env
                .set_flags(self.flags_to_clear, FlagSetMode::Disable);
        }
    }
}

/// `txid(32) || vout(4 BE)` — BE so the natural lex sort matches the
/// `(txid, vout)` ordering used by snapshots.
fn utxo_key(txid: &[u8; 32], vout: u32) -> [u8; UTXO_KEY_LEN] {
    let mut k = [0u8; UTXO_KEY_LEN];
    k[..32].copy_from_slice(txid);
    k[32..].copy_from_slice(&vout.to_be_bytes());
    k
}

/// `block_height(4 BE) || idx(4 BE)` — BE on both fields so undo entries
/// scan as a contiguous range per height for prune/rollback.
fn undo_key(height: u32, idx: u32) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[..4].copy_from_slice(&height.to_be_bytes());
    k[4..].copy_from_slice(&idx.to_be_bytes());
    k
}

/// `height(4 BE) || txid(32) || vout(4 BE)` — height-prefixed so a single
/// `prefix_iter` returns every UTXO created at that block height.
fn height_index_key(height: u32, txid: &[u8; 32], vout: u32) -> [u8; HEIGHT_INDEX_KEY_LEN] {
    let mut k = [0u8; HEIGHT_INDEX_KEY_LEN];
    k[..4].copy_from_slice(&height.to_be_bytes());
    k[4..36].copy_from_slice(txid);
    k[36..].copy_from_slice(&vout.to_be_bytes());
    k
}

/// `amount(8 LE) || height(4 LE) || flags(1) || script(rest)`
fn encode_utxo_value(entry: &UtxoEntry) -> Vec<u8> {
    let mut v = Vec::with_capacity(UTXO_VALUE_HEADER_LEN + entry.script_pubkey.len());
    v.extend_from_slice(&entry.amount.to_le_bytes());
    v.extend_from_slice(&entry.height.to_le_bytes());
    v.push(if entry.is_coinbase { FLAG_COINBASE } else { 0 });
    v.extend_from_slice(&entry.script_pubkey);
    v
}

fn decode_utxo_value(bytes: &[u8]) -> Result<UtxoEntry, UtxoError> {
    if bytes.len() < UTXO_VALUE_HEADER_LEN {
        return Err(UtxoError(format!(
            "corrupt utxo value: len {} < {}",
            bytes.len(),
            UTXO_VALUE_HEADER_LEN
        )));
    }
    let amount = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    if amount > MAX_MONEY {
        return Err(UtxoError(format!(
            "corrupt UTXO: amount {} exceeds MAX_MONEY",
            amount
        )));
    }
    let height = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let flags = bytes[12];
    let is_coinbase = (flags & FLAG_COINBASE) != 0;
    let script_pubkey = bytes[UTXO_VALUE_HEADER_LEN..].to_vec();
    Ok(UtxoEntry {
        amount,
        script_pubkey,
        height,
        is_coinbase,
    })
}

/// `txid(32) || vout(4 LE) || amount(8 LE) || orig_height(4 LE) || flags(1) || script`
fn encode_undo_value(txid: &[u8; 32], vout: u32, entry: &UtxoEntry) -> Vec<u8> {
    let mut v = Vec::with_capacity(UNDO_VALUE_HEADER_LEN + entry.script_pubkey.len());
    v.extend_from_slice(txid);
    v.extend_from_slice(&vout.to_le_bytes());
    v.extend_from_slice(&entry.amount.to_le_bytes());
    v.extend_from_slice(&entry.height.to_le_bytes());
    v.push(if entry.is_coinbase { FLAG_COINBASE } else { 0 });
    v.extend_from_slice(&entry.script_pubkey);
    v
}

fn decode_undo_value(bytes: &[u8]) -> Result<([u8; 32], u32, UtxoEntry), UtxoError> {
    if bytes.len() < UNDO_VALUE_HEADER_LEN {
        return Err(UtxoError(format!(
            "corrupt undo value: len {} < {}",
            bytes.len(),
            UNDO_VALUE_HEADER_LEN
        )));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&bytes[0..32]);
    let vout = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
    let amount = u64::from_le_bytes(bytes[36..44].try_into().unwrap());
    if amount > MAX_MONEY {
        return Err(UtxoError(format!(
            "corrupt undo: amount {} exceeds MAX_MONEY",
            amount
        )));
    }
    let orig_height = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
    let flags = bytes[48];
    let is_coinbase = (flags & FLAG_COINBASE) != 0;
    let script_pubkey = bytes[UNDO_VALUE_HEADER_LEN..].to_vec();
    Ok((
        txid,
        vout,
        UtxoEntry {
            amount,
            script_pubkey,
            height: orig_height,
            is_coinbase,
        },
    ))
}

#[derive(Debug)]
pub struct UtxoError(pub String);

impl std::fmt::Display for UtxoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "utxo error: {}", self.0)
    }
}

impl std::error::Error for UtxoError {}

// ── Test helpers ────────────────────────────────────────────────────
//
// These exist only under `cfg(test)` so we can write surgical state-setup
// in tests that exercised raw SQL inserts in the SQLite version. Production
// code goes through `apply_block` / `rollback_block` exclusively.

#[cfg(test)]
impl UtxoSet {
    /// Insert a UTXO directly. Bypasses block validation; tests use this to
    /// simulate "this UTXO existed before the block we're about to roll back".
    /// `pub(crate)` so the mempool test suite can build a populated UTXO set
    /// without going through `apply_block`.
    pub(crate) fn test_insert_utxo(
        &self,
        txid: [u8; 32],
        vout: u32,
        entry: UtxoEntry,
    ) -> Result<(), UtxoError> {
        let _gate = self.read_gate()?;
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin: {}", e)))?;
        let key = utxo_key(&txid, vout);
        let val = encode_utxo_value(&entry);
        self.utxos
            .put(&mut wtxn, &key, &val)
            .map_err(|e| UtxoError(format!("put: {}", e)))?;
        let hi_k = height_index_key(entry.height, &txid, vout);
        self.height_index
            .put(&mut wtxn, &hi_k, &())
            .map_err(|e| UtxoError(format!("put hi: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Insert raw bytes into the utxos DB. For corruption-detection tests
    /// that need to plant a value the encoder would reject.
    fn test_insert_raw_utxo(
        &self,
        txid: [u8; 32],
        vout: u32,
        raw_value: &[u8],
    ) -> Result<(), UtxoError> {
        let _gate = self.read_gate()?;
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin: {}", e)))?;
        let key = utxo_key(&txid, vout);
        self.utxos
            .put(&mut wtxn, &key, raw_value)
            .map_err(|e| UtxoError(format!("put: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Insert an undo entry directly. Used to set up rollback tests without
    /// going through a real apply_block first.
    fn test_insert_undo(
        &self,
        block_height: u32,
        idx: u32,
        txid: [u8; 32],
        vout: u32,
        entry: UtxoEntry,
    ) -> Result<(), UtxoError> {
        let _gate = self.read_gate()?;
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin: {}", e)))?;
        let k = undo_key(block_height, idx);
        let v = encode_undo_value(&txid, vout, &entry);
        self.undo
            .put(&mut wtxn, &k, &v)
            .map_err(|e| UtxoError(format!("put: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Count of undo entries currently persisted (across all heights).
    fn test_count_undo(&self) -> Result<u64, UtxoError> {
        let _gate = self.read_gate()?;
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        self.undo
            .len(&rtxn)
            .map_err(|e| UtxoError(format!("len: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Block;
    use bitcoin::consensus::deserialize;
    use tempfile::TempDir;

    /// Open a fresh UtxoSet backed by a temp directory. The TempDir is
    /// returned so the caller keeps it alive (drop = cleanup).
    fn fresh() -> (UtxoSet, TempDir) {
        let dir = TempDir::new().unwrap();
        let utxo = UtxoSet::open(dir.path().to_str().unwrap()).unwrap();
        (utxo, dir)
    }

    /// Build a synthetic snapshot byte stream containing `n` distinct UTXOs
    /// with strictly increasing txids (`[0;32]`, `[1;32]`, ...). The
    /// returned anchor matches the snapshot's header and content hash,
    /// suitable for passing to `load_snapshot` as `Some(&anchor)`.
    ///
    /// Used by the periodic-commit and clear_all tests to drive
    /// `SNAPSHOT_LOAD_BATCH` (which is lowered to 4 under cfg(test))
    /// across multiple batch boundaries with a small entry count.
    fn make_snapshot_with_n_utxos(n: u8) -> (Vec<u8>, SnapshotAnchor) {
        let (utxo, _dir) = fresh();
        for i in 0..n {
            let mut txid = [0u8; 32];
            txid[0] = i;
            utxo.test_insert_utxo(
                txid,
                0,
                UtxoEntry {
                    amount: 1000 + i as u64,
                    script_pubkey: vec![0xac],
                    height: 1,
                    is_coinbase: false,
                },
            )
            .unwrap();
        }
        let mut buf = Vec::new();
        let meta = utxo.write_snapshot(&mut buf, 1, &[0u8; 32]).unwrap();
        (buf, anchor_of(&meta))
    }

    /// The anchor a written snapshot commits to (header fields + hash).
    fn anchor_of(meta: &SnapshotMeta) -> SnapshotAnchor {
        SnapshotAnchor {
            height: meta.height,
            block_hash: meta.block_hash,
            utxo_hash: meta.utxo_hash,
        }
    }

    /// The full genesis block (header + coinbase transaction).
    fn genesis_block() -> Block {
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c\
             01\
             01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030\
             39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e6420\
             6261696c6f757420666f722062616e6b73ffffffff0100f2052a010000004341\
             0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c\
             52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858\
             eeac00000000",
        )
        .unwrap();
        deserialize(&raw).unwrap()
    }

    #[test]
    fn map_size_candidates_fresh_env_prefers_floor_of_32_gib() {
        let c = map_size_candidates(0);
        assert_eq!(c[0], 32 * GIB);
        assert_eq!(*c.last().unwrap(), 4 * GIB);
        assert!(c.windows(2).all(|w| w[0] > w[1]), "strictly decreasing: {:?}", c);
    }

    #[test]
    fn map_size_candidates_grow_with_data_file() {
        // Full mainnet UTXO set: ~12 GiB on disk -> 2x = 24 GiB < floor, so 32.
        assert_eq!(map_size_candidates(12 * GIB)[0], 32 * GIB);
        // Larger env: 2x, rounded up to whole GiB.
        assert_eq!(map_size_candidates(20 * GIB + 1)[0], 41 * GIB);
        // Capped at MAX_MAP_SIZE, but never below data + headroom.
        assert_eq!(map_size_candidates(100 * GIB)[0], 128 * GIB);
        assert_eq!(map_size_candidates(130 * GIB)[0], 134 * GIB);
        for len in [0, GIB, 12 * GIB, 20 * GIB + 1, 100 * GIB] {
            let c = map_size_candidates(len);
            assert!(c.iter().all(|s| s % GIB == 0 && *s >= len + MIN_MAP_HEADROOM));
            assert_eq!(*c.last().unwrap(), (len + MIN_MAP_HEADROOM).div_ceil(GIB) * GIB);
        }
    }

    #[test]
    fn reopen_with_existing_data_uses_larger_map() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("utxo-lmdb");
        {
            let set = UtxoSet::open(path.to_str().unwrap()).unwrap();
            set.apply_block(&genesis_block(), 0).unwrap();
        }
        let set = UtxoSet::open(path.to_str().unwrap()).unwrap();
        assert_eq!(set.count().unwrap(), 1);
        assert!(set.env.info().map_size >= (32 * GIB) as usize);
    }

    /// Shrink the map-sizing knobs for this test thread so a few MiB of data
    /// exercise growth (the real floor is 32 GiB). Restored on drop.
    struct SmallMaps;
    impl SmallMaps {
        fn install() -> SmallMaps {
            TEST_SIZING.with(|c| {
                c.set(Some(MapSizing {
                    min: 1 << 20,
                    max: GIB,
                    headroom: 1 << 20,
                    granule: 1 << 20,
                }))
            });
            SmallMaps
        }
    }
    impl Drop for SmallMaps {
        fn drop(&mut self) {
            TEST_SIZING.with(|c| c.set(None));
        }
    }

    /// A coinbase-only block whose single tx carries `outputs` outputs with
    /// `script_len`-byte scripts (~`outputs * script_len` bytes of UTXOs).
    /// `tag` makes the txid unique per block.
    fn fat_block(tag: u32, outputs: u32, script_len: usize) -> Block {
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Transaction, TxIn, TxOut};
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::from_consensus(tag),
            input: vec![TxIn::default()],
            output: (0..outputs)
                .map(|i| TxOut {
                    value: Amount::from_sat(1_000 + i as u64),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51; script_len]),
                })
                .collect(),
        };
        Block { header: genesis_block().header, txdata: vec![tx] }
    }

    #[test]
    fn same_path_opened_twice_after_growth_shares_one_env() {
        // Ticket 030: the map size depends on data.mdb's size at open, and
        // heed rejects a second open of a live path with different options
        // (BadOpenOptions). A push-wake node opening the env while the
        // foreground node is running, after the data file grew, must still
        // succeed, and the map must grow in place on MDB_MAP_FULL.
        let _small = SmallMaps::install();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("utxo-lmdb");
        let path = path.to_str().unwrap();

        let a = UtxoSet::open(path).unwrap();
        let initial_map = a.map_size();
        // ~6 MiB of UTXOs into a 1 MiB map: only works if MAP_FULL grows it.
        for tag in 0..40 {
            a.apply_block(&fat_block(tag, 300, 500), tag).unwrap();
        }
        assert!(a.map_size() > initial_map, "map should have grown from {}", initial_map);
        let data_len = fs::metadata(Path::new(path).join("data.mdb")).unwrap().len();
        assert!(
            map_size_candidates_with(data_len, &sizing())[0] != initial_map,
            "test needs the fresh-open size to differ from the live env's"
        );

        // Second open while `a` is live: same env, no BadOpenOptions.
        let b = UtxoSet::open(path).unwrap();
        assert_eq!(b.count().unwrap(), a.count().unwrap());
        b.apply_block(&fat_block(1000, 10, 500), 1000).unwrap();
        assert_eq!(a.count().unwrap(), b.count().unwrap());

        // Dropping one user must not close the env under the other, nor
        // make later opens fail with DatabaseClosing.
        let expected = b.count().unwrap();
        drop(a);
        assert_eq!(b.count().unwrap(), expected);
        let c = UtxoSet::open(path).unwrap();
        assert_eq!(c.count().unwrap(), expected);
        drop(b);
        drop(c);

        // Full close, then reopen: starts from the remembered (grown) size.
        let d = UtxoSet::open(path).unwrap();
        assert_eq!(d.count().unwrap(), expected);
        assert!(d.map_size() as u64 >= data_len);
    }

    /// BIP 30 guard (ticket 026): re-creating an unspent output trips the
    /// debug assertion instead of silently overwriting it.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "BIP 30")]
    fn apply_block_overwriting_unspent_output_asserts() {
        let (utxo, _dir) = fresh();
        utxo.apply_block(&genesis_block(), 0).unwrap();
        // Same coinbase again: same txid, output 0 still unspent.
        let _ = utxo.apply_block(&genesis_block(), 1);
    }

    #[test]
    fn ensure_map_capacity_fails_cleanly_without_address_space() {
        let (utxo, _dir) = fresh();
        utxo.apply_block(&genesis_block(), 0).unwrap();
        let before = utxo.map_size();
        // No process can reserve 2^62 bytes: the probe fails, so the env
        // must be left mapped and usable (not poisoned).
        let err = utxo.ensure_map_capacity(1 << 62).unwrap_err();
        assert!(err.0.contains("can't map the UTXO set"), "got: {}", err);
        assert_eq!(utxo.map_size(), before);
        assert_eq!(utxo.count().unwrap(), 1);
        utxo.ensure_map_capacity(before).unwrap();
    }

    #[test]
    fn snapshot_load_grows_map_between_batches() {
        // Source set with ~3 MiB of entries (few, large: every batch of 4
        // commits with an fsync), written at default sizing.
        let (src, _src_dir) = fresh();
        for i in 0..250u32 {
            let mut txid = [0u8; 32];
            txid[..4].copy_from_slice(&i.to_be_bytes());
            src.test_insert_utxo(
                txid,
                0,
                UtxoEntry { amount: 1, script_pubkey: vec![0x51; 12_000], height: 1, is_coinbase: false },
            )
            .unwrap();
        }
        let mut buf = Vec::new();
        let meta = src.write_snapshot(&mut buf, 1, &[0u8; 32]).unwrap();

        let _small = SmallMaps::install();
        let dir = TempDir::new().unwrap();
        let dst = UtxoSet::open(dir.path().join("utxo").to_str().unwrap()).unwrap();
        let initial_map = dst.map_size();
        dst.load_snapshot(std::io::Cursor::new(&buf), Some(&anchor_of(&meta)), |_, _| true)
            .unwrap();
        assert_eq!(dst.count().unwrap(), 250);
        assert!(dst.map_size() > initial_map);
    }

    #[test]
    fn snapshot_load_errors_say_whether_the_file_is_bad() {
        let (buf, anchor) = make_snapshot_with_n_utxos(10);

        // Cancelled from the progress callback: a storage error (keep the
        // file), and the env is left empty for a retry.
        let (utxo, _dir) = fresh();
        let err = utxo
            .load_snapshot(std::io::Cursor::new(&buf), Some(&anchor), |_, _| false)
            .unwrap_err();
        assert!(matches!(err, SnapshotLoadError::Storage(ref m) if m.contains("cancelled")), "got: {}", err);
        assert_eq!(utxo.count().unwrap(), 0);
        utxo.load_snapshot(std::io::Cursor::new(&buf), Some(&anchor), |_, _| true)
            .unwrap();

        // Wrong content hash: the file is bad.
        let (utxo, _dir) = fresh();
        let wrong = SnapshotAnchor { utxo_hash: [0xEE; 32], ..anchor };
        let err = utxo
            .load_snapshot(std::io::Cursor::new(&buf), Some(&wrong), |_, _| true)
            .unwrap_err();
        assert!(matches!(err, SnapshotLoadError::Invalid(_)), "got: {}", err);

        // Truncated stream: the file is bad.
        let (utxo, _dir) = fresh();
        let err = utxo
            .load_snapshot(std::io::Cursor::new(&buf[..buf.len() - 3]), Some(&anchor), |_, _| true)
            .unwrap_err();
        assert!(matches!(err, SnapshotLoadError::Invalid(_)), "got: {}", err);
    }

    #[test]
    fn empty_utxo_set_has_zero_count() {
        let (utxo, _dir) = fresh();
        assert_eq!(utxo.count().unwrap(), 0);
    }

    #[test]
    fn get_missing_utxo_returns_none() {
        let (utxo, _dir) = fresh();
        let txid = Txid::from_byte_array([0u8; 32]);
        assert!(utxo.get(&txid, 0).unwrap().is_none());
    }

    #[test]
    fn apply_genesis_creates_one_utxo() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);

        let coinbase_txid = genesis.txdata[0].compute_txid();
        let entry = utxo.get(&coinbase_txid, 0).unwrap().unwrap();
        assert_eq!(entry.amount, 50 * 100_000_000);
        assert!(entry.is_coinbase);
        assert_eq!(entry.height, 0);
    }

    #[test]
    fn rollback_genesis_restores_empty_set() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);

        utxo.rollback_block(0).unwrap();
        assert_eq!(utxo.count().unwrap(), 0);

        let coinbase_txid = genesis.txdata[0].compute_txid();
        assert!(utxo.get(&coinbase_txid, 0).unwrap().is_none());
    }

    #[test]
    fn best_block_tracks_apply_and_rollback() {
        let (utxo, _dir) = fresh();
        assert_eq!(utxo.best_block().unwrap(), None, "fresh set has no best block");
        let genesis = genesis_block();
        let hash = genesis.block_hash().to_byte_array();
        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.best_block().unwrap(), Some((0, hash)));

        utxo.test_insert_utxo([2u8; 32], 0, UtxoEntry {
            amount: 500,
            script_pubkey: vec![0x51],
            height: 1,
            is_coinbase: false,
        })
        .unwrap();
        utxo.rollback_block_to(1, hash).unwrap();
        assert_eq!(utxo.best_block().unwrap(), Some((0, hash)));

        // The test-only rollback can't name the parent: marker becomes unknown.
        utxo.rollback_block(0).unwrap();
        assert_eq!(utxo.best_block().unwrap(), None);
    }

    #[test]
    fn apply_and_rollback_roundtrip() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);
        utxo.rollback_block(0).unwrap();
        assert_eq!(utxo.count().unwrap(), 0);
    }

    #[test]
    fn rollback_restores_spent_utxos() {
        let (utxo, _dir) = fresh();

        // Plant a UTXO at height 5 (the "previous" output) and an undo entry
        // at height 10 saying "block 10 spent it". Then plant the new output
        // block 10 created. Rolling back block 10 should remove the new
        // output and restore the old one.
        let old_entry = UtxoEntry {
            amount: 1000,
            script_pubkey: vec![0x76, 0xa9],
            height: 5,
            is_coinbase: false,
        };
        let new_entry = UtxoEntry {
            amount: 500,
            script_pubkey: vec![0x76, 0xa9],
            height: 10,
            is_coinbase: false,
        };

        utxo.test_insert_undo(10, 0, [1u8; 32], 0, old_entry.clone())
            .unwrap();
        utxo.test_insert_utxo([2u8; 32], 0, new_entry).unwrap();

        let txid_old = Txid::from_byte_array([1u8; 32]);
        let txid_new = Txid::from_byte_array([2u8; 32]);
        assert_eq!(utxo.count().unwrap(), 1);
        assert!(utxo.get(&txid_old, 0).unwrap().is_none());
        assert!(utxo.get(&txid_new, 0).unwrap().is_some());

        utxo.rollback_block(10).unwrap();

        assert_eq!(utxo.count().unwrap(), 1);
        let restored = utxo.get(&txid_old, 0).unwrap().unwrap();
        assert_eq!(restored.amount, 1000);
        assert_eq!(restored.height, 5);
        assert!(!restored.is_coinbase);
        assert!(utxo.get(&txid_new, 0).unwrap().is_none());
    }

    #[test]
    fn rollback_unwinds_chain_of_blocks_in_reverse_order() {
        // A multi-height reorg scenario. We build a "chain":
        //
        //   h=5  : create UTXO A (txid 0xaa)
        //   h=10 : create UTXO B (txid 0xbb), spend A (undo at h=10 restores A)
        //   h=11 : create UTXO C (txid 0xcc), spend B (undo at h=11 restores B)
        //   h=12 : create UTXO D (txid 0xdd), spend C (undo at h=12 restores C)
        //
        // After this seed, only D should be live ({A,B,C} are spent), and
        // there should be three undo records (one per spent height).
        //
        // We then roll back 12 → 11 → 10 → 5 in order and verify the live
        // UTXO set after each step:
        //
        //   after rollback(12): {C}
        //   after rollback(11): {B}
        //   after rollback(10): {A}
        //   after rollback(5):  {}
        //
        // This is the closest unit-level test we can write to a real reorg
        // — it exercises rollback's two-phase walk (delete-by-height +
        // undo-replay) across multiple heights and checks that the
        // height_index entries the next rollback depends on are correctly
        // re-planted by the undo step.
        let (utxo, _dir) = fresh();

        let mk = |amt: u64, h: u32, coinbase: bool| UtxoEntry {
            amount: amt,
            script_pubkey: vec![0xac],
            height: h,
            is_coinbase: coinbase,
        };
        let txid_a = [0xaa; 32];
        let txid_b = [0xbb; 32];
        let txid_c = [0xcc; 32];
        let txid_d = [0xdd; 32];

        // Seed the FINAL on-disk state (after all four blocks have been
        // applied): only D is live, and the undo log has restorations for
        // A, B, C at the heights that consumed them.
        utxo.test_insert_utxo(txid_d, 0, mk(40, 12, false)).unwrap();
        utxo.test_insert_undo(12, 0, txid_c, 0, mk(30, 11, false))
            .unwrap();
        utxo.test_insert_undo(11, 0, txid_b, 0, mk(20, 10, false))
            .unwrap();
        utxo.test_insert_undo(10, 0, txid_a, 0, mk(10, 5, false))
            .unwrap();

        let id_a = Txid::from_byte_array(txid_a);
        let id_b = Txid::from_byte_array(txid_b);
        let id_c = Txid::from_byte_array(txid_c);
        let id_d = Txid::from_byte_array(txid_d);

        assert_eq!(utxo.count().unwrap(), 1);
        assert_eq!(utxo.test_count_undo().unwrap(), 3);
        assert!(utxo.get(&id_d, 0).unwrap().is_some());

        // Step 1: rollback height 12 → D removed, C restored.
        utxo.rollback_block(12).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);
        assert!(utxo.get(&id_d, 0).unwrap().is_none());
        let restored_c = utxo
            .get(&id_c, 0)
            .unwrap()
            .expect("C should be restored after rollback(12)");
        assert_eq!(restored_c.amount, 30);
        assert_eq!(restored_c.height, 11);
        // The undo entry consumed by this rollback should be gone, but the
        // earlier ones remain.
        assert_eq!(utxo.test_count_undo().unwrap(), 2);

        // Step 2: rollback height 11 → C removed, B restored.
        utxo.rollback_block(11).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);
        assert!(utxo.get(&id_c, 0).unwrap().is_none());
        let restored_b = utxo
            .get(&id_b, 0)
            .unwrap()
            .expect("B should be restored after rollback(11)");
        assert_eq!(restored_b.amount, 20);
        assert_eq!(restored_b.height, 10);
        assert_eq!(utxo.test_count_undo().unwrap(), 1);

        // Step 3: rollback height 10 → B removed, A restored.
        utxo.rollback_block(10).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);
        assert!(utxo.get(&id_b, 0).unwrap().is_none());
        let restored_a = utxo
            .get(&id_a, 0)
            .unwrap()
            .expect("A should be restored after rollback(10)");
        assert_eq!(restored_a.amount, 10);
        assert_eq!(restored_a.height, 5);
        assert_eq!(utxo.test_count_undo().unwrap(), 0);

        // Step 4: rollback height 5 → A removed (no undo to replay; this
        // is the first block in the chain so it created A from nothing).
        // This is the same shape as the rollback_genesis_restores_empty_set
        // case, but we're verifying it works after a sequence of restorations.
        utxo.rollback_block(5).unwrap();
        assert_eq!(utxo.count().unwrap(), 0);
        assert!(utxo.get(&id_a, 0).unwrap().is_none());
    }

    #[test]
    fn rollback_handles_height_with_multiple_outputs_and_spends() {
        // Single block at height 7 that creates two UTXOs (X and Y) and
        // simultaneously spends two pre-existing UTXOs (P and Q from h=3).
        // Rolling back must:
        //   - delete both new outputs from `utxos` AND `height_index`
        //   - restore both spent inputs from the undo log
        //   - leave the undo log empty for height 7
        let (utxo, _dir) = fresh();
        let mk = |amt: u64, h: u32| UtxoEntry {
            amount: amt,
            script_pubkey: vec![0xac],
            height: h,
            is_coinbase: false,
        };

        let txid_x = [0x11; 32];
        let txid_y = [0x22; 32];
        let txid_p = [0x33; 32];
        let txid_q = [0x44; 32];

        // Final state: X and Y are live at h=7. P and Q have been spent
        // (so they're not in the live set) but their undo entries at h=7
        // can resurrect them.
        utxo.test_insert_utxo(txid_x, 0, mk(100, 7)).unwrap();
        utxo.test_insert_utxo(txid_y, 0, mk(200, 7)).unwrap();
        utxo.test_insert_undo(7, 0, txid_p, 0, mk(50, 3)).unwrap();
        utxo.test_insert_undo(7, 1, txid_q, 0, mk(75, 3)).unwrap();

        assert_eq!(utxo.count().unwrap(), 2);
        assert_eq!(utxo.test_count_undo().unwrap(), 2);

        utxo.rollback_block(7).unwrap();

        let id_x = Txid::from_byte_array(txid_x);
        let id_y = Txid::from_byte_array(txid_y);
        let id_p = Txid::from_byte_array(txid_p);
        let id_q = Txid::from_byte_array(txid_q);
        assert!(utxo.get(&id_x, 0).unwrap().is_none());
        assert!(utxo.get(&id_y, 0).unwrap().is_none());
        let restored_p = utxo.get(&id_p, 0).unwrap().expect("P restored");
        let restored_q = utxo.get(&id_q, 0).unwrap().expect("Q restored");
        assert_eq!(restored_p.amount, 50);
        assert_eq!(restored_p.height, 3);
        assert_eq!(restored_q.amount, 75);
        assert_eq!(restored_q.height, 3);
        // Live set is now {P, Q}; the undo log for height 7 is drained.
        assert_eq!(utxo.count().unwrap(), 2);
        assert_eq!(utxo.test_count_undo().unwrap(), 0);
    }

    #[test]
    fn prune_undo_removes_old_data() {
        let (utxo, _dir) = fresh();
        let dummy = UtxoEntry {
            amount: 100,
            script_pubkey: vec![0xac],
            height: 0,
            is_coinbase: false,
        };
        for h in [5u32, 10, 15, 20] {
            utxo.test_insert_undo(h, 0, [h as u8; 32], 0, dummy.clone())
                .unwrap();
        }

        utxo.prune_undo_below(15).unwrap();
        assert_eq!(utxo.test_count_undo().unwrap(), 2); // heights 15 and 20
    }

    #[test]
    fn corrupt_amount_detected_on_read() {
        let (utxo, _dir) = fresh();
        // Plant a value with amount = MAX_MONEY + 1, which decode_utxo_value
        // must reject as a corruption indicator.
        let bad_amount: u64 = MAX_MONEY + 1;
        let mut raw = Vec::new();
        raw.extend_from_slice(&bad_amount.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes()); // height
        raw.push(0); // flags
                     // No script bytes — header-only is fine for the decoder.
        utxo.test_insert_raw_utxo([9u8; 32], 0, &raw).unwrap();

        let txid = Txid::from_byte_array([9u8; 32]);
        let result = utxo.get(&txid, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds MAX_MONEY"));
    }

    #[test]
    fn compute_hash_deterministic() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();

        let hash1 = utxo.compute_hash().unwrap();
        let hash2 = utxo.compute_hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn snapshot_write_and_load_roundtrip() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo1.count().unwrap(), 1);

        let block_hash = [0xABu8; 32];
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 0, &block_hash).unwrap();
        assert_eq!(meta.height, 0);
        assert_eq!(meta.block_hash, block_hash);
        assert_eq!(meta.utxo_count, 1);

        let (utxo2, _dir2) = fresh();
        let loaded = utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&anchor_of(&meta)), |_, _| true)
            .unwrap();
        assert_eq!(loaded.height, 0);
        assert_eq!(loaded.utxo_count, 1);
        assert_eq!(utxo2.count().unwrap(), 1);
        assert_eq!(utxo2.best_block().unwrap(), Some((0, block_hash)), "snapshot sets best block");

        let coinbase_txid = genesis.txdata[0].compute_txid();
        let entry = utxo2.get(&coinbase_txid, 0).unwrap().unwrap();
        assert_eq!(entry.amount, 50 * 100_000_000);
        assert!(entry.is_coinbase);
        assert_eq!(utxo1.compute_hash().unwrap(), utxo2.compute_hash().unwrap());
    }

    #[test]
    fn snapshot_rejects_wrong_hash() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();

        let mut buf = Vec::new();
        utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let (utxo2, _dir2) = fresh();
        let result = utxo2.load_snapshot(
            std::io::Cursor::new(&buf),
            Some(&SnapshotAnchor {
                height: 0,
                block_hash: [0u8; 32],
                utxo_hash: [0xFFu8; 32],
            }),
            |_, _| true,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }

    #[test]
    fn snapshot_rejects_nonempty_set() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();

        let mut buf = Vec::new();
        utxo.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let result = utxo.load_snapshot(std::io::Cursor::new(&buf), None, |_, _| true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be empty"));
    }

    #[test]
    fn snapshot_rejects_bad_magic() {
        let (utxo, _dir) = fresh();
        let result = utxo.load_snapshot(
            std::io::Cursor::new(b"BADXsomegarbagedata"),
            None,
            |_, _| true,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid snapshot magic"));
    }

    #[test]
    fn snapshot_load_does_not_populate_height_index() {
        // Confirm the optimization: snapshot rows must NOT land in
        // height_index, since rollback past the snapshot height is
        // forbidden by design.
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();

        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let (utxo2, _dir2) = fresh();
        utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&anchor_of(&meta)), |_, _| true)
            .unwrap();

        // utxos populated as expected.
        assert_eq!(utxo2.count().unwrap(), 1);
        // height_index empty: has_utxos_at_height should report false even
        // though height 0 has a UTXO in the main table.
        assert!(!utxo2.has_utxos_at_height(0).unwrap());
    }

    #[test]
    fn assume_valid_floor_defaults_to_zero() {
        // A fresh-from-genesis env has no snapshot, so the floor must be 0
        // and rollback_block(0) must still be allowed (for the genesis
        // rollback path that other tests in this file already exercise).
        let (utxo, _dir) = fresh();
        assert_eq!(utxo.assume_valid_floor().unwrap(), 0);
    }

    #[test]
    fn load_snapshot_records_assume_valid_floor() {
        // After a successful snapshot load at height H, the floor must
        // equal H and persist across `assume_valid_floor()` reads.
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 12345, &[0u8; 32]).unwrap();

        let (utxo2, _dir2) = fresh();
        assert_eq!(utxo2.assume_valid_floor().unwrap(), 0);
        utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&anchor_of(&meta)), |_, _| true)
            .unwrap();
        assert_eq!(utxo2.assume_valid_floor().unwrap(), 12345);
    }

    #[test]
    fn assume_valid_floor_persists_across_reopen() {
        // Critical for the rollback guard to be effective across process
        // restarts: the floor must come back from disk on reopen.
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 700_000, &[0u8; 32]).unwrap();

        let dir2 = TempDir::new().unwrap();
        let env_path = dir2.path().join("utxo");
        {
            let utxo2 = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
            utxo2
                .load_snapshot(
                    std::io::Cursor::new(&buf),
                    Some(&anchor_of(&meta)),
                    |_, _| true,
                )
                .unwrap();
            assert_eq!(utxo2.assume_valid_floor().unwrap(), 700_000);
        } // drop closes the env

        let utxo_reopened = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        assert_eq!(utxo_reopened.assume_valid_floor().unwrap(), 700_000);
    }

    #[test]
    fn rollback_block_rejects_at_or_below_assume_valid_floor() {
        // After a snapshot load at H, rollback_block(H) and any
        // rollback_block(< H) must error: snapshot rows have no
        // height_index entries and would silently survive a rollback,
        // corrupting the UTXO set.
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 100, &[0u8; 32]).unwrap();

        let (utxo2, _dir2) = fresh();
        utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&anchor_of(&meta)), |_, _| true)
            .unwrap();

        // Below the floor.
        let err = utxo2
            .rollback_block(50)
            .expect_err("rollback below floor must be rejected");
        assert!(
            err.to_string().contains("assume-valid floor"),
            "unexpected error: {}",
            err
        );

        // At the floor (still rejected — the snapshot height itself is
        // unrecoverable since its rows are not in height_index).
        let err = utxo2
            .rollback_block(100)
            .expect_err("rollback at floor must be rejected");
        assert!(err.to_string().contains("assume-valid floor"));

        // Just above the floor — this would be rejected later by missing
        // undo data, but the floor guard must NOT block it.
        let result = utxo2.rollback_block(101);
        assert!(
            result.is_ok() || !format!("{}", result.unwrap_err()).contains("assume-valid floor"),
            "rollback just above floor must not be blocked by the floor guard"
        );
    }

    #[test]
    fn snapshot_load_removes_marker_on_success() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let dir2 = TempDir::new().unwrap();
        let env_path = dir2.path().join("utxo");
        let utxo2 = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&anchor_of(&meta)), |_, _| true)
            .unwrap();

        // Marker must be gone after a clean load.
        let marker = loading_marker_path(&env_path);
        assert!(
            !marker.exists(),
            "loading marker should be removed on success"
        );
    }

    #[test]
    fn snapshot_load_does_not_write_marker_on_header_hash_failure() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        let mut buf = Vec::new();
        utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let dir2 = TempDir::new().unwrap();
        let env_path = dir2.path().join("utxo");
        let utxo2 = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        let result = utxo2.load_snapshot(
            std::io::Cursor::new(&buf),
            Some(&SnapshotAnchor {
                height: 0,
                block_hash: [0u8; 32],
                utxo_hash: [0xFFu8; 32],
            }),
            |_, _| true,
        );
        assert!(result.is_err());

        // The expected-hash check in the header runs before any flag/marker
        // setup, so the marker is never written and the env was never
        // touched. Both invariants matter: leaving a marker on a no-op
        // failure would force an unnecessary wipe on next open.
        let marker = loading_marker_path(&env_path);
        assert!(!marker.exists());
        assert_eq!(utxo2.count().unwrap(), 0);
    }

    /// Load `bytes` into a fresh env against `anchor` and assert it was
    /// rejected with `needle` before the env or marker were touched.
    fn assert_rejected_untouched(bytes: &[u8], anchor: &SnapshotAnchor, needle: &str) {
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("utxo");
        let utxo = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        let err = utxo
            .load_snapshot(std::io::Cursor::new(bytes), Some(anchor), |_, _| true)
            .unwrap_err();
        assert!(err.to_string().contains(needle), "got: {}", err);
        assert!(!loading_marker_path(&env_path).exists());
        assert_eq!(utxo.count().unwrap(), 0);
        assert_eq!(utxo.assume_valid_floor().unwrap(), 0);
        assert_eq!(utxo.snapshot_block_hash().unwrap(), None);
    }

    #[test]
    fn snapshot_rejects_tampered_header_height() {
        // Edit only the header's height field (bytes 8..12). The content
        // hash covers only the entries, so it still matches — the explicit
        // anchor check must catch it.
        let (mut bytes, anchor) = make_snapshot_with_n_utxos(3);
        bytes[8..12].copy_from_slice(&(anchor.height + 1).to_le_bytes());
        assert_rejected_untouched(&bytes, &anchor, "snapshot height mismatch");
    }

    #[test]
    fn snapshot_rejects_tampered_header_block_hash() {
        // Edit only the header's block_hash field (bytes 12..44).
        let (mut bytes, anchor) = make_snapshot_with_n_utxos(3);
        bytes[12] ^= 0xFF;
        assert_rejected_untouched(&bytes, &anchor, "snapshot block hash mismatch");
    }

    #[test]
    fn snapshot_rejects_header_not_matching_anchor() {
        // An untampered file for a different block than the anchor.
        let (bytes, anchor) = make_snapshot_with_n_utxos(3);
        let other_height = SnapshotAnchor { height: 943_500, ..anchor };
        assert_rejected_untouched(&bytes, &other_height, "snapshot height mismatch");
        let other_block = SnapshotAnchor { block_hash: [0x11; 32], ..anchor };
        assert_rejected_untouched(&bytes, &other_block, "snapshot block hash mismatch");
    }

    #[test]
    fn load_snapshot_records_snapshot_block_hash() {
        let (utxo1, _dir1) = fresh();
        utxo1.apply_block(&genesis_block(), 0).unwrap();
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 7, &[0x5Au8; 32]).unwrap();

        let (utxo2, _dir2) = fresh();
        utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&anchor_of(&meta)), |_, _| true)
            .unwrap();
        assert_eq!(utxo2.snapshot_block_hash().unwrap(), Some([0x5Au8; 32]));
    }

    #[test]
    fn open_wipes_env_when_loading_marker_present() {
        // Set up a populated env, then synthesize an interrupted-load
        // condition by writing the marker file. Reopening should wipe the
        // env to empty state and remove the marker.
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("utxo");
        {
            let utxo = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
            let genesis = genesis_block();
            utxo.apply_block(&genesis, 0).unwrap();
            assert_eq!(utxo.count().unwrap(), 1);
        } // drop closes the env

        let marker = loading_marker_path(&env_path);
        std::fs::write(&marker, b"interrupted\n").unwrap();
        assert!(marker.exists());

        let utxo = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        assert_eq!(
            utxo.count().unwrap(),
            0,
            "interrupted load marker should trigger a wipe"
        );
        assert!(!marker.exists(), "marker should be removed after wipe");
    }

    #[test]
    fn loading_marker_path_is_sibling_of_env_dir() {
        let p = loading_marker_path(Path::new("/tmp/foo/utxo-lmdb"));
        assert_eq!(p, PathBuf::from("/tmp/foo/utxo-lmdb.loading"));
    }

    #[test]
    fn snapshot_load_periodic_commits_persist_all_entries() {
        // SNAPSHOT_LOAD_BATCH is 4 under cfg(test), so loading 13 entries
        // forces 3 batch commits at i=4, 8, 12 plus a final commit. The
        // entire periodic-commit code path is exercised here — the whole
        // optimization being added — and every entry must round-trip.
        let (snapshot_bytes, expected) = make_snapshot_with_n_utxos(13);

        let (utxo, _dir) = fresh();
        let meta = utxo
            .load_snapshot(
                std::io::Cursor::new(&snapshot_bytes),
                Some(&expected),
                |_, _| true,
            )
            .unwrap();
        assert_eq!(meta.utxo_count, 13);
        assert_eq!(utxo.count().unwrap(), 13);

        // Spot-check entries on either side of every batch boundary.
        for i in 0u8..13 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            let txid = Txid::from_byte_array(bytes);
            let entry = utxo.get(&txid, 0).unwrap().unwrap();
            assert_eq!(entry.amount, 1000 + i as u64);
            assert_eq!(entry.height, 1);
            assert!(!entry.is_coinbase);
            assert_eq!(entry.script_pubkey, vec![0xac]);
        }

        // The "skip height_index for snapshot rows" optimization holds
        // even across batched commits — height_index must still be empty.
        assert!(!utxo.has_utxos_at_height(1).unwrap());
    }

    #[test]
    fn snapshot_load_clears_partial_batches_on_post_commit_hash_failure() {
        // Build a 13-entry snapshot, then flip the last byte (the script
        // byte of entry 12) so the streaming hash check fails AFTER batch
        // commits at i=4, 8, 12 have already persisted 12 entries to disk.
        // The cleanup path must clear_all those persisted entries — leaving
        // a non-empty env without a marker would be unrecoverable. The
        // marker must also be removed, since cleanup_ok == true here.
        let (mut snapshot_bytes, expected) = make_snapshot_with_n_utxos(13);
        let last = snapshot_bytes.len() - 1;
        snapshot_bytes[last] ^= 0xFF;

        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("utxo");
        let utxo = UtxoSet::open(env_path.to_str().unwrap()).unwrap();

        let result = utxo.load_snapshot(
            std::io::Cursor::new(&snapshot_bytes),
            Some(&expected),
            |_, _| true,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("verification failed"));

        // clear_all wiped every previously committed batch.
        assert_eq!(utxo.count().unwrap(), 0);

        // cleanup_ok was true (clear_all and force_sync both succeeded),
        // so the marker must be gone — the env is back in a known-empty
        // state and a fresh load can proceed without going through
        // open()'s wipe path.
        let marker = loading_marker_path(&env_path);
        assert!(
            !marker.exists(),
            "marker should be removed when cleanup succeeds"
        );
    }

    #[test]
    fn has_utxos_at_height_after_apply() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();
        assert!(utxo.has_utxos_at_height(0).unwrap());
        assert!(!utxo.has_utxos_at_height(1).unwrap());
    }

    #[test]
    fn has_utxos_at_height_clears_after_rollback() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();
        utxo.rollback_block(0).unwrap();
        assert!(!utxo.has_utxos_at_height(0).unwrap());
    }
}

/// Snapshot-format, apply/rollback and corruption edge cases.
#[cfg(test)]
#[path = "utxo_tests.rs"]
mod edge_tests;
