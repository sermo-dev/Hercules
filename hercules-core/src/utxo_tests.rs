//! Edge cases and invariants for the UTXO set and the HUTX snapshot format.
//!
//! Mounted inside `utxo` (see the bottom of `utxo.rs`) so it can inspect
//! the raw LMDB databases. Three groups:
//!
//! - **HUTX parsing.** Snapshots are built by an independent encoder below
//!   (`Hutx`), checked byte-for-byte against `write_snapshot`, then
//!   truncated, reordered, overflowed and fuzzed. Whatever the input, a
//!   rejected load must leave the env empty with no crash marker, and an
//!   accepted one must hold exactly a set whose hash is the header's.
//! - **Apply / rollback.** Random block sequences applied to a seeded set
//!   and rolled back must restore every database (utxos, undo,
//!   height_index, best block) exactly, block by block.
//! - **Persistence and corruption.** Undo data across reopen, the prune
//!   horizon against a maximum-depth reorg, atomicity of a failed write,
//!   and corrupt rows surfacing as errors instead of bad data.

use std::collections::{BTreeMap, HashMap};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::transaction::Version;
use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness};
use proptest::prelude::*;
use proptest::test_runner::{Config as PropConfig, TestRunner};
use tempfile::TempDir;

use super::*;

// ── Helpers ──────────────────────────────────────────────────────────

/// A fresh set at `<tmp>/utxo`, so the `.loading` marker (a sibling of the
/// env dir) also lives inside the temp dir.
fn fresh() -> (UtxoSet, TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("utxo");
    let utxo = UtxoSet::open(path.to_str().unwrap()).unwrap();
    (utxo, dir, path)
}

/// The anchor a snapshot commits to. One constructor, so a new anchor field
/// is a one-line change here.
fn anchor(height: u32, block_hash: [u8; 32], utxo_hash: [u8; 32]) -> SnapshotAnchor {
    SnapshotAnchor { height, block_hash, utxo_hash }
}

/// One HUTX entry, exactly as it appears in the file (the coinbase byte is
/// raw: anything non-zero means coinbase).
#[derive(Debug, Clone, PartialEq, Eq)]
struct HutxEntry {
    txid: [u8; 32],
    vout: u32,
    amount: u64,
    height: u32,
    coinbase: u8,
    script: Vec<u8>,
}

impl HutxEntry {
    fn new(txid_byte: u8, vout: u32, amount: u64) -> HutxEntry {
        HutxEntry { txid: [txid_byte; 32], vout, amount, height: 7, coinbase: 0, script: vec![0x51] }
    }
}

/// Independent HUTX v1 encoder (see `write_snapshot` for the format), with
/// knobs for every header field so tests can build malformed files.
struct Hutx {
    version: u32,
    height: u32,
    block_hash: [u8; 32],
    /// Header count; `None` = the number of entries.
    count: Option<u64>,
    /// Header hash; `None` = the canonical hash of the entries.
    hash: Option<[u8; 32]>,
    entries: Vec<HutxEntry>,
}

impl Hutx {
    fn new(entries: Vec<HutxEntry>) -> Hutx {
        Hutx { version: 1, height: 10, block_hash: [0x42; 32], count: None, hash: None, entries }
    }

    /// The canonical content hash: SHA256 over every entry's fields in
    /// `compute_hash` order, with the coinbase byte normalized to 0/1.
    fn content_hash(entries: &[HutxEntry]) -> [u8; 32] {
        let mut h = Sha256::new();
        for e in entries {
            h.update(e.txid);
            h.update(e.vout.to_le_bytes());
            h.update(e.amount.to_le_bytes());
            h.update((e.script.len() as u16).to_le_bytes());
            h.update(&e.script);
            h.update(e.height.to_le_bytes());
            h.update([(e.coinbase != 0) as u8]);
        }
        h.finalize().into()
    }

    fn hash(&self) -> [u8; 32] {
        self.hash.unwrap_or_else(|| Self::content_hash(&self.entries))
    }

    fn anchor(&self) -> SnapshotAnchor {
        anchor(self.height, self.block_hash, self.hash())
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"HUTX");
        b.extend_from_slice(&self.version.to_le_bytes());
        b.extend_from_slice(&self.height.to_le_bytes());
        b.extend_from_slice(&self.block_hash);
        b.extend_from_slice(&self.count.unwrap_or(self.entries.len() as u64).to_le_bytes());
        b.extend_from_slice(&self.hash());
        for e in &self.entries {
            b.extend_from_slice(&e.txid);
            b.extend_from_slice(&e.vout.to_le_bytes());
            b.extend_from_slice(&e.amount.to_le_bytes());
            b.extend_from_slice(&e.height.to_le_bytes());
            b.push(e.coinbase);
            b.extend_from_slice(&(e.script.len() as u16).to_le_bytes());
            b.extend_from_slice(&e.script);
        }
        b
    }
}

const HEADER_LEN: usize = 4 + 4 + 4 + 32 + 8 + 32;

fn load(utxo: &UtxoSet, bytes: &[u8], anchor: Option<&SnapshotAnchor>) -> Result<SnapshotMeta, SnapshotLoadError> {
    utxo.load_snapshot(std::io::Cursor::new(bytes), anchor, |_, _| true)
}

/// A rejected load must leave nothing behind: no rows, no meta, no marker.
fn assert_untouched(utxo: &UtxoSet, path: &Path) {
    assert_eq!(utxo.count().unwrap(), 0, "rows left behind");
    assert_eq!(utxo.assume_valid_floor().unwrap(), 0, "floor left behind");
    assert_eq!(utxo.snapshot_block_hash().unwrap(), None);
    assert_eq!(utxo.best_block().unwrap(), None);
    assert_eq!(utxo.muhash().unwrap(), None);
    assert!(!loading_marker_path(path).exists(), "marker left behind");
}

/// Every row of every database, for exact before/after comparisons.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DbState {
    utxos: Vec<(Vec<u8>, Vec<u8>)>,
    undo: Vec<(Vec<u8>, Vec<u8>)>,
    height_index: Vec<Vec<u8>>,
}

fn dump(u: &UtxoSet) -> DbState {
    let _gate = u.read_gate().unwrap();
    let rtxn = u.env.read_txn().unwrap();
    let rows = |db: &Database<Bytes, Bytes>| -> Vec<(Vec<u8>, Vec<u8>)> {
        db.iter(&rtxn).unwrap().map(|r| r.unwrap()).map(|(k, v)| (k.to_vec(), v.to_vec())).collect()
    };
    DbState {
        utxos: rows(&u.utxos),
        undo: rows(&u.undo),
        height_index: u.height_index.iter(&rtxn).unwrap().map(|r| r.unwrap().0.to_vec()).collect(),
    }
}

/// The `utxos` database as decoded entries keyed by (txid, vout).
fn decoded(u: &UtxoSet) -> BTreeMap<([u8; 32], u32), (u64, Vec<u8>, u32, bool)> {
    dump(u)
        .utxos
        .into_iter()
        .map(|(k, v)| {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&k[..32]);
            let vout = u32::from_be_bytes(k[32..36].try_into().unwrap());
            let e = decode_utxo_value(&v).unwrap();
            ((txid, vout), (e.amount, e.script_pubkey, e.height, e.is_coinbase))
        })
        .collect()
}

fn put_raw(u: &UtxoSet, db: &Database<Bytes, Bytes>, key: &[u8], value: &[u8]) {
    let _gate = u.read_gate().unwrap();
    let mut wtxn = u.env.write_txn().unwrap();
    db.put(&mut wtxn, key, value).unwrap();
    wtxn.commit().unwrap();
}

/// SplitMix64: a tiny deterministic PRNG so a proptest seed fully
/// determines a generated chain (and failures replay exactly).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

fn block_of(height: u32, txdata: Vec<Transaction>) -> Block {
    Block {
        header: Header {
            version: BlockVersion::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        },
        txdata,
    }
}

fn coinbase(height: u32, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(height.to_le_bytes().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn spend_tx(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|op| TxIn {
                previous_output: *op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    }
}

fn out(value: u64, script: Vec<u8>) -> TxOut {
    TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from_bytes(script) }
}

// ── HUTX: the format itself ──────────────────────────────────────────

fn arb_entries(max: usize) -> impl Strategy<Value = Vec<HutxEntry>> {
    prop::collection::btree_map(
        (any::<[u8; 32]>(), any::<u32>()),
        (0..=MAX_MONEY, any::<u32>(), any::<bool>(), prop::collection::vec(any::<u8>(), 0..64)),
        0..max,
    )
    .prop_map(|m| {
        // BTreeMap order on (txid, vout) is the file order.
        m.into_iter()
            .map(|((txid, vout), (amount, height, cb, script))| HutxEntry {
                txid,
                vout,
                amount,
                height,
                coinbase: cb as u8,
                script,
            })
            .collect()
    })
}

/// The test encoder and `write_snapshot` agree byte for byte, so the
/// malformed files below are malformed versions of the real format, and
/// a loaded set re-exports to the identical file.
#[test]
fn independent_encoder_matches_write_snapshot_and_round_trips() {
    let mut runner = TestRunner::new(PropConfig { cases: 24, ..PropConfig::default() });
    runner
        .run(&arb_entries(40), |entries| {
            let (src, _d, _) = fresh();
            for e in &entries {
                src.test_insert_utxo(
                    e.txid,
                    e.vout,
                    UtxoEntry {
                        amount: e.amount,
                        script_pubkey: e.script.clone(),
                        height: e.height,
                        is_coinbase: e.coinbase != 0,
                    },
                )
                .unwrap();
            }
            let hutx = Hutx::new(entries.clone());
            let mut written = Vec::new();
            let meta = src.write_snapshot(&mut written, hutx.height, &hutx.block_hash).unwrap();
            prop_assert_eq!(&written, &hutx.bytes());
            prop_assert_eq!(meta.utxo_hash, src.compute_hash().unwrap());
            prop_assert_eq!(meta.utxo_count, entries.len() as u64);

            // Load into a fresh set: same rows, same hash, anchor recorded.
            let (dst, _d2, path) = fresh();
            let loaded = load(&dst, &written, Some(&hutx.anchor())).unwrap();
            prop_assert_eq!(loaded.utxo_count, entries.len() as u64);
            prop_assert_eq!(dump(&dst).utxos, dump(&src).utxos);
            prop_assert_eq!(dst.compute_hash().unwrap(), hutx.hash());
            prop_assert_eq!(dst.assume_valid_floor().unwrap(), hutx.height);
            prop_assert_eq!(dst.snapshot_block_hash().unwrap(), Some(hutx.block_hash));
            prop_assert_eq!(dst.best_block().unwrap(), Some((hutx.height, hutx.block_hash)));
            prop_assert!(dst.muhash().unwrap().is_some());
            prop_assert!(!loading_marker_path(&path).exists());
            // Snapshot rows have no height_index entries (by design).
            prop_assert!(dump(&dst).height_index.is_empty());
            // And it re-exports to the identical file.
            let mut again = Vec::new();
            dst.write_snapshot(&mut again, hutx.height, &hutx.block_hash).unwrap();
            prop_assert_eq!(again, written);
            Ok(())
        })
        .unwrap();
}

/// The converter (`src/bin/convert_snapshot.rs`) and the loader must hash
/// identically, or every snapshot it produces is rejected (or worse, a
/// hash mismatch is papered over). The three coins of
/// `tests/convert_snapshot_test.rs::build_core_dump`, inserted through the
/// library, hash to the value that test pins for the converter's header.
#[test]
fn compute_hash_matches_the_converter_golden_value() {
    const GOLDEN_HASH: &str = "15087b9e28011c20d17569a2303049e1916d080070972d9439707d3cafda8d88";
    let (utxo, _d, _) = fresh();
    let script = |pre: &[u8], body: &[u8], post: &[u8]| [pre, body, post].concat();
    let coins = [
        ([0x01; 32], 0, 50_000, 100, true, script(&[0x76, 0xa9, 0x14], &[0xaa; 20], &[0x88, 0xac])),
        ([0x01; 32], 2, 1_000, 100, true, script(&[0xa9, 0x14], &[0xcc; 20], &[0x87])),
        ([0x02; 32], 1, 10_000, 200, false, script(&[0x00, 0x20], &[0xbb; 32], &[])),
    ];
    for (txid, vout, amount, height, is_coinbase, script_pubkey) in coins {
        utxo.test_insert_utxo(txid, vout, UtxoEntry { amount, script_pubkey, height, is_coinbase }).unwrap();
    }
    assert_eq!(hex::encode(utxo.compute_hash().unwrap()), GOLDEN_HASH);
}

#[test]
fn snapshot_with_zero_entries_loads_and_records_the_anchor() {
    let (utxo, _d, _) = fresh();
    let hutx = Hutx::new(vec![]);
    // The empty content hash is SHA256 of nothing.
    let empty: [u8; 32] = Sha256::digest([]).into();
    assert_eq!(hutx.hash(), empty);
    let meta = load(&utxo, &hutx.bytes(), Some(&hutx.anchor())).unwrap();
    assert_eq!(meta.utxo_count, 0);
    assert_eq!(utxo.count().unwrap(), 0);
    assert_eq!(utxo.assume_valid_floor().unwrap(), hutx.height);
    assert_eq!(utxo.best_block().unwrap(), Some((hutx.height, hutx.block_hash)));
}

#[test]
fn snapshot_progress_ends_with_total_and_starts_at_zero() {
    let (utxo, _d, _) = fresh();
    let hutx = Hutx::new((0..10u8).map(|i| HutxEntry::new(i, 0, 1_000)).collect());
    let calls = std::sync::Mutex::new(Vec::new());
    utxo.load_snapshot(std::io::Cursor::new(hutx.bytes()), Some(&hutx.anchor()), |done, total| {
        calls.lock().unwrap().push((done, total));
        true
    })
    .unwrap();
    let calls = calls.into_inner().unwrap();
    assert_eq!(calls.first(), Some(&(0, 10)));
    assert_eq!(calls.last(), Some(&(10, 10)));
}

// ── HUTX: malformed input ────────────────────────────────────────────

/// Every proper prefix of a valid file is rejected as a bad file (so the
/// app deletes and re-downloads it), and leaves the env exactly empty,
/// including when the cut falls after a committed batch.
#[test]
fn snapshot_truncated_at_any_byte_is_invalid_and_leaves_nothing() {
    // 9 entries crosses two batch commits (SNAPSHOT_LOAD_BATCH = 4 in tests).
    let entries: Vec<HutxEntry> = (0..9u8)
        .map(|i| HutxEntry { script: vec![0xac; i as usize], ..HutxEntry::new(i, i as u32, 5_000) })
        .collect();
    let hutx = Hutx::new(entries);
    let bytes = hutx.bytes();
    let (utxo, _d, path) = fresh();
    for cut in 0..bytes.len() {
        match load(&utxo, &bytes[..cut], Some(&hutx.anchor())) {
            Err(SnapshotLoadError::Invalid(_)) => {}
            other => panic!("cut at {}/{}: expected Invalid, got {:?}", cut, bytes.len(), other),
        }
        assert_untouched(&utxo, &path);
    }
    // The full file still loads in the same env afterwards.
    load(&utxo, &bytes, Some(&hutx.anchor())).unwrap();
    assert_eq!(utxo.count().unwrap(), 9);
}

#[test]
fn snapshot_version_other_than_one_is_rejected() {
    let (utxo, _d, path) = fresh();
    for version in [0u32, 2, 0x0100_0000, u32::MAX] {
        let hutx = Hutx { version, ..Hutx::new(vec![HutxEntry::new(1, 0, 1)]) };
        let err = load(&utxo, &hutx.bytes(), None).unwrap_err();
        assert!(
            matches!(err, SnapshotLoadError::Invalid(ref m) if m.contains("unsupported snapshot version")),
            "version {}: {}",
            version,
            err
        );
        assert_untouched(&utxo, &path);
    }
}

#[test]
fn snapshot_magic_must_be_exact() {
    let (utxo, _d, path) = fresh();
    let good = Hutx::new(vec![]).bytes();
    for i in 0..4 {
        let mut bad = good.clone();
        bad[i] ^= 0x20; // e.g. "hUTX"
        let err = load(&utxo, &bad, None).unwrap_err();
        assert!(matches!(err, SnapshotLoadError::Invalid(ref m) if m.contains("magic")), "{}", err);
        assert_untouched(&utxo, &path);
    }
}

#[test]
fn snapshot_amount_bound_is_exactly_max_money() {
    // MAX_MONEY itself is a valid amount.
    let (utxo, _d, path) = fresh();
    let ok = Hutx::new(vec![HutxEntry::new(1, 0, MAX_MONEY)]);
    load(&utxo, &ok.bytes(), Some(&ok.anchor())).unwrap();
    assert_eq!(utxo.get(&Txid::from_byte_array([1; 32]), 0).unwrap().unwrap().amount, MAX_MONEY);

    // One satoshi more is a bad file, even with a matching content hash,
    // and even when it is the last entry after two committed batches.
    for amount in [MAX_MONEY + 1, u64::MAX] {
        let (utxo, _d, path2) = fresh();
        let mut entries: Vec<HutxEntry> = (0..9u8).map(|i| HutxEntry::new(i, 0, 1)).collect();
        entries.push(HutxEntry::new(9, 0, amount));
        let bad = Hutx::new(entries);
        let err = load(&utxo, &bad.bytes(), Some(&bad.anchor())).unwrap_err();
        assert!(matches!(err, SnapshotLoadError::Invalid(ref m) if m.contains("MAX_MONEY")), "{}", err);
        assert_untouched(&utxo, &path2);
    }
    let _ = path;
}

/// Entries must be strictly ascending by (txid, vout) with vout compared
/// numerically: the LMDB key stores vout big-endian, so 255 < 256 holds
/// even though their little-endian file bytes sort the other way.
#[test]
fn snapshot_order_is_strictly_ascending_txid_then_numeric_vout() {
    let (utxo, _d, _) = fresh();
    let ok = Hutx::new(vec![
        HutxEntry::new(1, 0, 1),
        HutxEntry::new(1, 255, 1),
        HutxEntry::new(1, 256, 1),
        HutxEntry::new(1, u32::MAX, 1),
        HutxEntry::new(2, 0, 1),
    ]);
    load(&utxo, &ok.bytes(), Some(&ok.anchor())).unwrap();
    assert_eq!(utxo.count().unwrap(), 5);

    let unsorted: Vec<(&str, Vec<HutxEntry>)> = vec![
        ("descending vout", vec![HutxEntry::new(1, 256, 1), HutxEntry::new(1, 255, 1)]),
        ("descending txid", vec![HutxEntry::new(2, 0, 1), HutxEntry::new(1, 0, 1)]),
        ("duplicate key", vec![HutxEntry::new(1, 3, 1), HutxEntry::new(1, 3, 2)]),
        (
            // The repeat lands right after a batch commit (entry index 4).
            "duplicate across a batch boundary",
            (0..4u8).map(|i| HutxEntry::new(i, 0, 1)).chain([HutxEntry::new(3, 0, 1)]).collect(),
        ),
    ];
    for (what, entries) in unsorted {
        let (utxo, _d, path) = fresh();
        let bad = Hutx::new(entries);
        let err = load(&utxo, &bad.bytes(), Some(&bad.anchor())).unwrap_err();
        assert!(matches!(err, SnapshotLoadError::Invalid(ref m) if m.contains("not sorted")), "{}: {}", what, err);
        assert_untouched(&utxo, &path);
    }
}

#[test]
fn snapshot_script_length_extremes_round_trip() {
    let (utxo, _d, _) = fresh();
    let hutx = Hutx::new(vec![
        HutxEntry { script: vec![], ..HutxEntry::new(1, 0, 1) },
        HutxEntry { script: vec![0x6a; u16::MAX as usize], ..HutxEntry::new(2, 0, 1) },
    ]);
    load(&utxo, &hutx.bytes(), Some(&hutx.anchor())).unwrap();
    assert!(utxo.get(&Txid::from_byte_array([1; 32]), 0).unwrap().unwrap().script_pubkey.is_empty());
    assert_eq!(utxo.get(&Txid::from_byte_array([2; 32]), 0).unwrap().unwrap().script_pubkey.len(), 65_535);
    assert_eq!(utxo.compute_hash().unwrap(), hutx.hash());
}

#[test]
fn snapshot_header_count_must_match_the_body() {
    let entries: Vec<HutxEntry> = (0..6u8).map(|i| HutxEntry::new(i, 0, 1)).collect();

    // More entries announced than present: runs off the end.
    let (utxo, _d, path) = fresh();
    let over = Hutx { count: Some(7), ..Hutx::new(entries.clone()) };
    let err = load(&utxo, &over.bytes(), Some(&over.anchor())).unwrap_err();
    assert!(matches!(err, SnapshotLoadError::Invalid(_)), "{}", err);
    assert_untouched(&utxo, &path);

    // Fewer announced than present, hash over all of them: the hash of
    // what was read can't match.
    let (utxo, _d, path) = fresh();
    let under = Hutx { count: Some(5), ..Hutx::new(entries.clone()) };
    let err = load(&utxo, &under.bytes(), Some(&under.anchor())).unwrap_err();
    assert!(matches!(err, SnapshotLoadError::Invalid(ref m) if m.contains("verification failed")), "{}", err);
    assert_untouched(&utxo, &path);

    // Fewer announced and hashed: the extra bytes are never read, so they
    // can't add a single coin to what the anchor commits to.
    let (utxo, _d, _) = fresh();
    let hash5 = Hutx::content_hash(&entries[..5]);
    let trailing = Hutx { count: Some(5), hash: Some(hash5), ..Hutx::new(entries) };
    load(&utxo, &trailing.bytes(), Some(&trailing.anchor())).unwrap();
    assert_eq!(utxo.count().unwrap(), 5);
    assert!(utxo.get(&Txid::from_byte_array([5; 32]), 0).unwrap().is_none());
    assert_eq!(utxo.compute_hash().unwrap(), hash5);
}

/// The coinbase byte is hashed normalized (any non-zero = 1). A file with
/// a non-canonical byte therefore loads as the canonical set, and what
/// lands in the database still hashes to the anchor.
#[test]
fn snapshot_noncanonical_coinbase_byte_loads_as_canonical_set() {
    let (utxo, _d, _) = fresh();
    let hutx = Hutx::new(vec![HutxEntry { coinbase: 0x02, ..HutxEntry::new(1, 0, 1) }]);
    load(&utxo, &hutx.bytes(), Some(&hutx.anchor())).unwrap();
    assert!(utxo.get(&Txid::from_byte_array([1; 32]), 0).unwrap().unwrap().is_coinbase);
    assert_eq!(utxo.compute_hash().unwrap(), hutx.hash());
}

#[test]
fn snapshot_content_is_verified_without_an_anchor_too() {
    let hutx = Hutx::new((0..6u8).map(|i| HutxEntry::new(i, 0, 1_000)).collect());
    let mut bytes = hutx.bytes();
    // Flip one bit of the last entry's amount.
    let amount_at = bytes.len() - (1 + 2 + 1 + 4 + 8);
    bytes[amount_at] ^= 1;
    let (utxo, _d, path) = fresh();
    let err = load(&utxo, &bytes, None).unwrap_err();
    assert!(matches!(err, SnapshotLoadError::Invalid(ref m) if m.contains("verification failed")), "{}", err);
    assert_untouched(&utxo, &path);
}

/// A corrupt header announcing ~2^64 entries must fail cleanly (it used
/// to overflow the map-size rounding: a panic in debug builds).
#[test]
fn snapshot_absurd_entry_count_fails_without_touching_the_env() {
    for count in [u64::MAX, u64::MAX / SNAPSHOT_EST_BYTES_PER_UTXO + 1] {
        let (utxo, _d, path) = fresh();
        let hutx = Hutx { count: Some(count), ..Hutx::new(vec![HutxEntry::new(1, 0, 1)]) };
        assert!(load(&utxo, &hutx.bytes(), Some(&hutx.anchor())).is_err());
        assert_untouched(&utxo, &path);
        // The env is still usable.
        let ok = Hutx::new(vec![HutxEntry::new(1, 0, 1)]);
        load(&utxo, &ok.bytes(), Some(&ok.anchor())).unwrap();
    }
}

/// The app deletes a snapshot file only on `Invalid`. A header count no
/// real set can have says the file is bad, not that storage is short.
#[test]
#[ignore = "BUG: an absurd header utxo_count is reported as Storage (app keeps the corrupt file and retries forever); fixed by PR #27 (anchor utxo_count checked before ensure_map_capacity)"]
fn snapshot_absurd_entry_count_is_a_bad_file() {
    let (utxo, _d, _) = fresh();
    let hutx = Hutx { count: Some(u64::MAX), ..Hutx::new(vec![HutxEntry::new(1, 0, 1)]) };
    let err = load(&utxo, &hutx.bytes(), Some(&hutx.anchor())).unwrap_err();
    assert!(matches!(err, SnapshotLoadError::Invalid(_)), "{}", err);
}

/// Refusing to load into a non-empty set must not destroy that set.
#[test]
#[ignore = "BUG: load_snapshot on a non-empty set returns Storage but its cleanup path wipes the existing set; fixed by PR #27 (emptiness checked before the marker/env are touched)"]
fn rejected_load_into_a_nonempty_set_keeps_the_set() {
    let (utxo, _d, path) = fresh();
    utxo.apply_block(&block_of(1, vec![coinbase(1, vec![out(50, vec![0x51])])]), 1).unwrap();
    let before = dump(&utxo);
    let hutx = Hutx::new(vec![HutxEntry::new(1, 0, 1)]);
    let err = load(&utxo, &hutx.bytes(), Some(&hutx.anchor())).unwrap_err();
    assert!(matches!(err, SnapshotLoadError::Storage(ref m) if m.contains("must be empty")), "{}", err);
    assert_eq!(dump(&utxo), before);
    assert!(!loading_marker_path(&path).exists());
}

/// Fuzz-style property over arbitrary and mutated snapshot bytes: a load
/// never panics; if it fails the env is left exactly empty with no marker;
/// if it succeeds the set holds the announced number of rows and hashes to
/// the header's hash (so tampering can never produce a set the anchor
/// didn't commit to).
#[test]
fn snapshot_parser_is_total_and_never_leaves_partial_state() {
    let valid = arb_entries(12).prop_map(|e| Hutx::new(e).bytes());
    let mutated = (arb_entries(12), any::<prop::sample::Index>(), any::<u8>()).prop_map(|(e, i, x)| {
        let mut b = Hutx::new(e).bytes();
        let i = i.index(b.len());
        b[i] ^= x.max(1);
        b
    });
    let truncated = (arb_entries(12), any::<prop::sample::Index>()).prop_map(|(e, i)| {
        let b = Hutx::new(e).bytes();
        let n = i.index(b.len());
        b[..n].to_vec()
    });
    // Valid header with a small count, then garbage.
    let garbage_body = (0u64..6, prop::collection::vec(any::<u8>(), 0..400)).prop_map(|(n, body)| {
        let mut b = Hutx { count: Some(n), ..Hutx::new(vec![]) }.bytes();
        b.extend(body);
        b
    });
    let random = prop::collection::vec(any::<u8>(), 0..200);
    let strategy = prop_oneof![valid, mutated, truncated, garbage_body, random];

    let (utxo, _d, path) = fresh();
    let mut runner = TestRunner::new(PropConfig { cases: 400, ..PropConfig::default() });
    runner
        .run(&strategy, |bytes| {
            utxo.clear_all().unwrap();
            let header_hash: Option<[u8; 32]> =
                (bytes.len() >= HEADER_LEN).then(|| bytes[52..84].try_into().unwrap());
            let header_count: Option<u64> =
                (bytes.len() >= HEADER_LEN).then(|| u64::from_le_bytes(bytes[44..52].try_into().unwrap()));
            match load(&utxo, &bytes, None) {
                Ok(meta) => {
                    prop_assert_eq!(Some(meta.utxo_hash), header_hash);
                    prop_assert_eq!(Some(meta.utxo_count), header_count);
                    prop_assert_eq!(utxo.count().unwrap(), meta.utxo_count);
                    prop_assert_eq!(utxo.compute_hash().unwrap(), meta.utxo_hash);
                    prop_assert!(!loading_marker_path(&path).exists());
                }
                Err(_) => {
                    prop_assert_eq!(utxo.count().unwrap(), 0);
                    prop_assert_eq!(utxo.assume_valid_floor().unwrap(), 0);
                    prop_assert!(!loading_marker_path(&path).exists());
                }
            }
            Ok(())
        })
        .unwrap();
}

// ── Apply / rollback ─────────────────────────────────────────────────

/// What the set should contain: (amount, script, height, coinbase).
type Model = HashMap<OutPoint, (u64, Vec<u8>, u32, bool)>;

fn model_rows(m: &Model) -> BTreeMap<([u8; 32], u32), (u64, Vec<u8>, u32, bool)> {
    m.iter().map(|(op, v)| ((op.txid.to_byte_array(), op.vout), v.clone())).collect()
}

fn random_script(rng: &mut Rng) -> Vec<u8> {
    if rng.chance(12) {
        // OP_RETURN: never stored.
        let mut s = vec![0x6a];
        s.extend((0..rng.below(20)).map(|_| rng.next() as u8));
        return s;
    }
    let mut s: Vec<u8> = (0..rng.below(40)).map(|_| rng.next() as u8).collect();
    if s.first() == Some(&0x6a) {
        s[0] = 0x51; // keep "spendable" an explicit choice above
    }
    s
}

/// Build the block at `height` spending from `model` (and from outputs
/// created earlier in the same block), and apply its effect to `model`.
fn random_block(rng: &mut Rng, height: u32, model: &mut Model) -> Block {
    let cb_outs: Vec<TxOut> =
        (0..1 + rng.below(2)).map(|_| out(rng.below(MAX_MONEY / 4), random_script(rng))).collect();
    let mut txs = vec![coinbase(height, cb_outs)];
    // Coins spendable in this block: the set plus this block's earlier
    // non-coinbase outputs.
    let mut available: Vec<OutPoint> = model.keys().copied().collect();
    available.sort(); // HashMap order is random; keep the seed authoritative.
    for _ in 0..rng.below(5) {
        if available.is_empty() {
            break;
        }
        let n_in = 1 + rng.below(3.min(available.len() as u64));
        let inputs: Vec<OutPoint> =
            (0..n_in).map(|_| available.swap_remove(rng.below(available.len() as u64) as usize)).collect();
        let outs: Vec<TxOut> =
            (0..1 + rng.below(3)).map(|_| out(rng.below(MAX_MONEY / 4), random_script(rng))).collect();
        let tx = spend_tx(&inputs, outs);
        let txid = tx.compute_txid();
        for (vout, o) in tx.output.iter().enumerate() {
            if !o.script_pubkey.is_op_return() {
                available.push(OutPoint::new(txid, vout as u32));
            }
        }
        txs.push(tx);
    }
    let block = block_of(height, txs);
    for tx in &block.txdata {
        if !tx.is_coinbase() {
            for i in &tx.input {
                model.remove(&i.previous_output).expect("spent coin exists");
            }
        }
        let txid = tx.compute_txid();
        for (vout, o) in tx.output.iter().enumerate() {
            if !o.script_pubkey.is_op_return() {
                model.insert(
                    OutPoint::new(txid, vout as u32),
                    (o.value.to_sat(), o.script_pubkey.to_bytes(), height, tx.is_coinbase()),
                );
            }
        }
    }
    block
}

/// Applying random blocks (multi-input spends, in-block chains, OP_RETURN
/// outputs, spends of coinbases and of seeded coins) keeps the set equal
/// to a simple model; rolling them back one at a time, newest first,
/// restores every database exactly as it was before that block, down to
/// the initial state with no undo data left.
#[test]
fn apply_then_rollback_restores_every_database_exactly() {
    let mut runner = TestRunner::new(PropConfig { cases: 32, ..PropConfig::default() });
    runner
        .run(&(any::<u64>(), 1u32..14), |(seed, n_blocks)| {
            let mut rng = Rng(seed);
            let (utxo, _d, _) = fresh();
            let mut model = Model::new();
            for i in 0..1 + rng.below(6) as u8 {
                let script = random_script(&mut rng).into_iter().filter(|b| *b != 0x6a).collect::<Vec<_>>();
                let e = UtxoEntry { amount: rng.below(MAX_MONEY), script_pubkey: script, height: 1, is_coinbase: rng.chance(30) };
                utxo.test_insert_utxo([i; 32], i as u32, e.clone()).unwrap();
                model.insert(
                    OutPoint::new(Txid::from_byte_array([i; 32]), i as u32),
                    (e.amount, e.script_pubkey, e.height, e.is_coinbase),
                );
            }
            let initial = dump(&utxo);
            let base_hash = [0xb0; 32];

            let mut states = vec![initial.clone()];
            let mut blocks = vec![];
            for h in 2..2 + n_blocks {
                let block = random_block(&mut rng, h, &mut model);
                utxo.apply_block(&block, h).unwrap();
                prop_assert_eq!(decoded(&utxo), model_rows(&model), "after applying block {}", h);
                prop_assert_eq!(utxo.best_block().unwrap(), Some((h, block.block_hash().to_byte_array())));
                states.push(dump(&utxo));
                blocks.push(block);
            }

            for (i, h) in (2..2 + n_blocks).enumerate().rev() {
                let parent = if i == 0 { base_hash } else { blocks[i - 1].block_hash().to_byte_array() };
                utxo.rollback_block_to(h, parent).unwrap();
                prop_assert_eq!(&dump(&utxo), &states[i], "after rolling back block {}", h);
                prop_assert_eq!(utxo.best_block().unwrap(), Some((h - 1, parent)));
            }
            prop_assert_eq!(dump(&utxo), initial);
            prop_assert_eq!(utxo.test_count_undo().unwrap(), 0);
            Ok(())
        })
        .unwrap();
}

/// A block whose second transaction spends a coin that doesn't exist must
/// leave no trace of its first transaction: one LMDB txn, all or nothing.
#[test]
fn failed_apply_block_writes_nothing() {
    let (utxo, _d, _) = fresh();
    let coin = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
    utxo.test_insert_utxo([1; 32], 0, UtxoEntry { amount: 10, script_pubkey: vec![0x51], height: 1, is_coinbase: false })
        .unwrap();
    utxo.apply_block(&block_of(2, vec![coinbase(2, vec![out(1, vec![0x51])])]), 2).unwrap();
    let before = dump(&utxo);
    let best = utxo.best_block().unwrap();

    let ghost = OutPoint::new(Txid::from_byte_array([9; 32]), 0);
    let block = block_of(
        3,
        vec![
            coinbase(3, vec![out(1, vec![0x51])]),
            spend_tx(&[coin], vec![out(5, vec![0x52])]),
            spend_tx(&[ghost], vec![out(5, vec![0x53])]),
        ],
    );
    let err = utxo.apply_block(&block, 3).unwrap_err();
    assert!(err.0.contains("missing utxo"), "{}", err);
    assert_eq!(dump(&utxo), before);
    assert_eq!(utxo.best_block().unwrap(), best);
}

/// A rollback that hits a corrupt undo row fails without having deleted
/// the block's outputs: the set stays at the block, consistent.
#[test]
fn failed_rollback_writes_nothing() {
    let (utxo, _d, _) = fresh();
    utxo.test_insert_utxo([1; 32], 0, UtxoEntry { amount: 10, script_pubkey: vec![0x51], height: 1, is_coinbase: false })
        .unwrap();
    let block = block_of(
        2,
        vec![
            coinbase(2, vec![out(1, vec![0x51])]),
            spend_tx(&[OutPoint::new(Txid::from_byte_array([1; 32]), 0)], vec![out(5, vec![0x52])]),
        ],
    );
    utxo.apply_block(&block, 2).unwrap();
    // Corrupt a second undo row for height 2 (too short to decode).
    put_raw(&utxo, &utxo.undo, &undo_key(2, 7), &[0u8; 10]);
    let before = dump(&utxo);
    let err = utxo.rollback_block_to(2, [0; 32]).unwrap_err();
    assert!(err.0.contains("corrupt undo"), "{}", err);
    assert_eq!(dump(&utxo), before);
}

#[test]
fn in_block_chain_never_reaches_the_database() {
    let (utxo, _d, _) = fresh();
    let seeded = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
    utxo.test_insert_utxo([1; 32], 0, UtxoEntry { amount: 100, script_pubkey: vec![0x51], height: 1, is_coinbase: false })
        .unwrap();
    let before = dump(&utxo);
    let a = spend_tx(&[seeded], vec![out(90, vec![0x51])]);
    let b = spend_tx(&[OutPoint::new(a.compute_txid(), 0)], vec![out(80, vec![0x51])]);
    let c = spend_tx(&[OutPoint::new(b.compute_txid(), 0)], vec![out(70, vec![0x51]), out(0, vec![0x6a, 0x01, 0xff])]);
    let block = block_of(2, vec![coinbase(2, vec![out(1, vec![0x51])]), a.clone(), b.clone(), c.clone()]);
    utxo.apply_block(&block, 2).unwrap();

    // Only the coinbase and c's spendable output exist; a and b never did.
    assert_eq!(utxo.count().unwrap(), 2);
    assert!(utxo.get(&a.compute_txid(), 0).unwrap().is_none());
    assert!(utxo.get(&b.compute_txid(), 0).unwrap().is_none());
    assert!(utxo.get(&c.compute_txid(), 0).unwrap().is_some());
    assert!(utxo.get(&c.compute_txid(), 1).unwrap().is_none(), "OP_RETURN stored");
    // One undo row: the seeded coin. In-block spends need none.
    assert_eq!(utxo.test_count_undo().unwrap(), 1);

    utxo.rollback_block_to(2, [0; 32]).unwrap();
    assert_eq!(dump(&utxo), before);
}

#[test]
fn rollback_restores_coinbase_flag_and_original_height() {
    let (utxo, _d, _) = fresh();
    let cb = coinbase(5, vec![out(50, vec![0x51])]);
    utxo.apply_block(&block_of(5, vec![cb.clone()]), 5).unwrap();
    let coin = OutPoint::new(cb.compute_txid(), 0);
    let spend = block_of(105, vec![coinbase(105, vec![out(1, vec![0x52])]), spend_tx(&[coin], vec![out(40, vec![0x53])])]);
    utxo.apply_block(&spend, 105).unwrap();
    assert!(utxo.get(&coin.txid, 0).unwrap().is_none());
    utxo.rollback_block_to(105, [0; 32]).unwrap();
    let restored = utxo.get(&coin.txid, 0).unwrap().unwrap();
    assert!(restored.is_coinbase);
    assert_eq!(restored.height, 5);
    assert_eq!(restored.amount, 50);
    assert!(utxo.has_utxos_at_height(5).unwrap());
    assert!(!utxo.has_utxos_at_height(105).unwrap());
}

/// Undo data is on disk: a node restarted between a block and its reorg
/// can still roll it back.
#[test]
fn rollback_works_across_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("utxo");
    let mut rng = Rng(7);
    let mut model = Model::new();
    let (before, states) = {
        let utxo = UtxoSet::open(path.to_str().unwrap()).unwrap();
        for i in 0..4u8 {
            utxo.test_insert_utxo([i; 32], 0, UtxoEntry { amount: 1_000, script_pubkey: vec![0x51], height: 1, is_coinbase: false })
                .unwrap();
            model.insert(OutPoint::new(Txid::from_byte_array([i; 32]), 0), (1_000, vec![0x51], 1, false));
        }
        let before = dump(&utxo);
        let mut states = vec![before.clone()];
        for h in 2..6 {
            let b = random_block(&mut rng, h, &mut model);
            utxo.apply_block(&b, h).unwrap();
            states.push(dump(&utxo));
        }
        (before, states)
    };
    let utxo = UtxoSet::open(path.to_str().unwrap()).unwrap();
    assert_eq!(&dump(&utxo), states.last().unwrap());
    for h in (2..6).rev() {
        utxo.rollback_block_to(h, [h as u8; 32]).unwrap();
        assert_eq!(dump(&utxo), states[(h - 2) as usize]);
    }
    assert_eq!(dump(&utxo), before);
}

/// The sync loop prunes undo below `tip - 288` and accepts reorgs up to
/// 288 deep. With exactly that horizon, a maximum-depth reorg (rolling
/// back 288 blocks) must restore the fork point's state exactly; the
/// block at the horizon keeps its undo and everything below loses it.
#[test]
fn prune_horizon_keeps_everything_a_max_depth_reorg_needs() {
    const DEPTH: u32 = 288;
    const TIP: u32 = 300;
    let (utxo, _d, _) = fresh();
    utxo.test_insert_utxo([1; 32], 0, UtxoEntry { amount: 1_000_000, script_pubkey: vec![0x51], height: 1, is_coinbase: false })
        .unwrap();
    let mut prev = OutPoint::new(Txid::from_byte_array([1; 32]), 0);
    let mut states = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    // Every block spends the previous block's output and the coinbase
    // from 100 blocks earlier, so every height has undo rows.
    let mut coinbases = BTreeMap::new();
    for h in 2..=TIP {
        let cb = coinbase(h, vec![out(50, vec![0x51])]);
        coinbases.insert(h, OutPoint::new(cb.compute_txid(), 0));
        let mut inputs = vec![prev];
        if let Some(old) = coinbases.remove(&h.saturating_sub(100)) {
            inputs.push(old);
        }
        let tx = spend_tx(&inputs, vec![out(999_000, vec![0x52, h as u8])]);
        prev = OutPoint::new(tx.compute_txid(), 0);
        let block = block_of(h, vec![cb, tx]);
        hashes.insert(h, block.block_hash().to_byte_array());
        utxo.apply_block(&block, h).unwrap();
        states.insert(h, dump(&utxo));
    }

    utxo.prune_undo_below(TIP - DEPTH).unwrap();
    let undo_heights: std::collections::BTreeSet<u32> =
        dump(&utxo).undo.iter().map(|(k, _)| u32::from_be_bytes(k[..4].try_into().unwrap())).collect();
    assert_eq!(undo_heights.first(), Some(&(TIP - DEPTH)), "horizon block keeps its undo");
    assert_eq!(undo_heights.len() as u32, DEPTH + 1);

    // Max-depth reorg: the fork point is TIP - DEPTH; roll back the DEPTH
    // blocks above it.
    for h in ((TIP - DEPTH + 1)..=TIP).rev() {
        utxo.rollback_block_to(h, hashes[&(h - 1)]).unwrap();
    }
    // Identical to the fork point's state, except for the undo rows the
    // prune legitimately removed below the horizon.
    let mut expected = states[&(TIP - DEPTH)].clone();
    expected.undo.retain(|(k, _)| u32::from_be_bytes(k[..4].try_into().unwrap()) >= TIP - DEPTH);
    assert_eq!(dump(&utxo), expected);
    assert_eq!(utxo.best_block().unwrap(), Some((TIP - DEPTH, hashes[&(TIP - DEPTH)])));
}

#[test]
fn prune_undo_below_is_exclusive_and_idempotent() {
    let (utxo, _d, _) = fresh();
    for h in [0u32, 1, 255, 256, 257, 65_536, u32::MAX] {
        utxo.test_insert_undo(h, 0, [h as u8; 32], 0, UtxoEntry { amount: 1, script_pubkey: vec![], height: 0, is_coinbase: false })
            .unwrap();
    }
    utxo.prune_undo_below(256).unwrap();
    let left = |u: &UtxoSet| -> Vec<u32> {
        dump(u).undo.iter().map(|(k, _)| u32::from_be_bytes(k[..4].try_into().unwrap())).collect()
    };
    assert_eq!(left(&utxo), vec![256, 257, 65_536, u32::MAX]);
    utxo.prune_undo_below(256).unwrap();
    assert_eq!(left(&utxo), vec![256, 257, 65_536, u32::MAX]);
    utxo.prune_undo_below(0).unwrap();
    assert_eq!(left(&utxo).len(), 4);
}

/// After a snapshot, a block spending a snapshot coin can be rolled back
/// (its undo restores the coin), but nothing at or below the floor can.
#[test]
fn rollback_just_above_the_snapshot_floor_restores_snapshot_coins() {
    let (utxo, _d, _) = fresh();
    let hutx = Hutx::new(vec![HutxEntry::new(1, 0, 5_000), HutxEntry::new(2, 3, 6_000)]);
    load(&utxo, &hutx.bytes(), Some(&hutx.anchor())).unwrap();
    let floor = hutx.height;
    let coin = OutPoint::new(Txid::from_byte_array([2; 32]), 3);
    let block = block_of(floor + 1, vec![coinbase(floor + 1, vec![out(1, vec![0x51])]), spend_tx(&[coin], vec![out(5_500, vec![0x52])])]);
    utxo.apply_block(&block, floor + 1).unwrap();
    assert!(utxo.get(&coin.txid, 3).unwrap().is_none());

    utxo.rollback_block_to(floor + 1, hutx.block_hash).unwrap();
    let back = utxo.get(&coin.txid, 3).unwrap().unwrap();
    assert_eq!((back.amount, back.height), (6_000, 7));
    assert_eq!(utxo.compute_hash().unwrap(), hutx.hash());
    assert_eq!(utxo.best_block().unwrap(), Some((floor, hutx.block_hash)));

    for h in [floor, floor - 1, 1] {
        let err = utxo.rollback_block_to(h, [0; 32]).unwrap_err();
        assert!(err.0.contains("assume-valid floor"), "{}", err);
    }
    assert_eq!(utxo.compute_hash().unwrap(), hutx.hash());
}

#[test]
fn rollback_of_an_empty_height_only_moves_the_best_block() {
    let (utxo, _d, _) = fresh();
    utxo.test_insert_utxo([1; 32], 0, UtxoEntry { amount: 1, script_pubkey: vec![0x51], height: 1, is_coinbase: false })
        .unwrap();
    let before = dump(&utxo);
    utxo.rollback_block_to(50, [0x50; 32]).unwrap();
    assert_eq!(dump(&utxo), before);
    assert_eq!(utxo.best_block().unwrap(), Some((49, [0x50; 32])));
}

// ── Encoding and corruption ──────────────────────────────────────────

#[test]
fn utxo_value_decoding_bounds() {
    assert!(decode_utxo_value(&[0u8; UTXO_VALUE_HEADER_LEN - 1]).is_err());
    let e = decode_utxo_value(&[0u8; UTXO_VALUE_HEADER_LEN]).unwrap();
    assert!(e.script_pubkey.is_empty() && !e.is_coinbase && e.amount == 0);
    let with = |amount: u64, flags: u8| {
        let mut v = amount.to_le_bytes().to_vec();
        v.extend_from_slice(&9u32.to_le_bytes());
        v.push(flags);
        v
    };
    assert_eq!(decode_utxo_value(&with(MAX_MONEY, 0)).unwrap().amount, MAX_MONEY);
    assert!(decode_utxo_value(&with(MAX_MONEY + 1, 0)).is_err());
    // Only bit 0 is the coinbase flag.
    assert!(decode_utxo_value(&with(1, 0x01)).unwrap().is_coinbase);
    assert!(decode_utxo_value(&with(1, 0xff)).unwrap().is_coinbase);
    assert!(!decode_utxo_value(&with(1, 0xfe)).unwrap().is_coinbase);

    assert!(decode_undo_value(&[0u8; UNDO_VALUE_HEADER_LEN - 1]).is_err());
    assert!(decode_undo_value(&[0u8; UNDO_VALUE_HEADER_LEN]).is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn utxo_and_undo_values_round_trip(
        txid in any::<[u8; 32]>(),
        vout in any::<u32>(),
        amount in 0..=MAX_MONEY,
        height in any::<u32>(),
        cb in any::<bool>(),
        script in prop::collection::vec(any::<u8>(), 0..200),
    ) {
        let e = UtxoEntry { amount, script_pubkey: script.clone(), height, is_coinbase: cb };
        let d = decode_utxo_value(&encode_utxo_value(&e)).unwrap();
        prop_assert_eq!((d.amount, d.script_pubkey, d.height, d.is_coinbase), (amount, script.clone(), height, cb));
        let (t, v, u) = decode_undo_value(&encode_undo_value(&txid, vout, &e)).unwrap();
        prop_assert_eq!((t, v), (txid, vout));
        prop_assert_eq!((u.amount, u.script_pubkey, u.height, u.is_coinbase), (amount, script, height, cb));
    }

    /// Decoders never panic on arbitrary bytes.
    #[test]
    fn value_decoders_are_total(bytes in prop::collection::vec(any::<u8>(), 0..80)) {
        let _ = decode_utxo_value(&bytes);
        let _ = decode_undo_value(&bytes);
    }

    /// Key byte order equals (txid, vout) numeric order, which the
    /// snapshot's APPEND loading and `write_snapshot`'s cursor order rely on.
    #[test]
    fn utxo_key_order_matches_txid_then_numeric_vout(
        a in (any::<[u8; 32]>(), any::<u32>()),
        b in (any::<[u8; 32]>(), any::<u32>()),
    ) {
        prop_assert_eq!(utxo_key(&a.0, a.1).cmp(&utxo_key(&b.0, b.1)), a.cmp(&b));
        prop_assert_eq!(
            undo_key(a.1, b.1).cmp(&undo_key(b.1, a.1)),
            (a.1, b.1).cmp(&(b.1, a.1))
        );
        let hi = height_index_key(a.1, &a.0, b.1);
        prop_assert!(hi.starts_with(&a.1.to_be_bytes()));
        prop_assert_eq!(&hi[4..], &utxo_key(&a.0, b.1)[..]);
    }

    /// Map sizes to try: whole granules, largest first, strictly
    /// decreasing, never below data + headroom, ending exactly there.
    #[test]
    fn map_size_candidates_are_well_formed(data_len in 0u64..(1 << 40)) {
        let sizes = map_size_candidates(data_len);
        let floor = round_up(data_len + MIN_MAP_HEADROOM, GIB);
        prop_assert_eq!(*sizes.last().unwrap(), floor);
        prop_assert!(sizes[0] >= MIN_MAP_SIZE.max(floor));
        prop_assert!(sizes[0] <= MAX_MAP_SIZE.max(floor));
        for w in sizes.windows(2) {
            prop_assert!(w[0] > w[1]);
        }
        for s in &sizes {
            prop_assert_eq!(s % GIB, 0);
            prop_assert!(*s >= floor);
        }
    }
}

#[test]
fn round_up_saturates_instead_of_overflowing() {
    assert_eq!(round_up(0, GIB), 0);
    assert_eq!(round_up(1, GIB), GIB);
    assert_eq!(round_up(GIB, GIB), GIB);
    assert_eq!(round_up(GIB + 1, GIB), 2 * GIB);
    // The largest whole number of GiB still fits...
    assert_eq!(round_up(u64::MAX - GIB, GIB), u64::MAX - GIB + 1);
    assert_eq!(round_up(u64::MAX - GIB + 1, GIB), u64::MAX - GIB + 1);
    // ...anything above it saturates.
    assert_eq!(round_up(u64::MAX - GIB + 2, GIB), u64::MAX);
    assert_eq!(round_up(u64::MAX, GIB), u64::MAX);
}

#[test]
fn corrupt_meta_rows_are_errors_not_defaults() {
    let (utxo, _d, _) = fresh();
    put_raw(&utxo, &utxo.meta, META_KEY_BEST_BLOCK, &[0u8; 35]);
    assert!(utxo.best_block().is_err());
    put_raw(&utxo, &utxo.meta, META_KEY_ASSUME_VALID_FLOOR, &[0u8; 3]);
    assert!(utxo.assume_valid_floor().is_err());
    // A rollback can't proceed without knowing the floor.
    assert!(utxo.rollback_block_to(5, [0; 32]).is_err());
    put_raw(&utxo, &utxo.meta, META_KEY_SNAPSHOT_BLOCK_HASH, &[0u8; 31]);
    assert!(utxo.snapshot_block_hash().is_err());
    put_raw(&utxo, &utxo.meta, META_KEY_MUHASH, &[0u8; 33]);
    assert!(utxo.muhash().is_err());
}

#[test]
fn corrupt_utxo_rows_fail_hashing_and_export() {
    let (utxo, _d, _) = fresh();
    utxo.test_insert_raw_utxo([1; 32], 0, &[0u8; 5]).unwrap();
    assert!(utxo.compute_hash().is_err());
    assert!(utxo.write_snapshot(Vec::new(), 1, &[0; 32]).is_err());
    assert!(utxo.get(&Txid::from_byte_array([1; 32]), 0).is_err());
}

#[test]
fn open_with_marker_but_no_env_starts_fresh() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("utxo");
    let marker = loading_marker_path(&path);
    std::fs::write(&marker, b"x").unwrap();
    let utxo = UtxoSet::open(path.to_str().unwrap()).unwrap();
    assert!(!marker.exists());
    assert_eq!(utxo.count().unwrap(), 0);
}

/// Reader that serves `limit` bytes and then panics: a process killed in
/// the middle of a snapshot load, after some batches have committed.
struct DiesAfter<'a> {
    data: &'a [u8],
    pos: usize,
    limit: usize,
}
impl std::io::Read for DiesAfter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.limit {
            panic!("simulated kill mid-load");
        }
        let n = buf.len().min(self.limit - self.pos).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A load killed after some batches committed leaves rows and the marker
/// on disk; the next open must wipe them instead of trusting a partial,
/// unverified set.
#[test]
fn load_killed_mid_stream_is_wiped_on_next_open() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("utxo");
    let hutx = Hutx::new((0..9u8).map(|i| HutxEntry::new(i, 0, 1)).collect());
    let bytes = hutx.bytes();
    {
        let utxo = UtxoSet::open(path.to_str().unwrap()).unwrap();
        // Die inside entry 8, after the batches at 4 and 8 committed.
        let entry_len = 32 + 4 + 8 + 4 + 1 + 2 + 1;
        let limit = HEADER_LEN + 8 * entry_len + 10;
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let reader = DiesAfter { data: &bytes, pos: 0, limit };
            let _ = utxo.load_snapshot(reader, Some(&hutx.anchor()), |_, _| true);
        }));
        assert!(crashed.is_err());
        assert_eq!(utxo.count().unwrap(), 8, "two batches committed before the kill");
        assert!(loading_marker_path(&path).exists());
    }
    let utxo = UtxoSet::open(path.to_str().unwrap()).unwrap();
    assert_eq!(utxo.count().unwrap(), 0);
    assert_eq!(utxo.assume_valid_floor().unwrap(), 0);
    assert!(!loading_marker_path(&path).exists());
    load(&utxo, &bytes, Some(&hutx.anchor())).unwrap();
    assert_eq!(utxo.count().unwrap(), 9);
}

#[test]
fn has_utxos_at_height_misses_blocks_with_no_stored_outputs() {
    // Documented limitation of the legacy crash-recovery probe: a block
    // whose outputs are all OP_RETURN (or spent in-block) leaves no trace.
    let (utxo, _d, _) = fresh();
    utxo.apply_block(&block_of(3, vec![coinbase(3, vec![out(0, vec![0x6a])])]), 3).unwrap();
    assert!(!utxo.has_utxos_at_height(3).unwrap());
    assert_eq!(utxo.best_block().unwrap().map(|b| b.0), Some(3));
}
