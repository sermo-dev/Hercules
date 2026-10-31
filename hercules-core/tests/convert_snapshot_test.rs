//! Integration test for the snapshot converter.
//!
//! Creates a minimal Bitcoin Core-style dumptxoutset in memory, converts it,
//! then verifies the Hercules HUTX output is valid.

use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};

// -- Encoding helpers (mirror Bitcoin Core's serialization) --

fn write_varint(w: &mut Vec<u8>, mut n: u64) {
    let mut tmp = Vec::new();
    tmp.push((n & 0x7f) as u8);
    n >>= 7;
    while n > 0 {
        n -= 1;
        tmp.push(((n & 0x7f) | 0x80) as u8);
        n >>= 7;
    }
    tmp.reverse();
    w.extend_from_slice(&tmp);
}

fn write_compact_size(w: &mut Vec<u8>, n: u64) {
    if n < 253 {
        w.push(n as u8);
    } else if n <= 0xffff {
        w.push(253);
        w.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        w.push(254);
        w.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        w.push(255);
        w.extend_from_slice(&n.to_le_bytes());
    }
}

/// Bitcoin Core's CompressAmount
fn compress_amount(mut n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut e: u32 = 0;
    while e < 9 && n % 10 == 0 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        n /= 10;
        1 + (n * 9 + d - 1) * 10 + e as u64
    } else {
        1 + (n - 1) * 10 + 9
    }
}

/// Build a minimal Core v2 dump with 3 UTXOs in 2 txid groups:
///   Group 1 (txid_a): vout 0 (50000 sats, h=100, coinbase, P2PKH)
///                     vout 2 (1000 sats, h=100, coinbase, P2SH)
///   Group 2 (txid_b): vout 1 (10000 sats, h=200, not coinbase, raw P2WSH)
///
/// Core v2 grouped format:
///   txid(32) + CompactSize(num_coins) +
///   [CompactSize(vout) + VARINT(code) + VARINT(amount) + CompressedScript] * num_coins
fn build_core_dump() -> Vec<u8> {
    let mut buf = Vec::new();

    // Header: magic(5) + version(2) + network(4) + block_hash(32) + coin_count(8) = 51
    buf.extend_from_slice(&[b'u', b't', b'x', b'o', 0xff]); // 5-byte magic
    buf.extend_from_slice(&2u16.to_le_bytes()); // version 2
    buf.extend_from_slice(&[0xf9, 0xbe, 0xb4, 0xd9]); // mainnet
    let block_hash = [0xab_u8; 32];
    buf.extend_from_slice(&block_hash);
    buf.extend_from_slice(&3u64.to_le_bytes()); // 3 total coins

    let txid_a = [0x01_u8; 32];
    let txid_b = [0x02_u8; 32];

    // --- Group 1: txid_a with 2 outputs ---
    buf.extend_from_slice(&txid_a);
    write_compact_size(&mut buf, 2); // 2 coins in group

    // Coin: vout 0
    write_compact_size(&mut buf, 0); // vout = 0
    write_varint(&mut buf, (100 << 1) | 1); // code: height=100, coinbase=true
    write_varint(&mut buf, compress_amount(50000));
    write_varint(&mut buf, 0x00); // P2PKH script type
    buf.extend_from_slice(&[0xaa_u8; 20]); // 20-byte hash

    // Coin: vout 2
    write_compact_size(&mut buf, 2); // vout = 2
    write_varint(&mut buf, (100 << 1) | 1); // code: height=100, coinbase=true
    write_varint(&mut buf, compress_amount(1000));
    write_varint(&mut buf, 0x01); // P2SH script type
    buf.extend_from_slice(&[0xcc_u8; 20]); // 20-byte hash

    // --- Group 2: txid_b with 1 output ---
    buf.extend_from_slice(&txid_b);
    write_compact_size(&mut buf, 1); // 1 coin in group

    // Coin: vout 1
    write_compact_size(&mut buf, 1); // vout = 1
    write_varint(&mut buf, (200 << 1) | 0); // code: height=200, not coinbase
    write_varint(&mut buf, compress_amount(10000));
    write_varint(&mut buf, 40); // raw script: type = 6 + 34 = 40
    buf.push(0x00); // OP_0
    buf.push(0x20); // PUSH 32
    buf.extend_from_slice(&[0xbb_u8; 32]); // 32-byte hash

    buf
}

#[test]
fn test_round_trip_core_to_hutx() {
    let core_data = build_core_dump();
    let input_path = std::env::temp_dir().join("test_core_dump_v2.dat");
    let output_path = std::env::temp_dir().join("test_output_v2.hutx");

    std::fs::write(&input_path, &core_data).unwrap();

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_convert_snapshot"))
        .arg(input_path.to_str().unwrap())
        .arg(output_path.to_str().unwrap())
        .status()
        .expect("failed to run converter");
    assert!(status.success(), "converter exited with error");

    // Read and verify the HUTX output
    let hutx = std::fs::read(&output_path).unwrap();
    let mut c = Cursor::new(&hutx);

    // Verify header
    let mut magic = [0u8; 4];
    c.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"HUTX");

    let mut buf4 = [0u8; 4];
    c.read_exact(&mut buf4).unwrap();
    assert_eq!(u32::from_le_bytes(buf4), 1); // version

    c.read_exact(&mut buf4).unwrap();
    let height = u32::from_le_bytes(buf4);
    assert_eq!(height, 200); // max height seen

    let mut block_hash = [0u8; 32];
    c.read_exact(&mut block_hash).unwrap();
    assert_eq!(block_hash, [0xab_u8; 32]);

    let mut buf8 = [0u8; 8];
    c.read_exact(&mut buf8).unwrap();
    let utxo_count = u64::from_le_bytes(buf8);
    assert_eq!(utxo_count, 3);

    let mut file_hash = [0u8; 32];
    c.read_exact(&mut file_hash).unwrap();

    // Read entry 1: txid_a:0 (P2PKH, 50000 sats, coinbase)
    let mut txid = [0u8; 32];
    c.read_exact(&mut txid).unwrap();
    assert_eq!(txid, [0x01; 32]);

    c.read_exact(&mut buf4).unwrap();
    assert_eq!(u32::from_le_bytes(buf4), 0); // vout

    c.read_exact(&mut buf8).unwrap();
    assert_eq!(i64::from_le_bytes(buf8), 50000); // amount

    c.read_exact(&mut buf4).unwrap();
    assert_eq!(u32::from_le_bytes(buf4), 100); // height

    let mut cb = [0u8; 1];
    c.read_exact(&mut cb).unwrap();
    assert_eq!(cb[0], 1); // coinbase

    let mut buf2 = [0u8; 2];
    c.read_exact(&mut buf2).unwrap();
    let script_len = u16::from_le_bytes(buf2);
    assert_eq!(script_len, 25); // P2PKH = 25 bytes

    let mut script = vec![0u8; script_len as usize];
    c.read_exact(&mut script).unwrap();
    assert_eq!(script[0], 0x76); // OP_DUP
    assert_eq!(&script[3..23], &[0xaa; 20]);

    // Read entry 2: txid_a:2 (P2SH, 1000 sats, coinbase)
    c.read_exact(&mut txid).unwrap();
    assert_eq!(txid, [0x01; 32]); // same txid

    c.read_exact(&mut buf4).unwrap();
    assert_eq!(u32::from_le_bytes(buf4), 2); // vout

    c.read_exact(&mut buf8).unwrap();
    assert_eq!(i64::from_le_bytes(buf8), 1000); // amount

    c.read_exact(&mut buf4).unwrap();
    assert_eq!(u32::from_le_bytes(buf4), 100); // height

    c.read_exact(&mut cb).unwrap();
    assert_eq!(cb[0], 1); // coinbase

    c.read_exact(&mut buf2).unwrap();
    let script_len = u16::from_le_bytes(buf2);
    assert_eq!(script_len, 23); // P2SH = 23 bytes

    let mut script = vec![0u8; script_len as usize];
    c.read_exact(&mut script).unwrap();
    assert_eq!(script[0], 0xa9); // OP_HASH160

    // Read entry 3: txid_b:1 (P2WSH raw, 10000 sats, not coinbase)
    c.read_exact(&mut txid).unwrap();
    assert_eq!(txid, [0x02; 32]);

    c.read_exact(&mut buf4).unwrap();
    assert_eq!(u32::from_le_bytes(buf4), 1); // vout

    c.read_exact(&mut buf8).unwrap();
    assert_eq!(i64::from_le_bytes(buf8), 10000);

    c.read_exact(&mut buf4).unwrap();
    assert_eq!(u32::from_le_bytes(buf4), 200);

    c.read_exact(&mut cb).unwrap();
    assert_eq!(cb[0], 0); // not coinbase

    c.read_exact(&mut buf2).unwrap();
    let script_len = u16::from_le_bytes(buf2);
    assert_eq!(script_len, 34); // P2WSH = 34 bytes

    let mut script = vec![0u8; script_len as usize];
    c.read_exact(&mut script).unwrap();
    assert_eq!(script[0], 0x00); // OP_0
    assert_eq!(script[1], 0x20); // PUSH 32
    assert_eq!(&script[2..34], &[0xbb; 32]);

    // Verify at EOF
    assert_eq!(c.position() as usize, hutx.len());

    // Verify hash
    let mut hasher = Sha256::new();

    // Entry 1: txid_a:0
    hasher.update(&[0x01u8; 32]);
    hasher.update(&0u32.to_le_bytes());
    hasher.update(&50000i64.to_le_bytes());
    hasher.update(&25u16.to_le_bytes());
    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&[0xaa; 20]);
    p2pkh.push(0x88);
    p2pkh.push(0xac);
    hasher.update(&p2pkh);
    hasher.update(&100u32.to_le_bytes());
    hasher.update(&[1u8]);

    // Entry 2: txid_a:2
    hasher.update(&[0x01u8; 32]);
    hasher.update(&2u32.to_le_bytes());
    hasher.update(&1000i64.to_le_bytes());
    hasher.update(&23u16.to_le_bytes());
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&[0xcc; 20]);
    p2sh.push(0x87);
    hasher.update(&p2sh);
    hasher.update(&100u32.to_le_bytes());
    hasher.update(&[1u8]);

    // Entry 3: txid_b:1
    hasher.update(&[0x02u8; 32]);
    hasher.update(&1u32.to_le_bytes());
    hasher.update(&10000i64.to_le_bytes());
    hasher.update(&34u16.to_le_bytes());
    let mut p2wsh = vec![0x00, 0x20];
    p2wsh.extend_from_slice(&[0xbb; 32]);
    hasher.update(&p2wsh);
    hasher.update(&200u32.to_le_bytes());
    hasher.update(&[0u8]);

    let expected_hash: [u8; 32] = hasher.finalize().into();
    assert_eq!(file_hash, expected_hash, "HUTX hash mismatch");

    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&output_path);
}

#[test]
fn test_amount_compression_round_trip() {
    let test_values: &[u64] = &[
        0, 1, 100, 330, 546, 1000, 10000, 50000, 100000, 500000000,
        2100000000000000,
    ];

    for &amount in test_values {
        let compressed = compress_amount(amount);
        let decompressed = decompress_amount(compressed);
        assert_eq!(
            decompressed, amount,
            "round-trip failed for amount {}",
            amount
        );
    }
}

fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let e = (x % 10) as u32;
    x /= 10;
    let mut n: u64;
    if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    for _ in 0..e {
        n *= 10;
    }
    n
}

// ── Data-path pass: every compressed-script type, numeric encodings,
//    malformed dumps, and agreement with the loader's hash ─────────────

/// One coin as Core serializes it inside a txid group.
struct Coin {
    vout: u64,
    height: u32,
    coinbase: bool,
    amount: u64,
    /// `ScriptCompression` encoding: VARINT(type/size) then payload.
    script: Vec<u8>,
}

/// A v2 dump of `groups` (txid, coins), in the order given.
fn dump(groups: &[([u8; 32], Vec<Coin>)], count: Option<u64>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[b'u', b't', b'x', b'o', 0xff]);
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&[0xf9, 0xbe, 0xb4, 0xd9]);
    buf.extend_from_slice(&[0xab; 32]);
    let n: u64 = groups.iter().map(|g| g.1.len() as u64).sum();
    buf.extend_from_slice(&count.unwrap_or(n).to_le_bytes());
    for (txid, coins) in groups {
        buf.extend_from_slice(txid);
        write_compact_size(&mut buf, coins.len() as u64);
        for c in coins {
            write_compact_size(&mut buf, c.vout);
            write_varint(&mut buf, ((c.height as u64) << 1) | c.coinbase as u64);
            write_varint(&mut buf, compress_amount(c.amount));
            buf.extend_from_slice(&c.script);
        }
    }
    buf
}

fn raw_script(script: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    write_varint(&mut v, script.len() as u64 + 6);
    v.extend_from_slice(script);
    v
}

fn coin(vout: u64, script: Vec<u8>) -> Coin {
    Coin { vout, height: 100, coinbase: false, amount: 50_000, script }
}

/// Parsed HUTX entry: (txid, vout, amount, height, coinbase, script).
type Entry = ([u8; 32], u32, u64, u32, u8, Vec<u8>);

#[derive(Debug)]
struct Hutx {
    height: u32,
    block_hash: [u8; 32],
    count: u64,
    hash: [u8; 32],
    entries: Vec<Entry>,
}

/// Run the converter on `core` bytes. `Err(stderr)` if it failed.
fn convert(core: &[u8]) -> Result<Hutx, String> {
    let dir = tempfile::TempDir::new().unwrap();
    let input = dir.path().join("dump.dat");
    let output = dir.path().join("out.hutx");
    std::fs::write(&input, core).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_convert_snapshot"))
        .arg(&input)
        .arg(&output)
        .output()
        .expect("run converter");
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(parse_hutx(&std::fs::read(&output).unwrap()))
}

fn parse_hutx(b: &[u8]) -> Hutx {
    let mut c = Cursor::new(b);
    let mut take = |n: usize| {
        let mut v = vec![0u8; n];
        c.read_exact(&mut v).unwrap();
        v
    };
    assert_eq!(take(4), b"HUTX");
    assert_eq!(take(4), 1u32.to_le_bytes());
    let height = u32::from_le_bytes(take(4).try_into().unwrap());
    let block_hash: [u8; 32] = take(32).try_into().unwrap();
    let count = u64::from_le_bytes(take(8).try_into().unwrap());
    let hash: [u8; 32] = take(32).try_into().unwrap();
    let mut entries = Vec::new();
    for _ in 0..count {
        let txid: [u8; 32] = take(32).try_into().unwrap();
        let vout = u32::from_le_bytes(take(4).try_into().unwrap());
        let amount = u64::from_le_bytes(take(8).try_into().unwrap());
        let h = u32::from_le_bytes(take(4).try_into().unwrap());
        let cb = take(1)[0];
        let len = u16::from_le_bytes(take(2).try_into().unwrap()) as usize;
        entries.push((txid, vout, amount, h, cb, take(len)));
    }
    assert_eq!(c.position() as usize, b.len(), "trailing bytes in HUTX output");
    Hutx { height, block_hash, count, hash, entries }
}

/// The HUTX content hash, recomputed independently from parsed entries.
fn content_hash(entries: &[Entry]) -> [u8; 32] {
    let mut h = Sha256::new();
    for (txid, vout, amount, height, cb, script) in entries {
        h.update(txid);
        h.update(vout.to_le_bytes());
        h.update(amount.to_le_bytes());
        h.update((script.len() as u16).to_le_bytes());
        h.update(script);
        h.update(height.to_le_bytes());
        h.update([*cb]);
    }
    h.finalize().into()
}

fn single(script: Vec<u8>) -> Vec<u8> {
    let out = convert(&dump(&[([7; 32], vec![coin(0, script)])], None)).unwrap();
    assert_eq!(out.entries.len(), 1);
    out.entries[0].5.clone()
}

#[test]
fn compressed_script_types_0_to_3_decompress_to_standard_scripts() {
    let mut p2pkh = vec![0x00];
    p2pkh.extend_from_slice(&[0x11; 20]);
    let mut expected = vec![0x76, 0xa9, 0x14];
    expected.extend_from_slice(&[0x11; 20]);
    expected.extend_from_slice(&[0x88, 0xac]);
    assert_eq!(single(p2pkh), expected);

    let mut p2sh = vec![0x01];
    p2sh.extend_from_slice(&[0x22; 20]);
    let mut expected = vec![0xa9, 0x14];
    expected.extend_from_slice(&[0x22; 20]);
    expected.push(0x87);
    assert_eq!(single(p2sh), expected);

    for kind in [0x02u8, 0x03] {
        let mut p2pk = vec![kind];
        p2pk.extend_from_slice(&[0x33; 32]);
        let mut expected = vec![0x21, kind];
        expected.extend_from_slice(&[0x33; 32]);
        expected.push(0xac);
        assert_eq!(single(p2pk), expected, "type {}", kind);
    }
}

/// Block 1's coinbase output: P2PK with an uncompressed key, which Core
/// stores as type 4 (even y) / 5 (odd y) plus x. The real script is the
/// 67-byte `41 04 <x> <y> ac`; a `21 02 <x> ac` stand-in is a different
/// output, so a block spending the coin would fail script validation.
#[test]
#[ignore = "BUG (consensus-critical, snapshot content): uncompressed P2PK (types 4/5) emitted as 35-byte compressed-key scripts; fixed by PR #27"]
fn uncompressed_p2pk_types_4_and_5_decompress_to_the_full_key() {
    use bitcoin::secp256k1::PublicKey;
    let block1_key = hex::decode(
        "0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee",
    )
    .unwrap();
    let odd_y = block1_key[64] & 1;
    for parity in [odd_y, odd_y ^ 1] {
        let compressed = [&[0x02 | parity][..], &block1_key[1..33]].concat();
        let pk = PublicKey::from_slice(&compressed).unwrap();
        let mut enc = vec![0x04 | parity];
        enc.extend_from_slice(&block1_key[1..33]);
        let mut expected = vec![0x41];
        expected.extend_from_slice(&pk.serialize_uncompressed());
        expected.push(0xac);
        if parity == odd_y {
            assert_eq!(&expected[1..66], &block1_key[..], "decompression reproduces block 1's key");
        }
        assert_eq!(single(enc), expected, "type {}", 4 | parity);
    }
}

#[test]
fn raw_scripts_round_trip_up_to_max_script_size() {
    assert!(single(raw_script(&[])).is_empty());
    let s: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(single(raw_script(&s)), s);
}

/// Core's ScriptCompression replaces scripts over MAX_SCRIPT_SIZE (they
/// are unspendable) with a single OP_RETURN.
#[test]
#[ignore = "BUG (snapshot content): raw scripts over 10,000 bytes are kept verbatim (Core: OP_RETURN, so UTXO count/MuHash differ); fixed by PR #27"]
fn raw_scripts_over_max_script_size_become_op_return() {
    let s = vec![0x51u8; 10_001];
    assert_eq!(single(raw_script(&s)), vec![0x6a]);
}

/// Core's amount compression test vectors (compress_tests.cpp), and a few
/// more amounts decompressed by the binary itself.
#[test]
fn core_amount_vectors_decompress_through_the_converter() {
    for (amount, compressed) in [
        (0u64, 0x0u64),
        (1, 0x1),
        (1_000_000, 0x7),
        (100_000_000, 0x9),
        (5_000_000_000, 0x32),
        (2_100_000_000_000_000, 0x1406f40),
    ] {
        assert_eq!(compress_amount(amount), compressed, "{}", amount);
    }
    let amounts = [0u64, 1, 1_000_000, 100_000_000, 5_000_000_000, 2_100_000_000_000_000, 546, 12_345_678_901];
    let coins: Vec<Coin> =
        amounts.iter().enumerate().map(|(i, a)| Coin { amount: *a, ..coin(i as u64, raw_script(&[0x51])) }).collect();
    let out = convert(&dump(&[([7; 32], coins)], None)).unwrap();
    let got: Vec<u64> = out.entries.iter().map(|e| e.2).collect();
    assert_eq!(got, amounts);
}

/// Multi-byte VARINT heights, the coinbase bit, CompactSize vouts past
/// 252 and 65,535, vouts sorted within a group, and the header height
/// being the highest coin height.
#[test]
fn numeric_encodings_and_ordering() {
    let groups = [
        (
            [0x01; 32],
            vec![
                Coin { vout: 70_000, height: 943_500, coinbase: true, ..coin(0, raw_script(&[0x51])) },
                Coin { vout: 300, height: 1, coinbase: false, ..coin(0, raw_script(&[0x52])) },
                Coin { vout: 0, height: 0x7fff_ffff, coinbase: true, ..coin(0, raw_script(&[0x53])) },
            ],
        ),
        ([0x02; 32], vec![Coin { vout: 252, height: 128, ..coin(0, raw_script(&[0x54])) }]),
    ];
    let out = convert(&dump(&groups, None)).unwrap();
    let got: Vec<([u8; 32], u32, u32, u8)> = out.entries.iter().map(|e| (e.0, e.1, e.3, e.4)).collect();
    assert_eq!(
        got,
        vec![
            ([0x01; 32], 0, 0x7fff_ffff, 1),
            ([0x01; 32], 300, 1, 0),
            ([0x01; 32], 70_000, 943_500, 1),
            ([0x02; 32], 252, 128, 0),
        ]
    );
    assert_eq!(out.height, 0x7fff_ffff);
    assert_eq!(out.count, 4);
    assert_eq!(out.block_hash, [0xab; 32]);
    assert_eq!(out.hash, content_hash(&out.entries));
}

/// The header hash is the function the node's loader checks
/// (`UtxoSet::compute_hash`), pinned to the golden value that
/// `utxo::edge_tests::compute_hash_matches_the_converter_golden_value`
/// computes from the same three coins through the library.
#[test]
fn header_hash_matches_the_library_golden_value() {
    let out = convert(&build_core_dump()).unwrap();
    assert_eq!(out.hash, content_hash(&out.entries));
    assert_eq!(hex::encode(out.hash), GOLDEN_HASH);
}

/// Shared with `src/utxo_tests.rs` (same constant there).
const GOLDEN_HASH: &str = "15087b9e28011c20d17569a2303049e1916d080070972d9439707d3cafda8d88";

#[test]
fn malformed_dumps_fail_without_claiming_success() {
    let good = dump(&[([7; 32], vec![coin(0, raw_script(&[0x51]))])], None);
    convert(&good).unwrap();
    // Every truncation of the dump fails.
    for cut in 0..good.len() {
        assert!(convert(&good[..cut]).is_err(), "truncated at {} accepted", cut);
    }
    // Bad magic.
    let mut bad = good.clone();
    bad[0] = b'U';
    assert!(convert(&bad).unwrap_err().contains("magic"));
    // More coins announced than present.
    assert!(convert(&dump(&[([7; 32], vec![coin(0, raw_script(&[0x51]))])], Some(2))).is_err());
}

#[test]
#[ignore = "BUG (pipeline robustness): dump version is not checked and trailing bytes after the last coin are ignored; fixed by PR #27"]
fn unsupported_version_and_trailing_bytes_are_rejected() {
    let good = dump(&[([7; 32], vec![coin(0, raw_script(&[0x51]))])], None);
    let mut v1 = good.clone();
    v1[5..7].copy_from_slice(&1u16.to_le_bytes());
    assert!(convert(&v1).is_err(), "version 1 accepted");
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(convert(&trailing).is_err(), "trailing byte accepted");
    // Fewer coins announced than present leaves the rest as trailing data.
    let two = vec![coin(0, raw_script(&[0x51])), coin(1, raw_script(&[0x51]))];
    assert!(convert(&dump(&[([7; 32], two)], Some(1))).is_err());
}
