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
