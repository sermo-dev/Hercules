//! Convert a Bitcoin Core `dumptxoutset` file to Hercules HUTX snapshot format.
//!
//! Usage:
//!   cargo run --release --bin convert_snapshot -- <core_dump.dat> <output.hutx>
//!
//! Core dump format (v2):
//!   Header: magic("utxo\xff", 5) + version(u16, 2) + network_magic(4)
//!           + block_hash(32) + coin_count(u64, 8) = 51 bytes
//!   Body:   Entries grouped by txid:
//!           txid(32) + CompactSize(num_coins) +
//!           [CompactSize(vout) + Coin(VARINT(code) + VARINT(amount) + CompressedScript)] * num_coins
//!
//! HUTX format: See utxo.rs — flat entries sorted by (txid, vout).

use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::process;

const HUTX_MAGIC: [u8; 4] = [b'H', b'U', b'T', b'X'];
const HUTX_VERSION: u32 = 1;
const CORE_MAGIC: [u8; 5] = [b'u', b't', b'x', b'o', 0xff];
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: convert_snapshot <core_dump.dat> <output.hutx>");
        process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];

    eprintln!("Reading Bitcoin Core dump: {}", input_path);
    let file = File::open(input_path).expect("failed to open input file");
    let mut r = BufReader::new(file);

    // -- Parse Core header (51 bytes) --
    let mut magic = [0u8; 5];
    r.read_exact(&mut magic).expect("read magic");
    if magic != CORE_MAGIC {
        eprintln!("ERROR: expected magic 'utxo\\xff'");
        process::exit(1);
    }

    let mut ver_buf = [0u8; 2];
    r.read_exact(&mut ver_buf).expect("read version");
    let version = u16::from_le_bytes(ver_buf);
    eprintln!("Snapshot version: {}", version);
    if version != 2 {
        // v2 (Core 28+) is the txid-grouped body format parsed below.
        eprintln!("ERROR: unsupported dumptxoutset version {} (expected 2)", version);
        process::exit(1);
    }

    let mut net_magic = [0u8; 4];
    r.read_exact(&mut net_magic).expect("read network magic");
    if net_magic != MAINNET_MAGIC {
        eprintln!("WARNING: not mainnet");
    }

    let mut block_hash = [0u8; 32];
    r.read_exact(&mut block_hash).expect("read block hash");
    eprintln!("Block hash: {}", hex_encode_reversed(&block_hash));

    let mut count_buf = [0u8; 8];
    r.read_exact(&mut count_buf).expect("read coin count");
    let coin_count = u64::from_le_bytes(count_buf);
    eprintln!("Coin count: {}", coin_count);

    // -- Output setup --
    let out_file = File::create(output_path).expect("failed to create output file");
    let mut w = BufWriter::new(out_file);

    // Placeholder HUTX header (84 bytes)
    let header_size = 4 + 4 + 4 + 32 + 8 + 32;
    w.write_all(&vec![0u8; header_size])
        .expect("write placeholder");

    let mut hasher = Sha256::new();
    let mut total_written: u64 = 0;
    let mut max_height: u32 = 0;

    // -- Read grouped coin entries --
    // Core dumps are grouped by txid, sorted by txid in internal byte order.
    // Each group: txid(32) + CompactSize(num_coins) +
    //   [CompactSize(vout) + Coin] * num_coins
    // Within each group, vouts are sorted by the LevelDB key order.

    let mut coins_read: u64 = 0;

    while coins_read < coin_count {
        let mut txid = [0u8; 32];
        r.read_exact(&mut txid).unwrap_or_else(|e| {
            panic!("read txid at coin {}: {}", coins_read, e);
        });

        let num_coins = read_compact_size(&mut r).unwrap_or_else(|e| {
            panic!("read num_coins at coin {}: {}", coins_read, e);
        });

        let mut pending: Vec<(u32, i64, u32, u8, Vec<u8>)> = Vec::with_capacity(num_coins as usize);

        for _j in 0..num_coins {
            let vout = read_compact_size(&mut r).unwrap_or_else(|e| {
                panic!("read vout at coin {}: {}", coins_read, e);
            }) as u32;

            let code = read_varint(&mut r).unwrap_or_else(|e| {
                panic!("read code at coin {} vout {}: {}", coins_read, vout, e);
            });
            let height = (code >> 1) as u32;
            let is_coinbase = (code & 1) as u8;

            let comp_amount = read_varint(&mut r).unwrap_or_else(|e| {
                panic!("read amount at coin {} vout {}: {}", coins_read, vout, e);
            });
            let amount = decompress_amount(comp_amount) as i64;

            let script = read_compressed_script(&mut r).unwrap_or_else(|e| {
                panic!(
                    "read script at coin {} vout {} height {} amount {}: {}",
                    coins_read, vout, height, amount, e
                );
            });

            if height > max_height {
                max_height = height;
            }

            pending.push((vout, amount, height, is_coinbase, script));
            coins_read += 1;
        }

        // Sort by vout within group and write
        flush_entries(&txid, &mut pending, &mut w, &mut hasher, &mut total_written);

        if coins_read % 5_000_000 < num_coins {
            eprintln!(
                "  progress: {}/{} ({:.1}%)...",
                coins_read,
                coin_count,
                coins_read as f64 / coin_count as f64 * 100.0
            );
        }
    }

    // Core writes nothing after the last coin; trailing bytes mean the
    // header count and the body disagree.
    let mut extra = [0u8; 1];
    match r.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => {
            eprintln!("ERROR: trailing data after {} coins", coin_count);
            process::exit(1);
        }
        Err(e) => panic!("read after last coin: {}", e),
    }
    assert_eq!(total_written, coin_count, "written count != header coin count");

    w.flush().expect("flush output");

    let utxo_hash: [u8; 32] = hasher.finalize().into();

    eprintln!();
    eprintln!("Total UTXOs written: {}", total_written);
    eprintln!("Max height seen: {}", max_height);
    eprintln!("HUTX hash: {}", hex_encode(&utxo_hash));

    // Rewrite HUTX header
    drop(w);
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .open(output_path)
        .expect("reopen output");

    use std::io::Seek;
    out.seek(io::SeekFrom::Start(0)).expect("seek");

    out.write_all(&HUTX_MAGIC).expect("magic");
    out.write_all(&HUTX_VERSION.to_le_bytes()).expect("ver");
    out.write_all(&max_height.to_le_bytes()).expect("height");
    out.write_all(&block_hash).expect("hash");
    out.write_all(&total_written.to_le_bytes()).expect("count");
    out.write_all(&utxo_hash).expect("uhash");

    eprintln!();
    eprintln!("=== Conversion complete ===");
    eprintln!("Output: {}", output_path);
    eprintln!("Height: {}", max_height);
    eprintln!("UTXOs:  {}", total_written);
    eprintln!("Hash:   {}", hex_encode(&utxo_hash));
    eprintln!();
    eprintln!("Hardcode this in your Rust code:");
    eprintln!("  const ASSUMEUTXO_HEIGHT: u32 = {};", max_height);
    eprintln!(
        "  const ASSUMEUTXO_HASH: &str = \"{}\";",
        hex_encode(&utxo_hash)
    );
}

fn flush_entries(
    txid: &[u8; 32],
    pending: &mut Vec<(u32, i64, u32, u8, Vec<u8>)>,
    w: &mut BufWriter<File>,
    hasher: &mut Sha256,
    total: &mut u64,
) {
    pending.sort_by_key(|e| e.0); // sort by vout
    for (vout, amount, height, is_coinbase, script) in pending.drain(..) {
        let script_len = script.len() as u16;

        // Write HUTX entry
        w.write_all(txid).expect("w txid");
        w.write_all(&vout.to_le_bytes()).expect("w vout");
        w.write_all(&amount.to_le_bytes()).expect("w amount");
        w.write_all(&height.to_le_bytes()).expect("w height");
        w.write_all(&[is_coinbase]).expect("w cb");
        w.write_all(&script_len.to_le_bytes()).expect("w slen");
        w.write_all(&script).expect("w script");

        // Hash in Hercules compute_hash() order
        hasher.update(txid);
        hasher.update(&vout.to_le_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(&script_len.to_le_bytes());
        hasher.update(&script);
        hasher.update(&height.to_le_bytes());
        hasher.update(&[is_coinbase]);

        *total += 1;
    }
}

// ---------------------------------------------------------------------------
// Bitcoin Core serialization helpers
// ---------------------------------------------------------------------------

fn read_compact_size<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    match b[0] {
        0..=252 => Ok(b[0] as u64),
        253 => {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        254 => {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        255 => {
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }
}

fn read_varint<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut n: u64 = 0;
    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        let byte = b[0];
        if byte & 0x80 != 0 {
            n = (n << 7) | ((byte & 0x7f) as u64);
            n += 1;
        } else {
            n = (n << 7) | (byte as u64);
            return Ok(n);
        }
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

/// Bitcoin Core's `MAX_SCRIPT_SIZE`. `ScriptCompression` stores longer
/// scripts as a bare `OP_RETURN` (they are unspendable and never enter the
/// coins DB, so a real `dumptxoutset` should not contain any).
const MAX_SCRIPT_SIZE: u64 = 10_000;

/// Mirror of Core's `ScriptCompression::Unser` + `DecompressScript`
/// (`src/compressor.{h,cpp}`).
///
/// Special sizes 0x00..=0x05 encode the six template scripts; anything
/// else is a raw script of length `nSize - 6`.
///   0x00 P2PKH(hash160)          -> 76 a9 14 <20> 88 ac
///   0x01 P2SH(hash160)           -> a9 14 <20> 87
///   0x02/0x03 compressed P2PK    -> 21 02|03 <x> ac
///   0x04/0x05 UNCOMPRESSED P2PK  -> 41 04 <x> <y> ac, where the point is
///        recovered by decompressing (0x04 -> 02, 0x05 -> 03) || x.
///        An x that isn't on the curve is a decode failure, as in Core.
fn read_compressed_script<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let size = read_varint(r)?;
    match size {
        0x00 => {
            let mut hash = [0u8; 20];
            r.read_exact(&mut hash)?;
            let mut s = Vec::with_capacity(25);
            s.extend_from_slice(&[0x76, 0xa9, 0x14]);
            s.extend_from_slice(&hash);
            s.extend_from_slice(&[0x88, 0xac]);
            Ok(s)
        }
        0x01 => {
            let mut hash = [0u8; 20];
            r.read_exact(&mut hash)?;
            let mut s = Vec::with_capacity(23);
            s.extend_from_slice(&[0xa9, 0x14]);
            s.extend_from_slice(&hash);
            s.push(0x87);
            Ok(s)
        }
        0x02 | 0x03 => {
            let mut x = [0u8; 32];
            r.read_exact(&mut x)?;
            let mut s = Vec::with_capacity(35);
            s.push(0x21);
            s.push(size as u8);
            s.extend_from_slice(&x);
            s.push(0xac);
            Ok(s)
        }
        0x04 | 0x05 => {
            let mut compressed = [0u8; 33];
            compressed[0] = (size - 2) as u8;
            r.read_exact(&mut compressed[1..])?;
            let pk = bitcoin::secp256k1::PublicKey::from_slice(&compressed).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("compressed script type {:#04x}: x not on curve: {}", size, e),
                )
            })?;
            let mut s = Vec::with_capacity(67);
            s.push(0x41);
            s.extend_from_slice(&pk.serialize_uncompressed());
            s.push(0xac);
            Ok(s)
        }
        other => {
            let len = other - 6;
            if len > MAX_SCRIPT_SIZE {
                // Core: `script << OP_RETURN; s.ignore(nSize);`
                io::copy(&mut r.by_ref().take(len), &mut io::sink()).and_then(|n| {
                    if n == len {
                        Ok(())
                    } else {
                        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "oversized script"))
                    }
                })?;
                return Ok(vec![0x6a]);
            }
            let mut s = vec![0u8; len as usize];
            r.read_exact(&mut s)?;
            Ok(s)
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_encode_reversed(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut r = bytes;
        let s = read_compressed_script(&mut r)?;
        assert!(r.is_empty(), "trailing bytes after compressed script");
        Ok(s)
    }

    // Block 1 coinbase output 0 (txid 0e3e2357...512098:0), uncompressed P2PK.
    const BLOCK1_PUBKEY: &str = "0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee";

    #[test]
    fn p2pkh_and_p2sh() {
        let h = [0x11u8; 20];
        let mut b = vec![0x00];
        b.extend_from_slice(&h);
        let s = decode(&b).unwrap();
        assert_eq!(s, [&[0x76, 0xa9, 0x14][..], &h, &[0x88, 0xac]].concat());

        let mut b = vec![0x01];
        b.extend_from_slice(&h);
        let s = decode(&b).unwrap();
        assert_eq!(s, [&[0xa9, 0x14][..], &h, &[0x87]].concat());
    }

    #[test]
    fn compressed_p2pk() {
        let pk = hex::decode(BLOCK1_PUBKEY).unwrap();
        let x = &pk[1..33];
        for t in [0x02u8, 0x03] {
            let mut b = vec![t];
            b.extend_from_slice(x);
            let s = decode(&b).unwrap();
            assert_eq!(s, [&[0x21, t][..], x, &[0xac]].concat());
        }
    }

    #[test]
    fn uncompressed_p2pk_block1_coinbase() {
        let pk = hex::decode(BLOCK1_PUBKEY).unwrap();
        // y is even -> Core's CompressScript stores 0x04 | (y & 1) = 0x04.
        assert_eq!(pk[64] & 1, 0);
        let mut b = vec![0x04];
        b.extend_from_slice(&pk[1..33]);
        let s = decode(&b).unwrap();
        assert_eq!(s.len(), 67);
        assert_eq!(s, [&[0x41][..], &pk, &[0xac]].concat());
    }

    #[test]
    fn uncompressed_p2pk_odd_y() {
        // Negating the point flips y parity; 0x05 must recover it.
        let pk = bitcoin::secp256k1::PublicKey::from_slice(&hex::decode(BLOCK1_PUBKEY).unwrap())
            .unwrap()
            .negate(&bitcoin::secp256k1::Secp256k1::verification_only());
        let full = pk.serialize_uncompressed();
        assert_eq!(full[64] & 1, 1);
        let mut b = vec![0x05];
        b.extend_from_slice(&full[1..33]);
        let s = decode(&b).unwrap();
        assert_eq!(s, [&[0x41][..], &full, &[0xac]].concat());
    }

    #[test]
    fn uncompressed_p2pk_off_curve_is_error() {
        // x = 5 has no y on secp256k1 (5^3 + 7 = 132 is a non-residue).
        let mut b = vec![0x04];
        let mut x = [0u8; 32];
        x[31] = 5;
        b.extend_from_slice(&x);
        let err = decode(&b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn raw_scripts() {
        // nSize = len + 6.
        assert_eq!(decode(&[0x06]).unwrap(), Vec::<u8>::new());
        assert_eq!(decode(&[0x08, 0x51, 0x52]).unwrap(), vec![0x51, 0x52]);
        // P2WPKH: 22 bytes -> nSize 28.
        let mut b = vec![28u8, 0x00, 0x14];
        b.extend_from_slice(&[0xab; 20]);
        assert_eq!(decode(&b).unwrap(), b[1..].to_vec());
        // Truncated raw script errors.
        assert!(decode(&[0x0a, 0x51]).is_err());
    }

    #[test]
    fn oversized_script_becomes_op_return() {
        // nSize = 10_001 + 6 as a Core VARINT, followed by 10_001 bytes.
        let n: u64 = 10_001 + 6;
        let mut v = Vec::new();
        let mut tmp = Vec::new();
        let mut x = n;
        loop {
            tmp.push((x & 0x7f) as u8 | if tmp.is_empty() { 0 } else { 0x80 });
            if x <= 0x7f {
                break;
            }
            x = (x >> 7) - 1;
        }
        tmp.reverse();
        v.extend_from_slice(&tmp);
        assert_eq!(read_varint(&mut &v[..]).unwrap(), n);
        v.extend(std::iter::repeat(0u8).take(10_001));
        assert_eq!(decode(&v).unwrap(), vec![0x6a]);
    }

    #[test]
    fn amounts_round_trip_core_vectors() {
        // From Core's compress_tests.cpp.
        assert_eq!(decompress_amount(0x0), 0);
        assert_eq!(decompress_amount(0x1), 1);
        assert_eq!(decompress_amount(0x7), 1_000_000);
        assert_eq!(decompress_amount(0x9), 100_000_000);
        assert_eq!(decompress_amount(0x32), 50 * 100_000_000);
        assert_eq!(decompress_amount(0x1406f40), 21_000_000 * 100_000_000);
    }
}
