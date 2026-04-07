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
        0x02 | 0x03 | 0x04 | 0x05 => {
            let mut x = [0u8; 32];
            r.read_exact(&mut x)?;
            let mut s = Vec::with_capacity(35);
            let prefix = if size == 0x02 || size == 0x04 { 0x02 } else { 0x03 };
            s.push(0x21);
            s.push(prefix);
            s.extend_from_slice(&x);
            s.push(0xac);
            Ok(s)
        }
        other => {
            let len = (other - 6) as usize;
            let mut s = vec![0u8; len];
            if len > 0 {
                r.read_exact(&mut s)?;
            }
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
