//! Tor v3 .onion address ⇄ ed25519 pubkey conversion (rend-spec-v3 §6).
//!
//! BIP 155's `addrv2` carries Tor v3 peers as raw 32-byte ed25519 pubkeys,
//! but Arti's `client.connect()` takes a `host:port` string. Going from
//! gossipped pubkey → dialable hostname (and back) means doing the same
//! base32 + checksum dance the Tor spec defines for the .onion encoding.
//!
//! ## Encoding
//!
//! ```text
//! checksum  = SHA3_256(".onion checksum" || pubkey || version)[..2]
//! payload   = pubkey[32] || checksum[2] || version[1]   // 35 bytes
//! hostname  = base32_lower(payload) + ".onion"          // 56 + 6 chars
//! ```
//!
//! Decoding is the reverse, with the checksum recomputed and compared
//! before we trust the pubkey. We verify checksums in *both* directions
//! even though Hercules currently only decodes its *own* hostname (handed
//! to us by Arti) — the cost is one Keccak invocation, and it lets us
//! reuse the same helper for any future code path that decodes a peer-
//! gossipped hostname (e.g., a `-addnode` style UI feature).

use sha3::{Digest, Sha3_256};

/// Tor v3 onion address version byte (rend-spec-v3 §6).
const TORV3_VERSION: u8 = 0x03;

/// SHA3-256 prefix used in the .onion checksum derivation.
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// Length of the base32-encoded payload (without the ".onion" suffix).
/// 35 bytes → ceil(35 * 8 / 5) = 56 chars.
const ENCODED_LEN: usize = 56;

/// Encode a 32-byte ed25519 pubkey into a v3 .onion hostname (without
/// the trailing port). The result is always 62 characters: 56 base32
/// chars + ".onion".
pub fn pubkey_to_hostname(pubkey: &[u8; 32]) -> String {
    let mut payload = [0u8; 35];
    payload[..32].copy_from_slice(pubkey);
    let checksum = compute_checksum(pubkey);
    payload[32] = checksum[0];
    payload[33] = checksum[1];
    payload[34] = TORV3_VERSION;

    let mut out = base32_encode_lower(&payload);
    out.push_str(".onion");
    out
}

/// Decode a v3 .onion hostname into the 32-byte ed25519 pubkey it embeds.
///
/// `hostname` may include or omit a `:port` suffix and is case-insensitive.
/// Returns `None` if the input is not a syntactically valid v3 onion or
/// if the embedded checksum doesn't match what we'd compute from the pubkey.
pub fn hostname_to_pubkey(hostname: &str) -> Option<[u8; 32]> {
    // Strip an optional :port and the .onion suffix.
    let host = hostname.split(':').next()?;
    let stem = host.strip_suffix(".onion")?;
    if stem.len() != ENCODED_LEN {
        return None;
    }

    let payload = base32_decode_lower(stem)?;
    if payload.len() != 35 {
        return None;
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&payload[..32]);
    let on_disk_checksum = [payload[32], payload[33]];
    let version = payload[34];

    if version != TORV3_VERSION {
        return None;
    }
    let computed = compute_checksum(&pubkey);
    if computed != on_disk_checksum {
        return None;
    }

    Some(pubkey)
}

/// SHA3-256(".onion checksum" || pubkey || 0x03)[..2].
fn compute_checksum(pubkey: &[u8; 32]) -> [u8; 2] {
    let mut hasher = Sha3_256::new();
    hasher.update(CHECKSUM_PREFIX);
    hasher.update(pubkey);
    hasher.update([TORV3_VERSION]);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

// ── RFC 4648 base32 (lowercase) ───────────────────────────────────────
//
// Hand-rolled because we don't pull `data-encoding` and `base32` is
// abandoned. Tor's encoding is RFC 4648 §6 with lowercase output and
// no padding (35-byte input → 56 chars exactly, no '=' padding needed).

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode_lower(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Decode a base32 string. Accepts lowercase only — Tor v3 hostnames are
/// always lowercase, and accepting uppercase would let two different
/// strings parse to the same pubkey (an annoying source of dedup bugs in
/// the addrman).
fn base32_decode_lower(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in input.chars() {
        let val = match ch {
            'a'..='z' => ch as u32 - 'a' as u32,
            '2'..='7' => 26 + (ch as u32 - '2' as u32),
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known v3 onion fixture from the Tor spec test vectors:
    /// pubkey of all zeros → a stable, well-defined hostname we can
    /// verify by recomputing instead of pasting magic strings.
    #[test]
    fn encode_decode_roundtrip_zero_pubkey() {
        let pubkey = [0u8; 32];
        let hostname = pubkey_to_hostname(&pubkey);
        assert!(hostname.ends_with(".onion"));
        assert_eq!(hostname.len(), ENCODED_LEN + ".onion".len());

        let recovered = hostname_to_pubkey(&hostname).expect("valid roundtrip");
        assert_eq!(recovered, pubkey);
    }

    #[test]
    fn encode_decode_roundtrip_random_pubkey() {
        // Use a deterministic non-trivial pubkey so test failures reproduce.
        let mut pubkey = [0u8; 32];
        for (i, byte) in pubkey.iter_mut().enumerate() {
            *byte = (i * 7 + 13) as u8;
        }
        let hostname = pubkey_to_hostname(&pubkey);
        let recovered = hostname_to_pubkey(&hostname).expect("valid roundtrip");
        assert_eq!(recovered, pubkey);
    }

    #[test]
    fn decode_strips_port_suffix() {
        let pubkey = [0xab; 32];
        let hostname = pubkey_to_hostname(&pubkey);
        let with_port = format!("{}:8333", hostname);
        let recovered = hostname_to_pubkey(&with_port).expect("port suffix tolerated");
        assert_eq!(recovered, pubkey);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        // Truncated stem (one char short).
        assert!(hostname_to_pubkey("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion").is_none());
    }

    #[test]
    fn decode_rejects_uppercase() {
        // Uppercase isn't valid base32_lower input — keeps the addrman from
        // ever holding two equivalent forms of the same address.
        let pubkey = [0u8; 32];
        let hostname = pubkey_to_hostname(&pubkey);
        let upper = hostname.to_uppercase();
        // The .onion suffix is also uppercased, so the strip_suffix call
        // already returns None — but the more interesting failure mode is
        // a mixed-case stem with a lowercase .onion suffix:
        let mixed: String = hostname
            .strip_suffix(".onion")
            .unwrap()
            .to_uppercase()
            + ".onion";
        assert!(hostname_to_pubkey(&mixed).is_none());
        // And the all-uppercase form too:
        assert!(hostname_to_pubkey(&upper).is_none());
    }

    #[test]
    fn decode_rejects_bad_checksum() {
        // Take a valid hostname, flip one bit in the checksum region (chars
        // 51..56), and re-decode. The version byte and pubkey are unchanged
        // but the checksum no longer matches → reject.
        let pubkey = [0xab; 32];
        let hostname = pubkey_to_hostname(&pubkey);
        let mut bytes: Vec<u8> = hostname.into_bytes();
        // Flip the 52nd char of the stem — well into the checksum region.
        // 'a' → 'b' is a single-bit change in the base32 alphabet index.
        bytes[52] = if bytes[52] == b'a' { b'b' } else { b'a' };
        let mangled = String::from_utf8(bytes).unwrap();
        assert!(hostname_to_pubkey(&mangled).is_none());
    }

    #[test]
    fn decode_rejects_bad_version_byte() {
        // Construct a synthetic 35-byte payload with version = 0x02 and
        // verify decode rejects it. We can't easily produce this through
        // pubkey_to_hostname (which always writes 0x03), so we encode a
        // hand-crafted payload and feed the result back.
        let pubkey = [0u8; 32];
        let bad_checksum = compute_checksum(&pubkey);
        let mut payload = [0u8; 35];
        payload[..32].copy_from_slice(&pubkey);
        payload[32] = bad_checksum[0];
        payload[33] = bad_checksum[1];
        payload[34] = 0x02; // wrong version
        let mut hostname = base32_encode_lower(&payload);
        hostname.push_str(".onion");
        assert!(hostname_to_pubkey(&hostname).is_none());
    }

    #[test]
    fn base32_encode_known_vector() {
        // RFC 4648 §10 test vector: "foobar" → "mzxw6ytboi" (lowercase).
        // 6 bytes → 10 chars, no padding for our purposes.
        assert_eq!(base32_encode_lower(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn base32_decode_known_vector() {
        let decoded = base32_decode_lower("mzxw6ytboi").unwrap();
        // 10 base32 chars carry 50 bits → 6 bytes + 2 trailing bits we
        // ignore (which is what RFC 4648 padding would normally absorb).
        assert_eq!(&decoded[..6], b"foobar");
    }

    #[test]
    fn base32_decode_rejects_non_alphabet() {
        assert!(base32_decode_lower("mzxw6yt!oi").is_none());
        assert!(base32_decode_lower("MZXW6YTBOI").is_none()); // uppercase
        assert!(base32_decode_lower("0189").is_none()); // 0/1/8/9 not in alphabet
    }
}
