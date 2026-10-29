//! Port of Bitcoin Core's `ParseScript` (src/core_io.cpp), so Core's script
//! test vectors can be built here. Test-only; from the ticket 047 spike.

const OPCODES: &[(&str, u8)] = &[
    ("OP_RESERVED", 0x50),
    ("OP_NOP", 0x61),
    ("OP_VER", 0x62),
    ("OP_IF", 0x63),
    ("OP_NOTIF", 0x64),
    ("OP_VERIF", 0x65),
    ("OP_VERNOTIF", 0x66),
    ("OP_ELSE", 0x67),
    ("OP_ENDIF", 0x68),
    ("OP_VERIFY", 0x69),
    ("OP_RETURN", 0x6a),
    ("OP_TOALTSTACK", 0x6b),
    ("OP_FROMALTSTACK", 0x6c),
    ("OP_2DROP", 0x6d),
    ("OP_2DUP", 0x6e),
    ("OP_3DUP", 0x6f),
    ("OP_2OVER", 0x70),
    ("OP_2ROT", 0x71),
    ("OP_2SWAP", 0x72),
    ("OP_IFDUP", 0x73),
    ("OP_DEPTH", 0x74),
    ("OP_DROP", 0x75),
    ("OP_DUP", 0x76),
    ("OP_NIP", 0x77),
    ("OP_OVER", 0x78),
    ("OP_PICK", 0x79),
    ("OP_ROLL", 0x7a),
    ("OP_ROT", 0x7b),
    ("OP_SWAP", 0x7c),
    ("OP_TUCK", 0x7d),
    ("OP_CAT", 0x7e),
    ("OP_SUBSTR", 0x7f),
    ("OP_LEFT", 0x80),
    ("OP_RIGHT", 0x81),
    ("OP_SIZE", 0x82),
    ("OP_INVERT", 0x83),
    ("OP_AND", 0x84),
    ("OP_OR", 0x85),
    ("OP_XOR", 0x86),
    ("OP_EQUAL", 0x87),
    ("OP_EQUALVERIFY", 0x88),
    ("OP_RESERVED1", 0x89),
    ("OP_RESERVED2", 0x8a),
    ("OP_1ADD", 0x8b),
    ("OP_1SUB", 0x8c),
    ("OP_2MUL", 0x8d),
    ("OP_2DIV", 0x8e),
    ("OP_NEGATE", 0x8f),
    ("OP_ABS", 0x90),
    ("OP_NOT", 0x91),
    ("OP_0NOTEQUAL", 0x92),
    ("OP_ADD", 0x93),
    ("OP_SUB", 0x94),
    ("OP_MUL", 0x95),
    ("OP_DIV", 0x96),
    ("OP_MOD", 0x97),
    ("OP_LSHIFT", 0x98),
    ("OP_RSHIFT", 0x99),
    ("OP_BOOLAND", 0x9a),
    ("OP_BOOLOR", 0x9b),
    ("OP_NUMEQUAL", 0x9c),
    ("OP_NUMEQUALVERIFY", 0x9d),
    ("OP_NUMNOTEQUAL", 0x9e),
    ("OP_LESSTHAN", 0x9f),
    ("OP_GREATERTHAN", 0xa0),
    ("OP_LESSTHANOREQUAL", 0xa1),
    ("OP_GREATERTHANOREQUAL", 0xa2),
    ("OP_MIN", 0xa3),
    ("OP_MAX", 0xa4),
    ("OP_WITHIN", 0xa5),
    ("OP_RIPEMD160", 0xa6),
    ("OP_SHA1", 0xa7),
    ("OP_SHA256", 0xa8),
    ("OP_HASH160", 0xa9),
    ("OP_HASH256", 0xaa),
    ("OP_CODESEPARATOR", 0xab),
    ("OP_CHECKSIG", 0xac),
    ("OP_CHECKSIGVERIFY", 0xad),
    ("OP_CHECKMULTISIG", 0xae),
    ("OP_CHECKMULTISIGVERIFY", 0xaf),
    ("OP_NOP1", 0xb0),
    ("OP_CHECKLOCKTIMEVERIFY", 0xb1),
    ("OP_CHECKSEQUENCEVERIFY", 0xb2),
    ("OP_NOP4", 0xb3),
    ("OP_NOP5", 0xb4),
    ("OP_NOP6", 0xb5),
    ("OP_NOP7", 0xb6),
    ("OP_NOP8", 0xb7),
    ("OP_NOP9", 0xb8),
    ("OP_NOP10", 0xb9),
    ("OP_CHECKSIGADD", 0xba),
];

fn opcode(name: &str) -> Option<u8> {
    OPCODES
        .iter()
        .find(|(n, _)| *n == name || n.strip_prefix("OP_") == Some(name))
        .map(|(_, v)| *v)
}

/// Minimal-length data push, as `CScript::operator<<(std::vector<unsigned char>)`.
pub fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < 0x4c {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(0x4c);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// `CScript::operator<<(int64_t)`: OP_0 / OP_1NEGATE / OP_1..OP_16, else CScriptNum push.
fn push_int(out: &mut Vec<u8>, n: i64) {
    if n == -1 || (1..=16).contains(&n) {
        out.push((n + 0x50) as u8);
    } else if n == 0 {
        out.push(0x00);
    } else {
        let neg = n < 0;
        let mut abs = n.unsigned_abs();
        let mut v = Vec::new();
        while abs > 0 {
            v.push((abs & 0xff) as u8);
            abs >>= 8;
        }
        if v.last().unwrap() & 0x80 != 0 {
            v.push(if neg { 0x80 } else { 0x00 });
        } else if neg {
            *v.last_mut().unwrap() |= 0x80;
        }
        push_data(out, &v);
    }
}

pub fn parse_script(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for w in s.split([' ', '\t', '\n']) {
        if w.is_empty() {
            continue;
        }
        let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
        if digits(w) || (w.starts_with('-') && digits(&w[1..])) {
            let n: i64 = w.parse().map_err(|_| format!("bad number {w}"))?;
            if n > 0xffff_ffff || n < -0xffff_ffff {
                return Err(format!("number out of range {w}"));
            }
            push_int(&mut out, n);
        } else if w.len() > 2 && w.starts_with("0x") && hex::decode(&w[2..]).is_ok() {
            out.extend(hex::decode(&w[2..]).unwrap());
        } else if w.len() >= 2 && w.starts_with('\'') && w.ends_with('\'') {
            push_data(&mut out, &w.as_bytes()[1..w.len() - 1]);
        } else {
            out.push(opcode(w).ok_or_else(|| format!("unknown opcode {w}"))?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_core_examples() {
        assert_eq!(parse_script("0").unwrap(), vec![0x00]);
        assert_eq!(parse_script("-1 16 17").unwrap(), vec![0x4f, 0x60, 0x01, 0x11]);
        assert_eq!(parse_script("DUP OP_HASH160 0x14 0x00").unwrap(), vec![0x76, 0xa9, 0x14, 0x00]);
        assert_eq!(parse_script("-128").unwrap(), vec![0x02, 0x80, 0x80]);
        assert_eq!(parse_script("'ab'").unwrap(), vec![0x02, b'a', b'b']);
        assert_eq!(parse_script("CHECKLOCKTIMEVERIFY NOP2").ok(), None); // NOP2 is not a Core name
        assert_eq!(parse_script("CHECKLOCKTIMEVERIFY").unwrap(), vec![0xb1]);
    }
}
