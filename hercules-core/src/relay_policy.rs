//! Knots-aligned relay policy filters.
//!
//! Pure functions that inspect a transaction for non-monetary patterns
//! (inscriptions, token protocols, data injection) and reject them before
//! they enter the mempool. Policy-only — consensus validity is unaffected.

use bitcoin::opcodes::all::{OP_DROP, OP_IF};
use bitcoin::script::Instruction;
use bitcoin::Transaction;

// ── Constants ─────────────────────────────────────────────────────────

/// Maximum size of any single witness element (bytes).
/// Matches Knots's `-maxscriptsize` default. Catches large inscriptions
/// before the more expensive opcode-level scanning.
const MAX_WITNESS_ITEM_SIZE: usize = 1650;

/// Minimum push size to flag a `<data> OP_DROP` as data injection.
/// Normal script constants (pubkeys 33 B, hashes 20-32 B) stay well
/// below this. Inscription-style payloads are typically hundreds+ bytes.
const OP_DROP_DATA_THRESHOLD: usize = 75;

/// First byte of a taproot annex (BIP 341 `ANNEX_TAG`).
const TAPROOT_ANNEX_TAG: u8 = 0x50;

// ── Rejection reasons ─────────────────────────────────────────────────

/// Why a transaction was rejected by relay policy.
#[derive(Debug)]
pub enum PolicyRejection {
    /// CAT-21 parasitic protocol (`nLockTime == 21`).
    Cat21,
    /// Runes token protocol (OP_RETURN starting with OP_13).
    Runes { output_index: usize },
    /// Witness element exceeds the 1650-byte cap.
    OversizedWitnessItem { input_index: usize, size: usize },
    /// OLGA / Stamps data embedded in witness script.
    OlgaStamps { input_index: usize },
    /// Large `<data> OP_DROP` injection in witness script.
    OpDropData { input_index: usize },
    /// Inscription envelope (`OP_FALSE OP_IF ... OP_ENDIF`) in witness.
    InscriptionEnvelope { input_index: usize, tag: String },
}

// ── Public entry point ────────────────────────────────────────────────

/// Run all relay policy checks against a transaction whose spent outputs
/// aren't known, as for a warning before the inputs are looked up. Which
/// witness element is a script is then inferred from the witness's shape
/// (see [`witness_script`]); the mempool uses
/// [`check_relay_policy_with_spent`] instead.
pub fn check_relay_policy(tx: &Transaction) -> Result<(), PolicyRejection> {
    check_all(tx, None)
}

/// Run all relay policy checks, with `spent_scripts[i]` the scriptPubKey
/// input `i` spends: the script-content filters then read exactly the
/// P2WSH witnessScript or the tapscript leaf, and never a signature,
/// public key, control block or annex.
pub fn check_relay_policy_with_spent(tx: &Transaction, spent_scripts: &[&[u8]]) -> Result<(), PolicyRejection> {
    check_all(tx, Some(spent_scripts))
}

/// Checks are ordered cheapest-first so the common case (legitimate
/// payment) exits quickly. Returns the first rejection found.
fn check_all(tx: &Transaction, spent: Option<&[&[u8]]>) -> Result<(), PolicyRejection> {
    check_cat21(tx)?;
    check_runes(tx)?;
    check_witness_size(tx)?;
    for (i, input) in tx.input.iter().enumerate() {
        let spent_spk = spent.map(|s| s.get(i).copied().unwrap_or(&[]));
        if let Some(script) = witness_script(input, spent_spk) {
            check_olga_stamps(i, script)?;
            check_op_drop_data(i, script)?;
            check_inscription_envelope(i, script)?;
        }
    }
    Ok(())
}

/// The script an input's witness executes, if any: the witnessScript of a
/// P2WSH (or P2SH-wrapped P2WSH) spend, the last element; or the leaf
/// script of a taproot script-path spend, the element before the control
/// block once an annex (a last element starting 0x50, BIP 341) is set
/// aside. P2WPKH and taproot key-path spends execute no witness script.
///
/// Knots' witness filters (`IsWitnessStandard`'s datacarrier accounting)
/// likewise read only the tapscript, never signatures or keys.
///
/// With `spent_spk` (the output being spent) this follows the script's
/// type exactly. Without it the type is inferred: an annex, or a last
/// element shaped like a control block, marks taproot; two elements ending in a
/// compressed public key are taken as P2WPKH; any other witness of two or
/// more elements as P2WSH.
fn witness_script<'a>(input: &'a bitcoin::TxIn, spent_spk: Option<&[u8]>) -> Option<&'a [u8]> {
    let witness = &input.witness;
    let n = witness.len();
    // Items left once a taproot annex is set aside.
    let without_annex = if n >= 2 && witness.last().is_some_and(|a| a.first() == Some(&TAPROOT_ANNEX_TAG)) {
        n - 1
    } else {
        n
    };
    let leaf = || if without_annex >= 2 { witness.nth(without_annex - 2) } else { None };
    match spent_spk {
        Some(spk) => {
            let spk = bitcoin::Script::from_bytes(spk);
            if spk.is_p2wsh() {
                witness.last()
            } else if spk.is_p2tr() {
                leaf()
            } else if spk.is_p2sh() {
                // The redeem script is the scriptSig's last push.
                match input.script_sig.instructions().last()?.ok()? {
                    Instruction::PushBytes(b) if bitcoin::Script::from_bytes(b.as_bytes()).is_p2wsh() => {
                        witness.last()
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
        None => {
            // Only a taproot spend has an annex.
            if without_annex < n || (n >= 2 && is_control_block_shaped(witness.last()?)) {
                return leaf();
            }
            let last = witness.last()?;
            let p2wpkh_shaped = n == 2 && last.len() == 33 && matches!(last[0], 0x02 | 0x03);
            (n >= 2 && !p2wpkh_shaped).then_some(last)
        }
    }
}

/// BIP 341 control block: 33 + 32m bytes (m <= 128), and a tapscript leaf
/// version (0xc0, low bit the output key's parity).
fn is_control_block_shaped(item: &[u8]) -> bool {
    item.len() >= 33 && (item.len() - 33).is_multiple_of(32) && (item.len() - 33) / 32 <= 128 && item[0] & 0xfe == 0xc0
}

// ── Individual checks ─────────────────────────────────────────────────

/// CAT-21: pixelated-cat NFT protocol uses `nLockTime == 21` as marker.
/// Block height 21 was mined in 2009, so this never rejects a legitimate
/// time-locked transaction.
fn check_cat21(tx: &Transaction) -> Result<(), PolicyRejection> {
    if tx.lock_time.to_consensus_u32() == 21 {
        return Err(PolicyRejection::Cat21);
    }
    Ok(())
}

/// Runes: token protocol using OP_RETURN with OP_PUSHNUM_13 (0x5d) as
/// the first data byte after OP_RETURN.
fn check_runes(tx: &Transaction) -> Result<(), PolicyRejection> {
    for (i, output) in tx.output.iter().enumerate() {
        let spk = &output.script_pubkey;
        if spk.is_op_return() {
            let bytes = spk.as_bytes();
            // bytes[0] == OP_RETURN (0x6a), bytes[1] == first push/opcode
            if bytes.len() >= 2 && bytes[1] == 0x5d {
                return Err(PolicyRejection::Runes { output_index: i });
            }
        }
    }
    Ok(())
}

/// Witness element size cap: reject any element > 1650 bytes.
/// Catches most large inscriptions with zero opcode parsing.
fn check_witness_size(tx: &Transaction) -> Result<(), PolicyRejection> {
    for (i, input) in tx.input.iter().enumerate() {
        for elem in input.witness.iter() {
            if elem.len() > MAX_WITNESS_ITEM_SIZE {
                return Err(PolicyRejection::OversizedWitnessItem {
                    input_index: i,
                    size: elem.len(),
                });
            }
        }
    }
    Ok(())
}

/// OLGA / Bitcoin Stamps: data embedded in P2WSH witness scripts with
/// a `stamp:` prefix.
fn check_olga_stamps(input_index: usize, script: &[u8]) -> Result<(), PolicyRejection> {
    if script.len() >= 6 && script.windows(6).any(|w| w.eq_ignore_ascii_case(b"stamp:")) {
        return Err(PolicyRejection::OlgaStamps { input_index });
    }
    Ok(())
}

/// `<data> OP_DROP` injection: data pushed then immediately dropped.
/// Only flags pushes larger than `OP_DROP_DATA_THRESHOLD` to avoid
/// false-positives on normal hash preimage reveals and pubkeys.
fn check_op_drop_data(input_index: usize, script: &[u8]) -> Result<(), PolicyRejection> {
    let mut prev_push_len: usize = 0;
    for instruction in bitcoin::Script::from_bytes(script).instructions() {
        match instruction {
            Ok(Instruction::PushBytes(bytes)) => {
                prev_push_len = bytes.len();
            }
            Ok(Instruction::Op(op)) if op == OP_DROP => {
                if prev_push_len > OP_DROP_DATA_THRESHOLD {
                    return Err(PolicyRejection::OpDropData { input_index });
                }
                prev_push_len = 0;
            }
            _ => {
                prev_push_len = 0;
            }
        }
    }
    Ok(())
}

/// Inscription envelope: `OP_FALSE OP_IF ... OP_ENDIF` pattern in
/// witness data. Used by Ordinals, BRC-20, SNS, Atomicals, and every
/// other inscription protocol. We reject ALL envelopes regardless of
/// the protocol tag — the pattern itself is the signal.
///
/// In bitcoin 0.32, `OP_FALSE` (opcode 0x00) is parsed as
/// `Instruction::PushBytes(bytes)` with `bytes.is_empty()`, NOT as
/// `Instruction::Op(OP_PUSHBYTES_0)`.
fn check_inscription_envelope(input_index: usize, script: &[u8]) -> Result<(), PolicyRejection> {
    let script = bitcoin::Script::from_bytes(script);
    let mut saw_false = false;
    for instruction in script.instructions() {
        match instruction {
            // OP_FALSE == OP_PUSHBYTES_0 == push of zero bytes
            Ok(Instruction::PushBytes(bytes)) if bytes.is_empty() => {
                saw_false = true;
            }
            Ok(Instruction::Op(op)) if op == OP_IF && saw_false => {
                // Found OP_FALSE OP_IF — this is an envelope.
                // Capture the next push as the protocol tag for logging.
                let tag = capture_envelope_tag(script);
                return Err(PolicyRejection::InscriptionEnvelope { input_index, tag });
            }
            _ => {
                saw_false = false;
            }
        }
    }
    Ok(())
}

/// Walk the script from the start to find the first push after
/// `OP_FALSE OP_IF`, returning it as a lossy UTF-8 string for logging.
fn capture_envelope_tag(script: &bitcoin::Script) -> String {
    let mut saw_false = false;
    let mut in_envelope = false;

    for instruction in script.instructions() {
        match instruction {
            Ok(Instruction::PushBytes(bytes)) if bytes.is_empty() => {
                saw_false = true;
            }
            Ok(Instruction::Op(op)) if op == OP_IF && saw_false => {
                in_envelope = true;
                saw_false = false;
            }
            Ok(Instruction::PushBytes(bytes)) if in_envelope => {
                return String::from_utf8_lossy(bytes.as_bytes()).into_owned();
            }
            _ => {
                saw_false = false;
            }
        }
    }
    "<unknown>".to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};

    /// Build a minimal valid transaction for testing.
    fn base_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::all_zeros(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::all_zeros(),
                ),
            }],
        }
    }

    // ── CAT-21 ────────────────────────────────────────────────────────

    #[test]
    fn cat21_rejected() {
        let mut tx = base_tx();
        tx.lock_time = LockTime::from_consensus(21);
        assert!(matches!(
            check_relay_policy(&tx),
            Err(PolicyRejection::Cat21)
        ));
    }

    #[test]
    fn cat21_other_locktime_allowed() {
        let mut tx = base_tx();
        tx.lock_time = LockTime::from_consensus(0);
        assert!(check_relay_policy(&tx).is_ok());

        tx.lock_time = LockTime::from_consensus(500_000_000);
        assert!(check_relay_policy(&tx).is_ok());

        tx.lock_time = LockTime::from_consensus(22);
        assert!(check_relay_policy(&tx).is_ok());
    }

    // ── Runes ─────────────────────────────────────────────────────────

    #[test]
    fn runes_op_return_rejected() {
        let mut tx = base_tx();
        // OP_RETURN (0x6a) + OP_PUSHNUM_13 (0x5d) + some data
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x5d, 0x01, 0x02]),
        });
        assert!(matches!(
            check_relay_policy(&tx),
            Err(PolicyRejection::Runes { output_index: 1 })
        ));
    }

    #[test]
    fn normal_op_return_allowed() {
        let mut tx = base_tx();
        // OP_RETURN + OP_PUSHBYTES_4 + 4 data bytes (not Runes)
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]),
        });
        assert!(check_relay_policy(&tx).is_ok());
    }

    // ── Witness size cap ──────────────────────────────────────────────

    #[test]
    fn oversized_witness_rejected() {
        let mut tx = base_tx();
        let big_elem = vec![0u8; MAX_WITNESS_ITEM_SIZE + 1];
        tx.input[0].witness.push(big_elem);
        tx.input[0].witness.push(vec![0u8; 33]); // control block
        assert!(matches!(
            check_relay_policy(&tx),
            Err(PolicyRejection::OversizedWitnessItem { .. })
        ));
    }

    #[test]
    fn witness_at_limit_allowed() {
        let mut tx = base_tx();
        let elem = vec![0u8; MAX_WITNESS_ITEM_SIZE];
        tx.input[0].witness.push(elem);
        tx.input[0].witness.push(vec![0u8; 33]);
        assert!(check_relay_policy(&tx).is_ok());
    }

    // ── OLGA / Stamps ─────────────────────────────────────────────────

    #[test]
    fn olga_stamps_rejected() {
        let mut tx = base_tx();
        let mut ws = vec![0u8; 40];
        ws[10..16].copy_from_slice(b"stamp:");
        tx.input[0].witness.push(vec![0x01]); // dummy stack item
        tx.input[0].witness.push(ws); // witness script (last element)
        assert!(matches!(
            check_relay_policy(&tx),
            Err(PolicyRejection::OlgaStamps { input_index: 0 })
        ));
    }

    #[test]
    fn normal_p2wsh_allowed() {
        let mut tx = base_tx();
        tx.input[0].witness.push(vec![0x01; 72]); // signature
        tx.input[0].witness.push(vec![0xac; 25]); // simple witness script
        assert!(check_relay_policy(&tx).is_ok());
    }

    // ── OP_DROP injection ─────────────────────────────────────────────

    #[test]
    fn op_drop_large_data_rejected() {
        let mut tx = base_tx();
        // Build script: OP_PUSHDATA1 <100 bytes> OP_DROP
        let mut script_bytes = vec![0x4c, 100]; // OP_PUSHDATA1, length=100
        script_bytes.extend_from_slice(&[0xaa; 100]); // 100 bytes of data
        script_bytes.push(0x75); // OP_DROP

        tx.input[0].witness.push(vec![0x01]); // dummy
        tx.input[0].witness.push(script_bytes);
        assert!(matches!(
            check_relay_policy(&tx),
            Err(PolicyRejection::OpDropData { input_index: 0 })
        ));
    }

    #[test]
    fn op_drop_small_constant_allowed() {
        let mut tx = base_tx();
        // Build script: OP_PUSHBYTES_32 <32 bytes> OP_DROP (normal preimage reveal)
        let mut script_bytes = vec![0x20]; // OP_PUSHBYTES_32
        script_bytes.extend_from_slice(&[0xbb; 32]); // 32-byte hash
        script_bytes.push(0x75); // OP_DROP

        tx.input[0].witness.push(vec![0x01]); // dummy
        tx.input[0].witness.push(script_bytes);
        assert!(check_relay_policy(&tx).is_ok());
    }

    // ── Inscription envelopes ─────────────────────────────────────────

    #[test]
    fn inscription_envelope_rejected() {
        let mut tx = base_tx();
        // Build: <pubkey> OP_CHECKSIG OP_FALSE OP_IF OP_PUSH "ord" OP_ENDIF
        let mut script_bytes = Vec::new();
        script_bytes.push(0x20); // OP_PUSHBYTES_32
        script_bytes.extend_from_slice(&[0xcc; 32]); // fake pubkey
        script_bytes.push(0xac); // OP_CHECKSIG
        script_bytes.push(0x00); // OP_FALSE (OP_PUSHBYTES_0)
        script_bytes.push(0x63); // OP_IF
        script_bytes.push(0x03); // OP_PUSHBYTES_3
        script_bytes.extend_from_slice(b"ord"); // protocol tag
        script_bytes.push(0x68); // OP_ENDIF

        tx.input[0].witness.push(vec![0x01; 64]); // signature
        tx.input[0].witness.push(script_bytes); // leaf script
        tx.input[0].witness.push(vec![0xc0; 33]); // control block
        assert!(matches!(
            check_relay_policy(&tx),
            Err(PolicyRejection::InscriptionEnvelope { input_index: 0, .. })
        ));
    }

    #[test]
    fn inscription_unknown_tag_also_rejected() {
        let mut tx = base_tx();
        // Envelope with unknown tag — still rejected
        let mut script_bytes = Vec::new();
        script_bytes.push(0x00); // OP_FALSE
        script_bytes.push(0x63); // OP_IF
        script_bytes.push(0x05); // OP_PUSHBYTES_5
        script_bytes.extend_from_slice(b"xyzzy"); // unknown tag
        script_bytes.push(0x68); // OP_ENDIF

        tx.input[0].witness.push(vec![0x01; 64]);
        tx.input[0].witness.push(script_bytes);
        tx.input[0].witness.push(vec![0xc0; 33]);
        assert!(matches!(
            check_relay_policy(&tx),
            Err(PolicyRejection::InscriptionEnvelope { input_index: 0, .. })
        ));
    }

    #[test]
    fn normal_taproot_keypath_allowed() {
        let mut tx = base_tx();
        // Key-path spend: just a signature in witness
        tx.input[0].witness.push(vec![0x01; 64]); // Schnorr signature
        assert!(check_relay_policy(&tx).is_ok());
    }

    #[test]
    fn normal_p2wpkh_allowed() {
        let mut tx = base_tx();
        // P2WPKH: signature + pubkey
        tx.input[0].witness.push(vec![0x30; 72]); // DER signature
        tx.input[0].witness.push(vec![0x02; 33]); // compressed pubkey
        assert!(check_relay_policy(&tx).is_ok());
    }

    // ── Data-path pass: both sides of each filter ────────────────────

    fn with_witness(items: Vec<Vec<u8>>) -> Transaction {
        let mut tx = base_tx();
        tx.input[0].witness = Witness::from_slice(&items);
        tx
    }

    fn with_output(spk: Vec<u8>) -> Transaction {
        let mut tx = base_tx();
        tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) });
        tx
    }

    #[test]
    fn cat21_is_exactly_locktime_21() {
        for (lock, rejected) in [(20u32, false), (21, true), (22, false), (21 + 500_000_000, false)] {
            let mut tx = base_tx();
            tx.lock_time = LockTime::from_consensus(lock);
            assert_eq!(matches!(check_relay_policy(&tx), Err(PolicyRejection::Cat21)), rejected, "{}", lock);
        }
    }

    #[test]
    fn runes_marker_is_op_13_right_after_op_return() {
        assert!(matches!(check_relay_policy(&with_output(vec![0x6a, 0x5d])), Err(PolicyRejection::Runes { .. })));
        for ok in [
            vec![0x6a],                   // bare OP_RETURN
            vec![0x6a, 0x5c, 0x01],       // OP_12
            vec![0x6a, 0x5e, 0x01],       // OP_14
            vec![0x6a, 0x01, 0x5d],       // OP_13 only as pushed data
            vec![0x51, 0x5d],             // not an OP_RETURN
        ] {
            assert!(check_relay_policy(&with_output(ok.clone())).is_ok(), "{:02x?}", ok);
        }
    }

    #[test]
    fn op_drop_threshold_is_75_bytes() {
        let script = |n: usize| {
            let mut s = vec![0x4c, n as u8]; // OP_PUSHDATA1 n
            s.extend(std::iter::repeat(0x11).take(n));
            s.push(0x75); // OP_DROP
            s.push(0x51);
            s
        };
        assert!(check_relay_policy(&with_witness(vec![vec![0x01], script(75)])).is_ok());
        assert!(matches!(
            check_relay_policy(&with_witness(vec![vec![0x01], script(76)])),
            Err(PolicyRejection::OpDropData { input_index: 0 })
        ));
        // A key-path-like single element is never script-parsed.
        assert!(check_relay_policy(&with_witness(vec![script(76)])).is_ok());
    }

    #[test]
    fn stamps_marker_is_case_insensitive_and_only_in_the_witness_script() {
        let ws = |marker: &[u8]| {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(marker);
            s
        };
        for marker in [&b"stamp:"[..], b"STAMP:", b"StAmP:"] {
            assert!(
                matches!(check_relay_policy(&with_witness(vec![vec![0x01], ws(marker)])), Err(PolicyRejection::OlgaStamps { .. })),
                "{:?}",
                marker
            );
        }
        // No colon, only in a non-final element, or a lone element: allowed.
        assert!(check_relay_policy(&with_witness(vec![vec![0x01], ws(b"stamp")])).is_ok());
        assert!(check_relay_policy(&with_witness(vec![ws(b"stamp:"), vec![0x51]])).is_ok());
        assert!(check_relay_policy(&with_witness(vec![ws(b"stamp:")])).is_ok());
    }

    #[test]
    fn envelope_needs_op_false_immediately_before_op_if() {
        let envelope = |middle: &[u8]| {
            let mut s = vec![0x00];
            s.extend_from_slice(middle);
            s.extend_from_slice(&[0x63, 0x03, b'o', b'r', b'd', 0x68]);
            s
        };
        match check_relay_policy(&with_witness(vec![vec![0x01], envelope(&[])])) {
            Err(PolicyRejection::InscriptionEnvelope { tag, .. }) => assert_eq!(tag, "ord"),
            other => panic!("{:?}", other),
        }
        // Something between OP_FALSE and OP_IF breaks the pattern.
        assert!(check_relay_policy(&with_witness(vec![vec![0x01], envelope(&[0x61])])).is_ok()); // OP_NOP
        // OP_NOTIF is not an envelope.
        assert!(check_relay_policy(&with_witness(vec![vec![0x01], vec![0x00, 0x64, 0x51, 0x68]])).is_ok());
        // An envelope with no push after OP_IF still rejects, tag unknown.
        match check_relay_policy(&with_witness(vec![vec![0x01], vec![0x00, 0x63, 0x68, 0x51]])) {
            Err(PolicyRejection::InscriptionEnvelope { tag, .. }) => assert_eq!(tag, "<unknown>"),
            other => panic!("{:?}", other),
        }
    }

    /// The envelope and OP_DROP scans parse *every* witness element as a
    /// script, including signatures and public keys. A P2WPKH spend whose
    /// compressed pubkey happens to read `02 xx yy 00 63` (push 2, OP_FALSE,
    /// OP_IF) is a normal payment, but is refused as an inscription. A
    /// simulation over random keys and DER signatures puts it at about 1 in
    /// 17,000 pubkeys and 1 in 15,000 signatures, so ~1 in 8,000 P2WPKH
    /// inputs; and a pubkey is fixed per address, so every spend from an
    /// unlucky address is refused relay.
    #[test]
    fn p2wpkh_pubkey_that_parses_as_an_envelope_is_allowed() {
        let mut pubkey = vec![0x02, 0xaa, 0xbb, 0x00, 0x63];
        pubkey.resize(33, 0x42);
        // A signature-shaped first element that parses to nothing special.
        let tx = with_witness(vec![vec![0x30; 72], pubkey]);
        assert!(check_relay_policy(&tx).is_ok(), "{:?}", check_relay_policy(&tx));
    }

    // ── Which element is scanned, by the spent output's type ─────────

    fn envelope_script() -> Vec<u8> {
        vec![0x51, 0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68]
    }

    fn spk(s: ScriptBuf) -> Vec<u8> {
        s.into_bytes()
    }

    fn p2wsh_spk() -> Vec<u8> {
        spk(ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::all_zeros()))
    }

    fn p2tr_spk() -> Vec<u8> {
        let mut s = vec![0x51, 0x20];
        s.extend([0x11; 32]);
        s
    }

    fn check_spent(tx: &Transaction, spent: &[u8]) -> Result<(), PolicyRejection> {
        check_relay_policy_with_spent(tx, &[spent])
    }

    /// With the spent output known, a P2WPKH spend is never script-scanned,
    /// whatever its signature and key bytes look like, while the same
    /// bytes as a P2WSH witnessScript are.
    #[test]
    fn known_p2wpkh_spend_is_never_scanned_but_p2wsh_witness_script_is() {
        let p2wpkh = spk(ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()));
        // Even an envelope-shaped "signature" (no inference can rescue this one).
        let tx = with_witness(vec![envelope_script(), vec![0x03; 33]]);
        assert!(check_spent(&tx, &p2wpkh).is_ok());
        assert!(matches!(check_spent(&tx, &p2wsh_spk()), Ok(())), "the witnessScript is the last element");
        let tx = with_witness(vec![vec![0x01], envelope_script()]);
        assert!(matches!(check_spent(&tx, &p2wsh_spk()), Err(PolicyRejection::InscriptionEnvelope { input_index: 0, .. })));
        // Stamps and OP_DROP data read the same element.
        let mut stamp = vec![0x51, 0x20];
        stamp.extend_from_slice(b"stamp:");
        assert!(matches!(
            check_spent(&with_witness(vec![vec![0x01], stamp.clone()]), &p2wsh_spk()),
            Err(PolicyRejection::OlgaStamps { .. })
        ));
        assert!(check_spent(&with_witness(vec![stamp, vec![0x51]]), &p2wsh_spk()).is_ok());
        assert!(check_spent(&with_witness(vec![vec![0x01], vec![0x51]]), &p2wpkh).is_ok());
    }

    /// Taproot: only the leaf script before the control block is scanned,
    /// with an annex set aside; a key-path spend (with or without annex)
    /// has no script.
    #[test]
    fn taproot_scan_reads_only_the_leaf_script() {
        let control = {
            let mut c = vec![0xc0];
            c.extend([0x22; 32]);
            c
        };
        let annex = vec![TAPROOT_ANNEX_TAG, 0x00, 0x63];
        let reject = |w: Vec<Vec<u8>>| {
            let tx = with_witness(w);
            assert!(matches!(check_spent(&tx, &p2tr_spk()), Err(PolicyRejection::InscriptionEnvelope { .. })));
            assert!(matches!(check_relay_policy(&tx), Err(PolicyRejection::InscriptionEnvelope { .. })), "inferred");
        };
        let allow = |w: Vec<Vec<u8>>| {
            let tx = with_witness(w);
            assert!(check_spent(&tx, &p2tr_spk()).is_ok(), "{:?}", check_spent(&tx, &p2tr_spk()));
            assert!(check_relay_policy(&tx).is_ok(), "inferred: {:?}", check_relay_policy(&tx));
        };
        reject(vec![vec![0x01; 64], envelope_script(), control.clone()]);
        reject(vec![vec![0x01; 64], envelope_script(), control.clone(), annex.clone()]);
        // The envelope only in a stack element (a signature, a preimage),
        // the control block or the annex: not executed, not scanned.
        allow(vec![envelope_script(), vec![0x51], control.clone()]);
        let mut odd_control = control.clone();
        odd_control.extend(envelope_script());
        odd_control.resize(65, 0x00);
        allow(vec![vec![0x51], odd_control]);
        allow(vec![vec![0x01; 64], vec![0x51], control.clone(), envelope_script_as_annex()]);
        // Key path: a signature, optionally with an annex.
        allow(vec![envelope_script()]);
        let tx = with_witness(vec![vec![0x01; 64], annex]);
        assert!(check_spent(&tx, &p2tr_spk()).is_ok());
        assert!(check_relay_policy(&tx).is_ok());
    }

    fn envelope_script_as_annex() -> Vec<u8> {
        let mut a = vec![TAPROOT_ANNEX_TAG];
        a.extend(envelope_script());
        a
    }

    /// P2SH-wrapped P2WSH reads the witnessScript; P2SH-P2WPKH and legacy
    /// P2SH read nothing from the witness.
    #[test]
    fn p2sh_wrapped_witness_scripts() {
        let p2sh = spk(ScriptBuf::new_p2sh(&bitcoin::ScriptHash::all_zeros()));
        let wrap = |redeem: Vec<u8>, witness: Vec<Vec<u8>>| {
            let mut tx = with_witness(witness);
            tx.input[0].script_sig = bitcoin::script::Builder::new()
                .push_slice(<&bitcoin::script::PushBytes>::try_from(&redeem[..]).unwrap())
                .into_script();
            tx
        };
        let tx = wrap(p2wsh_spk(), vec![vec![0x01], envelope_script()]);
        assert!(matches!(check_spent(&tx, &p2sh), Err(PolicyRejection::InscriptionEnvelope { .. })));
        let p2wpkh = spk(ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::all_zeros()));
        assert!(check_spent(&wrap(p2wpkh, vec![vec![0x01], envelope_script()]), &p2sh).is_ok());
        assert!(check_spent(&wrap(vec![0x51], vec![vec![0x01], envelope_script()]), &p2sh).is_ok());
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// The filters never panic, whatever the witness and outputs hold.
        #[test]
        fn filters_are_total(
            items in proptest::collection::vec(proptest::collection::vec(proptest::prelude::any::<u8>(), 0..120), 0..5),
            spk in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..60),
            lock in proptest::prelude::any::<u32>(),
        ) {
            let mut tx = with_witness(items);
            tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) });
            tx.lock_time = LockTime::from_consensus(lock);
            let _ = check_relay_policy(&tx);
        }
    }
}
