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

/// Run all relay policy checks against a transaction.
///
/// Checks are ordered cheapest-first so the common case (legitimate
/// payment) exits quickly. Returns the first rejection found.
pub fn check_relay_policy(tx: &Transaction) -> Result<(), PolicyRejection> {
    check_cat21(tx)?;
    check_runes(tx)?;
    check_witness_size(tx)?;
    check_olga_stamps(tx)?;
    check_op_drop_data(tx)?;
    check_inscription_envelope(tx)?;
    Ok(())
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
/// a `stamp:` prefix. For P2WSH spends the last witness element is the
/// witness script.
fn check_olga_stamps(tx: &Transaction) -> Result<(), PolicyRejection> {
    for (i, input) in tx.input.iter().enumerate() {
        // P2WSH spends have >= 2 witness elements (items + witness script).
        if input.witness.len() < 2 {
            continue;
        }
        // The witness script is the last element.
        if let Some(ws) = input.witness.last() {
            if ws.len() >= 6 && ws.windows(6).any(|w| w.eq_ignore_ascii_case(b"stamp:")) {
                return Err(PolicyRejection::OlgaStamps { input_index: i });
            }
        }
    }
    Ok(())
}

/// `<data> OP_DROP` injection: data pushed then immediately dropped.
/// Only flags pushes larger than `OP_DROP_DATA_THRESHOLD` to avoid
/// false-positives on normal hash preimage reveals and pubkeys.
fn check_op_drop_data(tx: &Transaction) -> Result<(), PolicyRejection> {
    for (i, input) in tx.input.iter().enumerate() {
        // Only script-path spends carry meaningful script data.
        if input.witness.len() < 2 {
            continue;
        }
        for elem in input.witness.iter() {
            if elem.len() < 3 {
                continue;
            }
            let script = bitcoin::Script::from_bytes(elem);
            let mut prev_push_len: usize = 0;

            for instruction in script.instructions() {
                match instruction {
                    Ok(Instruction::PushBytes(bytes)) => {
                        prev_push_len = bytes.len();
                    }
                    Ok(Instruction::Op(op)) if op == OP_DROP => {
                        if prev_push_len > OP_DROP_DATA_THRESHOLD {
                            return Err(PolicyRejection::OpDropData { input_index: i });
                        }
                        prev_push_len = 0;
                    }
                    _ => {
                        prev_push_len = 0;
                    }
                }
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
fn check_inscription_envelope(tx: &Transaction) -> Result<(), PolicyRejection> {
    for (i, input) in tx.input.iter().enumerate() {
        if input.witness.len() < 2 {
            continue;
        }
        for elem in input.witness.iter() {
            if elem.len() < 4 {
                continue;
            }
            let script = bitcoin::Script::from_bytes(elem);
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
                        return Err(PolicyRejection::InscriptionEnvelope {
                            input_index: i,
                            tag,
                        });
                    }
                    _ => {
                        saw_false = false;
                    }
                }
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
    #[ignore = "BUG (policy): inscription/OP_DROP scans parse signatures and pubkeys as scripts; ~1 in 8,000 ordinary P2WPKH inputs is refused relay (every spend of an unlucky address)"]
    fn p2wpkh_pubkey_that_parses_as_an_envelope_is_allowed() {
        let mut pubkey = vec![0x02, 0xaa, 0xbb, 0x00, 0x63];
        pubkey.resize(33, 0x42);
        // A signature-shaped first element that parses to nothing special.
        let tx = with_witness(vec![vec![0x30; 72], pubkey]);
        assert!(check_relay_policy(&tx).is_ok(), "{:?}", check_relay_policy(&tx));
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
