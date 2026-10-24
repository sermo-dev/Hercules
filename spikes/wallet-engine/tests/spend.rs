//! Spike steps 2-4 (no bitcoind on this machine, so step 4 = consensus-library verification):
//! build PSBT -> sign (libsecp256k1 via rust-bitcoin) -> finalize (miniscript) -> extract,
//! then verify every input with libbitcoinconsensus v26.0 (Core's own script interpreter).
//! Each happy path has a negative twin proving the verifier is not vacuous.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use common::verify_tx;
use wallet_engine_spike::keys::{master_from_mnemonic, Account, Purpose};
use wallet_engine_spike::spend::*;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn setup() -> (Secp256k1<All>, bitcoin::bip32::Xpriv) {
    let secp = Secp256k1::new();
    let master = master_from_mnemonic(MNEMONIC, "", Network::Bitcoin);
    (secp, master)
}

/// A coin as the UTXO-set walk sees it: no parent transaction, only (outpoint, value, spk).
fn utxo_only_coin(acct: &Account, index: u32, sats: u64, txid_byte: u8) -> OwnedCoin {
    let descriptor = acct.at(0, index);
    OwnedCoin {
        outpoint: OutPoint { txid: Txid::from_byte_array([txid_byte; 32]), vout: 1 },
        txout: TxOut { value: Amount::from_sat(sats), script_pubkey: descriptor.script_pubkey() },
        descriptor,
        parent_tx: None,
    }
}

/// A plausible parent transaction paying `sats` to `spk` at vout 0.
fn parent_paying(spk: ScriptBuf, sats: u64, salt: u8) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([salt; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(sats), script_pubkey: spk }],
    }
}

fn external_payment(sats: u64) -> TxOut {
    // Pay to an arbitrary external P2WPKH (BIP84 vector address 0/1 is "ours", use a hash).
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7; 20])),
    }
}

fn prevouts(coins: &[OwnedCoin]) -> Vec<TxOut> {
    coins.iter().map(|c| c.txout.clone()).collect()
}

fn sign_and_finalize(coins: &[OwnedCoin], change: &miniscript::Descriptor<miniscript::DefiniteDescriptorKey>, pay: u64, change_sats: u64) -> Transaction {
    let (secp, master) = setup();
    let mut psbt = build_psbt(coins, &[external_payment(pay)], Some((Amount::from_sat(change_sats), change))).unwrap();
    sign(&mut psbt, &master, &secp).unwrap();
    finalize_and_extract(psbt, &secp).unwrap()
}

#[test]
fn p2wpkh_spend_from_utxo_entry_only() {
    let (secp, master) = setup();
    let acct = Account::new(&secp, master, Purpose::Bip84, 0);
    let coin = utxo_only_coin(&acct, 0, 100_000, 0xaa);
    // This is the BIP84 vector address m/84'/0'/0'/0/0.
    assert_eq!(acct.address(0, 0, Network::Bitcoin).to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

    let mut psbt = build_psbt(&[coin.clone()], &[external_payment(60_000)], Some((Amount::from_sat(39_000), &acct.at(1, 0)))).unwrap();
    assert!(psbt.inputs[0].non_witness_utxo.is_none(), "no parent tx anywhere in the PSBT");
    assert_eq!(psbt.inputs[0].bip32_derivation.len(), 1, "miniscript filled the key origin");
    assert_eq!(psbt.outputs[1].bip32_derivation.len(), 1, "change output annotated");

    sign(&mut psbt, &master, &secp).unwrap();
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    let tx = finalize_and_extract(psbt, &secp).unwrap();

    assert_eq!(tx.input[0].witness.len(), 2);
    assert!(tx.input[0].script_sig.is_empty());
    verify_tx(&tx, &[coin.txout.clone()]).expect("Core's interpreter accepts the spend");

    // Negative: segwit v0 sighash commits to the amount; a 1-sat mismatch must fail.
    let mut wrong = coin.txout.clone();
    wrong.value = Amount::from_sat(99_999);
    assert!(verify_tx(&tx, &[wrong]).is_err());
    // Negative: flip a byte in the DER signature.
    let mut bad = tx.clone();
    let mut items: Vec<Vec<u8>> = bad.input[0].witness.iter().map(|w| w.to_vec()).collect();
    items[0][10] ^= 1;
    bad.input[0].witness = Witness::from_slice(&items);
    assert!(verify_tx(&bad, &[coin.txout.clone()]).is_err());

    // Weight estimate used by coin selection is an upper bound on the real input.
    let est = coin.max_input_weight();
    let actual = tx.input[0].segwit_weight().to_wu();
    assert!(actual <= est, "actual {actual} <= est {est}");
    eprintln!("P2WPKH input: est {est} WU (Core uses 272), actual {actual} WU");
}

#[test]
fn p2tr_keypath_spend_from_utxo_entry_only() {
    let (secp, master) = setup();
    let acct = Account::new(&secp, master, Purpose::Bip86, 0);
    let coin = utxo_only_coin(&acct, 0, 250_000, 0xbb);
    assert_eq!(acct.address(0, 0, Network::Bitcoin).to_string(), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");

    let mut psbt = build_psbt(&[coin.clone()], &[external_payment(200_000)], Some((Amount::from_sat(49_000), &acct.at(1, 0)))).unwrap();
    assert!(psbt.inputs[0].non_witness_utxo.is_none());
    assert!(psbt.inputs[0].tap_internal_key.is_some());
    assert_eq!(psbt.inputs[0].tap_key_origins.len(), 1);

    sign(&mut psbt, &master, &secp).unwrap();
    assert!(psbt.inputs[0].tap_key_sig.is_some());
    let tx = finalize_and_extract(psbt, &secp).unwrap();
    assert_eq!(tx.input[0].witness.len(), 1);
    assert_eq!(tx.input[0].witness.nth(0).unwrap().len(), 64, "SIGHASH_DEFAULT schnorr sig");
    verify_tx(&tx, &[coin.txout.clone()]).expect("taproot key-path spend valid");

    let mut wrong = coin.txout.clone();
    wrong.value = Amount::from_sat(250_001);
    assert!(verify_tx(&tx, &[wrong]).is_err(), "BIP341 sighash commits to all amounts");

    let est = coin.max_input_weight();
    let actual = tx.input[0].segwit_weight().to_wu();
    assert!(actual <= est, "actual {actual} <= est {est}");
    eprintln!("P2TR input: est {est} WU (Core uses 230), actual {actual} WU");
}

#[test]
fn p2pkh_legacy_spend_with_parent_tx() {
    let (secp, master) = setup();
    let acct = Account::new(&secp, master, Purpose::Bip44, 0);
    let desc = acct.at(0, 0);
    let parent = parent_paying(desc.script_pubkey(), 80_000, 0x01);
    let coin = OwnedCoin {
        outpoint: OutPoint { txid: parent.compute_txid(), vout: 0 },
        txout: parent.output[0].clone(),
        descriptor: desc.clone(),
        parent_tx: Some(parent.clone()),
    };
    let change = Account::new(&secp, master, Purpose::Bip84, 0).at(1, 0);
    let tx = sign_and_finalize(&[coin.clone()], &change, 50_000, 28_000);
    assert!(!tx.input[0].script_sig.is_empty());
    assert!(tx.input[0].witness.is_empty());
    verify_tx(&tx, &[coin.txout.clone()]).expect("legacy spend valid");

    // Negative: signature checked against the wrong script fails.
    let mut wrong = coin.txout.clone();
    wrong.script_pubkey = acct.at(0, 1).script_pubkey();
    assert!(verify_tx(&tx, &[wrong]).is_err());

    let est = coin.max_input_weight();
    let actual = tx.input[0].legacy_weight().to_wu();
    assert!(actual <= est, "actual {actual} <= est {est}");
    eprintln!("P2PKH input: est {est} WU (Core uses 592), actual {actual} WU");
}

#[test]
fn legacy_without_parent_or_with_wrong_parent_is_refused() {
    let (secp, master) = setup();
    let acct = Account::new(&secp, master, Purpose::Bip44, 0);
    let desc = acct.at(0, 0);
    let parent = parent_paying(desc.script_pubkey(), 80_000, 0x02);
    let mut coin = OwnedCoin {
        outpoint: OutPoint { txid: parent.compute_txid(), vout: 0 },
        txout: parent.output[0].clone(),
        descriptor: desc.clone(),
        parent_tx: None,
    };
    assert!(matches!(build_psbt(&[coin.clone()], &[external_payment(1)], None), Err(SpendError::MissingParentTx(_))));

    // A parent whose txid does not match the outpoint is rejected by miniscript's check.
    coin.parent_tx = Some(parent_paying(desc.script_pubkey(), 80_000, 0x03));
    assert!(matches!(
        build_psbt(&[coin], &[external_payment(1)], None),
        Err(SpendError::Update(0, miniscript::psbt::UtxoUpdateError::UtxoCheck))
    ));
}

/// Hardware-wallet path: segwit input carrying BOTH witness_utxo and non_witness_utxo
/// (what Trezor/Ledger-style signers want since the 2020 segwit fee bug). Miniscript checks
/// they agree.
#[test]
fn segwit_with_optional_parent_tx() {
    let (secp, master) = setup();
    let acct = Account::new(&secp, master, Purpose::Bip84, 0);
    let desc = acct.at(0, 3);
    let parent = parent_paying(desc.script_pubkey(), 70_000, 0x04);
    let mut coin = OwnedCoin {
        outpoint: OutPoint { txid: parent.compute_txid(), vout: 0 },
        txout: parent.output[0].clone(),
        descriptor: desc.clone(),
        parent_tx: Some(parent),
    };
    let tx = sign_and_finalize(&[coin.clone()], &acct.at(1, 1), 40_000, 29_000);
    verify_tx(&tx, &[coin.txout.clone()]).unwrap();

    // witness_utxo amount disagreeing with the parent tx is caught before signing.
    coin.txout.value = Amount::from_sat(69_000);
    assert!(build_psbt(&[coin], &[external_payment(1)], None).is_err());
}

/// One transaction spending P2WPKH (utxo-only) + P2TR (utxo-only) + P2PKH (with parent).
/// Exercises BIP341's all-prevouts sighash pulling the legacy input's amount out of
/// non_witness_utxo.
#[test]
fn mixed_three_type_spend() {
    let (secp, master) = setup();
    let a84 = Account::new(&secp, master, Purpose::Bip84, 0);
    let a86 = Account::new(&secp, master, Purpose::Bip86, 0);
    let a44 = Account::new(&secp, master, Purpose::Bip44, 0);
    let legacy_desc = a44.at(0, 2);
    let parent = parent_paying(legacy_desc.script_pubkey(), 30_000, 0x05);
    let coins = vec![
        utxo_only_coin(&a84, 5, 10_000, 0x10),
        utxo_only_coin(&a86, 5, 20_000, 0x11),
        OwnedCoin {
            outpoint: OutPoint { txid: parent.compute_txid(), vout: 0 },
            txout: parent.output[0].clone(),
            descriptor: legacy_desc,
            parent_tx: Some(parent),
        },
    ];
    let tx = sign_and_finalize(&coins, &a86.at(1, 7), 45_000, 13_000);
    verify_tx(&tx, &prevouts(&coins)).expect("all three inputs valid");
    assert_eq!(tx.input.len(), 3);
}

/// The miniscript weight bound (used to size inputs for coin selection) must hold for every
/// signature libsecp256k1 produces, including high-R ones (71-byte DER).
#[test]
fn input_weight_estimate_is_an_upper_bound() {
    let (secp, master) = setup();
    for purpose in [Purpose::Bip84, Purpose::Bip86, Purpose::Bip44] {
        let acct = Account::new(&secp, master, purpose, 0);
        let mut sizes = std::collections::BTreeMap::new();
        for i in 0..64u32 {
            let mut coin = utxo_only_coin(&acct, i, 100_000 + i as u64, i as u8);
            if purpose == Purpose::Bip44 {
                let parent = parent_paying(coin.txout.script_pubkey.clone(), coin.txout.value.to_sat(), i as u8);
                coin.outpoint = OutPoint { txid: parent.compute_txid(), vout: 0 };
                coin.parent_tx = Some(parent);
            }
            let est = coin.max_input_weight();
            let mut p = build_psbt(&[coin.clone()], &[external_payment(50_000)], None).unwrap();
            sign(&mut p, &master, &secp).unwrap();
            let tx = finalize_and_extract(p, &secp).unwrap();
            verify_tx(&tx, &[coin.txout.clone()]).unwrap();
            let actual = if coin.is_segwit() { tx.input[0].segwit_weight() } else { tx.input[0].legacy_weight() }.to_wu();
            assert!(actual <= est, "{purpose:?} #{i}: {actual} > {est}");
            *sizes.entry(actual).or_insert(0) += 1;
        }
        eprintln!("{purpose:?}: est {} WU, actual weight histogram {sizes:?}", utxo_only_coin(&acct, 0, 1, 0).max_input_weight());
    }
}
