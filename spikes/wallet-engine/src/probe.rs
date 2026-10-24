//! A single exported C symbol that exercises the wallet path end to end, so that a
//! dead-stripping linker keeps exactly the code a real send flow would pull in. Used only
//! for the iOS size measurement (`--features stack` vs `--no-default-features`).

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, Network, OutPoint, Txid};

#[no_mangle]
pub extern "C" fn hercules_wallet_spike_probe(seed_byte: u8) -> u64 {
    let secp = Secp256k1::new();
    let coin_value = Amount::from_sat(100_000 + seed_byte as u64);
    let outpoint = OutPoint { txid: Txid::from_byte_array([seed_byte; 32]), vout: 0 };

    #[cfg(feature = "stack")]
    {
        use crate::keys::{master_from_mnemonic, Account, Purpose};
        use crate::spend::{build_psbt, finalize_and_extract, sign, OwnedCoin};
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let master = master_from_mnemonic(words, "", Network::Bitcoin);
        let mut weight = 0;
        for purpose in [Purpose::Bip84, Purpose::Bip86] {
            let acct = Account::new(&secp, master, purpose, 0);
            let desc = acct.at(0, seed_byte as u32);
            let coin = OwnedCoin {
                outpoint,
                txout: bitcoin::TxOut { value: coin_value, script_pubkey: desc.script_pubkey() },
                descriptor: desc,
                parent_tx: None,
            };
            let change = acct.at(1, 0);
            let mut psbt = build_psbt(&[coin], &[], Some((Amount::from_sat(90_000), &change))).unwrap();
            sign(&mut psbt, &master, &secp).unwrap();
            weight += finalize_and_extract(psbt, &secp).unwrap().weight().to_wu();
        }
        weight
    }

    #[cfg(not(feature = "stack"))]
    {
        // Same flow with rust-bitcoin only (no bip39, no miniscript): raw seed, hand-filled
        // PSBT key origins, Psbt::sign, hand-written finalizer for wpkh / tr key-path.
        use bitcoin::bip32::{DerivationPath, Xpriv};
        use bitcoin::key::{CompressedPublicKey, Keypair, TapTweak};
        use bitcoin::psbt::Psbt;
        use bitcoin::{absolute, transaction, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        let master = Xpriv::new_master(Network::Bitcoin, &[seed_byte; 64]).unwrap();
        let fp = master.fingerprint(&secp);
        let mut weight = 0;
        for purpose in [84u32, 86] {
            let path: DerivationPath = format!("m/{purpose}'/0'/0'/0/{seed_byte}").parse().unwrap();
            let sk = master.derive_priv(&secp, &path).unwrap().to_priv();
            let pk = CompressedPublicKey::from_private_key(&secp, &sk).unwrap();
            let xonly = Keypair::from_secret_key(&secp, &sk.inner).x_only_public_key().0;
            let spk = if purpose == 84 {
                ScriptBuf::new_p2wpkh(&pk.wpubkey_hash())
            } else {
                ScriptBuf::new_p2tr(&secp, xonly, None)
            };
            let tx = Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn { previous_output: outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }],
                output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: spk.clone() }],
            };
            let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
            psbt.inputs[0].witness_utxo = Some(TxOut { value: coin_value, script_pubkey: spk });
            if purpose == 84 {
                psbt.inputs[0].bip32_derivation.insert(pk.0, (fp, path));
            } else {
                psbt.inputs[0].tap_internal_key = Some(xonly);
                psbt.inputs[0].tap_key_origins.insert(xonly, (vec![], (fp, path)));
            }
            psbt.sign(&master, &secp).unwrap();
            let inp = &mut psbt.inputs[0];
            inp.final_script_witness = Some(if purpose == 84 {
                let sig = inp.partial_sigs.values().next().unwrap();
                Witness::p2wpkh(sig, &pk.0)
            } else {
                let _ = xonly.tap_tweak(&secp, None);
                Witness::p2tr_key_spend(inp.tap_key_sig.as_ref().unwrap())
            });
            weight += psbt.extract_tx().unwrap().weight().to_wu();
        }
        weight
    }
}
