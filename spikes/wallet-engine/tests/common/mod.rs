#![allow(dead_code)]
//! Independent verification: run every input of a finished transaction through
//! libbitcoinconsensus (Bitcoin Core v26.0 script interpreter, the same patched build
//! hercules-core links) with all pre-taproot flags + VERIFY_TAPROOT.

use bitcoin::consensus::serialize;
use bitcoin::{Transaction, TxOut};

pub const FLAGS: u32 = bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT;

pub fn verify_input(tx: &Transaction, prevouts: &[TxOut], index: usize) -> Result<(), bitcoinconsensus::Error> {
    let raw = serialize(tx);
    let spks: Vec<Vec<u8>> = prevouts.iter().map(|p| p.script_pubkey.to_bytes()).collect();
    let utxos: Vec<bitcoinconsensus::Utxo> = prevouts
        .iter()
        .zip(&spks)
        .map(|(p, spk)| bitcoinconsensus::Utxo {
            script_pubkey: spk.as_ptr(),
            script_pubkey_len: spk.len() as u32,
            value: p.value.to_sat() as i64,
        })
        .collect();
    bitcoinconsensus::verify_with_flags(&spks[index], prevouts[index].value.to_sat(), &raw, Some(&utxos), index, FLAGS)
}

pub fn verify_tx(tx: &Transaction, prevouts: &[TxOut]) -> Result<(), (usize, bitcoinconsensus::Error)> {
    assert_eq!(tx.input.len(), prevouts.len());
    for i in 0..tx.input.len() {
        verify_input(tx, prevouts, i).map_err(|e| (i, e))?;
    }
    Ok(())
}
