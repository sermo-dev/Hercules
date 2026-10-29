//! libbitcoinconsensus v26 backend (`script-consensus-legacy`).
//!
//! The pre-047 verifier, kept selectable so we can switch back: the patched
//! crate in `patches/bitcoinconsensus/`, called exactly as block validation
//! and the mempool called it before ticket 047.

use super::{InputResults, ScriptVerifyError, SpentOutput};

pub const NAME: &str = "libbitcoinconsensus v26 (legacy)";

pub fn verify_inputs(
    tx: &[u8],
    spent: &[SpentOutput],
    flags: u32,
    stop_at_first_failure: bool,
) -> Result<InputResults, ScriptVerifyError> {
    // The FFI Utxo array. Raw pointers reference the heap allocations owned
    // by `spent`, which outlives every verify call below. Passing it on every
    // call enables taproot validation when VERIFY_TAPROOT is set (BIP 341
    // sighash commits to all spent outputs); pre-taproot flags ignore it.
    let utxos: Vec<bitcoinconsensus::Utxo> = spent
        .iter()
        .map(|(amt, spk)| bitcoinconsensus::Utxo {
            script_pubkey: spk.as_ptr(),
            script_pubkey_len: spk.len() as u32,
            value: *amt as i64,
        })
        .collect();

    let mut results = Vec::with_capacity(spent.len());
    for (input_idx, (amount, script_pubkey)) in spent.iter().enumerate() {
        let r = bitcoinconsensus::verify_with_flags(
            script_pubkey,
            *amount,
            tx,
            Some(&utxos),
            input_idx,
            flags,
        )
        .map_err(|e| map_error(e, flags));
        match r {
            // Not input-specific; report it once for the whole tx, as the
            // kernel backend does.
            Err(ScriptVerifyError::TxDeserialize) => return Err(ScriptVerifyError::TxDeserialize),
            Err(_) if stop_at_first_failure => {
                results.push(r);
                break;
            }
            _ => results.push(r),
        }
    }
    Ok(results)
}

fn map_error(e: bitcoinconsensus::Error, flags: u32) -> ScriptVerifyError {
    use bitcoinconsensus::Error::*;
    match e {
        // ERR_SCRIPT is Core's ERR_OK: the call ran and the script failed.
        ERR_SCRIPT => ScriptVerifyError::ScriptFailed,
        ERR_TX_DESERIALIZE | ERR_TX_SIZE_MISMATCH => ScriptVerifyError::TxDeserialize,
        ERR_INVALID_FLAGS => ScriptVerifyError::InvalidFlags(flags),
        other => ScriptVerifyError::Library(format!("{}", other)),
    }
}
