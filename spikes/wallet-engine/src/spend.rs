//! PSBT construction, signing, finalization.
//!
//! - Construct: `bitcoin::Psbt` + `miniscript::psbt::PsbtExt::update_input_with_descriptor`
//!   (fills bip32_derivation / tap_key_origins / tap_internal_key and *checks* the UTXO
//!   fields against the descriptor, including non_witness_utxo txid for legacy inputs).
//! - Sign: `bitcoin::Psbt::sign` with the BIP32 master as the `GetKey` source
//!   (ECDSA via libsecp256k1 for pkh/wpkh, BIP340 Schnorr + BIP341 tweak for tr).
//! - Finalize: `miniscript::psbt::PsbtExt::finalize_mut` (builds scriptSig/witness from the
//!   descriptor, then runs miniscript's interpreter sanity check over the result).
//! - Extract: `bitcoin::Psbt::extract_tx` (refuses absurd fee rates).

use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{bip32::Xpriv, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use miniscript::descriptor::{DefiniteDescriptorKey, Descriptor};
use miniscript::psbt::PsbtExt;

/// A wallet coin as the 035 scanner will know it: `(outpoint, value, scriptPubKey)` from the
/// UTXO set, the descriptor that produced the script, and (optionally) the parent tx.
#[derive(Clone, Debug)]
pub struct OwnedCoin {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub descriptor: Descriptor<DefiniteDescriptorKey>,
    pub parent_tx: Option<Transaction>,
}

impl OwnedCoin {
    pub fn is_segwit(&self) -> bool {
        self.descriptor.desc_type().segwit_version().is_some()
    }
    /// Upper bound on the satisfied input's weight (txin + scriptSig + witness), in WU, per
    /// miniscript's contract: `TxIn::default().{segwit,legacy}_weight() + max_weight_to_satisfy()`.
    /// Miniscript assumes ECDSA sigs are <= 73 bytes incl. push + sighash byte, i.e. low-R
    /// (71-byte DER), same as Bitcoin Core. Feeds coin selection (`OutputGroup::weight`).
    pub fn max_input_weight(&self) -> u64 {
        let satisfaction = self.descriptor.max_weight_to_satisfy().expect("satisfiable");
        let empty = TxIn::default();
        let base = if self.is_segwit() { empty.segwit_weight() } else { empty.legacy_weight() };
        (base + satisfaction).to_wu()
    }
}

#[derive(Debug)]
pub enum SpendError {
    /// Legacy (non-segwit) input without its parent transaction.
    MissingParentTx(OutPoint),
    Update(usize, miniscript::psbt::UtxoUpdateError),
    OutputUpdate(usize, miniscript::psbt::OutputUpdateError),
    Sign(String),
    Finalize(Vec<miniscript::psbt::Error>),
    Extract(bitcoin::psbt::ExtractTxError),
}

/// Build an unsigned PSBT. `change` (if any) is appended as the last output and annotated
/// with its descriptor so a signer can recognise it.
pub fn build_psbt(
    coins: &[OwnedCoin],
    payments: &[TxOut],
    change: Option<(Amount, &Descriptor<DefiniteDescriptorKey>)>,
) -> Result<Psbt, SpendError> {
    let mut outputs: Vec<TxOut> = payments.to_vec();
    if let Some((value, desc)) = change {
        outputs.push(TxOut { value, script_pubkey: desc.script_pubkey() });
    }
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: coins
            .iter()
            .map(|c| TxIn {
                previous_output: c.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("empty scriptSigs/witnesses");

    for (i, c) in coins.iter().enumerate() {
        let inp = &mut psbt.inputs[i];
        if c.is_segwit() {
            // Segwit: amount + script commit via sighash, so the UTXO-set entry suffices.
            inp.witness_utxo = Some(c.txout.clone());
        } else if c.parent_tx.is_none() {
            return Err(SpendError::MissingParentTx(c.outpoint));
        }
        // Optional for segwit (some hardware signers demand it), mandatory for legacy.
        inp.non_witness_utxo = c.parent_tx.clone();
        psbt.update_input_with_descriptor(i, &c.descriptor)
            .map_err(|e| SpendError::Update(i, e))?;
    }
    if let Some((_, desc)) = change {
        let idx = psbt.outputs.len() - 1;
        psbt.update_output_with_descriptor(idx, desc)
            .map_err(|e| SpendError::OutputUpdate(idx, e))?;
    }
    Ok(psbt)
}

/// Sign every input we hold keys for (master xprv is the key source; inputs carry the
/// BIP32 origin of the key they need). ECDSA = RFC6979 + low-S via libsecp256k1 (no low-R
/// grinding; DER <= 71 bytes, which is what miniscript's and Core's 72-byte-with-sighash
/// bound assumes). Schnorr = BIP340 without aux randomness unless bitcoin's `rand-std`
/// feature is enabled.
pub fn sign(psbt: &mut Psbt, master: &Xpriv, secp: &Secp256k1<All>) -> Result<(), SpendError> {
    psbt.sign(master, secp).map(|_| ()).map_err(|(_, errs)| SpendError::Sign(format!("{errs:?}")))
}

/// Finalize with miniscript and extract the network transaction.
pub fn finalize_and_extract(mut psbt: Psbt, secp: &Secp256k1<All>) -> Result<Transaction, SpendError> {
    psbt.finalize_mut(secp).map_err(SpendError::Finalize)?;
    psbt.extract_tx().map_err(SpendError::Extract)
}
