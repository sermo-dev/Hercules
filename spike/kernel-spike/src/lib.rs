//! Ticket 047 spike: libbitcoinkernel vs our patched libbitcoinconsensus v26.
//!
//! Never merged. Provides:
//! - `asm`: a port of Bitcoin Core's `ParseScript` (core_io.cpp) so we can run
//!   Core's `script_tests.json` / `tx_valid.json` / `tx_invalid.json` vectors.
//! - `verify_consensus_tx` / `verify_kernel_tx`: the same per-input script
//!   verification through both libraries, with identical inputs and flags.
//! - `bench`: chainstate benchmarks used by the `kernel-bench` binary and by
//!   the C entry point `kernel_spike_run_bench` (for an on-device debug hook).

// Linking both libraries into one binary is an ODR violation: they share ~230
// identically-mangled C++/C symbols (SignatureHashSchnorr, CSHA256, secp256k1
// helpers, ...) from different Core versions, so the linker silently picks one
// copy for both. Every binary in this spike therefore links exactly one engine;
// comparisons are done across processes (see run-step1.sh).
#[cfg(all(feature = "kernel", feature = "consensus"))]
compile_error!("enable exactly one of the `kernel` / `consensus` features (ODR: see lib.rs)");

pub mod asm;
pub mod vectors;
pub mod step1;
#[cfg(feature = "kernel")]
pub mod bench;

/// A spent output (prevout) as both libraries need it: value + scriptPubKey.
#[derive(Clone, Debug)]
pub struct Spent {
    pub value: u64,
    pub spk: Vec<u8>,
}

/// Result of one input's script verification, normalised across libraries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    /// Script evaluated to false / failed a rule.
    Invalid,
    /// Library refused the request (bad flag set/combination, missing spent
    /// outputs, undeserializable tx) without evaluating the script.
    Rejected,
}

// Script verification flag bits. Identical numeric values in
// bitcoinconsensus 0.106 (Core v26) and bitcoinkernel.h (btck_ScriptVerificationFlags_*),
// verified in tests::flag_bits_match.
pub const VERIFY_P2SH: u32 = 1 << 0;
pub const VERIFY_DERSIG: u32 = 1 << 2;
pub const VERIFY_NULLDUMMY: u32 = 1 << 4;
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;
pub const VERIFY_WITNESS: u32 = 1 << 11;
pub const VERIFY_TAPROOT: u32 = 1 << 17;
pub const VERIFY_ALL: u32 = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS
    | VERIFY_TAPROOT;

/// Mainnet height -> flags, exactly what `block_validation.rs` uses today
/// (`bitcoinconsensus::height_to_flags`), reproduced so the kernel path can be
/// tested without the consensus crate. Ticket 047 Step 1 wants this as an
/// explicit table anyway.
pub fn mainnet_height_to_flags(height: u32) -> u32 {
    let mut f = 0;
    if height >= 173_805 {
        f |= VERIFY_P2SH;
    }
    if height >= 363_725 {
        f |= VERIFY_DERSIG;
    }
    if height >= 388_381 {
        f |= VERIFY_CHECKLOCKTIMEVERIFY;
    }
    if height >= 419_328 {
        f |= VERIFY_CHECKSEQUENCEVERIFY;
    }
    if height >= 481_824 {
        f |= VERIFY_NULLDUMMY | VERIFY_WITNESS;
    }
    if height > 709_632 {
        f |= VERIFY_TAPROOT;
    }
    f
}

/// Verify every input of `tx` (consensus-serialized, with witnesses) through
/// our current path: patched libbitcoinconsensus v26, called exactly like
/// `block_validation::validate_block_scripts` does.
#[cfg(feature = "consensus")]
pub fn verify_consensus_tx(tx: &[u8], spent: &[Spent], flags: u32) -> Vec<Outcome> {
    let utxos: Vec<bitcoinconsensus::Utxo> = spent
        .iter()
        .map(|s| bitcoinconsensus::Utxo {
            script_pubkey: s.spk.as_ptr(),
            script_pubkey_len: s.spk.len() as u32,
            value: s.value as i64,
        })
        .collect();
    spent
        .iter()
        .enumerate()
        .map(|(i, s)| {
            match bitcoinconsensus::verify_with_flags(&s.spk, s.value, tx, Some(&utxos), i, flags) {
                Ok(()) => Outcome::Valid,
                Err(bitcoinconsensus::Error::ERR_SCRIPT) => Outcome::Invalid,
                Err(_) => Outcome::Rejected,
            }
        })
        .collect()
}

/// Same verification through libbitcoinkernel's `btck_script_pubkey_verify`
/// (via the `bitcoinkernel` crate). One `PrecomputedTransactionData` per tx,
/// as Core does.
#[cfg(feature = "kernel")]
pub fn verify_kernel_tx(tx: &[u8], spent: &[Spent], flags: u32) -> Vec<Outcome> {
    use bitcoinkernel::{KernelError, PrecomputedTransactionData, ScriptPubkey, ScriptVerifyError, Transaction, TxOut};
    let ktx = match Transaction::new(tx) {
        Ok(t) => t,
        Err(_) => return vec![Outcome::Rejected; spent.len()],
    };
    let spks: Vec<ScriptPubkey> = spent
        .iter()
        .map(|s| ScriptPubkey::new(&s.spk).expect("script_pubkey"))
        .collect();
    let outs: Vec<TxOut> = spks
        .iter()
        .zip(spent)
        .map(|(spk, s)| TxOut::new(spk, s.value as i64))
        .collect();
    let pre = match PrecomputedTransactionData::new(&ktx, &outs) {
        Ok(p) => p,
        Err(_) => return vec![Outcome::Rejected; spent.len()],
    };
    spks.iter()
        .zip(spent)
        .enumerate()
        .map(|(i, (spk, s))| {
            match bitcoinkernel::verify(spk, Some(s.value as i64), &ktx, i, Some(flags), &pre) {
                Ok(()) => Outcome::Valid,
                Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid)) => Outcome::Invalid,
                Err(_) => Outcome::Rejected,
            }
        })
        .collect()
}

/// C entry point for an in-app debug hook (owner-run device benchmark).
/// `data_dir` must be a writable directory (e.g. the app's Caches dir).
/// Returns a heap-allocated JSON string; free with `kernel_spike_free_string`.
#[cfg(not(feature = "kernel"))]
#[no_mangle]
pub extern "C" fn kernel_spike_run_bench(_data_dir: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    std::ffi::CString::new(r#"{"error":"consensus build: no chainstate bench"}"#).unwrap().into_raw()
}

#[cfg(feature = "kernel")]
#[no_mangle]
pub extern "C" fn kernel_spike_run_bench(data_dir: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    let dir = unsafe { std::ffi::CStr::from_ptr(data_dir) }.to_string_lossy().into_owned();
    let json = match bench::run_all(std::path::Path::new(&dir)) {
        Ok(r) => r.to_string(),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    };
    std::ffi::CString::new(json).unwrap().into_raw()
}

/// C entry point: Step-1 vectors + mainnet block script-verify timings for the
/// engine this build links. `testdata_dir` = bundled spike testdata folder.
#[no_mangle]
pub extern "C" fn kernel_spike_run_verify(testdata_dir: *const std::os::raw::c_char) -> *mut std::os::raw::c_char {
    let dir = unsafe { std::ffi::CStr::from_ptr(testdata_dir) }.to_string_lossy().into_owned();
    let (_, summary) = step1::run(std::path::Path::new(&dir));
    std::ffi::CString::new(summary.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn kernel_spike_free_string(s: *mut std::os::raw::c_char) {
    if !s.is_null() {
        unsafe { drop(std::ffi::CString::from_raw(s)) };
    }
}

/// Whichever engine this binary links.
#[cfg(feature = "kernel")]
pub fn verify_tx(tx: &[u8], spent: &[Spent], flags: u32) -> Vec<Outcome> {
    verify_kernel_tx(tx, spent, flags)
}
#[cfg(feature = "consensus")]
pub fn verify_tx(tx: &[u8], spent: &[Spent], flags: u32) -> Vec<Outcome> {
    verify_consensus_tx(tx, spent, flags)
}
#[cfg(feature = "kernel")]
pub const ENGINE: &str = "libbitcoinkernel";
#[cfg(feature = "consensus")]
pub const ENGINE: &str = "libbitcoinconsensus-v26";

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "consensus")]
    #[test]
    fn flag_bits_match_consensus() {
        assert_eq!(VERIFY_P2SH, bitcoinconsensus::VERIFY_P2SH);
        assert_eq!(VERIFY_DERSIG, bitcoinconsensus::VERIFY_DERSIG);
        assert_eq!(VERIFY_NULLDUMMY, bitcoinconsensus::VERIFY_NULLDUMMY);
        assert_eq!(VERIFY_CHECKLOCKTIMEVERIFY, bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY);
        assert_eq!(VERIFY_CHECKSEQUENCEVERIFY, bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY);
        assert_eq!(VERIFY_WITNESS, bitcoinconsensus::VERIFY_WITNESS);
        assert_eq!(VERIFY_TAPROOT, bitcoinconsensus::VERIFY_TAPROOT);
        for h in [0, 173_805, 363_725, 388_381, 419_328, 481_824, 709_632, 709_633, 900_000] {
            assert_eq!(mainnet_height_to_flags(h), bitcoinconsensus::height_to_flags(h), "height {h}");
        }
    }
    #[cfg(feature = "kernel")]
    #[test]
    fn flag_bits_match_kernel() {
        assert_eq!(VERIFY_P2SH, bitcoinkernel::VERIFY_P2SH);
        assert_eq!(VERIFY_DERSIG, bitcoinkernel::VERIFY_DERSIG);
        assert_eq!(VERIFY_NULLDUMMY, bitcoinkernel::VERIFY_NULLDUMMY);
        assert_eq!(VERIFY_CHECKLOCKTIMEVERIFY, bitcoinkernel::VERIFY_CHECKLOCKTIMEVERIFY);
        assert_eq!(VERIFY_CHECKSEQUENCEVERIFY, bitcoinkernel::VERIFY_CHECKSEQUENCEVERIFY);
        assert_eq!(VERIFY_WITNESS, bitcoinkernel::VERIFY_WITNESS);
        assert_eq!(VERIFY_TAPROOT, bitcoinkernel::VERIFY_TAPROOT);
        assert_eq!(VERIFY_ALL, bitcoinkernel::VERIFY_ALL);
    }
}
