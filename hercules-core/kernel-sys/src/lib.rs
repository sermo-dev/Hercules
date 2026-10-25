//! Raw bindings to the script-verification subset of Bitcoin Core's
//! libbitcoinkernel C API (`src/kernel/bitcoinkernel.h`, pinned release in
//! build.rs). Only what `hercules-core/src/script_verify/kernel.rs` calls is
//! declared; the rest of the API (chainstate, block validation) is ticket
//! 047 Step 2 and deliberately not exposed.
//!
//! The C API is unversioned and not yet stable upstream. Signatures here
//! were checked against the pinned header; recheck them on every bump.

#![allow(non_camel_case_types)]

use std::ffi::{c_int, c_uint, c_void};
use std::marker::{PhantomData, PhantomPinned};

macro_rules! opaque {
    ($($name:ident),* $(,)?) => {$(
        #[repr(C)]
        pub struct $name {
            _data: [u8; 0],
            _marker: PhantomData<(*mut u8, PhantomPinned)>,
        }
    )*};
}

opaque!(
    btck_Transaction,
    btck_TransactionOutput,
    btck_ScriptPubkey,
    btck_PrecomputedTransactionData,
);

pub type btck_ScriptVerificationFlags = u32;
pub type btck_ScriptVerifyStatus = u8;

extern "C" {
    pub fn btck_transaction_create(
        raw_transaction: *const c_void,
        raw_transaction_len: usize,
    ) -> *mut btck_Transaction;
    pub fn btck_transaction_count_inputs(transaction: *const btck_Transaction) -> usize;
    pub fn btck_transaction_destroy(transaction: *mut btck_Transaction);

    pub fn btck_script_pubkey_create(
        script_pubkey: *const c_void,
        script_pubkey_len: usize,
    ) -> *mut btck_ScriptPubkey;
    pub fn btck_script_pubkey_destroy(script_pubkey: *mut btck_ScriptPubkey);

    pub fn btck_transaction_output_create(
        script_pubkey: *const btck_ScriptPubkey,
        amount: i64,
    ) -> *mut btck_TransactionOutput;
    pub fn btck_transaction_output_destroy(transaction_output: *mut btck_TransactionOutput);

    pub fn btck_precomputed_transaction_data_create(
        tx_to: *const btck_Transaction,
        spent_outputs: *mut *const btck_TransactionOutput,
        spent_outputs_len: usize,
    ) -> *mut btck_PrecomputedTransactionData;
    pub fn btck_precomputed_transaction_data_destroy(
        precomputed_txdata: *mut btck_PrecomputedTransactionData,
    );

    /// Returns 1 if valid. Aborts (C `assert`) on flags outside
    /// `btck_ScriptVerificationFlags_ALL` or `input_index` out of range, so
    /// callers must check both first.
    pub fn btck_script_pubkey_verify(
        script_pubkey: *const btck_ScriptPubkey,
        amount: i64,
        tx_to: *const btck_Transaction,
        precomputed_txdata: *const btck_PrecomputedTransactionData,
        input_index: c_uint,
        flags: btck_ScriptVerificationFlags,
        status: *mut btck_ScriptVerifyStatus,
    ) -> c_int;
}

// Values of the header's macros, from src/flags.c (compiled against the
// installed header).
extern "C" {
    pub static hercules_btck_flag_none: u32;
    pub static hercules_btck_flag_p2sh: u32;
    pub static hercules_btck_flag_dersig: u32;
    pub static hercules_btck_flag_nulldummy: u32;
    pub static hercules_btck_flag_checklocktimeverify: u32;
    pub static hercules_btck_flag_checksequenceverify: u32;
    pub static hercules_btck_flag_witness: u32;
    pub static hercules_btck_flag_taproot: u32;
    pub static hercules_btck_flag_all: u32;

    pub static hercules_btck_status_ok: u8;
    pub static hercules_btck_status_invalid_flags_combination: u8;
    pub static hercules_btck_status_spent_outputs_required: u8;
}

/// Bitcoin Core release the linked library was built from (e.g. "v32.0").
pub const CORE_TAG: &str = env!("HERCULES_BITCOIN_CORE_TAG");
/// "libbitcoinkernel <release>", for logs and error messages.
pub const LIBRARY_NAME: &str = concat!("libbitcoinkernel ", env!("HERCULES_BITCOIN_CORE_TAG"));
