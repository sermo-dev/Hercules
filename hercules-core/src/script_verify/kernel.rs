//! libbitcoinkernel backend (`script-kernel`, the default).
//!
//! One kernel transaction and one `PrecomputedTransactionData` per tx (as
//! Core's own validation does), then `btck_script_pubkey_verify` per input.
//! libbitcoinconsensus re-deserialized the tx and rebuilt the sighash cache
//! for every input, which is most of why this path is faster.

use std::ffi::c_uint;
use std::ptr::NonNull;

use hercules_kernel_sys as sys;

use super::{InputResults, ScriptVerifyError, SpentOutput};

pub const NAME: &str = sys::LIBRARY_NAME;

/// Owning handle to a kernel object; destroys it on drop.
struct Owned<T> {
    ptr: NonNull<T>,
    destroy: unsafe extern "C" fn(*mut T),
}

impl<T> Owned<T> {
    fn new(ptr: *mut T, destroy: unsafe extern "C" fn(*mut T)) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Owned { ptr, destroy })
    }

    fn as_ptr(&self) -> *const T {
        self.ptr.as_ptr()
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from the matching kernel `_create` call and is
        // destroyed exactly once.
        unsafe { (self.destroy)(self.ptr.as_ptr()) }
    }
}

pub fn verify_inputs(
    tx: &[u8],
    spent: &[SpentOutput],
    flags: u32,
    stop_at_first_failure: bool,
) -> Result<InputResults, ScriptVerifyError> {
    // SAFETY (whole function): every pointer handed to the kernel is either
    // a live Rust slice for the duration of the call or a handle owned by an
    // `Owned` that outlives every use. `precheck` guaranteed `flags` is a
    // subset of the consensus flags; the input count is checked below, so
    // the kernel's index/length asserts cannot fire.
    unsafe {
        let ktx = Owned::new(
            sys::btck_transaction_create(tx.as_ptr().cast(), tx.len()),
            sys::btck_transaction_destroy,
        )
        .ok_or(ScriptVerifyError::TxDeserialize)?;
        let inputs = sys::btck_transaction_count_inputs(ktx.as_ptr());
        if inputs != spent.len() {
            return Err(ScriptVerifyError::SpentOutputsMismatch { inputs, spent: spent.len() });
        }

        let mut spks = Vec::with_capacity(spent.len());
        let mut outs = Vec::with_capacity(spent.len());
        for (amount, spk) in spent {
            let s = Owned::new(
                sys::btck_script_pubkey_create(spk.as_ptr().cast(), spk.len()),
                sys::btck_script_pubkey_destroy,
            )
            .ok_or_else(|| ScriptVerifyError::Library("script_pubkey_create".into()))?;
            let o = Owned::new(
                sys::btck_transaction_output_create(s.as_ptr(), *amount as i64),
                sys::btck_transaction_output_destroy,
            )
            .ok_or_else(|| ScriptVerifyError::Library("transaction_output_create".into()))?;
            spks.push(s);
            outs.push(o);
        }

        // BIP 341: the sighash commits to every spent output, so the
        // precomputed data always gets the full list.
        let mut out_ptrs: Vec<*const sys::btck_TransactionOutput> =
            outs.iter().map(|o| o.as_ptr()).collect();
        let txdata = Owned::new(
            sys::btck_precomputed_transaction_data_create(
                ktx.as_ptr(),
                out_ptrs.as_mut_ptr(),
                out_ptrs.len(),
            ),
            sys::btck_precomputed_transaction_data_destroy,
        )
        .ok_or_else(|| ScriptVerifyError::Library("precomputed_transaction_data_create".into()))?;

        let mut results = Vec::with_capacity(spent.len());
        for (i, ((amount, _), spk)) in spent.iter().zip(&spks).enumerate() {
            let mut status = sys::hercules_btck_status_ok;
            let ok = sys::btck_script_pubkey_verify(
                spk.as_ptr(),
                *amount as i64,
                ktx.as_ptr(),
                txdata.as_ptr(),
                i as c_uint,
                flags,
                &mut status,
            );
            let r = if ok == 1 {
                Ok(())
            } else if status == sys::hercules_btck_status_ok {
                Err(ScriptVerifyError::ScriptFailed)
            } else if status == sys::hercules_btck_status_invalid_flags_combination {
                Err(ScriptVerifyError::InvalidFlags(flags))
            } else {
                Err(ScriptVerifyError::Library(format!("btck_script_pubkey_verify status {}", status)))
            };
            let failed = r.is_err();
            results.push(r);
            if failed && stop_at_first_failure {
                break;
            }
        }
        Ok(results)
    }
}
