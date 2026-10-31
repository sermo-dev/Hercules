//! Script verification: the one place Hercules calls a Bitcoin Core script
//! interpreter (ticket 047).
//!
//! Block validation (`block_validation::validate_block_scripts`) and mempool
//! acceptance (`Mempool::accept_tx`) both go through [`verify_transaction`].
//! Which library does the work is a compile-time choice:
//!
//! | Cargo features | Verifier |
//! |---|---|
//! | `script-kernel` (default) | libbitcoinkernel from a pinned Bitcoin Core release (`kernel-sys/`) |
//! | `--no-default-features --features script-consensus-legacy` | the frozen, patched libbitcoinconsensus v26 (`patches/bitcoinconsensus/`) |
//! | `--features script-differential` | differential: every check runs through both and aborts if they disagree |
//!
//! To switch back to the legacy library, build with `--no-default-features
//! --features script-consensus-legacy` (for the app: `HERCULES_SCRIPT_BACKEND=legacy
//! ./build-ios.sh`). Nothing else changes: callers, flags and error types are
//! backend-independent.
//!
//! Differential mode exists to prove the backends equivalent (`cargo test
//! --features script-differential` runs the whole suite through it) and
//! cannot ship: a release build of the library with it is a compile error,
//! as is enabling both backends without asking for differential mode.
//! Linking both is safe only because the legacy build seals its symbols
//! (see `patches/bitcoinconsensus/build.rs`).
//!
//! Whatever the consensus backend, mempool acceptance also runs a policy
//! pass under Core's STANDARD_SCRIPT_VERIFY_FLAGS
//! ([`verify_transaction_policy`], ticket 053) through the patched v26
//! library's `hercules_policy.cpp`, so that library is linked in every
//! build (sealed on Apple targets, as in differential mode).
//!
//! Both libraries take the same seven consensus flags with the same bit
//! values; `chain_params::SCRIPT_VERIFY_*` is the source of truth and the
//! tests below check it against each library's own constants.

#[cfg(not(any(feature = "script-kernel", feature = "script-consensus-legacy")))]
compile_error!("enable a script verification backend: `script-kernel` or `script-consensus-legacy`");

#[cfg(all(
    feature = "script-kernel",
    feature = "script-consensus-legacy",
    not(feature = "script-differential")
))]
compile_error!(
    "`script-kernel` and `script-consensus-legacy` are exclusive; for the legacy backend use \
     `--no-default-features --features script-consensus-legacy`, to compare both use \
     `--features script-differential` (tests only)"
);

#[cfg(all(feature = "script-differential", not(test), not(debug_assertions)))]
compile_error!(
    "`script-differential` is a test-only mode (it aborts the process on any backend \
     disagreement and links two script libraries); it must not be built for release"
);

use std::fmt;

use bitcoin::consensus::serialize;
use bitcoin::Transaction;

use crate::chain_params::{
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, SCRIPT_VERIFY_DERSIG,
    SCRIPT_VERIFY_NULLDUMMY, SCRIPT_VERIFY_P2SH, SCRIPT_VERIFY_TAPROOT, SCRIPT_VERIFY_WITNESS,
};

#[cfg(feature = "script-kernel")]
mod kernel;
#[cfg(feature = "script-consensus-legacy")]
mod legacy;

#[cfg(test)]
mod core_vectors;
#[cfg(test)]
mod script_asm;
#[cfg(test)]
mod tests;

/// Every flag either library accepts. Anything else is refused up front
/// (libbitcoinkernel would abort the process on an unknown bit).
pub const SCRIPT_VERIFY_ALL_CONSENSUS: u32 = SCRIPT_VERIFY_P2SH
    | SCRIPT_VERIFY_DERSIG
    | SCRIPT_VERIFY_NULLDUMMY
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_WITNESS
    | SCRIPT_VERIFY_TAPROOT;

/// One spent output: (amount in sats, scriptPubKey bytes), in input order.
pub type SpentOutput = (u64, Vec<u8>);

/// Why a script check did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptVerifyError {
    /// The script evaluated to false or broke a consensus script rule.
    ScriptFailed,
    /// Flag bits outside the consensus set, or WITNESS without P2SH.
    InvalidFlags(u32),
    /// `spent` must have exactly one entry per input (BIP 341 commits to all).
    SpentOutputsMismatch { inputs: usize, spent: usize },
    /// A transaction with no inputs has nothing to authorize. Its
    /// serialization is ambiguous with the segwit marker, so the libraries
    /// disagree on it (kernel: unparsable; v26: nothing to check, Ok).
    NoInputs,
    /// The library could not parse the transaction.
    TxDeserialize,
    /// Any other refusal by the library (should not happen with checked inputs).
    Library(String),
}

impl fmt::Display for ScriptVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScriptFailed => write!(f, "script verification failed"),
            Self::InvalidFlags(flags) => write!(f, "invalid script flags {:#x}", flags),
            Self::SpentOutputsMismatch { inputs, spent } => {
                write!(f, "{} spent outputs for {} inputs", spent, inputs)
            }
            Self::NoInputs => write!(f, "transaction has no inputs"),
            Self::TxDeserialize => write!(f, "transaction did not deserialize"),
            Self::Library(msg) => write!(f, "script library error: {}", msg),
        }
    }
}

/// First failing input of a transaction. Transaction-level errors (bad
/// flags, mismatched spent outputs) report input 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptVerifyFailure {
    pub input_index: usize,
    pub error: ScriptVerifyError,
}

/// A script verification library compiled into this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    #[cfg(feature = "script-kernel")]
    Kernel,
    #[cfg(feature = "script-consensus-legacy")]
    ConsensusLegacy,
}

/// Per-input results, in input order (shorter than the input count only
/// when verification stopped at the first failure).
type InputResults = Vec<Result<(), ScriptVerifyError>>;

impl Backend {
    /// Every backend linked into this build.
    #[cfg(test)]
    pub const ENABLED: &'static [Backend] = &[
        #[cfg(feature = "script-kernel")]
        Backend::Kernel,
        #[cfg(feature = "script-consensus-legacy")]
        Backend::ConsensusLegacy,
    ];

    pub fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "script-kernel")]
            Backend::Kernel => kernel::NAME,
            #[cfg(feature = "script-consensus-legacy")]
            Backend::ConsensusLegacy => legacy::NAME,
        }
    }

    /// Verify the inputs of a consensus-serialized `tx` whose arguments
    /// already passed [`precheck`]. `Err` = the library refused the whole
    /// transaction.
    fn verify_inputs(
        self,
        tx: &[u8],
        spent: &[SpentOutput],
        flags: u32,
        stop_at_first_failure: bool,
    ) -> Result<InputResults, ScriptVerifyError> {
        match self {
            #[cfg(feature = "script-kernel")]
            Backend::Kernel => kernel::verify_inputs(tx, spent, flags, stop_at_first_failure),
            #[cfg(feature = "script-consensus-legacy")]
            Backend::ConsensusLegacy => {
                legacy::verify_inputs(tx, spent, flags, stop_at_first_failure)
            }
        }
    }

    /// Verify every input of `tx` with this backend only.
    #[cfg_attr(feature = "script-differential", allow(dead_code))]
    pub fn verify_transaction(
        self,
        tx: &Transaction,
        spent: &[SpentOutput],
        flags: u32,
    ) -> Result<(), ScriptVerifyFailure> {
        precheck(tx, spent, flags)?;
        first_failure(self.verify_inputs(&serialize(tx), spent, flags, true))
    }
}

/// The library whose verdicts this build acts on. Part of the rules tag
/// stored with `failed_blocks` rows (`sync::rules_tag`), so switching
/// backends in either direction reconsiders blocks the other one failed.
/// Differential builds act on the kernel's result (and abort on any
/// disagreement), so they report the kernel.
pub fn active_backend_name() -> &'static str {
    #[cfg(feature = "script-kernel")]
    {
        Backend::Kernel.name()
    }
    #[cfg(not(feature = "script-kernel"))]
    {
        Backend::ConsensusLegacy.name()
    }
}

/// Verify every input of `tx` against the outputs it spends, under `flags`
/// (from `ChainParams::script_flags`). Returns the first failing input.
///
/// Coinbase transactions have no scripts to verify; callers skip them.
pub fn verify_transaction(
    tx: &Transaction,
    spent: &[SpentOutput],
    flags: u32,
) -> Result<(), ScriptVerifyFailure> {
    #[cfg(feature = "script-differential")]
    {
        verify_differential(tx, spent, flags)
    }
    #[cfg(all(feature = "script-kernel", not(feature = "script-differential")))]
    {
        Backend::Kernel.verify_transaction(tx, spent, flags)
    }
    #[cfg(all(feature = "script-consensus-legacy", not(feature = "script-kernel")))]
    {
        Backend::ConsensusLegacy.verify_transaction(tx, spent, flags)
    }
}

/// Bitcoin Core's `STANDARD_SCRIPT_VERIFY_FLAGS` (policy/policy.h): the
/// seven consensus flags plus the relay policy ones, which peers apply
/// before relaying a transaction. Bit values are Core's
/// `script_verify_flag_name` order, as both libraries number them; the
/// tests check this against the legacy library's own table.
pub const STANDARD_SCRIPT_VERIFY_FLAGS: u32 = SCRIPT_VERIFY_ALL_CONSENSUS
    | (1 << 1)  // STRICTENC
    | (1 << 3)  // LOW_S
    | (1 << 6)  // MINIMALDATA
    | (1 << 7)  // DISCOURAGE_UPGRADABLE_NOPS
    | (1 << 8)  // CLEANSTACK
    | (1 << 12) // DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
    | (1 << 13) // MINIMALIF
    | (1 << 14) // NULLFAIL
    | (1 << 15) // WITNESS_PUBKEYTYPE
    | (1 << 16) // CONST_SCRIPTCODE
    | (1 << 18) // DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
    | (1 << 19) // DISCOURAGE_OP_SUCCESS
    | (1 << 20); // DISCOURAGE_UPGRADABLE_PUBKEYTYPE

/// First input failing the policy-flag pass, with Core's `ScriptError`
/// string for the user (e.g. "Non-canonical signature: S value is
/// unnecessarily high").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyScriptFailure {
    pub input_index: usize,
    pub error: ScriptVerifyError,
    pub script_error: String,
}

/// Verify every input of `tx` under [`STANDARD_SCRIPT_VERIFY_FLAGS`]: Core's
/// `PolicyScriptChecks` (ticket 053). Mempool acceptance only; a failure
/// says nothing about consensus validity (rerun [`verify_transaction`] with
/// the consensus flags to classify it).
///
/// Always the patched libbitcoinconsensus v26 (`hercules_policy.cpp`),
/// whatever the consensus backend: the kernel's C API takes the consensus
/// flags only. v26's interpreter has the same policy flags and semantics
/// as the kernel's Core release; the consensus pass that follows runs on
/// the consensus backend.
pub fn verify_transaction_policy(tx: &Transaction, spent: &[SpentOutput]) -> Result<(), PolicyScriptFailure> {
    let fail = |input_index, error| PolicyScriptFailure { input_index, error, script_error: String::new() };
    if tx.input.is_empty() {
        return Err(fail(0, ScriptVerifyError::NoInputs));
    }
    if spent.len() != tx.input.len() {
        return Err(fail(0, ScriptVerifyError::SpentOutputsMismatch { inputs: tx.input.len(), spent: spent.len() }));
    }
    let raw = serialize(tx);
    let utxos: Vec<bitcoinconsensus::Utxo> = spent
        .iter()
        .map(|(amt, spk)| bitcoinconsensus::Utxo {
            script_pubkey: spk.as_ptr(),
            script_pubkey_len: spk.len() as u32,
            value: *amt as i64,
        })
        .collect();
    for (input_index, (amount, spk)) in spent.iter().enumerate() {
        if let Err((e, script_error)) = bitcoinconsensus::verify_with_policy_flags(
            spk,
            *amount,
            &raw,
            &utxos,
            input_index,
            STANDARD_SCRIPT_VERIFY_FLAGS,
        ) {
            use bitcoinconsensus::Error::*;
            let error = match e {
                ERR_SCRIPT => ScriptVerifyError::ScriptFailed,
                ERR_TX_DESERIALIZE | ERR_TX_SIZE_MISMATCH => ScriptVerifyError::TxDeserialize,
                ERR_INVALID_FLAGS => ScriptVerifyError::InvalidFlags(STANDARD_SCRIPT_VERIFY_FLAGS),
                other => ScriptVerifyError::Library(format!("{}", other)),
            };
            return Err(PolicyScriptFailure { input_index, error, script_error });
        }
    }
    Ok(())
}

/// Checks both libraries need but would handle differently (kernel aborts
/// on bad flags or a short spent-output list; v26 aborts on WITNESS without
/// P2SH; they disagree on a tx with no inputs), done once here so both see
/// only well-formed requests.
fn precheck(tx: &Transaction, spent: &[SpentOutput], flags: u32) -> Result<(), ScriptVerifyFailure> {
    let fail = |error| Err(ScriptVerifyFailure { input_index: 0, error });
    if tx.input.is_empty() {
        return fail(ScriptVerifyError::NoInputs);
    }
    if flags & !SCRIPT_VERIFY_ALL_CONSENSUS != 0
        || (flags & SCRIPT_VERIFY_WITNESS != 0 && flags & SCRIPT_VERIFY_P2SH == 0)
    {
        return fail(ScriptVerifyError::InvalidFlags(flags));
    }
    if spent.len() != tx.input.len() {
        return fail(ScriptVerifyError::SpentOutputsMismatch {
            inputs: tx.input.len(),
            spent: spent.len(),
        });
    }
    Ok(())
}

fn first_failure(
    results: Result<InputResults, ScriptVerifyError>,
) -> Result<(), ScriptVerifyFailure> {
    let results = results.map_err(|error| ScriptVerifyFailure { input_index: 0, error })?;
    match results.into_iter().enumerate().find_map(|(i, r)| r.err().map(|e| (i, e))) {
        Some((input_index, error)) => Err(ScriptVerifyFailure { input_index, error }),
        None => Ok(()),
    }
}

/// Differential mode: run every input through both libraries (no early
/// exit, so later inputs are compared too) and abort on any disagreement.
/// Abort rather than panic: verification also runs on sync worker threads,
/// where a panic could be caught and look like an ordinary invalid block.
#[cfg(feature = "script-differential")]
fn verify_differential(
    tx: &Transaction,
    spent: &[SpentOutput],
    flags: u32,
) -> Result<(), ScriptVerifyFailure> {
    precheck(tx, spent, flags)?;
    let bytes = serialize(tx);
    let kernel = Backend::Kernel.verify_inputs(&bytes, spent, flags, false);
    let legacy = Backend::ConsensusLegacy.verify_inputs(&bytes, spent, flags, false);
    if kernel != legacy {
        eprintln!(
            "script backends disagree on tx {} (flags {:#x}):\n  {}: {:?}\n  {}: {:?}\n  tx: {}",
            tx.compute_txid(),
            flags,
            Backend::Kernel.name(),
            kernel,
            Backend::ConsensusLegacy.name(),
            legacy,
            hex::encode(&bytes),
        );
        std::process::abort();
    }
    first_failure(kernel)
}
