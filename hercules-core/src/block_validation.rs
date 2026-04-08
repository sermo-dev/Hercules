use std::collections::{HashMap, HashSet};

use bitcoin::block::Block;
use bitcoin::consensus::serialize;
use bitcoin::script::Instruction;
use bitcoin::{Amount, Txid};

use crate::utxo::UtxoSet;

/// Maximum block weight (BIP-141 consensus rule).
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// BIP-34 activation height (coinbase must encode block height).
const BIP34_HEIGHT: u32 = 227_931;

/// SegWit activation height (witness commitment required).
const SEGWIT_HEIGHT: u32 = 481_824;

/// Halving interval in blocks.
const SUBSIDY_HALVING_INTERVAL: u32 = 210_000;

/// Initial block subsidy in satoshis (50 BTC).
const INITIAL_SUBSIDY: u64 = 50 * 100_000_000;

/// Maximum value of a single output (21 million BTC in satoshis).
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Maximum sigops cost per block (BIP-141).
const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// Sigops cost multiplier for legacy (non-witness) sigops.
const WITNESS_SCALE_FACTOR: u64 = 4;

/// Count legacy signature operations in a script.
/// Uses conservative counting: 20 for each CHECKMULTISIG (MAX_PUBKEYS_PER_MULTISIG).
/// This matches Bitcoin Core's `GetLegacySigOpCount` with fAccurate=false.
/// Continues counting through parse errors (malformed opcodes are skipped,
/// not silently dropped) to avoid sigops undercount on crafted scripts.
fn count_script_sigops(script: &bitcoin::Script) -> u64 {
    use bitcoin::opcodes::all::{
        OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    };
    let mut count = 0u64;
    for result in script.instructions() {
        match result {
            Ok(Instruction::Op(op)) => {
                if op == OP_CHECKSIG || op == OP_CHECKSIGVERIFY {
                    count += 1;
                } else if op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY {
                    count += 20;
                }
            }
            Ok(_) => {} // PushBytes — not a sigop
            Err(_) => {} // Malformed opcode — skip, keep counting
        }
    }
    count
}

/// Validate the structural properties of a full block.
/// This does NOT validate scripts or UTXO spends (Phase 2b/2c).
pub fn validate_block(block: &Block, height: u32) -> Result<(), BlockValidationError> {
    // 1. Block must have at least one transaction (the coinbase)
    if block.txdata.is_empty() {
        return Err(BlockValidationError::EmptyBlock { height });
    }

    // 2. First transaction must be coinbase
    if !block.txdata[0].is_coinbase() {
        return Err(BlockValidationError::NoCoinbase { height });
    }

    // 3. No other transaction may be coinbase
    for (i, tx) in block.txdata.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(BlockValidationError::MultipleCoinbase {
                height,
                index: i,
            });
        }
    }

    // 4. Verify merkle root matches header
    if !block.check_merkle_root() {
        return Err(BlockValidationError::BadMerkleRoot { height });
    }

    // 5. Block weight must not exceed limit
    let weight = block.weight().to_wu();
    if weight > MAX_BLOCK_WEIGHT {
        return Err(BlockValidationError::ExcessiveWeight {
            height,
            weight,
            max: MAX_BLOCK_WEIGHT,
        });
    }

    // 6. Transaction format validation + output value limits + sigops
    let mut block_sigops: u64 = 0;
    for (i, tx) in block.txdata.iter().enumerate() {
        if tx.input.is_empty() {
            return Err(BlockValidationError::EmptyInputs {
                height,
                tx_index: i,
            });
        }
        if tx.output.is_empty() {
            return Err(BlockValidationError::EmptyOutputs {
                height,
                tx_index: i,
            });
        }

        // Output value must not exceed MAX_MONEY
        for (j, output) in tx.output.iter().enumerate() {
            if output.value.to_sat() > MAX_MONEY {
                return Err(BlockValidationError::OutputExceedsMaxMoney {
                    height,
                    tx_index: i,
                    output_index: j,
                    amount: output.value.to_sat(),
                });
            }
            block_sigops += count_script_sigops(&output.script_pubkey);
        }

        // Count sigops in input scripts (including coinbase — matches Bitcoin Core)
        for input in &tx.input {
            block_sigops += count_script_sigops(&input.script_sig);
        }
    }

    // Block-level legacy sigops check (matches Bitcoin Core's CheckBlock)
    if block_sigops * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST {
        return Err(BlockValidationError::ExcessiveSigops {
            height,
            sigops: block_sigops,
            max: MAX_BLOCK_SIGOPS_COST / WITNESS_SCALE_FACTOR,
        });
    }

    // 7. No duplicate transactions (BIP-30)
    let mut seen_txids = HashSet::with_capacity(block.txdata.len());
    for tx in &block.txdata {
        if !seen_txids.insert(tx.compute_txid()) {
            return Err(BlockValidationError::DuplicateTx {
                height,
                txid: tx.compute_txid().to_string(),
            });
        }
    }

    // 8. Coinbase total output cannot exceed MAX_MONEY (trivial upper bound).
    // The exact fee-based check happens in validate_block_scripts where we
    // know the actual fees. We cannot compute exact fees here without the
    // UTXO set (fees = sum(inputs) - sum(outputs) requires input values).
    let coinbase_total: u64 = block.txdata[0]
        .output
        .iter()
        .try_fold(0u64, |acc, o| acc.checked_add(o.value.to_sat()))
        .ok_or(BlockValidationError::ValueOverflow { height, tx_index: 0 })?;

    if coinbase_total > MAX_MONEY {
        return Err(BlockValidationError::CoinbaseOverpayment {
            height,
            actual: coinbase_total,
            max_subsidy: MAX_MONEY,
        });
    }

    // 9. BIP-34: coinbase must encode block height (after activation)
    if height >= BIP34_HEIGHT {
        match block.bip34_block_height() {
            Ok(encoded_height) => {
                if encoded_height != height as u64 {
                    return Err(BlockValidationError::BadCoinbaseHeight {
                        height,
                        encoded: encoded_height,
                    });
                }
            }
            Err(_) => {
                return Err(BlockValidationError::BadCoinbaseHeight {
                    height,
                    encoded: 0,
                });
            }
        }
    }

    // 10. Witness commitment (post-SegWit)
    if height >= SEGWIT_HEIGHT {
        // check_witness_commitment returns true if commitment is valid
        // OR if the block has no witness data (pre-segwit txs only)
        if !block.check_witness_commitment() {
            return Err(BlockValidationError::BadWitnessCommitment { height });
        }
    }

    Ok(())
}

/// Coinbase outputs cannot be spent until this many blocks have passed.
const COINBASE_MATURITY: u32 = 100;

/// Calculate the block subsidy at a given height.
pub fn block_subsidy(height: u32) -> Amount {
    let halvings = height / SUBSIDY_HALVING_INTERVAL;
    if halvings >= 64 {
        return Amount::ZERO;
    }
    Amount::from_sat(INITIAL_SUBSIDY >> halvings)
}

/// Validate transaction scripts and input/output values against the UTXO set.
/// This verifies that every spend is authorized (valid script) and that no
/// value is created from nothing (inputs >= outputs for each tx).
///
/// Call this AFTER `validate_block()` succeeds. After this returns Ok,
/// call `utxo_set.apply_block()` to update the UTXO set.
pub fn validate_block_scripts(
    block: &Block,
    height: u32,
    utxo_set: &UtxoSet,
) -> Result<(), BlockValidationError> {
    let flags = bitcoinconsensus::height_to_flags(height);

    // Track outputs created within this block for in-block spend resolution.
    // Maps (txid, vout) -> (amount, script_pubkey_bytes, is_coinbase).
    let mut block_utxos: HashMap<(Txid, u32), (u64, Vec<u8>, bool)> = HashMap::new();
    // Track persistent UTXOs already spent in this block (double-spend detection).
    let mut spent_persistent: HashSet<(Txid, u32)> = HashSet::new();
    let mut total_fees: u64 = 0;

    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if !tx.is_coinbase() {
            let serialized_tx = serialize(tx);
            let mut input_sum: u64 = 0;

            // Phase A: resolve every spent output up-front. Taproot's BIP 341
            // sighash commits to *all* spent outputs in a transaction, so the
            // libbitcoinconsensus 26.0 API requires us to hand the full slice
            // of (amount, script_pubkey) to every per-input verification.
            // We collect once here, then verify in Phase C below.
            let mut spent: Vec<(u64, Vec<u8>)> = Vec::with_capacity(tx.input.len());
            for (input_idx, input) in tx.input.iter().enumerate() {
                let prev_txid = input.previous_output.txid;
                let prev_vout = input.previous_output.vout;
                let key = (prev_txid, prev_vout);

                let (amount, script_pubkey) =
                    if let Some(entry) = block_utxos.remove(&key) {
                        // In-block spend (output created earlier in this block).
                        // Coinbase outputs cannot be spent in the same block
                        // (maturity requires 100 confirmations).
                        if entry.2 {
                            return Err(BlockValidationError::PrematureCoinbaseSpend {
                                height,
                                tx_index: tx_idx,
                                input_index: input_idx,
                                coinbase_height: height,
                            });
                        }
                        (entry.0, entry.1)
                    } else {
                        // Double-spend check: ensure this persistent UTXO hasn't
                        // already been consumed by another input in this block
                        if !spent_persistent.insert(key) {
                            return Err(BlockValidationError::DuplicateSpend {
                                height,
                                tx_index: tx_idx,
                                input_index: input_idx,
                            });
                        }

                        let utxo = utxo_set
                            .get(&prev_txid, prev_vout)
                            .map_err(|e| BlockValidationError::UtxoError {
                                height,
                                msg: format!("{}", e),
                            })?
                            .ok_or(BlockValidationError::MissingUtxo {
                                height,
                                tx_index: tx_idx,
                                input_index: input_idx,
                            })?;

                        // Coinbase maturity: coinbase outputs need 100 confirmations
                        // Use saturating_sub to prevent overflow with large heights
                        if utxo.is_coinbase
                            && height.saturating_sub(utxo.height) < COINBASE_MATURITY
                        {
                            return Err(BlockValidationError::PrematureCoinbaseSpend {
                                height,
                                tx_index: tx_idx,
                                input_index: input_idx,
                                coinbase_height: utxo.height,
                            });
                        }

                        (utxo.amount, utxo.script_pubkey)
                    };

                input_sum = input_sum
                    .checked_add(amount)
                    .ok_or(BlockValidationError::ValueOverflow {
                        height,
                        tx_index: tx_idx,
                    })?;
                spent.push((amount, script_pubkey));
            }

            // Phase B: build the FFI Utxo array. The raw pointers reference
            // the heap allocations owned by `spent`, which lives until the
            // end of this scope (well past the verify calls below).
            let utxos: Vec<bitcoinconsensus::Utxo> = spent
                .iter()
                .map(|(amt, spk)| bitcoinconsensus::Utxo {
                    script_pubkey: spk.as_ptr(),
                    script_pubkey_len: spk.len() as u32,
                    value: *amt as i64,
                })
                .collect();

            // Phase C: verify each input. Passing `Some(&utxos)` enables
            // taproot validation when VERIFY_TAPROOT is set in `flags`
            // (post-709632). Pre-taproot blocks safely ignore the slice.
            for (input_idx, (amount, script_pubkey)) in spent.iter().enumerate() {
                bitcoinconsensus::verify_with_flags(
                    script_pubkey,
                    *amount,
                    &serialized_tx,
                    Some(&utxos),
                    input_idx,
                    flags,
                )
                .map_err(|e| BlockValidationError::ScriptFailure {
                    height,
                    tx_index: tx_idx,
                    input_index: input_idx,
                    error: format!("{}", e),
                })?;
            }

            let output_sum: u64 = tx
                .output
                .iter()
                .try_fold(0u64, |acc, o| acc.checked_add(o.value.to_sat()))
                .ok_or(BlockValidationError::ValueOverflow {
                    height,
                    tx_index: tx_idx,
                })?;

            // Total output value per transaction must not exceed MAX_MONEY
            if output_sum > MAX_MONEY {
                return Err(BlockValidationError::ValueOverflow {
                    height,
                    tx_index: tx_idx,
                });
            }

            if input_sum < output_sum {
                return Err(BlockValidationError::InsufficientInputValue {
                    height,
                    tx_index: tx_idx,
                    input_total: input_sum,
                    output_total: output_sum,
                });
            }

            total_fees = total_fees
                .checked_add(input_sum - output_sum)
                .ok_or(BlockValidationError::ValueOverflow {
                    height,
                    tx_index: tx_idx,
                })?;
        }

        // Add this transaction's outputs to the in-block map
        let txid = tx.compute_txid();
        for (vout, output) in tx.output.iter().enumerate() {
            if !output.script_pubkey.is_op_return() {
                block_utxos.insert(
                    (txid, vout as u32),
                    (
                        output.value.to_sat(),
                        output.script_pubkey.to_bytes(),
                        tx.is_coinbase(),
                    ),
                );
            }
        }
    }

    // Exact coinbase reward check (subsidy + actual fees)
    let subsidy = block_subsidy(height);
    let coinbase_total: u64 = block.txdata[0]
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let max_coinbase = subsidy
        .to_sat()
        .checked_add(total_fees)
        .ok_or(BlockValidationError::ValueOverflow {
            height,
            tx_index: 0,
        })?;

    if coinbase_total > max_coinbase {
        return Err(BlockValidationError::CoinbaseOverpayment {
            height,
            actual: coinbase_total,
            max_subsidy: max_coinbase,
        });
    }

    Ok(())
}

#[derive(Debug)]
pub enum BlockValidationError {
    EmptyBlock {
        height: u32,
    },
    NoCoinbase {
        height: u32,
    },
    MultipleCoinbase {
        height: u32,
        index: usize,
    },
    BadMerkleRoot {
        height: u32,
    },
    ExcessiveWeight {
        height: u32,
        weight: u64,
        max: u64,
    },
    EmptyInputs {
        height: u32,
        tx_index: usize,
    },
    EmptyOutputs {
        height: u32,
        tx_index: usize,
    },
    DuplicateTx {
        height: u32,
        txid: String,
    },
    CoinbaseOverpayment {
        height: u32,
        actual: u64,
        max_subsidy: u64,
    },
    BadCoinbaseHeight {
        height: u32,
        encoded: u64,
    },
    BadWitnessCommitment {
        height: u32,
    },
    // Phase 2b: script/UTXO validation errors
    MissingUtxo {
        height: u32,
        tx_index: usize,
        input_index: usize,
    },
    PrematureCoinbaseSpend {
        height: u32,
        tx_index: usize,
        input_index: usize,
        coinbase_height: u32,
    },
    ScriptFailure {
        height: u32,
        tx_index: usize,
        input_index: usize,
        error: String,
    },
    InsufficientInputValue {
        height: u32,
        tx_index: usize,
        input_total: u64,
        output_total: u64,
    },
    ValueOverflow {
        height: u32,
        tx_index: usize,
    },
    UtxoError {
        height: u32,
        msg: String,
    },
    OutputExceedsMaxMoney {
        height: u32,
        tx_index: usize,
        output_index: usize,
        amount: u64,
    },
    DuplicateSpend {
        height: u32,
        tx_index: usize,
        input_index: usize,
    },
    ExcessiveSigops {
        height: u32,
        sigops: u64,
        max: u64,
    },
}

impl std::fmt::Display for BlockValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBlock { height } => write!(f, "block {} has no transactions", height),
            Self::NoCoinbase { height } => {
                write!(f, "block {} first transaction is not coinbase", height)
            }
            Self::MultipleCoinbase { height, index } => {
                write!(f, "block {} has extra coinbase at index {}", height, index)
            }
            Self::BadMerkleRoot { height } => {
                write!(f, "block {} merkle root does not match transactions", height)
            }
            Self::ExcessiveWeight { height, weight, max } => {
                write!(f, "block {} weight {} exceeds max {}", height, weight, max)
            }
            Self::EmptyInputs { height, tx_index } => {
                write!(f, "block {} tx {} has no inputs", height, tx_index)
            }
            Self::EmptyOutputs { height, tx_index } => {
                write!(f, "block {} tx {} has no outputs", height, tx_index)
            }
            Self::DuplicateTx { height, txid } => {
                write!(f, "block {} has duplicate txid {}", height, txid)
            }
            Self::CoinbaseOverpayment {
                height,
                actual,
                max_subsidy,
            } => write!(
                f,
                "block {} coinbase {} sats exceeds allowed {} sats",
                height, actual, max_subsidy
            ),
            Self::BadCoinbaseHeight { height, encoded } => write!(
                f,
                "block {} coinbase encodes height {} (expected {})",
                height, encoded, height
            ),
            Self::BadWitnessCommitment { height } => {
                write!(f, "block {} has invalid witness commitment", height)
            }
            Self::MissingUtxo {
                height,
                tx_index,
                input_index,
            } => write!(
                f,
                "block {} tx {} input {} references missing UTXO",
                height, tx_index, input_index
            ),
            Self::PrematureCoinbaseSpend {
                height,
                tx_index,
                input_index,
                coinbase_height,
            } => write!(
                f,
                "block {} tx {} input {} spends immature coinbase from block {}",
                height, tx_index, input_index, coinbase_height
            ),
            Self::ScriptFailure {
                height,
                tx_index,
                input_index,
                error,
            } => write!(
                f,
                "block {} tx {} input {} script verification failed: {}",
                height, tx_index, input_index, error
            ),
            Self::InsufficientInputValue {
                height,
                tx_index,
                input_total,
                output_total,
            } => write!(
                f,
                "block {} tx {} inputs {} sats < outputs {} sats",
                height, tx_index, input_total, output_total
            ),
            Self::ValueOverflow { height, tx_index } => {
                write!(f, "block {} tx {} value overflow", height, tx_index)
            }
            Self::UtxoError { height, msg } => {
                write!(f, "block {} UTXO error: {}", height, msg)
            }
            Self::OutputExceedsMaxMoney {
                height,
                tx_index,
                output_index,
                amount,
            } => write!(
                f,
                "block {} tx {} output {} amount {} sats exceeds MAX_MONEY",
                height, tx_index, output_index, amount
            ),
            Self::DuplicateSpend {
                height,
                tx_index,
                input_index,
            } => write!(
                f,
                "block {} tx {} input {} double-spends a UTXO already consumed in this block",
                height, tx_index, input_index
            ),
            Self::ExcessiveSigops {
                height,
                sigops,
                max,
            } => write!(
                f,
                "block {} has {} legacy sigops, exceeds max {}",
                height, sigops, max
            ),
        }
    }
}

impl std::error::Error for BlockValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subsidy_at_genesis() {
        assert_eq!(block_subsidy(0).to_sat(), 50 * 100_000_000);
    }

    #[test]
    fn subsidy_first_halving() {
        assert_eq!(block_subsidy(210_000).to_sat(), 25 * 100_000_000);
    }

    #[test]
    fn subsidy_second_halving() {
        assert_eq!(block_subsidy(420_000).to_sat(), 1_250_000_000);
    }

    #[test]
    fn subsidy_current_era() {
        // After 4th halving (height 840,000): 3.125 BTC = 312,500,000 sats
        assert_eq!(block_subsidy(840_000).to_sat(), 312_500_000);
    }

    #[test]
    fn subsidy_eventually_zero() {
        // After 64 halvings, subsidy is 0
        assert_eq!(block_subsidy(210_000 * 64).to_sat(), 0);
    }

    #[test]
    fn subsidy_just_before_halving() {
        // Block 209,999 is still first era
        assert_eq!(block_subsidy(209_999).to_sat(), 50 * 100_000_000);
    }

    #[test]
    fn sigops_counts_checksig() {
        use bitcoin::script::Builder;
        use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};

        let script = Builder::new()
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        assert_eq!(count_script_sigops(&script), 3);
    }

    #[test]
    fn sigops_counts_checkmultisig_as_20() {
        use bitcoin::script::Builder;
        use bitcoin::opcodes::all::OP_CHECKMULTISIG;

        let script = Builder::new()
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(count_script_sigops(&script), 20);
    }

    #[test]
    fn sigops_empty_script_is_zero() {
        use bitcoin::script::Builder;
        let script = Builder::new().into_script();
        assert_eq!(count_script_sigops(&script), 0);
    }

    #[test]
    fn sigops_pushdata_not_counted() {
        use bitcoin::script::Builder;

        // A script with only push bytes should have 0 sigops
        let script = Builder::new()
            .push_slice(&[0x01, 0x02, 0x03])
            .into_script();
        assert_eq!(count_script_sigops(&script), 0);
    }

    // ── Real-mainnet taproot validation ─────────────────────────────
    //
    // Fixture: the historic first key-path P2TR spend on Bitcoin mainnet.
    //
    //   txid:   33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036
    //   block:  709635 (first block after taproot activation at 709632)
    //   memo:   "I like Schnorr sigs and I cannot lie. @bitbug42"
    //
    // The tx has a single P2TR input spending UTXO
    // 5849051cf3ce36257a1d844e28959f368a35adc9520fb9679175f6cdf8c1f1d1:1,
    // worth 88,480 sats with scriptPubKey
    // 5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0
    // (OP_PUSHNUM_1 OP_PUSHBYTES_32 <x-only pubkey>).
    //
    // The full witness is a single 64-byte Schnorr signature over the
    // BIP 341 sighash. Validating this exercises the libbitcoinconsensus
    // 0.106.0+26.0 spent_outputs path and the VERIFY_TAPROOT flag — both
    // of which were unavailable in the 0.105.0+25.1 version we used to
    // ship and would have caused this test to fail to compile or run.

    /// Hex of the spending transaction (BIP141 serialization, with witnesses).
    const TAPROOT_FIXTURE_TX_HEX: &str = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00";
    /// scriptPubKey of the prevout being spent (P2TR: OP_1 <32-byte x-only pk>).
    const TAPROOT_FIXTURE_PREV_SPK_HEX: &str =
        "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0";
    /// Value of the prevout being spent, in satoshis.
    const TAPROOT_FIXTURE_PREV_VALUE: u64 = 88_480;
    /// Block height containing the spending tx (must satisfy `> 709632` so
    /// that `bitcoinconsensus::height_to_flags` enables VERIFY_TAPROOT).
    const TAPROOT_FIXTURE_HEIGHT: u32 = 709_635;

    /// Build the (serialized_tx, prev_spk, prev_amount, flags) tuple shared by
    /// the positive and negative taproot tests so they can't drift apart.
    fn taproot_fixture() -> (Vec<u8>, Vec<u8>, u64, u32) {
        let tx_bytes = hex::decode(TAPROOT_FIXTURE_TX_HEX).expect("fixture tx hex parses");
        let prev_spk =
            hex::decode(TAPROOT_FIXTURE_PREV_SPK_HEX).expect("fixture prev spk hex parses");
        let flags = bitcoinconsensus::height_to_flags(TAPROOT_FIXTURE_HEIGHT);
        (tx_bytes, prev_spk, TAPROOT_FIXTURE_PREV_VALUE, flags)
    }

    #[test]
    fn taproot_activation_flag_is_set_post_709632() {
        // Sanity-check the precondition that the rest of the taproot tests
        // implicitly rely on: at the fixture block height, libbitcoinconsensus
        // returns flags that include VERIFY_TAPROOT. If this ever changes
        // upstream, the script-validation tests below would silently start
        // covering only pre-taproot rules and miss the whole point.
        let flags = bitcoinconsensus::height_to_flags(TAPROOT_FIXTURE_HEIGHT);
        assert!(
            flags & bitcoinconsensus::VERIFY_TAPROOT != 0,
            "expected VERIFY_TAPROOT in flags for height {}, got {:#x}",
            TAPROOT_FIXTURE_HEIGHT,
            flags
        );
    }

    #[test]
    fn verifies_real_mainnet_taproot_keypath_spend() {
        let (tx_bytes, prev_spk, prev_value, flags) = taproot_fixture();

        // Build the spent_outputs slice that BIP 341 sighash needs. For a
        // single-input tx this is one entry, but the FFI takes a slice so
        // we still allocate a Vec to keep the script_pubkey buffer rooted.
        let utxos = vec![bitcoinconsensus::Utxo {
            script_pubkey: prev_spk.as_ptr(),
            script_pubkey_len: prev_spk.len() as u32,
            value: prev_value as i64,
        }];

        let result = bitcoinconsensus::verify_with_flags(
            &prev_spk,
            prev_value,
            &tx_bytes,
            Some(&utxos),
            0,
            flags,
        );

        assert!(
            result.is_ok(),
            "real mainnet taproot key-path spend should validate, got {:?}",
            result
        );
    }

    #[test]
    fn rejects_taproot_spend_with_corrupted_witness_signature() {
        use bitcoin::consensus::deserialize;

        let (tx_bytes, prev_spk, prev_value, flags) = taproot_fixture();

        // Round-trip through the bitcoin crate so we can mutate the witness
        // safely without hand-editing serialized bytes (and so we exercise
        // the same deserialize path block validation uses).
        let mut tx: bitcoin::Transaction =
            deserialize(&tx_bytes).expect("fixture tx deserializes");
        assert_eq!(tx.input.len(), 1);

        // Flip the high bit of the first signature byte. The witness for
        // a key-path P2TR spend is a single 64-byte Schnorr signature; any
        // single-bit perturbation invalidates it under BIP 340.
        let witness_stack: Vec<Vec<u8>> = tx.input[0].witness.to_vec();
        assert_eq!(
            witness_stack.len(),
            1,
            "key-path spend should have a 1-element witness stack"
        );
        let mut sig = witness_stack[0].clone();
        assert_eq!(sig.len(), 64, "Schnorr signature should be 64 bytes");
        sig[0] ^= 0x80;
        tx.input[0].witness = bitcoin::Witness::from_slice(&[sig]);

        let mutated_tx_bytes = serialize(&tx);
        let utxos = vec![bitcoinconsensus::Utxo {
            script_pubkey: prev_spk.as_ptr(),
            script_pubkey_len: prev_spk.len() as u32,
            value: prev_value as i64,
        }];

        let result = bitcoinconsensus::verify_with_flags(
            &prev_spk,
            prev_value,
            &mutated_tx_bytes,
            Some(&utxos),
            0,
            flags,
        );

        assert!(
            result.is_err(),
            "corrupted Schnorr signature must fail BIP 340 verification, got Ok"
        );
    }
}
