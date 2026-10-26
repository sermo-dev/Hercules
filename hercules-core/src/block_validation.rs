use std::collections::{HashMap, HashSet};

use bitcoin::block::Block;
use bitcoin::consensus::serialize;
use bitcoin::{Amount, Txid};

use crate::chain_params::ChainParams;
use crate::contextual_checks::{
    calculate_sequence_locks, coinbase_commits_height, coinbase_script_len_ok,
    evaluate_sequence_locks, is_final_tx, legacy_sigop_count, transaction_sigop_cost,
    HeaderTimes, MedianTimes, MAX_BLOCK_SIGOPS_COST, WITNESS_SCALE_FACTOR,
};
use crate::utxo::UtxoSet;

/// Maximum block weight (BIP-141 consensus rule).
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Initial block subsidy in satoshis (50 BTC).
const INITIAL_SUBSIDY: u64 = 50 * 100_000_000;

/// Maximum value of a single output (21 million BTC in satoshis).
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Validate the structural properties of a full block: Core's
/// `CheckBlock` plus the parts of `ContextualCheckBlock` that need only the
/// height (BIP 34, witness commitment).
/// This does NOT validate scripts or UTXO spends (Phase 2b/2c), nor the
/// rules that need median-time-past (finality); those are in
/// `validate_block_scripts`.
/// BIP-34 and SegWit activation heights come from `params`.
pub fn validate_block(
    block: &Block,
    height: u32,
    params: &ChainParams,
) -> Result<(), BlockValidationError> {
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
        }

        // Coinbase scriptSig must be 2..=100 bytes (CheckTransaction,
        // `bad-cb-length`).
        if i == 0 && !coinbase_script_len_ok(tx) {
            return Err(BlockValidationError::BadCoinbaseLength {
                height,
                len: tx.input[0].script_sig.len(),
            });
        }

        // Legacy sigops in every scriptSig and scriptPubKey, coinbase
        // included (GetLegacySigOpCount).
        block_sigops += legacy_sigop_count(tx);
    }

    // Block-level legacy sigops check (Core's CheckBlock). The full cost,
    // with P2SH and witness sigops, needs the spent outputs and is checked
    // in `validate_block_scripts`.
    if block_sigops * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST {
        return Err(BlockValidationError::ExcessiveSigops {
            height,
            sigops: block_sigops,
            max: MAX_BLOCK_SIGOPS_COST / WITNESS_SCALE_FACTOR,
        });
    }

    // 7. No duplicate txids within the block. This is not BIP 30, which is
    // about txids already in the UTXO set (see `BIP34_IMPLIES_BIP30_LIMIT`
    // in contextual_checks); Core rejects in-block duplicates through its
    // merkle-mutation check (CVE-2012-2459).
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

    // 9. BIP-34: coinbase scriptSig must start with `CScript() << height`
    // after activation (ContextualCheckBlock, `bad-cb-height`). A byte
    // prefix comparison as in Core, so heights 1..=16 are `OP_1..OP_16`.
    // The block-version half of BIP 34 is a header rule (validate_headers).
    if height >= params.bip34_height && !coinbase_commits_height(&block.txdata[0], height) {
        return Err(BlockValidationError::BadCoinbaseHeight {
            height,
            // For the message only; 0 if the first push isn't a number.
            encoded: block.bip34_block_height().unwrap_or(0),
        });
    }

    // 10. Witness data must match the witness commitment, exactly as
    // Core's `CheckWitnessMalleation`. Not rust-bitcoin's
    // `Block::check_witness_commitment`: that returns true early whenever
    // no transaction has witness data, so it accepts a commitment with an
    // empty coinbase witness (Core: `bad-witness-nonce-size`), and it never
    // looks at witnesses before SegWit activation (Core:
    // `unexpected-witness`). `check_block_mutation` runs the same check
    // first on the sync paths; it is repeated here so `validate_block`
    // alone is never more lenient than Core.
    check_witness_malleation(block, height, params)?;

    Ok(())
}

/// Witness commitment output prefix: OP_RETURN, push 36, 0xaa21a9ed (BIP 141).
const WITNESS_COMMITMENT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Bitcoin Core's `IsBlockMutated`: does this block's transaction data fail
/// to match what its header commits to? The block hash covers only the
/// 80-byte header, so a peer can strip witnesses, pad them, or duplicate
/// transactions (CVE-2012-2459) and the hash still matches. Such a block
/// says nothing about the real one, so callers must treat a failure here as
/// a bad *delivery* (penalize the peer, fetch it elsewhere), never as proof
/// the block is invalid (ticket 024). Run it before `validate_block` and
/// script validation: a stripped witness would otherwise surface there as a
/// script failure, indistinguishable from a consensus-invalid block.
///
/// Checks the merkle root (including Core's duplicate-subtree mutation) and
/// Core's `CheckWitnessMalleation`: once SegWit is active, a coinbase
/// witness commitment, if present, must match the witness data (with a
/// single 32-byte reserved value); without one, no transaction may carry
/// witness data. Before activation no witness data is allowed at all.
pub fn check_block_mutation(
    block: &Block,
    height: u32,
    params: &ChainParams,
) -> Result<(), BlockValidationError> {
    if block.txdata.is_empty() {
        return Err(BlockValidationError::EmptyBlock { height });
    }
    if !block.check_merkle_root() {
        return Err(BlockValidationError::BadMerkleRoot { height });
    }
    if merkle_tree_mutated(block) {
        return Err(BlockValidationError::MutatedMerkleTree { height });
    }
    let coinbase = &block.txdata[0];
    if !coinbase.is_coinbase() {
        // Invalid either way, but Core counts a block like this as mutated
        // when a 64-byte transaction lets an attacker forge a merkle branch
        // (CVE-2017-12842). Treating every no-coinbase copy as a bad
        // delivery is safe and never condemns a block hash.
        return Err(BlockValidationError::NoCoinbase { height });
    }

    check_witness_malleation(block, height, params)
}

/// Core's `CheckWitnessMalleation` (with `GetWitnessCommitmentIndex`).
/// Once SegWit is active, if the coinbase has a witness commitment output
/// (the last one carrying the magic), the coinbase witness must be exactly
/// one 32-byte item (the reserved value) and the commitment must equal
/// `SHA256d(witness merkle root || reserved value)`. With no commitment, or
/// before activation, no transaction (the coinbase included) may carry
/// witness data. Core returns `BLOCK_MUTATED` for every failure here, and
/// so do we (`is_mutation`): witnesses aren't covered by the block hash, so
/// a relaying peer can produce any of these failures from a valid block.
///
/// Requires a non-empty block whose first transaction is a coinbase.
fn check_witness_malleation(
    block: &Block,
    height: u32,
    params: &ChainParams,
) -> Result<(), BlockValidationError> {
    let coinbase = &block.txdata[0];
    if height >= params.segwit_height {
        let commitment = coinbase.output.iter().rposition(|o| {
            o.script_pubkey.len() >= 38
                && o.script_pubkey.as_bytes()[..6] == WITNESS_COMMITMENT_MAGIC
        });
        if let Some(pos) = commitment {
            use bitcoin::hashes::Hash as _;
            // `bad-witness-nonce-size`
            let reserved: Vec<&[u8]> = coinbase.input[0].witness.iter().collect();
            if reserved.len() != 1 || reserved[0].len() != 32 {
                return Err(BlockValidationError::BadWitnessCommitment { height });
            }
            // `bad-witness-merkle-match`
            let committed = &coinbase.output[pos].script_pubkey.as_bytes()[6..38];
            let matches = block.witness_root().is_some_and(|root| {
                let computed = Block::compute_witness_commitment(&root, reserved[0]);
                computed.as_byte_array()[..] == *committed
            });
            if !matches {
                return Err(BlockValidationError::BadWitnessCommitment { height });
            }
            return Ok(());
        }
    }

    // `unexpected-witness`
    if block
        .txdata
        .iter()
        .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()))
    {
        return Err(BlockValidationError::UnexpectedWitness { height });
    }
    Ok(())
}

/// Core's `ComputeMerkleRoot` mutation flag: two identical adjacent hashes
/// at any level of the tree. Duplicating the last transaction(s) of a block
/// this way (CVE-2012-2459) leaves the merkle root unchanged.
fn merkle_tree_mutated(block: &Block) -> bool {
    use bitcoin::hashes::{sha256d, Hash};
    let mut level: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();
    while level.len() > 1 {
        if level.chunks_exact(2).any(|pair| pair[0] == pair[1]) {
            return true;
        }
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                sha256d::Hash::hash(&buf).to_byte_array()
            })
            .collect();
    }
    false
}

/// Map a script-verifier error to a `BlockValidationError`: the single seam
/// where ticket 024 decides what the verifier's errors mean. Only a script
/// that evaluated to false (`ERR_SCRIPT`) is a consensus failure; anything
/// else (deserialize, size mismatch, missing amount or spent outputs,
/// unsupported flags) is our own bug or API misuse and must never mark a
/// block invalid. A replacement verifier (ticket 047) only needs to adapt
/// this function.
fn script_error(
    height: u32,
    tx_index: usize,
    input_index: usize,
    e: bitcoinconsensus::Error,
) -> BlockValidationError {
    match e {
        bitcoinconsensus::Error::ERR_SCRIPT => BlockValidationError::ScriptFailure {
            height,
            tx_index,
            input_index,
            error: format!("{}", e),
        },
        other => BlockValidationError::ScriptVerifierError {
            height,
            tx_index,
            input_index,
            error: format!("{}", other),
        },
    }
}

/// Coinbase outputs cannot be spent until this many blocks have passed.
const COINBASE_MATURITY: u32 = 100;

/// Calculate the block subsidy at a given height.
pub fn block_subsidy(height: u32, params: &ChainParams) -> Amount {
    let halvings = height / params.subsidy_halving_interval;
    if halvings >= 64 {
        return Amount::ZERO;
    }
    Amount::from_sat(INITIAL_SUBSIDY >> halvings)
}

/// Validate transaction scripts and input/output values against the UTXO set.
/// This verifies that every spend is authorized (valid script) and that no
/// value is created from nothing (inputs >= outputs for each tx).
///
/// It also enforces the contextual rules that need the chain's
/// median-time-past or the spent coins (ticket 026): nLockTime finality
/// with BIP 113, BIP 68 sequence locks, and the full sigop cost.
///
/// `times` must give header timestamps of the chain this block extends, at
/// least for heights `0..height` (the header store does).
///
/// Call this AFTER `validate_block()` succeeds. After this returns Ok,
/// call `utxo_set.apply_block()` to update the UTXO set.
pub fn validate_block_scripts(
    block: &Block,
    height: u32,
    utxo_set: &UtxoSet,
    params: &ChainParams,
    times: &dyn HeaderTimes,
) -> Result<(), BlockValidationError> {
    let flags = params.script_flags(height);
    let mut mtp = MedianTimes::new(times);
    let context_err = |msg: String| BlockValidationError::MissingContext { height, msg };

    // BIP 113 and BIP 68 both switch on with the CSV deployment, and both
    // measure time by the parent block's median-time-past. Before CSV the
    // nLockTime cutoff is the block's own timestamp, and BIP 68 is off.
    let csv_active = height >= params.csv_height;
    let prev_mtp: i64 = if csv_active && height > 0 {
        mtp.at(height - 1).map_err(context_err)?
    } else {
        block.header.time as i64
    };

    // Finality of every transaction, coinbase included
    // (ContextualCheckBlock, `bad-txns-nonfinal`).
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if !is_final_tx(tx, height, prev_mtp) {
            return Err(BlockValidationError::NonFinalTx {
                height,
                tx_index: tx_idx,
                lock_time: tx.lock_time.to_consensus_u32(),
            });
        }
    }

    // Track outputs created within this block for in-block spend resolution.
    // Maps (txid, vout) -> (amount, script_pubkey_bytes, is_coinbase).
    let mut block_utxos: HashMap<(Txid, u32), (u64, Vec<u8>, bool)> = HashMap::new();
    // Track persistent UTXOs already spent in this block (double-spend detection).
    let mut spent_persistent: HashSet<(Txid, u32)> = HashSet::new();
    let mut total_fees: u64 = 0;
    // Running sigop cost (ConnectBlock, `bad-blk-sigops`).
    let mut sigop_cost: u64 = 0;

    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx.is_coinbase() {
            // A coinbase's cost is its legacy sigops.
            sigop_cost += transaction_sigop_cost(tx, &[], flags);
            if sigop_cost > MAX_BLOCK_SIGOPS_COST {
                return Err(BlockValidationError::ExcessiveSigopCost {
                    height,
                    cost: sigop_cost,
                    max: MAX_BLOCK_SIGOPS_COST,
                });
            }
        } else {
            let serialized_tx = serialize(tx);
            let mut input_sum: u64 = 0;
            // Height of the block that created each spent coin, for BIP 68.
            let mut prev_heights: Vec<u32> = Vec::with_capacity(tx.input.len());

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

                let (amount, script_pubkey, coin_height) =
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
                        // Created in this block: its height is ours.
                        (entry.0, entry.1, height)
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

                        (utxo.amount, utxo.script_pubkey, utxo.height)
                    };

                input_sum = input_sum
                    .checked_add(amount)
                    .ok_or(BlockValidationError::ValueOverflow {
                        height,
                        tx_index: tx_idx,
                    })?;
                spent.push((amount, script_pubkey));
                prev_heights.push(coin_height);
            }

            // BIP 68 relative lock-times (ConnectBlock → SequenceLocks,
            // `bad-txns-nonfinal`). Needs the spent coins' heights, so it
            // runs here rather than with the finality check above.
            let lock = calculate_sequence_locks(tx, csv_active, &prev_heights, &mut mtp)
                .map_err(context_err)?;
            if !evaluate_sequence_locks(height, prev_mtp, lock) {
                return Err(BlockValidationError::SequenceLockNotMet {
                    height,
                    tx_index: tx_idx,
                    min_height: lock.min_height,
                    min_time: lock.min_time,
                });
            }

            // Full sigop cost: legacy + P2SH + witness, checked before any
            // script runs, as in ConnectBlock (GetTransactionSigOpCost).
            let spent_spks: Vec<&[u8]> = spent.iter().map(|(_, spk)| spk.as_slice()).collect();
            sigop_cost += transaction_sigop_cost(tx, &spent_spks, flags);
            if sigop_cost > MAX_BLOCK_SIGOPS_COST {
                return Err(BlockValidationError::ExcessiveSigopCost {
                    height,
                    cost: sigop_cost,
                    max: MAX_BLOCK_SIGOPS_COST,
                });
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
                .map_err(|e| script_error(height, tx_idx, input_idx, e))?;
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
    let subsidy = block_subsidy(height, params);
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
    /// Duplicate adjacent subtree in the merkle tree (CVE-2012-2459).
    MutatedMerkleTree {
        height: u32,
    },
    /// Witness data in a block that does not commit to it.
    UnexpectedWitness {
        height: u32,
    },
    /// The script verifier itself failed (not a script evaluating to
    /// false): a local fault, see `script_error`.
    ScriptVerifierError {
        height: u32,
        tx_index: usize,
        input_index: usize,
        error: String,
    },
    // Ticket 026: contextual rules
    /// Coinbase scriptSig outside 2..=100 bytes (`bad-cb-length`).
    BadCoinbaseLength {
        height: u32,
        len: usize,
    },
    /// nLockTime not yet reached (`bad-txns-nonfinal`, IsFinalTx).
    NonFinalTx {
        height: u32,
        tx_index: usize,
        lock_time: u32,
    },
    /// BIP 68 relative lock not yet reached (`bad-txns-nonfinal`,
    /// SequenceLocks). `min_height`/`min_time` are the last invalid
    /// height/MTP, -1 if unconstrained.
    SequenceLockNotMet {
        height: u32,
        tx_index: usize,
        min_height: i64,
        min_time: i64,
    },
    /// Legacy + P2SH + witness sigop cost over the limit (`bad-blk-sigops`).
    ExcessiveSigopCost {
        height: u32,
        cost: u64,
        max: u64,
    },
    /// A header timestamp needed for median-time-past was unavailable.
    /// A local problem, not a verdict on the block.
    MissingContext {
        height: u32,
        msg: String,
    },
}

impl BlockValidationError {
    /// True when the error shows only that *this copy* of the block is not
    /// what its header commits to (a mutated or corrupted delivery), not
    /// that the block itself is invalid. The sync loop penalizes the peer
    /// and fetches the block elsewhere for these, and marks the block
    /// permanently failed for everything else (ticket 024). Deliberately an
    /// exhaustive match: a new variant must be classified here.
    pub fn is_mutation(&self) -> bool {
        match self {
            Self::EmptyBlock { .. }
            | Self::NoCoinbase { .. }
            | Self::BadMerkleRoot { .. }
            | Self::MutatedMerkleTree { .. }
            | Self::BadWitnessCommitment { .. }
            | Self::UnexpectedWitness { .. } => true,
            Self::MultipleCoinbase { .. }
            | Self::ExcessiveWeight { .. }
            | Self::EmptyInputs { .. }
            | Self::EmptyOutputs { .. }
            | Self::DuplicateTx { .. }
            | Self::CoinbaseOverpayment { .. }
            | Self::BadCoinbaseHeight { .. }
            | Self::MissingUtxo { .. }
            | Self::PrematureCoinbaseSpend { .. }
            | Self::ScriptFailure { .. }
            | Self::InsufficientInputValue { .. }
            | Self::ValueOverflow { .. }
            | Self::UtxoError { .. }
            | Self::OutputExceedsMaxMoney { .. }
            | Self::DuplicateSpend { .. }
            | Self::ExcessiveSigops { .. }
            | Self::ScriptVerifierError { .. }
            | Self::BadCoinbaseLength { .. }
            | Self::NonFinalTx { .. }
            | Self::SequenceLockNotMet { .. }
            | Self::ExcessiveSigopCost { .. }
            | Self::MissingContext { .. } => false,
        }
    }

    /// True only when the block itself breaks a consensus rule, so it may
    /// be recorded as permanently invalid (ticket 024). False for
    /// mutations (`is_mutation`) and for local faults: the UTXO store or
    /// the script verifier failing. Exhaustive for the same reason.
    pub fn is_consensus_failure(&self) -> bool {
        match self {
            // Local faults. `MissingContext` means *we* lack the header
            // timestamps for median-time-past; condemning the block for it
            // would mark a valid block invalid and ban honest peers.
            Self::UtxoError { .. }
            | Self::ScriptVerifierError { .. }
            | Self::MissingContext { .. } => false,
            e if e.is_mutation() => false,
            Self::EmptyBlock { .. }
            | Self::NoCoinbase { .. }
            | Self::BadMerkleRoot { .. }
            | Self::MutatedMerkleTree { .. }
            | Self::BadWitnessCommitment { .. }
            | Self::UnexpectedWitness { .. }
            | Self::MultipleCoinbase { .. }
            | Self::ExcessiveWeight { .. }
            | Self::EmptyInputs { .. }
            | Self::EmptyOutputs { .. }
            | Self::DuplicateTx { .. }
            | Self::CoinbaseOverpayment { .. }
            | Self::BadCoinbaseHeight { .. }
            | Self::MissingUtxo { .. }
            | Self::PrematureCoinbaseSpend { .. }
            | Self::ScriptFailure { .. }
            | Self::InsufficientInputValue { .. }
            | Self::ValueOverflow { .. }
            | Self::OutputExceedsMaxMoney { .. }
            | Self::DuplicateSpend { .. }
            | Self::ExcessiveSigops { .. }
            // Ticket 026 rules. Each one judges data the header commits
            // to (the coinbase scriptSig, nLockTime and nSequence are in
            // the txid; witnesses, which feed the sigop cost, are bound by
            // the commitment `check_block_mutation` verified first), against
            // context taken from our own header chain and UTXO set, which
            // `HeaderSync::check_block` confirms are at this block's parent.
            | Self::BadCoinbaseLength { .. }
            | Self::NonFinalTx { .. }
            | Self::SequenceLockNotMet { .. }
            | Self::ExcessiveSigopCost { .. } => true,
        }
    }
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
            Self::MutatedMerkleTree { height } => {
                write!(f, "block {} has a mutated (duplicated) merkle tree", height)
            }
            Self::UnexpectedWitness { height } => {
                write!(f, "block {} has witness data without a witness commitment", height)
            }
            Self::ScriptVerifierError {
                height,
                tx_index,
                input_index,
                error,
            } => write!(
                f,
                "block {} tx {} input {} script verifier error: {}",
                height, tx_index, input_index, error
            ),
            Self::BadCoinbaseLength { height, len } => write!(
                f,
                "block {} coinbase scriptSig is {} bytes (must be 2..=100)",
                height, len
            ),
            Self::NonFinalTx {
                height,
                tx_index,
                lock_time,
            } => write!(
                f,
                "block {} tx {} is not final (nLockTime {})",
                height, tx_index, lock_time
            ),
            Self::SequenceLockNotMet {
                height,
                tx_index,
                min_height,
                min_time,
            } => write!(
                f,
                "block {} tx {} violates BIP 68 relative lock (min height {}, min time {})",
                height, tx_index, min_height, min_time
            ),
            Self::ExcessiveSigopCost { height, cost, max } => write!(
                f,
                "block {} sigop cost {} exceeds max {}",
                height, cost, max
            ),
            Self::MissingContext { height, msg } => write!(
                f,
                "block {} cannot be validated: header context unavailable: {}",
                height, msg
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
        assert_eq!(block_subsidy(0, ChainParams::mainnet()).to_sat(), 50 * 100_000_000);
    }

    #[test]
    fn subsidy_first_halving() {
        assert_eq!(block_subsidy(210_000, ChainParams::mainnet()).to_sat(), 25 * 100_000_000);
    }

    #[test]
    fn subsidy_second_halving() {
        assert_eq!(block_subsidy(420_000, ChainParams::mainnet()).to_sat(), 1_250_000_000);
    }

    #[test]
    fn subsidy_current_era() {
        // After 4th halving (height 840,000): 3.125 BTC = 312,500,000 sats
        assert_eq!(block_subsidy(840_000, ChainParams::mainnet()).to_sat(), 312_500_000);
    }

    #[test]
    fn subsidy_eventually_zero() {
        // After 64 halvings, subsidy is 0
        assert_eq!(block_subsidy(210_000 * 64, ChainParams::mainnet()).to_sat(), 0);
    }

    #[test]
    fn subsidy_just_before_halving() {
        // Block 209,999 is still first era
        assert_eq!(block_subsidy(209_999, ChainParams::mainnet()).to_sat(), 50 * 100_000_000);
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
        assert_eq!(crate::contextual_checks::script_sigop_count(script.as_bytes(), false), 3);
    }

    #[test]
    fn sigops_counts_checkmultisig_as_20() {
        use bitcoin::script::Builder;
        use bitcoin::opcodes::all::OP_CHECKMULTISIG;

        let script = Builder::new()
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(crate::contextual_checks::script_sigop_count(script.as_bytes(), false), 20);
    }

    /// Ticket 024: only a script evaluating to false is a consensus
    /// failure; every other verifier error (and UTXO store errors) is local.
    #[test]
    fn only_script_failures_are_consensus_failures() {
        use bitcoinconsensus::Error::*;
        let e = script_error(5, 1, 0, ERR_SCRIPT);
        assert!(matches!(e, BlockValidationError::ScriptFailure { .. }));
        assert!(e.is_consensus_failure() && !e.is_mutation());
        for other in [
            ERR_TX_INDEX,
            ERR_TX_SIZE_MISMATCH,
            ERR_TX_DESERIALIZE,
            ERR_AMOUNT_REQUIRED,
            ERR_INVALID_FLAGS,
            ERR_SPENT_OUTPUTS_REQUIRED,
            ERR_SPENT_OUTPUTS_MISMATCH,
        ] {
            let e = script_error(5, 1, 0, other);
            assert!(matches!(e, BlockValidationError::ScriptVerifierError { .. }), "{:?}", e);
            assert!(!e.is_consensus_failure() && !e.is_mutation(), "{:?}", e);
        }
        let utxo = BlockValidationError::UtxoError { height: 5, msg: "disk".into() };
        assert!(!utxo.is_consensus_failure() && !utxo.is_mutation());
    }

    #[test]
    fn sigops_empty_script_is_zero() {
        use bitcoin::script::Builder;
        let script = Builder::new().into_script();
        assert_eq!(crate::contextual_checks::script_sigop_count(script.as_bytes(), false), 0);
    }

    #[test]
    fn sigops_pushdata_not_counted() {
        use bitcoin::script::Builder;

        // A script with only push bytes should have 0 sigops
        let script = Builder::new()
            .push_slice(&[0x01, 0x02, 0x03])
            .into_script();
        assert_eq!(crate::contextual_checks::script_sigop_count(script.as_bytes(), false), 0);
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
    /// that the mainnet script-flag table enables VERIFY_TAPROOT).
    const TAPROOT_FIXTURE_HEIGHT: u32 = 709_635;

    /// Build the (serialized_tx, prev_spk, prev_amount, flags) tuple shared by
    /// the positive and negative taproot tests so they can't drift apart.
    fn taproot_fixture() -> (Vec<u8>, Vec<u8>, u64, u32) {
        let tx_bytes = hex::decode(TAPROOT_FIXTURE_TX_HEX).expect("fixture tx hex parses");
        let prev_spk =
            hex::decode(TAPROOT_FIXTURE_PREV_SPK_HEX).expect("fixture prev spk hex parses");
        let flags = ChainParams::mainnet().script_flags(TAPROOT_FIXTURE_HEIGHT);
        (tx_bytes, prev_spk, TAPROOT_FIXTURE_PREV_VALUE, flags)
    }

    #[test]
    fn taproot_activation_flag_is_set_post_709632() {
        // Sanity-check the precondition that the rest of the taproot tests
        // implicitly rely on: at the fixture block height, the mainnet
        // script-flag table includes VERIFY_TAPROOT. If this ever changes,
        // the script-validation tests below would silently start covering
        // only pre-taproot rules and miss the whole point.
        let flags = ChainParams::mainnet().script_flags(TAPROOT_FIXTURE_HEIGHT);
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

    // ── Structural validation: synthetic block builders ──────────────
    //
    // The structural rules in `validate_block` are independently checked
    // in the tests below. We build minimal blocks from scratch (rather
    // than mutating the genesis fixture) so each test can target one
    // failure mode without dragging in BIP-34 / SegWit / merkle-root
    // interactions from a real block.
    //
    // All synthetic blocks here use `height = 1` so they sit in the
    // pre-BIP-34 / pre-SegWit window — we want to test rules 1-7 in
    // isolation, not the witness-commitment / coinbase-height paths.

    /// Build a coinbase transaction with the given output value (in sats).
    fn synth_coinbase(value_sats: u64) -> bitcoin::Transaction {
        use bitcoin::blockdata::transaction::{OutPoint, Sequence, TxIn, TxOut, Version};
        use bitcoin::{absolute::LockTime, Amount, ScriptBuf, Witness};
        bitcoin::Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                // Coinbase: previous_output is the null outpoint.
                previous_output: OutPoint::null(),
                // Pre-BIP-34 we can put anything in script_sig, as long as
                // it is 2..=100 bytes (`bad-cb-length`).
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x00]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value_sats),
                script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
            }],
        }
    }

    /// Build a non-coinbase transaction (real-looking input pointing at a
    /// dummy outpoint). The validator's structural pass doesn't check that
    /// the input actually exists — that's `validate_block_scripts`.
    fn synth_noncoinbase(marker: u8) -> bitcoin::Transaction {
        use bitcoin::blockdata::transaction::{OutPoint, Sequence, TxIn, TxOut, Version};
        use bitcoin::hashes::Hash;
        use bitcoin::{absolute::LockTime, Amount, ScriptBuf, Txid, Witness};
        bitcoin::Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_slice(&[marker; 32]).unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0xac, marker]),
            }],
        }
    }

    /// Wrap a list of transactions into a Block whose merkle root is set
    /// to the *correct* value computed from the transactions. Tests that
    /// want a bad merkle root mutate the resulting block afterwards.
    fn wrap_block(txdata: Vec<bitcoin::Transaction>) -> Block {
        use bitcoin::blockdata::block::{Header, Version};
        use bitcoin::hashes::Hash;
        use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};

        // Compute the correct merkle root for the supplied txdata so the
        // BadMerkleRoot path isn't taken accidentally by tests targeting
        // a different rule.
        let merkle_root = bitcoin::merkle_tree::calculate_root(
            txdata.iter().map(|tx| tx.compute_txid().to_raw_hash()),
        )
        .map(|h| TxMerkleNode::from_raw_hash(h))
        .unwrap_or(TxMerkleNode::all_zeros());

        Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root,
                time: 0,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata,
        }
    }

    #[test]
    fn rejects_empty_block() {
        let block = wrap_block(vec![]);
        let err = validate_block(&block, 1, ChainParams::mainnet()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::EmptyBlock { height: 1 }),
            "expected EmptyBlock at height 1, got {:?}",
            err
        );
    }

    #[test]
    fn rejects_block_whose_first_tx_is_not_coinbase() {
        // A single non-coinbase tx — the very first tx must be a coinbase.
        let block = wrap_block(vec![synth_noncoinbase(1)]);
        let err = validate_block(&block, 1, ChainParams::mainnet()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::NoCoinbase { height: 1 }),
            "expected NoCoinbase at height 1, got {:?}",
            err
        );
    }

    #[test]
    fn rejects_block_with_two_coinbase_transactions() {
        // Two valid coinbases back-to-back. Bitcoin allows exactly one;
        // the second must be flagged at index 1.
        let block = wrap_block(vec![synth_coinbase(50), synth_coinbase(50)]);
        let err = validate_block(&block, 1, ChainParams::mainnet()).unwrap_err();
        match err {
            BlockValidationError::MultipleCoinbase { height, index } => {
                assert_eq!(height, 1);
                assert_eq!(index, 1, "second coinbase should be flagged at index 1");
            }
            other => panic!("expected MultipleCoinbase, got {:?}", other),
        }
    }

    #[test]
    fn rejects_block_with_bad_merkle_root() {
        // Build a valid one-tx block, then poison the header's merkle root.
        use bitcoin::hashes::Hash;
        let mut block = wrap_block(vec![synth_coinbase(50)]);
        block.header.merkle_root = bitcoin::TxMerkleNode::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xff; 32]),
        );
        let err = validate_block(&block, 1, ChainParams::mainnet()).unwrap_err();
        assert!(
            matches!(err, BlockValidationError::BadMerkleRoot { height: 1 }),
            "expected BadMerkleRoot at height 1, got {:?}",
            err
        );
    }

    #[test]
    fn rejects_block_with_duplicate_transactions() {
        // BIP-30 / structural rule: every txid in a block must be unique.
        // Two identical coinbases would trip the MultipleCoinbase rule
        // (rule 3) first, so we use a coinbase plus two identical
        // non-coinbase txs to target the DuplicateTx path (rule 7) directly.
        let dup = synth_noncoinbase(7);
        let block = wrap_block(vec![synth_coinbase(50), dup.clone(), dup]);
        let err = validate_block(&block, 1, ChainParams::mainnet()).unwrap_err();
        match err {
            BlockValidationError::DuplicateTx { height, txid: _ } => {
                assert_eq!(height, 1);
            }
            other => panic!("expected DuplicateTx, got {:?}", other),
        }
    }

    #[test]
    fn rejects_coinbase_overpayment_above_max_money() {
        // Structural rule 8 catches the trivial upper bound: a coinbase
        // whose total output exceeds 21M BTC must be rejected even before
        // we know the actual subsidy + fees.
        let huge = MAX_MONEY + 1;
        let block = wrap_block(vec![synth_coinbase(huge)]);
        let err = validate_block(&block, 1, ChainParams::mainnet()).unwrap_err();
        // The output_value > MAX_MONEY check (rule 6) catches this first
        // since it runs per-output before the coinbase-total check. Either
        // is a correct rejection of overpayment, but we assert which one
        // so future reorderings of the rules are caught explicitly.
        match err {
            BlockValidationError::OutputExceedsMaxMoney {
                height,
                tx_index,
                output_index,
                amount,
            } => {
                assert_eq!(height, 1);
                assert_eq!(tx_index, 0);
                assert_eq!(output_index, 0);
                assert_eq!(amount, huge);
            }
            other => panic!(
                "expected OutputExceedsMaxMoney for coinbase overpayment, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn rejects_block_exceeding_max_weight() {
        // Build a coinbase whose script_sig is enormous. Each script_sig
        // byte contributes 4 weight units (non-witness data is scaled by
        // WITNESS_SCALE_FACTOR=4), so >1MB of script_sig is enough to
        // blow past MAX_BLOCK_WEIGHT (4M WU) without needing real txs.
        use bitcoin::blockdata::transaction::{OutPoint, Sequence, TxIn, TxOut, Version};
        use bitcoin::{absolute::LockTime, Amount, ScriptBuf, Witness};
        let huge_script = vec![0x00u8; 1_100_000];
        let coinbase = bitcoin::Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(huge_script),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
            }],
        };
        let block = wrap_block(vec![coinbase]);
        let err = validate_block(&block, 1, ChainParams::mainnet()).unwrap_err();
        match err {
            BlockValidationError::ExcessiveWeight {
                height,
                weight,
                max,
            } => {
                assert_eq!(height, 1);
                assert_eq!(max, MAX_BLOCK_WEIGHT);
                assert!(
                    weight > MAX_BLOCK_WEIGHT,
                    "weight {} should exceed MAX_BLOCK_WEIGHT {}",
                    weight,
                    MAX_BLOCK_WEIGHT
                );
            }
            other => panic!("expected ExcessiveWeight, got {:?}", other),
        }
    }

    #[test]
    fn accepts_minimal_one_coinbase_block() {
        // Sanity check the synth helpers: a single-coinbase block at a
        // pre-BIP-34 height should pass structural validation cleanly.
        // This guards the helpers from silently regressing under the
        // negative tests above.
        let block = wrap_block(vec![synth_coinbase(50)]);
        validate_block(&block, 1, ChainParams::mainnet()).expect("minimal coinbase block should validate");
    }

    // ── Witness malleation (Core's CheckWitnessMalleation) ───────────

    /// SegWit active from genesis, BIP 34 never, so the synthetic blocks
    /// need no height in their coinbase.
    fn segwit_params() -> ChainParams {
        ChainParams {
            segwit_height: 0,
            bip34_height: u32::MAX,
            ..*ChainParams::mainnet()
        }
    }

    fn witness_of(items: &[&[u8]]) -> bitcoin::Witness {
        bitcoin::Witness::from_slice(items)
    }

    /// `txdata` with a commitment output appended to the coinbase,
    /// committing to `txdata`'s witness root and `reserved`. The coinbase
    /// witness is left as given, so tests can make it disagree.
    fn with_commitment(mut txdata: Vec<bitcoin::Transaction>, reserved: &[u8; 32]) -> Block {
        use bitcoin::hashes::Hash as _;
        let root = wrap_block(txdata.clone()).witness_root().unwrap();
        let commitment = Block::compute_witness_commitment(&root, reserved);
        let mut spk = WITNESS_COMMITMENT_MAGIC.to_vec();
        spk.extend_from_slice(commitment.as_byte_array());
        txdata[0].output.push(bitcoin::TxOut {
            value: Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(spk),
        });
        wrap_block(txdata)
    }

    /// Run both entry points: they must agree, and every failure must be a
    /// mutation (bad delivery, Core's `BLOCK_MUTATED`), never a consensus
    /// verdict.
    fn malleation_verdict(block: &Block, height: u32, params: &ChainParams) -> Result<(), BlockValidationError> {
        let via_mutation = check_block_mutation(block, height, params);
        let via_validate = validate_block(block, height, params);
        assert_eq!(
            format!("{:?}", via_mutation),
            format!("{:?}", via_validate),
            "check_block_mutation and validate_block disagree"
        );
        if let Err(e) = &via_validate {
            assert!(e.is_mutation() && !e.is_consensus_failure(), "{:?}", e);
        }
        via_validate
    }

    const RESERVED: [u8; 32] = [0u8; 32];

    #[test]
    fn witness_no_commitment_no_witness_is_valid() {
        let p = segwit_params();
        let block = wrap_block(vec![synth_coinbase(50), synth_noncoinbase(1)]);
        malleation_verdict(&block, 1, &p).expect("witness-free block without commitment");
    }

    #[test]
    fn witness_no_commitment_rejects_coinbase_witness() {
        let p = segwit_params();
        let mut cb = synth_coinbase(50);
        cb.input[0].witness = witness_of(&[&RESERVED]);
        let block = wrap_block(vec![cb, synth_noncoinbase(1)]);
        let err = malleation_verdict(&block, 1, &p).unwrap_err();
        assert!(matches!(err, BlockValidationError::UnexpectedWitness { .. }), "{:?}", err);
    }

    #[test]
    fn witness_no_commitment_rejects_spend_witness() {
        let p = segwit_params();
        let mut tx = synth_noncoinbase(1);
        tx.input[0].witness = witness_of(&[&[0x01; 72], &[0x02; 33]]);
        let block = wrap_block(vec![synth_coinbase(50), tx]);
        let err = malleation_verdict(&block, 1, &p).unwrap_err();
        assert!(matches!(err, BlockValidationError::UnexpectedWitness { .. }), "{:?}", err);
    }

    /// The rust-bitcoin gap: no transaction has witness data, so
    /// `Block::check_witness_commitment` returns true early, but the
    /// coinbase commits and has no reserved value (`bad-witness-nonce-size`).
    #[test]
    fn witness_commitment_without_reserved_value_is_rejected() {
        let p = segwit_params();
        let block = with_commitment(vec![synth_coinbase(50), synth_noncoinbase(1)], &RESERVED);
        assert!(block.check_witness_commitment(), "rust-bitcoin accepts this shape");
        let err = malleation_verdict(&block, 1, &p).unwrap_err();
        assert!(matches!(err, BlockValidationError::BadWitnessCommitment { .. }), "{:?}", err);
    }

    #[test]
    fn witness_commitment_with_no_spend_witnesses_is_valid() {
        let p = segwit_params();
        let mut cb = synth_coinbase(50);
        cb.input[0].witness = witness_of(&[&RESERVED]);
        let block = with_commitment(vec![cb, synth_noncoinbase(1)], &RESERVED);
        malleation_verdict(&block, 1, &p).expect("commitment over witness-free txs");
    }

    #[test]
    fn witness_commitment_with_spend_witnesses_is_valid() {
        let p = segwit_params();
        let reserved = [7u8; 32];
        let mut cb = synth_coinbase(50);
        cb.input[0].witness = witness_of(&[&reserved]);
        let mut tx = synth_noncoinbase(1);
        tx.input[0].witness = witness_of(&[&[0x01; 72], &[0x02; 33]]);
        let block = with_commitment(vec![cb, tx], &reserved);
        malleation_verdict(&block, 1, &p).expect("matching commitment");
    }

    #[test]
    fn witness_commitment_rejects_wrong_reserved_value_shape() {
        let p = segwit_params();
        let bad_stacks: [&[&[u8]]; 3] = [
            &[&RESERVED, &RESERVED], // two items
            &[&[0u8; 31]],           // short
            &[&[0u8; 33]],           // long
        ];
        for stack in bad_stacks {
            let mut cb = synth_coinbase(50);
            cb.input[0].witness = witness_of(stack);
            let block = with_commitment(vec![cb, synth_noncoinbase(1)], &RESERVED);
            let err = malleation_verdict(&block, 1, &p).unwrap_err();
            assert!(matches!(err, BlockValidationError::BadWitnessCommitment { .. }), "{:?}", err);
        }
    }

    #[test]
    fn witness_commitment_mismatch_is_rejected() {
        let p = segwit_params();
        // Reserved value differs from the one committed to.
        let mut cb = synth_coinbase(50);
        cb.input[0].witness = witness_of(&[&[1u8; 32]]);
        let block = with_commitment(vec![cb, synth_noncoinbase(1)], &RESERVED);
        let err = malleation_verdict(&block, 1, &p).unwrap_err();
        assert!(matches!(err, BlockValidationError::BadWitnessCommitment { .. }), "{:?}", err);

        // A spend witness changed after committing (a mangled relay).
        let mut cb = synth_coinbase(50);
        cb.input[0].witness = witness_of(&[&RESERVED]);
        let mut tx = synth_noncoinbase(1);
        tx.input[0].witness = witness_of(&[&[0x01; 72]]);
        let mut block = with_commitment(vec![cb, tx], &RESERVED);
        block.txdata[1].input[0].witness = witness_of(&[&[0x03; 72]]);
        let err = malleation_verdict(&block, 1, &p).unwrap_err();
        assert!(matches!(err, BlockValidationError::BadWitnessCommitment { .. }), "{:?}", err);
    }

    /// Core uses the *last* output carrying the magic; an earlier, stale
    /// commitment is ignored.
    #[test]
    fn witness_commitment_uses_last_magic_output() {
        let p = segwit_params();
        let mut cb = synth_coinbase(50);
        cb.input[0].witness = witness_of(&[&RESERVED]);
        let mut stale = WITNESS_COMMITMENT_MAGIC.to_vec();
        stale.extend_from_slice(&[0xee; 32]);
        cb.output.push(bitcoin::TxOut {
            value: Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::from_bytes(stale),
        });
        let block = with_commitment(vec![cb.clone(), synth_noncoinbase(1)], &RESERVED);
        malleation_verdict(&block, 1, &p).expect("last commitment matches");

        // And the other way round: a good commitment followed by a bad one.
        let mut block = block;
        let good = block.txdata[0].output.pop().unwrap();
        let bad = block.txdata[0].output.pop().unwrap();
        block.txdata[0].output.push(good);
        block.txdata[0].output.push(bad);
        let block = wrap_block(block.txdata);
        let err = malleation_verdict(&block, 1, &p).unwrap_err();
        assert!(matches!(err, BlockValidationError::BadWitnessCommitment { .. }), "{:?}", err);
    }

    /// Before SegWit activation a commitment output is just an OP_RETURN,
    /// and any witness data at all is unexpected.
    #[test]
    fn witness_rules_before_segwit_activation() {
        let p = ChainParams::mainnet(); // height 1: pre-SegWit, pre-BIP 34
        let mut cb = synth_coinbase(50);
        cb.input[0].witness = witness_of(&[&RESERVED]);
        let committed = with_commitment(vec![cb, synth_noncoinbase(1)], &RESERVED);
        let err = malleation_verdict(&committed, 1, p).unwrap_err();
        assert!(matches!(err, BlockValidationError::UnexpectedWitness { .. }), "{:?}", err);

        let no_witness = with_commitment(vec![synth_coinbase(50), synth_noncoinbase(1)], &RESERVED);
        malleation_verdict(&no_witness, 1, p).expect("commitment output alone is fine pre-SegWit");
    }

    /// Ticket 024 classes for the ticket 026 variants: `MissingContext` is
    /// ours (local), the rest are the block's own fault (consensus).
    #[test]
    fn contextual_rule_errors_are_classified() {
        let local = BlockValidationError::MissingContext { height: 5, msg: "no headers".into() };
        assert!(!local.is_mutation() && !local.is_consensus_failure());
        for e in [
            BlockValidationError::BadCoinbaseLength { height: 5, len: 1 },
            BlockValidationError::NonFinalTx { height: 5, tx_index: 1, lock_time: 6 },
            BlockValidationError::SequenceLockNotMet { height: 5, tx_index: 1, min_height: 5, min_time: -1 },
            BlockValidationError::ExcessiveSigopCost { height: 5, cost: 80_001, max: 80_000 },
        ] {
            assert!(!e.is_mutation() && e.is_consensus_failure(), "{:?}", e);
        }
    }
}
