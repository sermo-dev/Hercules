//! Block-level consensus boundaries (data-path test pass).
//!
//! Each rule gets a block on both sides of its limit, run through
//! `validate_block` + `validate_block_scripts` exactly as sync runs them:
//! coinbase maturity, in-block spend ordering, double spends, value
//! limits, the coinbase reward, block weight, legacy sigops, merkle
//! mutation (CVE-2012-2459) and the witness commitment's shape. Every
//! rejection is also checked to be classified as a consensus failure
//! (ticket 024), never a bad delivery.
//!
//! Chains come from `FixtureChain` (real signatures, regtest PoW). Rules
//! `validate_block` checks without context (weight, sigops, commitment
//! shape) use hand-built blocks, which need no PoW.

use bitcoin::block::{Block, Header, Version as BlockVersion};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use proptest::prelude::*;
use tempfile::TempDir;

use super::FixtureChain;
use crate::block_validation::{
    block_subsidy, check_block_mutation, validate_block, validate_block_scripts, BlockValidationError,
};
use crate::chain_params::ChainParams;
use crate::contextual_checks::bip34_height_prefix;
use crate::utxo::UtxoSet;

const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Validate blocks 1..=tip of `chain`, applying each to a fresh UTXO set.
fn validate_chain(chain: &FixtureChain) -> Result<(), (u32, BlockValidationError)> {
    let params = FixtureChain::params();
    let dir = TempDir::new().unwrap();
    let utxo = UtxoSet::open(dir.path().join("utxo").to_str().unwrap()).unwrap();
    for h in 1..=chain.tip_height() {
        let block = chain.block(h);
        validate_block(block, h, params).map_err(|e| (h, e))?;
        validate_block_scripts(block, h, &utxo, params, chain).map_err(|e| (h, e))?;
        utxo.apply_block(block, h).unwrap();
    }
    Ok(())
}

/// The tip block must fail with `what` (a `Debug` substring), the error
/// must be a consensus failure, and every earlier block must pass.
fn assert_tip_rejected(chain: &FixtureChain, what: &str) {
    match validate_chain(chain) {
        Err((h, e)) => {
            assert_eq!(h, chain.tip_height(), "rejected at {} instead of the tip: {}", h, e);
            assert!(format!("{:?}", e).contains(what), "expected {}, got {:?}", what, e);
            assert!(e.is_consensus_failure() && !e.is_mutation(), "{:?} must condemn the block", e);
        }
        Ok(()) => panic!("block {} should fail with {}", chain.tip_height(), what),
    }
}

fn p2wpkh(c: &FixtureChain, value: u64) -> TxOut {
    TxOut { value: Amount::from_sat(value), script_pubkey: c.p2wpkh_script() }
}

/// An unsigned spend: fine wherever the rule under test fires before
/// script verification (which runs last for each transaction).
fn unsigned(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|op| TxIn { previous_output: *op, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() })
            .collect(),
        output: outputs,
    }
}

/// 100 coinbase-only blocks: coinbase 1 is the only mature one at 101.
fn hundred_blocks() -> FixtureChain {
    let mut c = FixtureChain::new();
    c.mine(100);
    c
}

// ── Coinbase maturity ────────────────────────────────────────────────

#[test]
fn coinbase_spendable_after_exactly_100_blocks() {
    let base = hundred_blocks();
    // Block 101 may spend coinbase 1 (101 - 1 = 100 confirmations' worth).
    let mut ok = base.clone();
    let cb = ok.coinbase_outpoint(1);
    let v = ok.output(&cb).value.to_sat() - 1_000;
    let tx = ok.spend(&[cb], vec![p2wpkh(&ok, v)]);
    ok.mine_block(vec![tx]);
    validate_chain(&ok).unwrap_or_else(|(h, e)| panic!("{}: {}", h, e));

    // ...but not coinbase 2 (99).
    let mut bad = base.clone();
    let cb = bad.coinbase_outpoint(2);
    let v = bad.output(&cb).value.to_sat() - 1_000;
    let tx = bad.spend(&[cb], vec![p2wpkh(&bad, v)]);
    bad.mine_block(vec![tx]);
    assert_tip_rejected(&bad, "PrematureCoinbaseSpend");
}

#[test]
fn coinbase_cannot_be_spent_in_its_own_block() {
    let mut c = hundred_blocks();
    c.mine_custom(vec![], |b| {
        let cb = OutPoint::new(b.txdata[0].compute_txid(), 0);
        let value = b.txdata[0].output[0].value.to_sat() - 1_000;
        b.txdata.push(unsigned(&[cb], vec![TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }]));
    });
    assert_tip_rejected(&c, "PrematureCoinbaseSpend");
}

// ── Spend ordering and double spends ────────────────────────────────

/// 101 blocks, then block 102 splits coinbase 1 into a fresh coin.
fn chain_with_coin() -> (FixtureChain, OutPoint) {
    let mut c = FixtureChain::new();
    c.mine(101);
    let cb = c.coinbase_outpoint(1);
    let v = c.output(&cb).value.to_sat() - 1_000;
    let tx = c.spend(&[cb], vec![p2wpkh(&c, v)]);
    c.mine_block(vec![tx.clone()]);
    (c, OutPoint::new(tx.compute_txid(), 0))
}

#[test]
fn in_block_chain_of_spends_is_valid() {
    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    let a = c.spend(&[coin], vec![p2wpkh(&c, v - 1_000)]);
    let mut scratch = c.clone();
    scratch.mine_block(vec![a.clone()]);
    let b = scratch.spend(&[OutPoint::new(a.compute_txid(), 0)], vec![p2wpkh(&c, v - 2_000)]);
    scratch.mine_block(vec![b.clone()]);
    let d = scratch.spend(&[OutPoint::new(b.compute_txid(), 0)], vec![p2wpkh(&c, v - 3_000)]);
    c.mine_block(vec![a, b, d]);
    validate_chain(&c).unwrap_or_else(|(h, e)| panic!("{}: {}", h, e));
}

#[test]
fn spending_an_output_created_later_in_the_block_is_rejected() {
    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    let parent = c.spend(&[coin], vec![p2wpkh(&c, v - 1_000)]);
    let mut scratch = c.clone();
    scratch.mine_block(vec![parent.clone()]);
    let child = scratch.spend(&[OutPoint::new(parent.compute_txid(), 0)], vec![p2wpkh(&c, v - 2_000)]);
    // Child before parent: Core requires topological order within a block.
    c.mine_block(vec![child, parent]);
    assert_tip_rejected(&c, "MissingUtxo");
}

#[test]
fn spending_an_op_return_output_created_in_the_block_is_rejected() {
    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    let parent = c.spend(
        &[coin],
        vec![p2wpkh(&c, v - 2_000), TxOut { value: Amount::from_sat(1_000), script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x07]) }],
    );
    let child = unsigned(&[OutPoint::new(parent.compute_txid(), 1)], vec![p2wpkh(&c, 500)]);
    c.mine_block(vec![parent, child]);
    assert_tip_rejected(&c, "MissingUtxo");
}

#[test]
fn same_coin_spent_by_two_transactions_is_rejected() {
    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    let first = c.spend(&[coin], vec![p2wpkh(&c, v - 1_000)]);
    let second = c.spend(&[coin], vec![p2wpkh(&c, v - 2_000)]);
    c.mine_block(vec![first, second]);
    assert_tip_rejected(&c, "DuplicateSpend");
}

/// Core: CheckTransaction `bad-txns-inputs-duplicate`. Both inputs carry
/// a valid signature, so only the duplicate check can catch it.
#[test]
fn duplicate_input_within_one_transaction_is_rejected() {
    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    // Claims the coin's value twice.
    let tx = c.spend(&[coin, coin], vec![p2wpkh(&c, 2 * v - 1_000)]);
    c.mine_block(vec![tx]);
    assert_tip_rejected(&c, "DuplicateSpend");

    // Same with an output created earlier in the block.
    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    let parent = c.spend(&[coin], vec![p2wpkh(&c, v - 1_000)]);
    let p0 = OutPoint::new(parent.compute_txid(), 0);
    let mut scratch = c.clone();
    scratch.mine_block(vec![parent.clone()]);
    let child = scratch.spend(&[p0, p0], vec![p2wpkh(&c, 2 * v - 5_000)]);
    c.mine_block(vec![parent, child]);
    assert_tip_rejected(&c, "MissingUtxo");
}

// ── Values ──────────────────────────────────────────────────────────

#[test]
fn outputs_above_inputs_are_rejected() {
    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    let tx = c.spend(&[coin], vec![p2wpkh(&c, v + 1)]);
    c.mine_block(vec![tx]);
    assert_tip_rejected(&c, "InsufficientInputValue");

    let (mut c, coin) = chain_with_coin();
    let v = c.output(&coin).value.to_sat();
    let tx = c.spend(&[coin], vec![p2wpkh(&c, v)]); // zero fee is fine
    c.mine_block(vec![tx]);
    validate_chain(&c).unwrap_or_else(|(h, e)| panic!("{}: {}", h, e));
}

/// Core: `bad-txns-vout-toolarge` / `bad-txns-txouttotal-toolarge`.
#[test]
fn output_values_above_max_money_are_rejected() {
    let (mut c, coin) = chain_with_coin();
    let tx = c.spend(&[coin], vec![p2wpkh(&c, MAX_MONEY + 1)]);
    c.mine_block(vec![tx]);
    assert_tip_rejected(&c, "OutputExceedsMaxMoney");

    // Each output within range, the total not (signed, so only the value
    // rule can reject it).
    let (mut c, coin) = chain_with_coin();
    let tx = c.spend(&[coin], vec![p2wpkh(&c, MAX_MONEY), p2wpkh(&c, 1)]);
    c.mine_block(vec![tx]);
    assert_tip_rejected(&c, "ValueOverflow");
}

#[test]
fn coinbase_may_claim_exactly_subsidy_plus_fees() {
    let (base, coin) = chain_with_coin();
    let fee = 7_777;
    let v = base.output(&coin).value.to_sat() - fee;

    let mut exact = base.clone();
    let tx = exact.spend(&[coin], vec![p2wpkh(&exact, v)]);
    let block = exact.mine_block(vec![tx]);
    let height = exact.tip_height();
    assert_eq!(block.txdata[0].output[0].value.to_sat(), block_subsidy(height, FixtureChain::params()).to_sat() + fee);
    validate_chain(&exact).unwrap_or_else(|(h, e)| panic!("{}: {}", h, e));

    let mut over = base.clone();
    let tx = over.spend(&[coin], vec![p2wpkh(&over, v)]);
    over.mine_custom(vec![tx], |b| b.txdata[0].output[0].value += Amount::from_sat(1));
    assert_tip_rejected(&over, "CoinbaseOverpayment");

    // Underpaying is allowed (the difference is burned).
    let mut under = base.clone();
    let tx = under.spend(&[coin], vec![p2wpkh(&under, v)]);
    under.mine_custom(vec![tx], |b| b.txdata[0].output[0].value -= Amount::from_sat(fee + 1));
    validate_chain(&under).unwrap_or_else(|(h, e)| panic!("{}: {}", h, e));
}

#[test]
fn total_subsidy_is_just_under_21_million() {
    let mainnet = ChainParams::mainnet();
    let total: u64 = (0..64u32).map(|era| 210_000 * block_subsidy(era * 210_000, mainnet).to_sat()).sum();
    assert_eq!(total, 2_099_999_997_690_000);
    assert!(total < MAX_MONEY);
    // The last satoshi-paying era and the first empty one.
    assert_eq!(block_subsidy(32 * 210_000, mainnet).to_sat(), 1);
    assert_eq!(block_subsidy(33 * 210_000 - 1, mainnet).to_sat(), 1);
    assert_eq!(block_subsidy(33 * 210_000, mainnet).to_sat(), 0);
    assert_eq!(block_subsidy(u32::MAX, mainnet).to_sat(), 0);
    // Regtest halves every 150 blocks.
    let regtest = FixtureChain::params();
    assert_eq!(block_subsidy(149, regtest).to_sat(), 50 * 100_000_000);
    assert_eq!(block_subsidy(150, regtest).to_sat(), 25 * 100_000_000);
}

// ── Context-free block rules on hand-built blocks ───────────────────

const HEIGHT: u32 = 200;

fn header() -> Header {
    Header {
        version: BlockVersion::from_consensus(0x2000_0000),
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 1_700_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    }
}

fn coinbase_tx() -> Transaction {
    let mut script = bip34_height_prefix(HEIGHT);
    script.push(0xaa);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(1), script_pubkey: ScriptBuf::from_bytes(vec![0x51]) }],
    }
}

/// Coinbase + `txs`, with a witness commitment if any tx has witness data
/// (as a miner would add it) and the merkle root filled in.
fn hand_block(txs: Vec<Transaction>) -> Block {
    let mut block = Block { header: header(), txdata: std::iter::once(coinbase_tx()).chain(txs).collect() };
    if block.txdata.iter().skip(1).any(|t| t.input.iter().any(|i| !i.witness.is_empty())) {
        let reserved = [0u8; 32];
        block.txdata[0].input[0].witness = Witness::from_slice(&[reserved]);
        let root = block.witness_root().unwrap();
        let commitment = Block::compute_witness_commitment(&root, &reserved);
        let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        spk.extend_from_slice(commitment.as_byte_array());
        block.txdata[0].output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) });
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

fn filler(n: u8, output_script: Vec<u8>, witness: Option<usize>) -> Transaction {
    let mut tx = unsigned(
        &[OutPoint::new(Txid::from_byte_array([n; 32]), 0)],
        vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(output_script) }],
    );
    if let Some(len) = witness {
        tx.input[0].witness = Witness::from_slice(&[vec![0u8; len]]);
    }
    tx
}

/// A valid-looking block of exactly `target` weight units: one filler tx
/// padded with an OP_RETURN (4 WU/byte) and a witness item (1 WU/byte).
fn block_of_weight(target: u64) -> Block {
    let build = |pad: usize, wit: usize| {
        let mut script = vec![0x6a];
        script.resize(1 + pad, 0);
        hand_block(vec![filler(1, script, Some(wit))])
    };
    let w = |pad, wit| build(pad, wit).weight().to_wu();
    let mut pad = (target.saturating_sub(w(0, 0)) / 4).saturating_sub(80) as usize;
    loop {
        let base = w(pad, 0);
        assert!(base <= target, "overshot");
        if target - base <= 252 {
            let block = build(pad, (target - base) as usize);
            assert_eq!(block.weight().to_wu(), target);
            return block;
        }
        pad += 1;
    }
}

#[test]
fn block_weight_limit_is_exactly_4_million() {
    let params = ChainParams::regtest();
    validate_block(&block_of_weight(4_000_000), HEIGHT, params).expect("at the limit");
    let err = validate_block(&block_of_weight(4_000_001), HEIGHT, params).unwrap_err();
    assert!(matches!(err, BlockValidationError::ExcessiveWeight { weight: 4_000_001, .. }), "{:?}", err);
    assert!(err.is_consensus_failure());
}

#[test]
fn legacy_sigop_limit_is_exactly_20000() {
    let params = ChainParams::regtest();
    // One OP_CHECKSIG = one legacy sigop (x4 = 4 cost units of 80,000).
    let block = |n: usize| hand_block(vec![filler(1, vec![0xac; n], None)]);
    validate_block(&block(20_000), HEIGHT, params).expect("at the limit");
    let err = validate_block(&block(20_001), HEIGHT, params).unwrap_err();
    assert!(matches!(err, BlockValidationError::ExcessiveSigops { sigops: 20_001, .. }), "{:?}", err);
    assert!(err.is_consensus_failure());
    // CHECKMULTISIG counts 20 when not preceded by OP_1..OP_16 (legacy).
    validate_block(&hand_block(vec![filler(1, vec![0xae; 1_000], None)]), HEIGHT, params).unwrap();
    assert!(validate_block(&hand_block(vec![filler(1, vec![0xae; 1_001], None)]), HEIGHT, params).is_err());
}

#[test]
fn transactions_need_inputs_and_outputs() {
    let params = ChainParams::regtest();
    let mut no_out = filler(1, vec![0x51], None);
    no_out.output.clear();
    let err = validate_block(&hand_block(vec![no_out]), HEIGHT, params).unwrap_err();
    assert!(matches!(err, BlockValidationError::EmptyOutputs { tx_index: 1, .. }), "{:?}", err);
    let mut no_in = filler(1, vec![0x51], None);
    no_in.input.clear();
    let err = validate_block(&hand_block(vec![no_in]), HEIGHT, params).unwrap_err();
    assert!(matches!(err, BlockValidationError::EmptyInputs { tx_index: 1, .. }), "{:?}", err);
    // The coinbase too.
    let mut b = hand_block(vec![]);
    b.txdata[0].output.clear();
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    let err = validate_block(&b, HEIGHT, params).unwrap_err();
    assert!(matches!(err, BlockValidationError::EmptyOutputs { tx_index: 0, .. }), "{:?}", err);
}

/// Core's commitment is the *last* output whose script is at least 38
/// bytes and starts with the magic; trailing bytes after the 32-byte hash
/// are allowed, a 37-byte look-alike is not a commitment at all.
#[test]
fn witness_commitment_script_shape() {
    let params = ChainParams::regtest();
    let with_witness = || filler(1, vec![0x51], Some(3));

    // Trailing data after the commitment hash: still the commitment.
    let mut b = hand_block(vec![with_witness()]);
    let last = b.txdata[0].output.len() - 1;
    let mut spk = b.txdata[0].output[last].script_pubkey.to_bytes();
    spk.extend_from_slice(&[0xde, 0xad]);
    b.txdata[0].output[last].script_pubkey = ScriptBuf::from_bytes(spk);
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    validate_block(&b, HEIGHT, params).expect("39+ byte commitment script");

    // Truncated to 37 bytes: no commitment, so the witness is unexpected.
    let mut b = hand_block(vec![with_witness()]);
    let spk = b.txdata[0].output[last].script_pubkey.to_bytes();
    b.txdata[0].output[last].script_pubkey = ScriptBuf::from_bytes(spk[..37].to_vec());
    b.header.merkle_root = b.compute_merkle_root().unwrap();
    let err = validate_block(&b, HEIGHT, params).unwrap_err();
    assert!(matches!(err, BlockValidationError::UnexpectedWitness { .. }), "{:?}", err);
    assert!(err.is_mutation(), "witness problems are bad deliveries");
}

// ── Merkle mutation (CVE-2012-2459) ─────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// For any transaction count, repeating the last subtree at the first
    /// odd-sized level keeps the merkle root but must be flagged as a
    /// mutation; the honest block never is.
    #[test]
    fn merkle_duplicate_subtree_is_always_detected(n in 1usize..80) {
        let params = ChainParams::regtest();
        let txs: Vec<Transaction> = (0..n - 1).map(|i| filler((i % 250) as u8 + 1, vec![0x51, (i / 250) as u8], None)).collect();
        let honest = hand_block(txs);
        prop_assert!(check_block_mutation(&honest, HEIGHT, params).is_ok());
        prop_assert!(validate_block(&honest, HEIGHT, params).is_ok());

        // First level (bottom up) with an odd count > 1.
        let mut width = 1usize;
        let mut count = n;
        while count > 1 && count % 2 == 0 {
            count /= 2;
            width *= 2;
        }
        if count > 1 {
            let mut mutated = honest.clone();
            let tail: Vec<Transaction> = honest.txdata[n - width..].to_vec();
            mutated.txdata.extend(tail);
            prop_assert_eq!(mutated.compute_merkle_root(), honest.compute_merkle_root());
            let err = check_block_mutation(&mutated, HEIGHT, params).unwrap_err();
            prop_assert!(matches!(err, BlockValidationError::MutatedMerkleTree { .. }), "{:?}", err);
            prop_assert!(err.is_mutation() && !err.is_consensus_failure());
        }
    }
}
