//! `FixtureChain`: a regtest block chain mined on the fly (ticket 027).
//!
//! Regtest's minimum difficulty (`bits = 0x207fffff`) means about one nonce
//! in two satisfies proof-of-work, so a few hundred blocks are mined in
//! milliseconds. Blocks carry real transactions: every coinbase pays a
//! P2WPKH output to a fixed test key, and `spend` builds and signs real
//! P2WPKH / P2TR key-path spends, so Hercules' script validation runs for
//! real against what the harness serves.
//!
//! Invalid variants (`mine_invalid`, `strip_witness`, `wrong_merkle`) keep a
//! valid proof-of-work header so they get past header validation and
//! exercise block validation.

use std::collections::HashMap;

use bitcoin::block::{Block, Header, Version};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::key::{CompressedPublicKey, Keypair, TapTweak};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    absolute::LockTime, Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};

use crate::block_validation::block_subsidy;
use crate::chain_params::ChainParams;
use crate::contextual_checks::HeaderTimes;

/// Seconds between fixture block timestamps.
const BLOCK_SPACING: u32 = 600;

/// Ways `mine_invalid` can break a block while keeping valid PoW.
#[derive(Debug, Clone, Copy)]
pub enum Invalid {
    /// Coinbase claims one satoshi more than subsidy + fees.
    CoinbaseOverpay,
    /// A transaction spends an outpoint that never existed.
    SpendMissingInput,
    /// A signed spend whose signature has been corrupted.
    BadSignature,
}

/// A regtest chain whose block `i` sits at height `i` (block 0 is genesis).
#[derive(Clone)]
pub struct FixtureChain {
    blocks: Vec<Block>,
    /// Every output created on this chain, for signing and fee computation.
    outputs: HashMap<OutPoint, TxOut>,
    /// Mixed into coinbases and timestamps so forks get distinct hashes.
    salt: u32,
    key: SecretKey,
}

impl FixtureChain {
    /// A chain holding only the regtest genesis block.
    pub fn new() -> FixtureChain {
        FixtureChain {
            blocks: vec![genesis_block(Network::Regtest)],
            outputs: HashMap::new(),
            salt: 0,
            key: SecretKey::from_slice(&[0x27; 32]).expect("valid test key"),
        }
    }

    pub fn params() -> &'static ChainParams {
        ChainParams::regtest()
    }

    // ── Accessors ────────────────────────────────────────────────────

    pub fn tip_height(&self) -> u32 {
        (self.blocks.len() - 1) as u32
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.blocks.last().unwrap().block_hash()
    }

    pub fn block(&self, height: u32) -> &Block {
        &self.blocks[height as usize]
    }

    pub fn hash_at(&self, height: u32) -> BlockHash {
        self.block(height).block_hash()
    }

    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// The output at `op` (any output ever created on this chain).
    pub fn output(&self, op: &OutPoint) -> &TxOut {
        self.outputs.get(op).expect("output: unknown outpoint")
    }

    /// Outpoint of the coinbase output at `height` (always vout 0).
    pub fn coinbase_outpoint(&self, height: u32) -> OutPoint {
        OutPoint::new(self.block(height).txdata[0].compute_txid(), 0)
    }

    /// The UTXO set this chain implies (genesis excluded, matching Hercules,
    /// which never applies block 0; OP_RETURN outputs excluded).
    pub fn expected_utxos(&self) -> HashMap<OutPoint, TxOut> {
        let mut set = HashMap::new();
        for block in self.blocks.iter().skip(1) {
            for tx in &block.txdata {
                for input in &tx.input {
                    set.remove(&input.previous_output);
                }
                let txid = tx.compute_txid();
                for (vout, out) in tx.output.iter().enumerate() {
                    if !out.script_pubkey.is_op_return() {
                        set.insert(OutPoint::new(txid, vout as u32), out.clone());
                    }
                }
            }
        }
        set
    }

    // ── Keys and scripts ─────────────────────────────────────────────

    fn keypair(&self) -> Keypair {
        Keypair::from_secret_key(&Secp256k1::new(), &self.key)
    }

    /// P2WPKH script paying the test key.
    pub fn p2wpkh_script(&self) -> ScriptBuf {
        let pk = CompressedPublicKey(self.keypair().public_key());
        ScriptBuf::new_p2wpkh(&pk.wpubkey_hash())
    }

    /// P2TR (key path, no script tree) script paying the test key.
    pub fn p2tr_script(&self) -> ScriptBuf {
        let (xonly, _) = self.keypair().x_only_public_key();
        ScriptBuf::new_p2tr(&Secp256k1::new(), xonly, None)
    }

    // ── Chain construction ───────────────────────────────────────────

    /// Mine `n` coinbase-only blocks.
    pub fn mine(&mut self, n: u32) -> &mut Self {
        for _ in 0..n {
            self.mine_block(vec![]);
        }
        self
    }

    /// Mine one block containing `txs` (after the coinbase). The coinbase
    /// claims exactly subsidy + fees.
    pub fn mine_block(&mut self, txs: Vec<Transaction>) -> Block {
        self.mine_custom(txs, |_| {})
    }

    /// Mine one block, letting `tweak` edit it (header fields, transactions)
    /// just before the merkle root is computed and PoW is solved.
    pub fn mine_custom(&mut self, txs: Vec<Transaction>, tweak: impl FnOnce(&mut Block)) -> Block {
        let height = self.tip_height() + 1;
        let fees: u64 = txs.iter().map(|tx| self.fee(tx)).sum();
        let reward = block_subsidy(height, Self::params()).to_sat() + fees;
        let mut block = self.assemble(height, reward, txs);
        tweak(&mut block);
        self.seal(&mut block);
        self.push(block.clone());
        block
    }

    /// Mine a block that is consensus-invalid in the given way but has a
    /// valid header (PoW, linkage, timestamp).
    pub fn mine_invalid(&mut self, kind: Invalid) -> Block {
        let height = self.tip_height() + 1;
        match kind {
            Invalid::CoinbaseOverpay => {
                let reward = block_subsidy(height, Self::params()).to_sat() + 1;
                let mut block = self.assemble(height, reward, vec![]);
                self.seal(&mut block);
                self.push(block.clone());
                block
            }
            Invalid::SpendMissingInput => {
                let ghost = OutPoint::new(Txid::from_byte_array([0x66; 32]), 0);
                let tx = Transaction {
                    version: TxVersion::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![TxIn {
                        previous_output: ghost,
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence::MAX,
                        witness: Witness::from_slice(&[vec![0u8; 72], vec![2u8; 33]]),
                    }],
                    output: vec![TxOut {
                        value: Amount::from_sat(1_000),
                        script_pubkey: self.p2wpkh_script(),
                    }],
                };
                let reward = block_subsidy(height, Self::params()).to_sat();
                let mut block = self.assemble(height, reward, vec![tx]);
                self.seal(&mut block);
                self.push(block.clone());
                block
            }
            Invalid::BadSignature => {
                let prev = self
                    .first_mature_coinbase(height)
                    .expect("BadSignature needs a mature coinbase (mine 101+ blocks first)");
                let value = self.outputs[&prev].value - Amount::from_sat(1_000);
                let mut tx = self.spend(
                    &[prev],
                    vec![TxOut { value, script_pubkey: self.p2wpkh_script() }],
                );
                // Flip a byte inside the DER signature body.
                let mut items: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();
                items[0][10] ^= 0x01;
                tx.input[0].witness = Witness::from_slice(&items);
                self.mine_custom(vec![tx], |_| {})
            }
        }
    }

    /// A sibling chain sharing blocks `0..=height` with this one. Blocks
    /// mined on it get different hashes (salted coinbase and timestamps).
    pub fn fork_at(&self, height: u32) -> FixtureChain {
        let mut fork = self.prefix(height);
        fork.salt = self.salt + 1 + height;
        fork
    }

    /// This chain truncated to `0..=height`, same salt (so re-mining gives
    /// identical blocks only if the same transactions are mined).
    pub fn prefix(&self, height: u32) -> FixtureChain {
        let mut c = FixtureChain {
            blocks: self.blocks[..=height as usize].to_vec(),
            outputs: HashMap::new(),
            salt: self.salt,
            key: self.key,
        };
        c.reindex_outputs();
        c
    }

    // ── Transactions ─────────────────────────────────────────────────

    /// Build and sign a transaction spending `prevs` (outputs on this chain
    /// paying the test key, P2WPKH or P2TR) into `outputs`.
    pub fn spend(&self, prevs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
        self.spend_with(prevs, outputs, |_| {})
    }

    /// `spend`, letting `edit` set fields the signatures commit to
    /// (version, nLockTime, nSequence) before signing.
    pub fn spend_with(
        &self,
        prevs: &[OutPoint],
        outputs: Vec<TxOut>,
        edit: impl FnOnce(&mut Transaction),
    ) -> Transaction {
        let prev_outs: Vec<TxOut> = prevs
            .iter()
            .map(|p| self.outputs.get(p).cloned().expect("spend: unknown outpoint"))
            .collect();
        let mut tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: prevs
                .iter()
                .map(|p| TxIn {
                    previous_output: *p,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs,
        };
        edit(&mut tx);

        let secp = Secp256k1::new();
        let keypair = self.keypair();
        let mut witnesses = Vec::with_capacity(prevs.len());
        {
            let mut cache = SighashCache::new(&tx);
            for (i, prev) in prev_outs.iter().enumerate() {
                let spk = &prev.script_pubkey;
                if spk.is_p2wpkh() {
                    let sighash = cache
                        .p2wpkh_signature_hash(i, spk, prev.value, EcdsaSighashType::All)
                        .expect("p2wpkh sighash");
                    let msg = Message::from_digest(sighash.to_byte_array());
                    let sig = bitcoin::ecdsa::Signature {
                        signature: secp.sign_ecdsa(&msg, &self.key),
                        sighash_type: EcdsaSighashType::All,
                    };
                    witnesses.push(Witness::p2wpkh(&sig, &keypair.public_key()));
                } else if spk.is_p2tr() {
                    let sighash = cache
                        .taproot_key_spend_signature_hash(
                            i,
                            &Prevouts::All(&prev_outs),
                            TapSighashType::Default,
                        )
                        .expect("taproot sighash");
                    let msg = Message::from_digest(sighash.to_byte_array());
                    let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
                    let sig = bitcoin::taproot::Signature {
                        signature: secp.sign_schnorr_no_aux_rand(&msg, &tweaked),
                        sighash_type: TapSighashType::Default,
                    };
                    witnesses.push(Witness::p2tr_key_spend(&sig));
                } else {
                    panic!("spend: unsupported script {}", spk);
                }
            }
        }
        for (input, w) in tx.input.iter_mut().zip(witnesses) {
            input.witness = w;
        }
        tx
    }

    /// Oldest coinbase that is spendable in a block at `height` and not yet
    /// spent on this chain.
    pub fn first_mature_coinbase(&self, height: u32) -> Option<OutPoint> {
        let utxos = self.expected_utxos();
        (1..self.blocks.len() as u32)
            .take_while(|h| height.saturating_sub(*h) >= 100)
            .map(|h| self.coinbase_outpoint(h))
            .find(|op| utxos.contains_key(op))
    }

    // ── Invalid variants of an existing block ────────────────────────

    /// Same header (so same hash), non-coinbase witnesses removed: a mutated
    /// delivery that fails the witness commitment.
    ///
    /// The coinbase's witness reserved value is kept, so the commitment
    /// check sees witness data that doesn't match. `strip_all_witness`
    /// covers the other shape.
    pub fn strip_witness(block: &Block) -> Block {
        let mut b = block.clone();
        for tx in b.txdata.iter_mut().skip(1) {
            for input in &mut tx.input {
                input.witness = Witness::new();
            }
        }
        b
    }

    /// Same header (so same hash), *all* witnesses removed, the coinbase's
    /// reserved value included: a block with no witness data at all that
    /// still carries a witness commitment. rust-bitcoin's
    /// `check_witness_commitment` (and so `validate_block`) accepts that
    /// shape; Core's `CheckWitnessMalleation`, which Hercules' sync paths
    /// now run first as `check_block_mutation`, flags it as mutated. Without
    /// that check it would only fail in script validation and be mistaken
    /// for a consensus-invalid block (ticket 024).
    pub fn strip_all_witness(block: &Block) -> Block {
        let mut b = block.clone();
        for tx in b.txdata.iter_mut() {
            for input in &mut tx.input {
                input.witness = Witness::new();
            }
        }
        b
    }

    /// Same header (so same hash), the last transaction repeated so the
    /// merkle root is unchanged (CVE-2012-2459). Only meaningful when the
    /// block has an odd number of transactions.
    pub fn duplicate_last_tx(block: &Block) -> Block {
        let mut b = block.clone();
        let last = b.txdata.last().unwrap().clone();
        b.txdata.push(last);
        b
    }

    /// Same header (so same hash), transaction list altered so the merkle
    /// root no longer matches.
    pub fn wrong_merkle(block: &Block) -> Block {
        let mut b = block.clone();
        b.txdata[0].output[0].value += Amount::from_sat(1);
        b
    }

    // ── Internals ────────────────────────────────────────────────────

    fn fee(&self, tx: &Transaction) -> u64 {
        let input: u64 = tx
            .input
            .iter()
            .map(|i| self.outputs.get(&i.previous_output).map(|o| o.value.to_sat()).unwrap_or(0))
            .sum();
        let output: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        input.saturating_sub(output)
    }

    /// Block at `height` with a coinbase paying `reward` to the test key,
    /// followed by `txs`. Merkle root and PoW are filled in by `seal`.
    fn assemble(&self, height: u32, reward: u64, txs: Vec<Transaction>) -> Block {
        let prev = self.blocks.last().unwrap();
        let coinbase = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: coinbase_script(height, self.salt),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(reward),
                script_pubkey: self.p2wpkh_script(),
            }],
        };
        let mut txdata = vec![coinbase];
        txdata.extend(txs);
        Block {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: prev.block_hash(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: prev.header.time + BLOCK_SPACING + (self.salt % 7),
                bits: prev.header.bits,
                nonce: 0,
            },
            txdata,
        }
    }

    /// Add the witness commitment (if any tx has witness data), compute the
    /// merkle root, and grind the nonce until the header meets its target.
    fn seal(&self, block: &mut Block) {
        let has_witness = block
            .txdata
            .iter()
            .skip(1)
            .any(|tx| tx.input.iter().any(|i| !i.witness.is_empty()));
        if has_witness && block.txdata[0].input[0].witness.is_empty() {
            let reserved = [0u8; 32];
            block.txdata[0].input[0].witness = Witness::from_slice(&[reserved]);
            let root = block.witness_root().expect("witness root");
            let commitment = Block::compute_witness_commitment(&root, &reserved);
            let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script.extend_from_slice(commitment.as_byte_array());
            block.txdata[0].output.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(script),
            });
        }
        block.header.merkle_root = block.compute_merkle_root().expect("merkle root");
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
    }

    fn push(&mut self, block: Block) {
        index_outputs(&mut self.outputs, &block);
        self.blocks.push(block);
    }

    fn reindex_outputs(&mut self) {
        let mut outputs = HashMap::new();
        for block in &self.blocks {
            index_outputs(&mut outputs, block);
        }
        self.outputs = outputs;
    }
}

/// Header timestamps for the block-level time rules (ticket 026), so
/// fixture tests can validate without a header store.
impl HeaderTimes for FixtureChain {
    fn timestamp_at(&self, height: u32) -> Result<u32, String> {
        self.blocks
            .get(height as usize)
            .map(|b| b.header.time)
            .ok_or_else(|| format!("no fixture block at height {}", height))
    }
}

fn index_outputs(outputs: &mut HashMap<OutPoint, TxOut>, block: &Block) {
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        for (vout, out) in tx.output.iter().enumerate() {
            outputs.insert(OutPoint::new(txid, vout as u32), out.clone());
        }
    }
}

/// Coinbase scriptSig: BIP 34 height exactly as Bitcoin Core writes it
/// (`CScript() << nHeight`, so `OP_1..OP_16` for heights 1..=16), then the
/// chain salt.
fn coinbase_script(height: u32, salt: u32) -> ScriptBuf {
    Builder::new()
        .push_int(height as i64)
        .push_slice(salt.to_le_bytes())
        .into_script()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_validation::{
        check_block_mutation, validate_block, validate_block_scripts, BlockValidationError,
    };
    use crate::utxo::UtxoSet;
    use crate::validation::validate_headers;
    use tempfile::TempDir;

    /// Apply `chain` to a fresh UTXO set through Hercules' own validators.
    fn validate_all(chain: &FixtureChain) -> Result<(TempDir, UtxoSet), BlockValidationError> {
        let dir = TempDir::new().unwrap();
        let utxo = UtxoSet::open(dir.path().join("utxo").to_str().unwrap()).unwrap();
        let p = FixtureChain::params();
        for h in 1..=chain.tip_height() {
            let block = chain.block(h);
            validate_block(block, h, p)?;
            validate_block_scripts(block, h, &utxo, p, chain)?;
            utxo.apply_block(block, h).unwrap();
        }
        Ok((dir, utxo))
    }

    fn chain_with_spends() -> FixtureChain {
        let mut c = FixtureChain::new();
        c.mine(101);
        // Coinbase 1 → one P2TR and one P2WPKH output.
        let cb = c.coinbase_outpoint(1);
        let value = c.outputs[&cb].value;
        let tx1 = c.spend(
            &[cb],
            vec![
                TxOut { value: value / 2, script_pubkey: c.p2tr_script() },
                TxOut {
                    value: value / 2 - Amount::from_sat(500),
                    script_pubkey: c.p2wpkh_script(),
                },
            ],
        );
        c.mine_block(vec![tx1.clone()]);
        // Spend both (taproot key path + segwit v0) in one tx.
        let tx2 = c.spend(
            &[OutPoint::new(tx1.compute_txid(), 0), OutPoint::new(tx1.compute_txid(), 1)],
            vec![TxOut { value: value - Amount::from_sat(2_000), script_pubkey: c.p2wpkh_script() }],
        );
        c.mine_block(vec![tx2]);
        c.mine(2);
        c
    }

    #[test]
    fn fixture_chain_headers_pass_header_validation() {
        let c = chain_with_spends();
        let headers: Vec<Header> = c.blocks().iter().skip(1).map(|b| b.header).collect();
        let genesis = c.block(0).header;
        validate_headers(
            FixtureChain::params(),
            &headers,
            genesis.block_hash(),
            0,
            &[genesis.time],
            genesis.bits,
            &|_| Err("regtest never retargets".into()),
        )
        .expect("fixture headers validate");
    }

    #[test]
    fn fixture_chain_blocks_pass_block_and_script_validation() {
        let c = chain_with_spends();
        let (_dir, utxo) = validate_all(&c).expect("fixture validates");
        assert_eq!(utxo.count().unwrap(), c.expected_utxos().len() as u64);
        for op in c.expected_utxos().keys() {
            assert!(utxo.get(&op.txid, op.vout).unwrap().is_some(), "missing {}", op);
        }
    }

    #[test]
    fn subsidy_halves_at_regtest_interval() {
        let mut c = FixtureChain::new();
        c.mine(151);
        assert_eq!(c.block(149).txdata[0].output[0].value.to_sat(), 50 * 100_000_000);
        assert_eq!(c.block(150).txdata[0].output[0].value.to_sat(), 25 * 100_000_000);
        validate_all(&c).expect("halving chain validates");
    }

    #[test]
    fn forks_diverge_after_fork_point() {
        let mut a = FixtureChain::new();
        a.mine(5);
        let mut b = a.fork_at(3);
        b.mine(3);
        assert_eq!(a.hash_at(3), b.hash_at(3));
        assert_ne!(a.hash_at(4), b.hash_at(4));
        assert_eq!(b.tip_height(), 6);
        validate_all(&b).expect("fork validates");
    }

    #[test]
    fn invalid_variants_fail_validation_with_valid_pow() {
        let mut base = FixtureChain::new();
        base.mine(101);
        let p = FixtureChain::params();
        for (kind, expect) in [
            (Invalid::CoinbaseOverpay, "CoinbaseOverpayment"),
            (Invalid::SpendMissingInput, "MissingUtxo"),
            (Invalid::BadSignature, "ScriptFailure"),
        ] {
            let mut c = base.clone();
            let bad = c.mine_invalid(kind);
            assert!(bad.header.validate_pow(bad.header.target()).is_ok());
            let err = match validate_all(&c) {
                Ok(_) => panic!("{:?}: invalid block validated", kind),
                Err(e) => e,
            };
            assert!(format!("{:?}", err).contains(expect), "{:?}: {:?}", kind, err);
        }

        // Mutations keep the hash but break structure.
        let mut c = base.clone();
        let cb = c.coinbase_outpoint(1);
        let v = c.outputs[&cb].value - Amount::from_sat(1_000);
        let tx = c.spend(&[cb], vec![TxOut { value: v, script_pubkey: c.p2wpkh_script() }]);
        let good = c.mine_block(vec![tx]);
        let stripped = FixtureChain::strip_witness(&good);
        assert_eq!(stripped.block_hash(), good.block_hash());
        assert!(validate_block(&stripped, 102, p).is_err());
        let wrong = FixtureChain::wrong_merkle(&good);
        assert_eq!(wrong.block_hash(), good.block_hash());
        assert!(matches!(
            validate_block(&wrong, 102, p),
            Err(BlockValidationError::BadMerkleRoot { .. })
        ));
    }

    /// Ticket 024: every mutation of a valid block is caught by
    /// `check_block_mutation` and classified as a mutation; every invalid
    /// variant passes it and fails later with a non-mutation error.
    #[test]
    fn mutations_are_detected_before_validation() {
        let p = FixtureChain::params();
        let c = chain_with_spends();
        for h in 1..=c.tip_height() {
            check_block_mutation(c.block(h), h, p).expect("honest block flagged as mutated");
        }

        // Block 102 spends with witnesses; build an odd-length block (3 txs)
        // for the duplicate-tx mutation.
        let mut odd = c.prefix(101);
        let cb = odd.coinbase_outpoint(1);
        let v = odd.outputs[&cb].value;
        let parent = odd.spend(
            &[cb],
            vec![TxOut { value: v - Amount::from_sat(1_000), script_pubkey: odd.p2wpkh_script() }],
        );
        let mut scratch = odd.clone();
        scratch.mine_block(vec![parent.clone()]);
        let child = scratch.spend(
            &[OutPoint::new(parent.compute_txid(), 0)],
            vec![TxOut { value: v - Amount::from_sat(2_000), script_pubkey: odd.p2wpkh_script() }],
        );
        let three = odd.mine_block(vec![parent, child]);
        assert_eq!(three.txdata.len(), 3);

        let good = c.block(102);
        for (name, mutated, original) in [
            ("strip_witness", FixtureChain::strip_witness(good), good),
            ("strip_all_witness", FixtureChain::strip_all_witness(good), good),
            ("wrong_merkle", FixtureChain::wrong_merkle(good), good),
            ("duplicate_last_tx", FixtureChain::duplicate_last_tx(&three), &three),
        ] {
            assert_eq!(mutated.block_hash(), original.block_hash(), "{}", name);
            let err = check_block_mutation(&mutated, 102, p)
                .err()
                .unwrap_or_else(|| panic!("{}: mutation not detected", name));
            assert!(err.is_mutation(), "{}: {:?} not classified as mutation", name, err);
        }

        let mut base = FixtureChain::new();
        base.mine(101);
        for kind in [Invalid::CoinbaseOverpay, Invalid::SpendMissingInput, Invalid::BadSignature] {
            let mut c = base.clone();
            let bad = c.mine_invalid(kind);
            check_block_mutation(&bad, 102, p)
                .unwrap_or_else(|e| panic!("{:?}: flagged as mutated: {}", kind, e));
            let err = validate_all(&c).err().expect("invalid block validated");
            assert!(!err.is_mutation(), "{:?}: {:?} classified as mutation", kind, err);
        }
    }

    /// Witness data without a commitment (after activation), any witness
    /// data before activation, and a block without a coinbase are all
    /// mutations (bad deliveries), never consensus verdicts.
    #[test]
    fn witness_and_coinbase_mutations_are_classified_as_delivery() {
        let p = FixtureChain::params();
        let c = chain_with_spends();
        let good = c.block(102);
        let reseal = |mut b: Block| {
            b.header.merkle_root = b.compute_merkle_root().unwrap();
            b
        };

        // Commitment output and reserved value removed, spend witnesses kept.
        let mut no_commit = good.clone();
        no_commit.txdata[0].output.retain(|o| {
            !(o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[..2] == [0x6a, 0x24])
        });
        no_commit.txdata[0].input[0].witness = Witness::new();
        let err = check_block_mutation(&reseal(no_commit), 102, p).unwrap_err();
        assert!(matches!(err, BlockValidationError::UnexpectedWitness { .. }), "{:?}", err);
        assert!(err.is_mutation() && !err.is_consensus_failure());

        // Before SegWit activation no witness data is allowed at all, even
        // with a valid commitment; a witness-free block is fine.
        let pre_segwit: &'static ChainParams = Box::leak(Box::new(ChainParams {
            segwit_height: 1_000,
            ..*ChainParams::regtest()
        }));
        let err = check_block_mutation(good, 102, pre_segwit).unwrap_err();
        assert!(matches!(err, BlockValidationError::UnexpectedWitness { .. }), "{:?}", err);
        check_block_mutation(c.block(101), 101, pre_segwit).expect("witness-free block");

        // No coinbase: invalid either way, but blamed on the delivery.
        let mut no_coinbase = good.clone();
        no_coinbase.txdata.remove(0);
        let err = check_block_mutation(&reseal(no_coinbase), 102, p).unwrap_err();
        assert!(matches!(err, BlockValidationError::NoCoinbase { .. }), "{:?}", err);
        assert!(err.is_mutation() && !err.is_consensus_failure());
    }

    #[test]
    fn coinbase_height_encoding_matches_core() {
        assert_eq!(coinbase_script(1, 0).as_bytes()[0], 0x51); // OP_1
        assert_eq!(coinbase_script(16, 0).as_bytes()[0], 0x60); // OP_16
        assert_eq!(&coinbase_script(17, 0).as_bytes()[..2], &[0x01, 0x11]);
        assert_eq!(&coinbase_script(300, 0).as_bytes()[..3], &[0x02, 0x2c, 0x01]);
    }

    /// Bitcoin Core's regtest enforces BIP 34 from height 1, encoding
    /// heights 1..=16 as `OP_1..OP_16`. Hercules' old BIP 34 check
    /// (rust-bitcoin `bip34_block_height`) only accepted a minimal data
    /// push and rejected these; ticket 026 ports Core's byte-prefix check,
    /// and regtest now activates BIP 34 at 1 like Core.
    #[test]
    fn bip34_accepts_core_encoding_at_low_heights() {
        let mut c = FixtureChain::new();
        c.mine(20);
        let p = FixtureChain::params();
        assert_eq!(p.bip34_height, 1);
        for h in 1..=20 {
            validate_block(c.block(h), h, p)
                .unwrap_or_else(|e| panic!("Core-encoded height {} coinbase: {}", h, e));
        }
        // The encoding is checked, not just tolerated: block 5 at height 6.
        assert!(matches!(
            validate_block(c.block(5), 6, p),
            Err(BlockValidationError::BadCoinbaseHeight { height: 6, .. })
        ));
    }
}
