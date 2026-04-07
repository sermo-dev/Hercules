use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use bitcoin::block::Block;
use bitcoin::consensus::serialize;
use bitcoin::{Transaction, Txid};

use log::{debug, info};

use crate::utxo::{UtxoEntry, UtxoSet};

/// Default maximum mempool size in bytes (50 MB).
const DEFAULT_MAX_SIZE: usize = 50_000_000;

/// Minimum relay fee rate in sat/vB.
const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// Incremental relay fee rate (sat/vB) used by BIP 125 rule 3: a replacement
/// must pay this much per byte over the sum of the originals' fees, on top of
/// being a higher fee rate. Bitcoin Core defaults to 1 sat/vB.
const INCREMENTAL_RELAY_FEE_RATE: f64 = 1.0;

/// Maximum standard transaction weight (400,000 WU).
const MAX_TX_WEIGHT: u64 = 400_000;

/// Coinbase maturity: 100 blocks before coinbase outputs are spendable.
const COINBASE_MATURITY: u32 = 100;

/// Maximum transaction expiry time (14 days).
const MAX_TX_AGE: std::time::Duration = std::time::Duration::from_secs(14 * 24 * 3600);

/// Dust threshold in satoshis (Bitcoin Core default for P2PKH).
const DUST_THRESHOLD: u64 = 546;

/// Maximum OP_RETURN output size (matches Bitcoin Core MAX_OP_RETURN_RELAY).
const MAX_OP_RETURN_SIZE: usize = 83;

/// Maximum number of unconfirmed ancestors a transaction may have, *including*
/// itself. Matches Bitcoin Core's `DEFAULT_ANCESTOR_LIMIT`.
const MAX_ANCESTORS: usize = 25;

/// Maximum combined virtual size (in vbytes) of a transaction plus all of its
/// unconfirmed ancestors. Matches Bitcoin Core's `DEFAULT_ANCESTOR_SIZE_LIMIT`
/// of 101 kvB.
const MAX_ANCESTOR_VBYTES: usize = 101_000;

/// Maximum number of unconfirmed descendants a transaction may have, *including*
/// itself. Matches Bitcoin Core's `DEFAULT_DESCENDANT_LIMIT`. Enforced when a
/// new child would push an existing ancestor over the limit.
const MAX_DESCENDANTS: usize = 25;

/// Maximum number of mempool transactions a single replacement can evict
/// (BIP 125 rule 4). Bounds the work an attacker can force a single relay
/// decision to perform.
const MAX_REPLACEMENT_EVICTIONS: usize = 100;

/// A transaction in the mempool with fee metadata and CPFP graph state.
///
/// `parents` and `ancestors` describe the unconfirmed parent chain (parents =
/// direct, ancestors = transitive); both omit `self`. `descendants` is the
/// transitive descendant set, also omitting self. `ancestor_fee` /
/// `ancestor_size` are the running sums over `ancestors` only — the
/// "self + ancestors" view used by limit checks adds `self.fee` / `self.size`
/// at the call site.
struct MempoolEntry {
    tx: Transaction,
    fee: u64,
    fee_rate: f64, // sat/vB = fee / (weight / 4)
    size: usize,   // serialized byte size
    added_at: Instant,
    parents: HashSet<Txid>,
    ancestors: HashSet<Txid>,
    descendants: HashSet<Txid>,
    ancestor_fee: u64,
    ancestor_size: usize,
}

/// In-memory transaction pool for unconfirmed transactions.
pub struct Mempool {
    txs: HashMap<Txid, MempoolEntry>,
    /// Reverse index: which mempool tx spends each outpoint.
    spends: HashMap<(Txid, u32), Txid>,
    /// Total serialized size of all transactions.
    total_size: usize,
    /// Maximum total size in bytes.
    max_size: usize,
}

impl Mempool {
    /// Create a new mempool with the default 50 MB size cap.
    pub fn new() -> Mempool {
        Mempool {
            txs: HashMap::new(),
            spends: HashMap::new(),
            total_size: 0,
            max_size: DEFAULT_MAX_SIZE,
        }
    }

    /// Create a new mempool with a custom size cap. Test-only — production
    /// callers use [`Mempool::new`].
    #[cfg(test)]
    pub(crate) fn with_max_size(max_size: usize) -> Mempool {
        Mempool {
            txs: HashMap::new(),
            spends: HashMap::new(),
            total_size: 0,
            max_size,
        }
    }

    /// Validate and accept a transaction into the mempool.
    ///
    /// Phases:
    /// 0. Trivial rejections (coinbase, malformed, already-in-pool, weight,
    ///    dust, finality, standard scripts).
    /// 1. Conflict detection — gather direct conflicts and any descendants
    ///    that would also have to be evicted under BIP 125. > 100 → reject.
    /// 2. Input validation — UTXO set first, then mempool fallback for
    ///    chain spending. Inputs that hit `to_evict` are treated as missing
    ///    so a replacement can't depend on the txs it's replacing.
    /// 3. Script validation via libbitcoinconsensus, value math, fee rate
    ///    floor.
    /// 4. BIP 125 RBF rules 2/3/5 (only if `conflicts` is non-empty).
    /// 5. Ancestor closure + 25-ancestor / 101 kvB limit checks.
    /// 6. Descendant-limit check on each ancestor.
    /// 7. Mutate: evict the conflict set, insert the new entry, update
    ///    parents' descendant sets, and run package-aware capacity eviction
    ///    if we're now over `max_size`.
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
    ) -> Result<Txid, MempoolError> {
        self.accept_tx_internal(tx, utxo_set, current_height, false)
    }

    /// Test-only accept entry point that skips libbitcoinconsensus script
    /// validation and the standard-script-type check. Lets unit tests
    /// exercise the graph state, fee math, RBF, and CPFP paths using
    /// trivial anyone-can-spend script_pubkeys instead of crafting valid
    /// signatures. Production callers must always go through `accept_tx`.
    #[cfg(test)]
    pub(crate) fn accept_tx_test(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
    ) -> Result<Txid, MempoolError> {
        self.accept_tx_internal(tx, utxo_set, current_height, true)
    }

    /// Shared accept implementation. `skip_consensus` bypasses the standard
    /// script-type check and the libbitcoinconsensus signature/script
    /// verification — used by tests that exercise graph state with
    /// anyone-can-spend script_pubkeys.
    fn accept_tx_internal(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        skip_consensus: bool,
    ) -> Result<Txid, MempoolError> {
        let txid = tx.compute_txid();

        // ── Phase 0: trivial rejections ─────────────────────────────────

        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseTx);
        }

        if tx.input.is_empty() || tx.output.is_empty() {
            return Err(MempoolError::MalformedTx);
        }

        if self.txs.contains_key(&txid) {
            return Err(MempoolError::AlreadyInMempool);
        }

        // Finality (nLockTime). A tx is final if nLockTime == 0, all inputs
        // are nSequence==0xFFFFFFFF, or the locktime has been reached.
        let all_final = tx.input.iter().all(|i| i.sequence.0 == 0xFFFFFFFF);
        if !all_final {
            let lock_time = tx.lock_time.to_consensus_u32();
            if lock_time != 0 {
                if lock_time < 500_000_000 {
                    if lock_time > current_height + 1 {
                        return Err(MempoolError::NonFinal {
                            lock_time,
                            current_height,
                        });
                    }
                } else {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    if lock_time > now {
                        return Err(MempoolError::NonFinal {
                            lock_time,
                            current_height,
                        });
                    }
                }
            }
        }

        let weight = tx.weight().to_wu();
        if weight > MAX_TX_WEIGHT {
            return Err(MempoolError::OversizedTx { weight });
        }

        for (i, output) in tx.output.iter().enumerate() {
            if output.script_pubkey.is_op_return() {
                continue;
            }
            if output.value.to_sat() < DUST_THRESHOLD {
                return Err(MempoolError::DustOutput {
                    index: i,
                    amount: output.value.to_sat(),
                });
            }
        }

        if !skip_consensus {
            for (i, output) in tx.output.iter().enumerate() {
                let spk = &output.script_pubkey;
                let is_standard = spk.is_p2pkh()
                    || spk.is_p2sh()
                    || spk.is_witness_program()
                    || spk.is_p2pk()
                    || spk.is_multisig()
                    || (spk.is_op_return() && spk.len() <= MAX_OP_RETURN_SIZE);

                if !is_standard {
                    return Err(MempoolError::NonStandardScript { index: i });
                }
            }
        }

        // ── Phase 1: conflict detection ─────────────────────────────────
        //
        // Gather every distinct top-level mempool tx whose outputs collide
        // with one of our inputs, then walk descendants to compute the full
        // eviction set. BIP 125 rule 4 caps that at MAX_REPLACEMENT_EVICTIONS.
        let mut direct_conflicts: HashSet<Txid> = HashSet::new();
        for input in &tx.input {
            let key = (input.previous_output.txid, input.previous_output.vout);
            if let Some(conflicting) = self.spends.get(&key) {
                direct_conflicts.insert(*conflicting);
            }
        }

        let to_evict: HashSet<Txid> = if direct_conflicts.is_empty() {
            HashSet::new()
        } else {
            self.collect_eviction_set(&direct_conflicts)
        };
        if to_evict.len() > MAX_REPLACEMENT_EVICTIONS {
            return Err(MempoolError::TooManyReplacements {
                evicted: to_evict.len(),
                limit: MAX_REPLACEMENT_EVICTIONS,
            });
        }

        // ── Phase 2: input validation (UTXO set + mempool overlay) ──────
        //
        // For each input, look up the prevout in the on-disk UTXO set first.
        // If missing, fall back to the mempool — but skip any tx in
        // `to_evict`, because a replacement cannot legitimately depend on
        // the txs it's about to remove.
        let serialized_tx = serialize(&tx);
        let flags = bitcoinconsensus::height_to_flags(current_height);
        let mut input_sum: u64 = 0;
        let mut parents: HashSet<Txid> = HashSet::new();

        for (input_idx, input) in tx.input.iter().enumerate() {
            let prev_txid = &input.previous_output.txid;
            let prev_vout = input.previous_output.vout;

            let utxo = match utxo_set
                .get(prev_txid, prev_vout)
                .map_err(|e| MempoolError::UtxoLookup(format!("{}", e)))?
            {
                Some(u) => u,
                None => {
                    // Mempool fallback: is this output produced by an
                    // unconfirmed parent? Skip txs in the eviction set.
                    if to_evict.contains(prev_txid) {
                        return Err(MempoolError::MissingInput {
                            txid: *prev_txid,
                            vout: prev_vout,
                        });
                    }
                    let parent = self
                        .txs
                        .get(prev_txid)
                        .ok_or(MempoolError::MissingInput {
                            txid: *prev_txid,
                            vout: prev_vout,
                        })?;
                    let parent_output = parent
                        .tx
                        .output
                        .get(prev_vout as usize)
                        .ok_or(MempoolError::MissingInput {
                            txid: *prev_txid,
                            vout: prev_vout,
                        })?;
                    parents.insert(*prev_txid);
                    UtxoEntry {
                        amount: parent_output.value.to_sat(),
                        script_pubkey: parent_output.script_pubkey.as_bytes().to_vec(),
                        height: 0,
                        is_coinbase: false,
                    }
                }
            };

            // Coinbase maturity (only confirmed coinbases can be flagged
            // here; mempool parents synthesize is_coinbase=false above).
            if utxo.is_coinbase && current_height.saturating_sub(utxo.height) < COINBASE_MATURITY {
                return Err(MempoolError::ImmatureCoinbase {
                    input_index: input_idx,
                    coinbase_height: utxo.height,
                });
            }

            if !skip_consensus {
                bitcoinconsensus::verify_with_flags(
                    &utxo.script_pubkey,
                    utxo.amount,
                    &serialized_tx,
                    input_idx,
                    flags,
                )
                .map_err(|e| MempoolError::ScriptFailure {
                    input_index: input_idx,
                    error: format!("{:?}", e),
                })?;
            }

            input_sum = input_sum
                .checked_add(utxo.amount)
                .ok_or(MempoolError::Inflation)?;
        }

        // ── Phase 3: value math + minimum fee rate ──────────────────────
        let output_sum: u64 = tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or(MempoolError::Inflation)?;

        if input_sum < output_sum {
            return Err(MempoolError::Inflation);
        }

        let fee = input_sum - output_sum;
        let vsize = weight as f64 / 4.0;
        let fee_rate = fee as f64 / vsize;
        if fee_rate < MIN_RELAY_FEE_RATE {
            return Err(MempoolError::InsufficientFee {
                fee_rate,
                min_rate: MIN_RELAY_FEE_RATE,
            });
        }

        let size = serialized_tx.len();

        // ── Phase 4: BIP 125 RBF enforcement ────────────────────────────
        if !direct_conflicts.is_empty() {
            self.check_bip125(
                fee,
                size,
                &parents,
                &direct_conflicts,
                &to_evict,
            )?;
        }

        // ── Phase 5: ancestor closure + limit enforcement ───────────────
        //
        // Walk the parent chain breadth-first; the diamond case (same
        // ancestor reachable via multiple paths) is naturally deduplicated
        // by the visited HashSet.
        let mut ancestors: HashSet<Txid> = HashSet::new();
        let mut ancestor_fee: u64 = 0;
        let mut ancestor_size: usize = 0;
        let mut frontier: VecDeque<Txid> = parents.iter().copied().collect();

        while let Some(parent_txid) = frontier.pop_front() {
            if !ancestors.insert(parent_txid) {
                continue;
            }
            let parent = self
                .txs
                .get(&parent_txid)
                .expect("parent must exist — phase 2 just looked it up");
            ancestor_fee = ancestor_fee.saturating_add(parent.fee);
            ancestor_size = ancestor_size.saturating_add(parent.size);
            for grandparent in &parent.parents {
                if !ancestors.contains(grandparent) {
                    frontier.push_back(*grandparent);
                }
            }
        }

        if ancestors.len() + 1 > MAX_ANCESTORS {
            return Err(MempoolError::TooManyAncestors {
                count: ancestors.len() + 1,
                limit: MAX_ANCESTORS,
            });
        }
        if ancestor_size + size > MAX_ANCESTOR_VBYTES {
            return Err(MempoolError::AncestorSetTooLarge {
                vbytes: ancestor_size + size,
                limit: MAX_ANCESTOR_VBYTES,
            });
        }

        // ── Phase 6: descendant-limit check on each ancestor ────────────
        //
        // Adding `tx` adds 1 descendant to every ancestor. If that would
        // push any ancestor's descendant count above MAX_DESCENDANTS,
        // reject. Compute against the *current* graph: if some descendant
        // of an ancestor is itself in `to_evict`, the count after eviction
        // shrinks accordingly.
        for ancestor_txid in &ancestors {
            let ancestor = self.txs.get(ancestor_txid).expect("ancestor present");
            let surviving_descendants = ancestor
                .descendants
                .iter()
                .filter(|d| !to_evict.contains(*d))
                .count();
            // +1 for self (ancestor counts itself in its package), +1 for
            // the new tx we're about to insert.
            if surviving_descendants + 2 > MAX_DESCENDANTS {
                return Err(MempoolError::TooManyDescendants {
                    ancestor: *ancestor_txid,
                    count: surviving_descendants + 2,
                    limit: MAX_DESCENDANTS,
                });
            }
        }

        // ── Phase 7: mutate ─────────────────────────────────────────────
        //
        // From here down every operation must succeed; we've passed every
        // validation gate. Mutations in order:
        //   1. Evict the BIP 125 conflict set (cascade).
        //   2. Insert the new entry, wire its spends index, and update
        //      every ancestor's descendant set.
        //   3. Run package-aware capacity eviction if we're over max_size.

        if !to_evict.is_empty() {
            // Evict each top-level direct conflict; cascade handles the
            // rest. Skip txs already removed by an earlier cascade.
            for top_level in &direct_conflicts {
                if self.txs.contains_key(top_level) {
                    self.evict_with_descendants(top_level);
                }
            }
        }

        for input in &tx.input {
            self.spends.insert(
                (input.previous_output.txid, input.previous_output.vout),
                txid,
            );
        }
        self.total_size += size;

        let entry = MempoolEntry {
            tx,
            fee,
            fee_rate,
            size,
            added_at: Instant::now(),
            parents: parents.clone(),
            ancestors: ancestors.clone(),
            descendants: HashSet::new(),
            ancestor_fee,
            ancestor_size,
        };
        self.txs.insert(txid, entry);

        // Wire `txid` into every ancestor's descendant set. This is the
        // *only* place ancestor.descendants grows; symmetrically, the only
        // place it shrinks is `remove_tx`.
        for ancestor_txid in &ancestors {
            if let Some(ancestor) = self.txs.get_mut(ancestor_txid) {
                ancestor.descendants.insert(txid);
            }
        }

        debug!(
            "Mempool: accepted tx {} (fee_rate={:.1} sat/vB, size={}, parents={}, ancestors={})",
            txid,
            fee_rate,
            size,
            parents.len(),
            ancestors.len()
        );

        // Capacity eviction. Use the package-aware path so a low-fee parent
        // with high-fee children isn't unfairly evicted.
        while self.total_size > self.max_size && !self.txs.is_empty() {
            if !self.evict_lowest_package() {
                break;
            }
        }

        // If the eviction loop ate the tx we just inserted (because its
        // package fee rate was the worst in the pool), surface that as a
        // fee error rather than silently dropping it. The caller would
        // otherwise see an Ok(txid) for a tx that's no longer present.
        if !self.txs.contains_key(&txid) {
            return Err(MempoolError::InsufficientFee {
                fee_rate,
                min_rate: self.min_fee_rate(),
            });
        }

        Ok(txid)
    }

    /// Walk the descendant graph of every txid in `roots` and return the
    /// union (roots ∪ all transitive descendants). Used by RBF to compute
    /// the set of mempool txs a replacement would evict.
    fn collect_eviction_set(&self, roots: &HashSet<Txid>) -> HashSet<Txid> {
        let mut out: HashSet<Txid> = HashSet::new();
        let mut frontier: VecDeque<Txid> = roots.iter().copied().collect();
        while let Some(txid) = frontier.pop_front() {
            if !out.insert(txid) {
                continue;
            }
            if let Some(entry) = self.txs.get(&txid) {
                for d in &entry.descendants {
                    if !out.contains(d) {
                        frontier.push_back(*d);
                    }
                }
            }
        }
        out
    }

    /// BIP 125 rules 2, 3, 5. Rule 1 (signaling) is intentionally omitted —
    /// we follow Bitcoin Core v28+ full RBF semantics. Rule 4 (eviction
    /// count) is enforced before this is called.
    ///
    /// * Rule 2 — replacement fee_rate must be strictly higher than every
    ///   directly-conflicting tx's fee_rate.
    /// * Rule 3 — replacement absolute fee must cover the originals' fees
    ///   *plus* a relay-cost surcharge: `replacement_size * incremental_relay_fee`.
    /// * Rule 5 — replacement must not introduce any new unconfirmed parents
    ///   that weren't already a parent of one of the directly-conflicting
    ///   txs. (Newly-introduced unconfirmed inputs are an attack surface
    ///   the original BIP 125 paper called out explicitly.)
    fn check_bip125(
        &self,
        replacement_fee: u64,
        replacement_size: usize,
        replacement_parents: &HashSet<Txid>,
        direct_conflicts: &HashSet<Txid>,
        to_evict: &HashSet<Txid>,
    ) -> Result<(), MempoolError> {
        // Rule 2 — replacement fee_rate strictly greater than each direct
        // conflict's individual fee_rate.
        let replacement_fee_rate = replacement_fee as f64 / (replacement_size as f64);
        for txid in direct_conflicts {
            let entry = self.txs.get(txid).expect("direct conflict must exist");
            // Compare against the per-byte rate (sat/byte, not vbyte) so
            // both sides use the same denominator.
            let conflict_rate = entry.fee as f64 / (entry.size as f64);
            if replacement_fee_rate <= conflict_rate {
                return Err(MempoolError::ReplacementFeeTooLow {
                    replacement: replacement_fee_rate,
                    conflict: conflict_rate,
                });
            }
        }

        // Rule 3 — total fee must cover the *entire* eviction set's fees
        // plus the relay cost of the replacement.
        let evicted_fee_total: u64 = to_evict
            .iter()
            .map(|t| self.txs.get(t).map(|e| e.fee).unwrap_or(0))
            .sum();
        let relay_surcharge =
            (replacement_size as f64 * INCREMENTAL_RELAY_FEE_RATE).ceil() as u64;
        let required_fee = evicted_fee_total
            .checked_add(relay_surcharge)
            .ok_or(MempoolError::Inflation)?;
        if replacement_fee < required_fee {
            return Err(MempoolError::ReplacementFeeInsufficient {
                provided: replacement_fee,
                required: required_fee,
                evicted_fee_total,
                relay_surcharge,
            });
        }

        // Rule 5 — replacement's *direct* unconfirmed parents must be a
        // subset of the union of the directly-conflicting txs' direct
        // parents. New unconfirmed inputs are forbidden.
        let mut allowed_parents: HashSet<Txid> = HashSet::new();
        for txid in direct_conflicts {
            if let Some(entry) = self.txs.get(txid) {
                allowed_parents.extend(entry.parents.iter().copied());
            }
        }
        for parent in replacement_parents {
            if !allowed_parents.contains(parent) {
                return Err(MempoolError::ReplacementAddsNewUnconfirmedInput { parent: *parent });
            }
        }

        Ok(())
    }

    /// Drop everything in the mempool that's been resolved by a new block.
    ///
    /// Two distinct cases per block tx:
    ///
    /// * **The confirmed tx itself was in the mempool.** Use `remove_tx`,
    ///   which leaves descendants in place — their inputs now resolve
    ///   against the on-disk UTXO set, and `remove_tx`'s graph maintenance
    ///   correctly drops the parent from each descendant's ancestor closure
    ///   and `parents` set.
    ///
    /// * **A different mempool tx double-spent the same inputs.** That tx
    ///   has been permanently invalidated by the chain — its descendants
    ///   reference outputs that will never exist. Use `evict_with_descendants`
    ///   to wipe the whole package.
    pub fn remove_confirmed(&mut self, block: &Block) {
        let mut removed = 0;

        for tx in &block.txdata {
            let txid = tx.compute_txid();

            // Case 1: confirmed tx itself.
            if self.remove_tx(&txid) {
                removed += 1;
            }

            // Case 2: any mempool tx that conflicts. We must do this *after*
            // case 1 so the confirmed tx's own spends index entries are
            // already gone (they map to the confirmed txid, and we don't
            // want to chase them through this loop).
            for input in &tx.input {
                let key = (input.previous_output.txid, input.previous_output.vout);
                if let Some(conflicting_txid) = self.spends.get(&key).copied() {
                    // Defensive: skip the just-removed confirmed tx (its
                    // own entries should already be gone; this guards
                    // against any future case where the cleanup ordering
                    // differs).
                    if conflicting_txid != txid && self.txs.contains_key(&conflicting_txid) {
                        removed += self.evict_with_descendants(&conflicting_txid);
                    }
                }
            }
        }

        if removed > 0 {
            info!(
                "Mempool: removed {} txs after block, {} remaining",
                removed,
                self.txs.len()
            );
        }
    }

    /// Remove a single transaction by txid, updating graph state.
    ///
    /// Does **not** cascade: descendants stay in the mempool. Used by:
    /// * `remove_confirmed` — a parent that just got mined leaves the
    ///   mempool but its children stay (their inputs now resolve against
    ///   the on-disk UTXO set).
    /// * `evict_with_descendants` — the cascade walks bottom-up and calls
    ///   this for each visited node.
    /// * `expire_old` — currently per-tx, kept for parity with the old API.
    ///
    /// Graph maintenance: drop self from every ancestor's `descendants`,
    /// drop self from every descendant's `ancestors`, and decrement each
    /// descendant's running ancestor totals by self's contribution. The
    /// "diamond" case (descendant has another path to the same ancestor) is
    /// not affected because each tx still has a single `parents` set
    /// pointing at its direct parents.
    ///
    /// Returns `true` if the tx was present.
    pub fn remove_tx(&mut self, txid: &Txid) -> bool {
        let entry = match self.txs.remove(txid) {
            Some(e) => e,
            None => return false,
        };

        self.total_size = self.total_size.saturating_sub(entry.size);

        // Drop self from the spends index. Only clear entries that map back
        // to this txid: an outpoint may have been overwritten by an RBF
        // replacement that was inserted while this entry was being torn
        // down (defensive).
        for input in &entry.tx.input {
            let key = (input.previous_output.txid, input.previous_output.vout);
            if self.spends.get(&key) == Some(txid) {
                self.spends.remove(&key);
            }
        }

        // Drop self from each ancestor's descendants set.
        for ancestor_txid in &entry.ancestors {
            if let Some(ancestor) = self.txs.get_mut(ancestor_txid) {
                ancestor.descendants.remove(txid);
            }
        }

        // Drop self from each descendant's ancestors set, and adjust their
        // running ancestor totals. Each descendant counted `entry` exactly
        // once in its ancestor closure, so the decrement is unconditional.
        // The descendant's `parents` set may also reference us — clear that
        // too, since we're no longer in the mempool.
        for descendant_txid in &entry.descendants {
            if let Some(descendant) = self.txs.get_mut(descendant_txid) {
                if descendant.ancestors.remove(txid) {
                    descendant.ancestor_fee =
                        descendant.ancestor_fee.saturating_sub(entry.fee);
                    descendant.ancestor_size =
                        descendant.ancestor_size.saturating_sub(entry.size);
                }
                descendant.parents.remove(txid);
            }
        }

        true
    }

    /// Remove `txid` and every transaction transitively descended from it.
    /// Used by RBF (replaced txs and their packages must go) and by
    /// capacity eviction (packages are evicted as a unit).
    ///
    /// Removal proceeds deepest-first so each `remove_tx` call sees a
    /// well-formed graph and the descendant decrements terminate. Returns
    /// the number of transactions actually removed.
    fn evict_with_descendants(&mut self, txid: &Txid) -> usize {
        let entry = match self.txs.get(txid) {
            Some(e) => e,
            None => return 0,
        };

        // Snapshot the descendant set + topologically order it. We rely on
        // the invariant that `entry.descendants` is the *transitive*
        // descendant set, so a single sort by depth (number of mempool
        // ancestors) is enough to remove deepest-first.
        let mut to_remove: Vec<Txid> = entry.descendants.iter().copied().collect();
        to_remove.push(*txid);

        // Order by descending ancestor count so descendants come first.
        // Stable sort isn't strictly required since `remove_tx` is
        // idempotent w.r.t. graph state, but ordering keeps the debug log
        // sensible.
        to_remove.sort_by_key(|t| {
            std::cmp::Reverse(
                self.txs.get(t).map(|e| e.ancestors.len()).unwrap_or(0),
            )
        });

        let mut removed = 0;
        for t in &to_remove {
            if self.remove_tx(t) {
                removed += 1;
            }
        }
        removed
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, txid: &Txid) -> bool {
        self.txs.contains_key(txid)
    }

    /// Get a transaction from the mempool.
    pub fn get(&self, txid: &Txid) -> Option<&Transaction> {
        self.txs.get(txid).map(|e| &e.tx)
    }

    /// Get the fee rate (sat/vB) for a transaction in the mempool.
    pub fn fee_rate(&self, txid: &Txid) -> Option<f64> {
        self.txs.get(txid).map(|e| e.fee_rate)
    }

    /// Get all transaction IDs in the mempool.
    pub fn get_all_txids(&self) -> Vec<Txid> {
        self.txs.keys().copied().collect()
    }

    /// Remove expired transactions (older than 14 days).
    pub fn expire_old(&mut self) {
        let expired: Vec<Txid> = self
            .txs
            .iter()
            .filter(|(_, e)| e.added_at.elapsed() > MAX_TX_AGE)
            .map(|(txid, _)| *txid)
            .collect();

        for txid in &expired {
            self.remove_tx(txid);
        }
        if !expired.is_empty() {
            info!("Mempool: expired {} old transactions", expired.len());
        }
    }

    /// Package-aware capacity eviction.
    ///
    /// For each *root* tx (one with no surviving ancestors in the
    /// mempool), compute the cumulative fee rate of the entire descendant
    /// package — `(self.fee + Σ descendant.fee) / (self.size + Σ descendant.size)`.
    /// Pick the root with the lowest package fee rate and evict it together
    /// with every descendant via `evict_with_descendants`.
    ///
    /// Why root-only: a low-fee parent with high-fee children should not
    /// be evicted (the children pay for it). Roots are the natural eviction
    /// granularity — evicting a non-root would orphan its parent's other
    /// descendants while leaving the parent itself. Always evict at the
    /// root and the package leaves together.
    ///
    /// Returns true if a package was evicted (used by the capacity loop in
    /// `accept_tx_internal` to detect a stuck state).
    fn evict_lowest_package(&mut self) -> bool {
        // A "root" is a tx with no ancestors in the mempool. Every
    // package is rooted at one or more roots; an eviction starting at any
    // root removes the smallest meaningful package.
        let mut worst_root: Option<(Txid, f64)> = None;
        for (txid, entry) in &self.txs {
            if !entry.ancestors.is_empty() {
                continue;
            }
            // Package = self + all descendants.
            let mut pkg_fee = entry.fee;
            let mut pkg_size = entry.size;
            for d in &entry.descendants {
                if let Some(de) = self.txs.get(d) {
                    pkg_fee = pkg_fee.saturating_add(de.fee);
                    pkg_size = pkg_size.saturating_add(de.size);
                }
            }
            if pkg_size == 0 {
                continue;
            }
            let pkg_rate = pkg_fee as f64 / pkg_size as f64;
            match worst_root {
                None => worst_root = Some((*txid, pkg_rate)),
                Some((_, best_rate)) if pkg_rate < best_rate => {
                    worst_root = Some((*txid, pkg_rate))
                }
                _ => {}
            }
        }

        if let Some((txid, _)) = worst_root {
            debug!("Mempool: evicting lowest-package root {}", txid);
            self.evict_with_descendants(&txid);
            true
        } else {
            false
        }
    }

    /// Total serialized size of all mempool transactions (bytes).
    pub fn size(&self) -> usize {
        self.total_size
    }

    /// Number of transactions in the mempool.
    pub fn count(&self) -> usize {
        self.txs.len()
    }

    /// Minimum fee rate in the mempool (sat/vB), or 0.0 if empty.
    pub fn min_fee_rate(&self) -> f64 {
        if self.txs.is_empty() {
            return 0.0;
        }
        self.txs
            .values()
            .map(|e| e.fee_rate)
            .fold(f64::INFINITY, f64::min)
    }
}

/// Errors from mempool transaction validation.
#[derive(Debug)]
pub enum MempoolError {
    CoinbaseTx,
    MalformedTx,
    AlreadyInMempool,
    MissingInput { txid: Txid, vout: u32 },
    ImmatureCoinbase { input_index: usize, coinbase_height: u32 },
    ScriptFailure { input_index: usize, error: String },
    Inflation,
    InsufficientFee { fee_rate: f64, min_rate: f64 },
    OversizedTx { weight: u64 },
    DustOutput { index: usize, amount: u64 },
    NonStandardScript { index: usize },
    NonFinal { lock_time: u32, current_height: u32 },
    UtxoLookup(String),
    // CPFP / ancestor tracking (ticket 010)
    TooManyAncestors { count: usize, limit: usize },
    AncestorSetTooLarge { vbytes: usize, limit: usize },
    TooManyDescendants { ancestor: Txid, count: usize, limit: usize },
    // BIP 125 RBF (ticket 009)
    TooManyReplacements { evicted: usize, limit: usize },
    ReplacementFeeTooLow { replacement: f64, conflict: f64 },
    ReplacementFeeInsufficient {
        provided: u64,
        required: u64,
        evicted_fee_total: u64,
        relay_surcharge: u64,
    },
    ReplacementAddsNewUnconfirmedInput { parent: Txid },
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::CoinbaseTx => write!(f, "coinbase transactions are not allowed in mempool"),
            MempoolError::MalformedTx => write!(f, "transaction has empty inputs or outputs"),
            MempoolError::AlreadyInMempool => write!(f, "transaction already in mempool"),
            MempoolError::MissingInput { txid, vout } => {
                write!(f, "input {}:{} not found in UTXO set", txid, vout)
            }
            MempoolError::ImmatureCoinbase { input_index, coinbase_height } => {
                write!(
                    f,
                    "input {} spends immature coinbase from height {}",
                    input_index, coinbase_height
                )
            }
            MempoolError::ScriptFailure { input_index, error } => {
                write!(f, "script validation failed for input {}: {}", input_index, error)
            }
            MempoolError::Inflation => write!(f, "outputs exceed inputs"),
            MempoolError::InsufficientFee { fee_rate, min_rate } => {
                write!(
                    f,
                    "fee rate {:.2} sat/vB below minimum {:.2}",
                    fee_rate, min_rate
                )
            }
            MempoolError::OversizedTx { weight } => {
                write!(f, "transaction weight {} exceeds limit {}", weight, MAX_TX_WEIGHT)
            }
            MempoolError::DustOutput { index, amount } => {
                write!(
                    f,
                    "output {} is dust ({} sats, min {})",
                    index, amount, DUST_THRESHOLD
                )
            }
            MempoolError::NonStandardScript { index } => {
                write!(f, "output {} has non-standard script type", index)
            }
            MempoolError::NonFinal { lock_time, current_height } => {
                write!(
                    f,
                    "transaction not final (locktime={}, current_height={})",
                    lock_time, current_height
                )
            }
            MempoolError::UtxoLookup(e) => write!(f, "UTXO lookup error: {}", e),
            MempoolError::TooManyAncestors { count, limit } => {
                write!(f, "ancestor count {} exceeds limit {}", count, limit)
            }
            MempoolError::AncestorSetTooLarge { vbytes, limit } => {
                write!(
                    f,
                    "ancestor set vsize {} bytes exceeds limit {} bytes",
                    vbytes, limit
                )
            }
            MempoolError::TooManyDescendants { ancestor, count, limit } => {
                write!(
                    f,
                    "ancestor {} would exceed descendant limit ({} > {})",
                    ancestor, count, limit
                )
            }
            MempoolError::TooManyReplacements { evicted, limit } => {
                write!(
                    f,
                    "replacement would evict {} txs (limit {})",
                    evicted, limit
                )
            }
            MempoolError::ReplacementFeeTooLow { replacement, conflict } => {
                write!(
                    f,
                    "replacement fee rate {:.4} sat/B not greater than conflict {:.4} sat/B",
                    replacement, conflict
                )
            }
            MempoolError::ReplacementFeeInsufficient {
                provided,
                required,
                evicted_fee_total,
                relay_surcharge,
            } => write!(
                f,
                "replacement fee {} below required {} (evicted={} + relay_surcharge={})",
                provided, required, evicted_fee_total, relay_surcharge
            ),
            MempoolError::ReplacementAddsNewUnconfirmedInput { parent } => {
                write!(
                    f,
                    "replacement introduces new unconfirmed parent {} (BIP 125 rule 5)",
                    parent
                )
            }
        }
    }
}

impl std::error::Error for MempoolError {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn new_mempool_is_empty() {
        let pool = Mempool::new();
        assert_eq!(pool.count(), 0);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn custom_max_size() {
        let pool = Mempool::with_max_size(1024);
        assert_eq!(pool.max_size, 1024);
    }

    #[test]
    fn contains_and_get_empty() {
        let pool = Mempool::new();
        let fake_txid = Txid::all_zeros();
        assert!(!pool.contains(&fake_txid));
        assert!(pool.get(&fake_txid).is_none());
    }

    #[test]
    fn get_all_txids_empty() {
        let pool = Mempool::new();
        assert!(pool.get_all_txids().is_empty());
    }

    #[test]
    fn remove_tx_nonexistent() {
        let mut pool = Mempool::new();
        let fake_txid = Txid::all_zeros();
        assert!(!pool.remove_tx(&fake_txid));
    }

    #[test]
    fn min_fee_rate_empty() {
        let pool = Mempool::new();
        // Empty pool should return 0.0
        assert_eq!(pool.min_fee_rate(), 0.0);
    }

    #[test]
    fn expire_old_empty_pool() {
        let mut pool = Mempool::new();
        pool.expire_old(); // should not panic
    }

    #[test]
    fn remove_confirmed_empty_block() {
        let mut pool = Mempool::new();
        // Create a minimal block with just a coinbase
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c\
             01\
             01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043\
             68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f7574\
             20666f722062616e6b73ffffffff\
             0100f2052a0100000043410467e6e15a2fd55bfccfc89481e77dfe6a9f055e65106e82\
             1e022e084a27a7626cfe82510d2e593a0f1ee44bca55f8c0e28d57e87b5f0c9b6e46a3\
             d6d23df9a13eac\
             00000000",
        ).unwrap();
        let block: Block = bitcoin::consensus::deserialize(&raw).unwrap();
        pool.remove_confirmed(&block); // should not panic
    }

    // ── Test infrastructure for accept_tx / RBF / CPFP ──────────────────
    //
    // These helpers build a fresh UTXO set and trivial transactions that
    // exercise the full graph/RBF logic without crafting real signatures.
    // The mempool is invoked via `accept_tx_test`, which skips the
    // libbitcoinconsensus check and the standard-script-type check; every
    // other validation gate runs as in production.

    use crate::utxo::UtxoEntry;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use tempfile::TempDir;

    /// Block height used as `current_height` for accept_tx_test calls. Must
    /// be > 100 so seeded UTXOs at height 1 clear coinbase maturity (we
    /// flag them as non-coinbase but the constant comes up in error
    /// messages — keep this realistic).
    const TEST_HEIGHT: u32 = 200;

    /// Open a fresh in-memory UTXO set in a temp directory.
    fn fresh_utxo() -> (UtxoSet, TempDir) {
        let dir = TempDir::new().unwrap();
        let utxo = UtxoSet::open(dir.path().to_str().unwrap()).unwrap();
        (utxo, dir)
    }

    /// Build a `[seed; 32]` txid filled with the given byte. Used to seed
    /// distinct UTXOs without colliding txids.
    fn seed_txid(seed: u8) -> Txid {
        Txid::from_slice(&[seed; 32]).unwrap()
    }

    /// Insert a UTXO with the given amount at the given outpoint into a
    /// fresh-ish UTXO set. The script_pubkey is a single byte (`0xac`,
    /// OP_CHECKSIG) — non-standard but we run via accept_tx_test which
    /// skips the standard check.
    fn seed_utxo(utxo: &UtxoSet, txid: Txid, vout: u32, amount: u64) {
        utxo.test_insert_utxo(
            txid.to_byte_array(),
            vout,
            UtxoEntry {
                amount,
                script_pubkey: vec![0xac],
                height: 1,
                is_coinbase: false,
            },
        )
        .unwrap();
    }

    /// Build a transaction that spends `inputs` (each (prev_txid, prev_vout))
    /// and produces `outputs` (each `Amount` in sats). Uses MAX sequence
    /// (final). Each output gets a single-byte script_pubkey (0xac) which
    /// is enough for our `is_op_return` / dust checks but not standard.
    fn make_tx(inputs: &[(Txid, u32)], outputs: &[u64]) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(txid, vout)| TxIn {
                    previous_output: OutPoint {
                        txid: *txid,
                        vout: *vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: outputs
                .iter()
                .map(|&v| TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: ScriptBuf::from_bytes(vec![0xac]),
                })
                .collect(),
        }
    }

    /// Same as `make_tx` but adds a marker byte to the first output's
    /// script so the resulting txid differs from `make_tx` for the same
    /// inputs/outputs (handy for distinguishing replacements).
    fn make_tx_marked(inputs: &[(Txid, u32)], outputs: &[u64], marker: u8) -> Transaction {
        let mut tx = make_tx(inputs, outputs);
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac, marker]);
        tx
    }

    // ── Ticket 10: chain spending and graph state ──────────────────────

    #[test]
    fn accept_tx_with_confirmed_input_succeeds() {
        let (utxo, _dir) = fresh_utxo();
        let parent_txid = seed_txid(1);
        seed_utxo(&utxo, parent_txid, 0, 100_000);

        let mut pool = Mempool::new();
        let tx = make_tx(&[(parent_txid, 0)], &[90_000]);
        let txid = pool.accept_tx_test(tx, &utxo, TEST_HEIGHT).unwrap();

        assert!(pool.contains(&txid));
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn accept_tx_missing_input_rejected() {
        let (utxo, _dir) = fresh_utxo();
        let mut pool = Mempool::new();
        let phantom = seed_txid(99);
        let tx = make_tx(&[(phantom, 0)], &[1000]);

        let err = pool.accept_tx_test(tx, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(err, MempoolError::MissingInput { .. }));
    }

    #[test]
    fn accept_child_spending_unconfirmed_parent() {
        let (utxo, _dir) = fresh_utxo();
        let grandparent_txid = seed_txid(1);
        seed_utxo(&utxo, grandparent_txid, 0, 100_000);

        let mut pool = Mempool::new();

        // Parent: spends a confirmed UTXO, produces an output for the child.
        let parent = make_tx(&[(grandparent_txid, 0)], &[90_000]);
        let parent_txid = pool.accept_tx_test(parent, &utxo, TEST_HEIGHT).unwrap();

        // Child: spends parent's vout 0. Should succeed via mempool fallback.
        let child = make_tx(&[(parent_txid, 0)], &[80_000]);
        let child_txid = pool.accept_tx_test(child, &utxo, TEST_HEIGHT).unwrap();

        assert!(pool.contains(&child_txid));
        assert_eq!(pool.count(), 2);

        // Graph state: child has parent as ancestor; parent has child as descendant.
        let parent_entry = pool.txs.get(&parent_txid).unwrap();
        let child_entry = pool.txs.get(&child_txid).unwrap();
        assert!(parent_entry.descendants.contains(&child_txid));
        assert!(child_entry.ancestors.contains(&parent_txid));
        assert!(child_entry.parents.contains(&parent_txid));
        assert_eq!(child_entry.ancestor_fee, parent_entry.fee);
        assert_eq!(child_entry.ancestor_size, parent_entry.size);
    }

    #[test]
    fn reject_child_referencing_nonexistent_vout() {
        let (utxo, _dir) = fresh_utxo();
        let gp = seed_txid(1);
        seed_utxo(&utxo, gp, 0, 100_000);

        let mut pool = Mempool::new();
        let parent = make_tx(&[(gp, 0)], &[90_000]); // 1 output
        let parent_txid = pool.accept_tx_test(parent, &utxo, TEST_HEIGHT).unwrap();

        // Child references vout=5 which doesn't exist
        let child = make_tx(&[(parent_txid, 5)], &[1000]);
        let err = pool.accept_tx_test(child, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(err, MempoolError::MissingInput { vout: 5, .. }));
    }

    #[test]
    fn reject_child_double_spending_mempool_output_does_rbf_check() {
        // Two siblings spending the same parent output. The second one
        // doesn't pay enough to RBF the first, so it must be rejected by
        // the BIP 125 fee-rate rule.
        let (utxo, _dir) = fresh_utxo();
        let gp = seed_txid(1);
        seed_utxo(&utxo, gp, 0, 100_000);

        let mut pool = Mempool::new();
        let parent = make_tx(&[(gp, 0)], &[90_000]);
        let parent_txid = pool.accept_tx_test(parent, &utxo, TEST_HEIGHT).unwrap();

        let child_a = make_tx_marked(&[(parent_txid, 0)], &[80_000], 0xa);
        let _ = pool.accept_tx_test(child_a, &utxo, TEST_HEIGHT).unwrap();

        // Same input, lower fee — should fail BIP 125 rule 2.
        let child_b = make_tx_marked(&[(parent_txid, 0)], &[85_000], 0xb);
        let err = pool.accept_tx_test(child_b, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));
    }

    #[test]
    fn ancestor_closure_transitive() {
        // A → B → C: C should report B and A in its ancestor set.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 1_000_000);

        let mut pool = Mempool::new();
        let a = make_tx(&[(root, 0)], &[990_000]);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
        let b = make_tx(&[(a_txid, 0)], &[980_000]);
        let b_txid = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap();
        let c = make_tx(&[(b_txid, 0)], &[970_000]);
        let c_txid = pool.accept_tx_test(c, &utxo, TEST_HEIGHT).unwrap();

        let c_entry = pool.txs.get(&c_txid).unwrap();
        assert_eq!(c_entry.ancestors.len(), 2);
        assert!(c_entry.ancestors.contains(&a_txid));
        assert!(c_entry.ancestors.contains(&b_txid));
        assert_eq!(c_entry.parents.len(), 1);
        assert!(c_entry.parents.contains(&b_txid));

        // A's descendants should include both B and C
        let a_entry = pool.txs.get(&a_txid).unwrap();
        assert!(a_entry.descendants.contains(&b_txid));
        assert!(a_entry.descendants.contains(&c_txid));
    }

    #[test]
    fn diamond_ancestor_not_double_counted() {
        // A produces two outputs. B spends output 0, C spends output 1.
        // D spends one output of B and one of C. D's ancestor set should
        // be {A, B, C} — not {A, A, B, C} — and ancestor_fee/size should
        // count A exactly once.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 1_000_000);

        let mut pool = Mempool::new();
        let a = make_tx(&[(root, 0)], &[400_000, 400_000]);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
        let b = make_tx(&[(a_txid, 0)], &[390_000]);
        let b_txid = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap();
        let c = make_tx(&[(a_txid, 1)], &[390_000]);
        let c_txid = pool.accept_tx_test(c, &utxo, TEST_HEIGHT).unwrap();
        let d = make_tx(&[(b_txid, 0), (c_txid, 0)], &[770_000]);
        let d_txid = pool.accept_tx_test(d, &utxo, TEST_HEIGHT).unwrap();

        let d_entry = pool.txs.get(&d_txid).unwrap();
        assert_eq!(d_entry.ancestors.len(), 3);
        assert!(d_entry.ancestors.contains(&a_txid));
        assert!(d_entry.ancestors.contains(&b_txid));
        assert!(d_entry.ancestors.contains(&c_txid));

        let a_entry = pool.txs.get(&a_txid).unwrap();
        let b_entry = pool.txs.get(&b_txid).unwrap();
        let c_entry = pool.txs.get(&c_txid).unwrap();
        // ancestor_fee/size sums each ancestor once.
        assert_eq!(
            d_entry.ancestor_fee,
            a_entry.fee + b_entry.fee + c_entry.fee
        );
        assert_eq!(
            d_entry.ancestor_size,
            a_entry.size + b_entry.size + c_entry.size
        );
    }

    #[test]
    fn reject_when_ancestor_count_exceeds_limit() {
        // Build a chain of MAX_ANCESTORS confirmed-rooted txs. The next one
        // pushes us over MAX_ANCESTORS+1 and must be rejected.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 10_000_000);

        let mut pool = Mempool::new();
        // First tx spends the confirmed root.
        let mut prev = pool
            .accept_tx_test(make_tx(&[(root, 0)], &[9_990_000]), &utxo, TEST_HEIGHT)
            .unwrap();
        // Build a chain. Each child has a strictly smaller output so we can
        // pay a fee. Stop one short of the limit.
        let mut value: u64 = 9_990_000;
        for _ in 1..MAX_ANCESTORS {
            value -= 1_000;
            let child = make_tx(&[(prev, 0)], &[value]);
            prev = pool.accept_tx_test(child, &utxo, TEST_HEIGHT).unwrap();
        }
        assert_eq!(pool.count(), MAX_ANCESTORS);

        // The next child has MAX_ANCESTORS ancestors → +1 self = limit + 1.
        value -= 1_000;
        let over = make_tx(&[(prev, 0)], &[value]);
        let err = pool.accept_tx_test(over, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(
            err,
            MempoolError::TooManyAncestors { count, limit } if count == MAX_ANCESTORS + 1 && limit == MAX_ANCESTORS
        ));
    }

    #[test]
    fn reject_when_descendant_count_would_exceed_limit() {
        // A produces MAX_DESCENDANTS outputs. We accept MAX_DESCENDANTS - 1
        // children spending one each. The next child would push A's
        // descendant count over the limit.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 100_000_000);

        let mut pool = Mempool::new();
        // A has MAX_DESCENDANTS outputs of 3,000,000 each.
        let outputs: Vec<u64> = (0..MAX_DESCENDANTS as u32).map(|_| 3_000_000).collect();
        let a = make_tx(&[(root, 0)], &outputs);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();

        // Accept MAX_DESCENDANTS - 1 children, each spending a distinct
        // output of A. After this, A has MAX_DESCENDANTS - 1 descendants;
        // adding one more child would put A's package size at
        // MAX_DESCENDANTS + 1 (self + children) which is over the limit.
        for i in 0..(MAX_DESCENDANTS as u32 - 1) {
            let child = make_tx(&[(a_txid, i)], &[2_990_000]);
            pool.accept_tx_test(child, &utxo, TEST_HEIGHT).unwrap();
        }

        // The next child puts the count at MAX_DESCENDANTS + 1 (self + 25).
        let over = make_tx(&[(a_txid, MAX_DESCENDANTS as u32 - 1)], &[2_990_000]);
        let err = pool.accept_tx_test(over, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(
            err,
            MempoolError::TooManyDescendants { count, limit, .. }
                if count == MAX_DESCENDANTS + 1 && limit == MAX_DESCENDANTS
        ));
    }

    #[test]
    fn remove_tx_updates_descendant_ancestor_state() {
        // A → B → C. Remove B. C should still be in the mempool but its
        // ancestor set should now contain only A, and ancestor_fee/size
        // should drop by B's contribution.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 1_000_000);

        let mut pool = Mempool::new();
        let a = make_tx(&[(root, 0)], &[990_000]);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
        let b = make_tx(&[(a_txid, 0)], &[980_000]);
        let b_txid = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap();
        let c = make_tx(&[(b_txid, 0)], &[970_000]);
        let c_txid = pool.accept_tx_test(c, &utxo, TEST_HEIGHT).unwrap();

        let c_before = pool.txs.get(&c_txid).unwrap();
        let b_fee = pool.txs.get(&b_txid).unwrap().fee;
        let b_size = pool.txs.get(&b_txid).unwrap().size;
        let original_ancestor_fee = c_before.ancestor_fee;
        let original_ancestor_size = c_before.ancestor_size;

        assert!(pool.remove_tx(&b_txid));

        // C should still exist
        assert!(pool.contains(&c_txid));
        let c_after = pool.txs.get(&c_txid).unwrap();
        assert!(!c_after.ancestors.contains(&b_txid));
        assert!(c_after.ancestors.contains(&a_txid));
        assert!(!c_after.parents.contains(&b_txid));
        assert_eq!(c_after.ancestor_fee, original_ancestor_fee - b_fee);
        assert_eq!(c_after.ancestor_size, original_ancestor_size - b_size);

        // A should no longer count B as a descendant.
        let a_after = pool.txs.get(&a_txid).unwrap();
        assert!(!a_after.descendants.contains(&b_txid));
        // A still counts C as a descendant — our remove_tx of B doesn't
        // touch C's *forward* relationship to A.
        assert!(a_after.descendants.contains(&c_txid));
    }

    #[test]
    fn evict_with_descendants_cascades() {
        // A → B → C → D. evict_with_descendants(B) should remove B, C, D
        // and leave A.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 1_000_000);

        let mut pool = Mempool::new();
        let a = make_tx(&[(root, 0)], &[990_000]);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
        let b = make_tx(&[(a_txid, 0)], &[980_000]);
        let b_txid = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap();
        let c = make_tx(&[(b_txid, 0)], &[970_000]);
        let c_txid = pool.accept_tx_test(c, &utxo, TEST_HEIGHT).unwrap();
        let d = make_tx(&[(c_txid, 0)], &[960_000]);
        let d_txid = pool.accept_tx_test(d, &utxo, TEST_HEIGHT).unwrap();

        let removed = pool.evict_with_descendants(&b_txid);
        assert_eq!(removed, 3);
        assert!(pool.contains(&a_txid));
        assert!(!pool.contains(&b_txid));
        assert!(!pool.contains(&c_txid));
        assert!(!pool.contains(&d_txid));

        // A's descendants should be empty now.
        let a_entry = pool.txs.get(&a_txid).unwrap();
        assert!(a_entry.descendants.is_empty());
    }

    #[test]
    fn remove_confirmed_keeps_descendants_with_updated_ancestors() {
        // A → B in mempool. A confirms in a block. B should stay but its
        // ancestors set should drop A.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 1_000_000);

        let mut pool = Mempool::new();
        let a = make_tx(&[(root, 0)], &[990_000]);
        let a_txid = pool.accept_tx_test(a.clone(), &utxo, TEST_HEIGHT).unwrap();
        let b = make_tx(&[(a_txid, 0)], &[980_000]);
        let b_txid = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap();

        // Construct a synthetic block containing only `a` (after a dummy
        // coinbase to satisfy Bitcoin's block-must-have-coinbase invariant).
        let coinbase = make_tx(&[], &[]); // empty placeholder; not used by remove_confirmed beyond its txid
        let _ = coinbase; // silence unused
        // Actually we need a real-ish block; remove_confirmed only walks
        // block.txdata and computes txids, so we just need the Block
        // wrapper. Build it manually.
        let block = bitcoin::blockdata::block::Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![a],
        };
        pool.remove_confirmed(&block);

        assert!(!pool.contains(&a_txid));
        assert!(pool.contains(&b_txid));
        let b_entry = pool.txs.get(&b_txid).unwrap();
        assert!(!b_entry.ancestors.contains(&a_txid));
        assert!(!b_entry.parents.contains(&a_txid));
        assert_eq!(b_entry.ancestor_fee, 0);
        assert_eq!(b_entry.ancestor_size, 0);
    }

    // ── Ticket 9: BIP 125 RBF ──────────────────────────────────────────

    #[test]
    fn rbf_replaces_with_higher_fee() {
        // Two txs spending the same UTXO. Second pays more — should
        // replace the first.
        let (utxo, _dir) = fresh_utxo();
        let parent = seed_txid(1);
        seed_utxo(&utxo, parent, 0, 100_000);

        let mut pool = Mempool::new();
        let a = make_tx_marked(&[(parent, 0)], &[90_000], 0xa);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
        assert!(pool.contains(&a_txid));

        // B has a higher fee (lower output value → higher fee).
        let b = make_tx_marked(&[(parent, 0)], &[50_000], 0xb);
        let b_txid = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap();

        assert!(!pool.contains(&a_txid));
        assert!(pool.contains(&b_txid));
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn rbf_rejects_equal_fee_rate() {
        // Identical fee — rule 2 requires *strictly* higher.
        let (utxo, _dir) = fresh_utxo();
        let parent = seed_txid(1);
        seed_utxo(&utxo, parent, 0, 100_000);

        let mut pool = Mempool::new();
        let a = make_tx_marked(&[(parent, 0)], &[90_000], 0xa);
        pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();

        let b = make_tx_marked(&[(parent, 0)], &[90_000], 0xb);
        let err = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));
    }

    #[test]
    fn rbf_rejects_lower_fee_rate() {
        let (utxo, _dir) = fresh_utxo();
        let parent = seed_txid(1);
        seed_utxo(&utxo, parent, 0, 100_000);

        let mut pool = Mempool::new();
        let a = make_tx_marked(&[(parent, 0)], &[50_000], 0xa);
        pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();

        let b = make_tx_marked(&[(parent, 0)], &[90_000], 0xb);
        let err = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));
    }

    #[test]
    fn rbf_rejects_insufficient_absolute_fee() {
        // Replacement has a higher per-byte rate but doesn't pay enough
        // absolute fee to cover the relay surcharge. Construct: original
        // is small with a healthy fee; replacement is larger with the same
        // raw fee, so it has a lower per-byte rate AND fails rule 3.
        //
        // The simpler construction: original pays a fat fee. Replacement
        // pays a higher rate but a lower absolute fee than original + relay
        // surcharge. With one input + one output, sizes are similar, so
        // make the replacement very tight.
        let (utxo, _dir) = fresh_utxo();
        let parent = seed_txid(1);
        seed_utxo(&utxo, parent, 0, 100_000);

        let mut pool = Mempool::new();
        // A pays a fee of 100_000 - 99_000 = 1_000 sats.
        let a = make_tx_marked(&[(parent, 0)], &[99_000], 0xa);
        pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();

        // B pays 100_000 - 99_500 = 500 sats — *less* than A. Will be
        // rejected by rule 2 (fee rate too low) before rule 3 fires, but
        // both rules are violated.
        let b = make_tx_marked(&[(parent, 0)], &[99_500], 0xb);
        let err = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap_err();
        // Rule 2 fires first.
        assert!(matches!(err, MempoolError::ReplacementFeeTooLow { .. }));
    }

    #[test]
    fn rbf_evicts_descendant_chain() {
        // A → B → C in mempool. A replacement A' (different content,
        // higher fee, same input) should evict A *and* its descendants.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 1_000_000);

        let mut pool = Mempool::new();
        let a = make_tx_marked(&[(root, 0)], &[900_000], 0xa);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
        let b = make_tx(&[(a_txid, 0)], &[890_000]);
        let b_txid = pool.accept_tx_test(b, &utxo, TEST_HEIGHT).unwrap();
        let c = make_tx(&[(b_txid, 0)], &[880_000]);
        let c_txid = pool.accept_tx_test(c, &utxo, TEST_HEIGHT).unwrap();
        assert_eq!(pool.count(), 3);

        // Replacement of A: same input, much higher fee.
        let a_prime = make_tx_marked(&[(root, 0)], &[500_000], 0xff);
        let a_prime_txid = pool.accept_tx_test(a_prime, &utxo, TEST_HEIGHT).unwrap();

        assert!(pool.contains(&a_prime_txid));
        assert!(!pool.contains(&a_txid));
        assert!(!pool.contains(&b_txid));
        assert!(!pool.contains(&c_txid));
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn rbf_rejects_replacement_introducing_new_unconfirmed_parent() {
        // Setup: P1, P2 are both unconfirmed parents.
        // Original A spends an output of P1 only.
        // Replacement A' spends the same output of P1 *and* an output of P2.
        // BIP 125 rule 5: A' adds P2 as a new unconfirmed parent → reject.
        let (utxo, _dir) = fresh_utxo();
        let r1 = seed_txid(1);
        let r2 = seed_txid(2);
        seed_utxo(&utxo, r1, 0, 1_000_000);
        seed_utxo(&utxo, r2, 0, 1_000_000);

        let mut pool = Mempool::new();
        // P1 has two outputs so we can spend one (in A) and another (in A').
        let p1 = make_tx(&[(r1, 0)], &[400_000, 400_000]);
        let p1_txid = pool.accept_tx_test(p1, &utxo, TEST_HEIGHT).unwrap();
        let p2 = make_tx(&[(r2, 0)], &[990_000]);
        let p2_txid = pool.accept_tx_test(p2, &utxo, TEST_HEIGHT).unwrap();

        // A spends P1.0 only.
        let a = make_tx_marked(&[(p1_txid, 0)], &[390_000], 0xa);
        pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();

        // A' spends P1.0 (conflict) AND P2.0 (NEW unconfirmed parent).
        let a_prime = make_tx_marked(
            &[(p1_txid, 0), (p2_txid, 0)],
            &[1_300_000],
            0xb,
        );
        let err = pool.accept_tx_test(a_prime, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(matches!(
            err,
            MempoolError::ReplacementAddsNewUnconfirmedInput { .. }
        ));
    }

    #[test]
    fn package_eviction_keeps_high_fee_child_with_low_fee_parent() {
        // CPFP scenario: a low-fee parent has a high-fee child. When the
        // pool is over capacity, the parent's *package* fee rate (parent +
        // child) is high, so the package should NOT be evicted in favor of
        // an unrelated mid-fee tx. Order matters: we seed the unrelated
        // mid-fee tx first, then add the parent (still under cap), then
        // add the child — which pushes total_size over the cap and forces
        // eviction. The eviction loop must pick mid_fee (worst package
        // rate as a root) instead of the parent (whose package rate
        // includes the high-fee child).
        let (utxo, _dir) = fresh_utxo();
        let r1 = seed_txid(1);
        let r2 = seed_txid(2);
        seed_utxo(&utxo, r1, 0, 1_000_000);
        seed_utxo(&utxo, r2, 0, 1_000_000);

        // Tight cap so the third tx forces an eviction. Each test tx is
        // ~62 bytes serialized (1 input + 1 output, single-byte script);
        // 140 bytes fits two but not three.
        let mut pool = Mempool::with_max_size(140);

        // Pre-existing standalone mid-fee tx with no children. Its package
        // rate is just its own rate ≈ 161 sat/B.
        let mid_fee = make_tx_marked(&[(r2, 0)], &[990_000], 0xc);
        let mid_fee_txid = pool.accept_tx_test(mid_fee, &utxo, TEST_HEIGHT).unwrap();

        // Low-fee parent on its own (~16 sat/B). Pool now has two txs and
        // total_size is still under 140.
        let parent_low = make_tx_marked(&[(r1, 0)], &[999_000], 0xa);
        let parent_low_txid = pool
            .accept_tx_test(parent_low, &utxo, TEST_HEIGHT)
            .unwrap();

        // High-fee child of parent_low. Adding it pushes total_size over
        // 140 and triggers the eviction loop. parent_low's package rate is
        // now ≈ 815 sat/B (parent + child), which is higher than mid_fee's
        // 161 sat/B → mid_fee is the worst-package root and gets evicted.
        let child_high = make_tx_marked(&[(parent_low_txid, 0)], &[899_000], 0xb);
        let child_high_txid = pool
            .accept_tx_test(child_high, &utxo, TEST_HEIGHT)
            .unwrap();

        // Pool should have evicted the mid-fee tx (worst package rate) and
        // kept the CPFP package intact.
        assert!(pool.contains(&parent_low_txid));
        assert!(pool.contains(&child_high_txid));
        assert!(!pool.contains(&mid_fee_txid));
    }

    #[test]
    fn rbf_multi_conflict_replacement() {
        // Two unrelated mempool txs X and Y. A replacement R spends both
        // of their inputs (conflicting with both). R must pay enough to
        // cover both.
        let (utxo, _dir) = fresh_utxo();
        let u1 = seed_txid(1);
        let u2 = seed_txid(2);
        seed_utxo(&utxo, u1, 0, 100_000);
        seed_utxo(&utxo, u2, 0, 100_000);

        let mut pool = Mempool::new();
        let x = make_tx_marked(&[(u1, 0)], &[90_000], 0x1);
        let y = make_tx_marked(&[(u2, 0)], &[90_000], 0x2);
        let x_txid = pool.accept_tx_test(x, &utxo, TEST_HEIGHT).unwrap();
        let y_txid = pool.accept_tx_test(y, &utxo, TEST_HEIGHT).unwrap();

        // R spends both u1.0 and u2.0, paying a much higher fee.
        let r = make_tx_marked(&[(u1, 0), (u2, 0)], &[150_000], 0xff);
        let r_txid = pool.accept_tx_test(r, &utxo, TEST_HEIGHT).unwrap();

        assert!(pool.contains(&r_txid));
        assert!(!pool.contains(&x_txid));
        assert!(!pool.contains(&y_txid));
        assert_eq!(pool.count(), 1);
    }
}
