use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use bitcoin::block::Block;
use bitcoin::consensus::serialize;
use bitcoin::{Transaction, Txid};

use log::{debug, info, warn};

use crate::chain_params::ChainParams;
use crate::contextual_checks::{
    calculate_sequence_locks, evaluate_sequence_locks, is_final_tx, median_time_past, HeaderTimes,
    MedianTimes,
};
use crate::script_verify;
use crate::utxo::{UtxoEntry, UtxoSet};

/// Default maximum mempool size: 50 MB of *serialized* transaction bytes.
///
/// The cap counts raw tx bytes (`MempoolEntry::size`), not resident memory.
/// Deserialized `Transaction`s plus the per-entry ancestor/descendant
/// `HashSet`s and the `spends` index cost roughly 2–3x that on the heap, so
/// 50 MB serialized is ~100–150 MB resident. That is about the most an iOS
/// app can hold without becoming a jetsam target, especially once
/// backgrounded: jetsam kills suspended apps largest-footprint-first, and
/// the foreground node keeps its mempool alive while suspended (background
/// wakes open a fresh node and never build one). Ticket 030 lowered this
/// from 150 MB.
///
/// 50 MB still covers typical mainnet occupancy (5–30 MB); under congestion
/// the pool fills and fee-rate evicts the cheapest packages, which only
/// affects what we relay at the low end, not block validation.
const DEFAULT_MAX_SIZE: usize = 50_000_000;

/// Minimum relay fee rate in sat/vB.
const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// Incremental relay fee rate (sat/vB), Bitcoin Core's
/// `DEFAULT_INCREMENTAL_RELAY_FEE` (1 sat/vB; ticket 053 keeps it). BIP 125
/// rule 3: a replacement must pay this much per byte over the sum of the
/// originals' fees. Capacity eviction: the rolling minimum fee rises to an
/// evicted package's rate plus this (`CTxMemPool::TrimToSize`).
const INCREMENTAL_RELAY_FEE_RATE: f64 = 1.0;

/// `INCREMENTAL_RELAY_FEE_RATE` in sat/kvB, the unit Core's rolling
/// minimum fee is kept in.
const INCREMENTAL_RELAY_FEE_PER_KVB: f64 = INCREMENTAL_RELAY_FEE_RATE * 1000.0;

/// Half-life of the rolling minimum fee's decay once a block has arrived
/// since it last rose (`CTxMemPool::ROLLING_FEE_HALFLIFE`, 12 hours);
/// halved again for a pool under half full, quartered under a quarter.
const ROLLING_FEE_HALFLIFE: Duration = Duration::from_secs(12 * 3600);

/// Removal events kept for [`Mempool::drain_removals`]. `HeaderSync`
/// drains after every mempool call, so this only bounds memory when
/// nobody does. Past it the oldest events that don't settle anything
/// (`RemovalReason::is_final` false) are dropped and counted; final ones
/// (a replacement, a block conflict) are never dropped, since an own tx
/// left out of one would stay "pending" for its whole expiry. ~70 bytes
/// each, and a call can only queue as many as it removed entries.
const MAX_QUEUED_REMOVALS: usize = 20_000;

/// Maximum standard transaction weight (400,000 WU).
const MAX_TX_WEIGHT: u64 = 400_000;

/// Coinbase maturity: 100 blocks before coinbase outputs are spendable.
const COINBASE_MATURITY: u32 = 100;

/// Bitcoin's MAX_MONEY in satoshis (CheckTransaction's MoneyRange bound).
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Maximum transaction expiry time (14 days).
const MAX_TX_AGE: std::time::Duration = std::time::Duration::from_secs(14 * 24 * 3600);

/// Dust relay fee in sat/kvB: Bitcoin Core's and Knots' `DUST_RELAY_TX_FEE`
/// (`-dustrelayfee` default). See [`dust_threshold`].
const DUST_RELAY_FEE_PER_KVB: u64 = 3_000;

/// Scripts longer than this are unspendable (`MAX_SCRIPT_SIZE`), so
/// `CScript::IsUnspendable` exempts them from the dust rule like OP_RETURN.
const MAX_SCRIPT_SIZE: usize = 10_000;

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

/// Anti-foot-shoot fee ceiling for the user's **own** transactions: one
/// whose absolute fee exceeds this is refused. Matches Bitcoin Core's
/// `-maxtxfee` default (0.1 BTC). The intent is to catch wallet bugs that
/// would burn the input value as fees. Core applies its cap only where the
/// local user broadcasts (`BroadcastTransaction`'s `max_tx_fee`), never to
/// relayed transactions, and neither do we: a high-fee exchange batch is
/// not ours to second-guess.
const ABSURD_FEE_THRESHOLD: u64 = 10_000_000;

/// Highest standard transaction version (`TX_MAX_STANDARD_VERSION` before
/// Core 28). Core 28+ and Knots also accept version 3 under the TRUC
/// rules (BIP 431); we don't implement TRUC, so a v3 tx is refused rather
/// than relayed without them. Stricter than Core 28+, deliberately.
const TX_MAX_STANDARD_VERSION: i32 = 2;

/// Largest standard scriptSig (`MAX_STANDARD_SCRIPTSIG_SIZE`): enough for
/// a 15-of-15 P2SH multisig spend.
const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

/// Largest standard sigop cost per transaction (`MAX_STANDARD_TX_SIGOPS_COST`
/// = `MAX_BLOCK_SIGOPS_COST / 5`), so one transaction can't fill a block's
/// sigop budget.
const MAX_STANDARD_TX_SIGOPS_COST: u64 = crate::contextual_checks::MAX_BLOCK_SIGOPS_COST / 5;

/// Smallest standard serialization without witness
/// (`MIN_STANDARD_TX_NONWITNESS_SIZE`, `tx-size-small`): a 64-byte
/// transaction could pass for an inner node of a block's merkle tree
/// (CVE-2017-12842), so Core relays nothing below 65 bytes.
const MIN_STANDARD_TX_NONWITNESS_SIZE: usize = 65;

/// Most sigops a P2SH redeem script may have (`MAX_P2SH_SIGOPS`), counted
/// accurately, so a spend can't pack a block's worth of CHECKMULTISIGs
/// into one input.
const MAX_P2SH_SIGOPS: u64 = 15;

/// Most legacy (non-witness) sigops one transaction may execute, counted
/// as BIP 54 does: in each scriptSig and in the scriptPubKey (or P2SH
/// redeem script) it spends (`MAX_TX_LEGACY_SIGOPS`, Core 30's
/// `CheckSigopsBIP54`). Bounds the quadratic legacy sighash cost.
const MAX_TX_LEGACY_SIGOPS: u64 = 2_500;

/// `IsWitnessStandard` limits: a P2WSH witness script of at most 3600
/// bytes with at most 100 stack items of at most 80 bytes each, and
/// tapscript stack items of at most 80 bytes.
const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3_600;
const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;
const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;

/// `EvalScript` limits that a push-only scriptSig can hit
/// (`MAX_SCRIPT_ELEMENT_SIZE`, `MAX_STACK_SIZE`).
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
const MAX_STACK_SIZE: usize = 1_000;

/// A transaction in the mempool with fee metadata and CPFP graph state.
///
/// `parents` and `ancestors` describe the unconfirmed parent chain (parents =
/// direct, ancestors = transitive); both omit `self`. `descendants` is the
/// transitive descendant set, also omitting self. `ancestor_fee` /
/// `ancestor_vsize` are the running sums over `ancestors` only — the
/// "self + ancestors" view used by limit checks adds `self.fee` / `self.vsize`
/// at the call site.
///
/// Two distinct sizes are tracked because they serve different purposes:
/// `size` is the raw serialized byte length and drives memory accounting
/// (`Mempool::total_size`, capped at `DEFAULT_MAX_SIZE`). `vsize` is the virtual size
/// (weight / 4, rounded up) and drives every fee-rate / policy decision
/// (BIP 125, ancestor / descendant limits, package eviction ordering).
/// Mixing the two — comparing a sat/vB rate against a sat/raw-byte rate —
/// causes SegWit txs to be ranked incorrectly relative to Bitcoin Core.
struct MempoolEntry {
    tx: Transaction,
    fee: u64,
    fee_rate: f64, // sat/vB = fee / vsize
    size: usize,   // serialized byte size (memory accounting)
    vsize: u64,    // virtual size = weight / 4, rounded up (policy)
    added_at: Instant,
    parents: HashSet<Txid>,
    ancestors: HashSet<Txid>,
    descendants: HashSet<Txid>,
    ancestor_fee: u64,
    ancestor_vsize: u64,
    /// Sums over `descendants` (self excluded, like `ancestor_*`): Core's
    /// `*WithDescendants` less this entry. A root's package is self plus
    /// these.
    descendant_fee: u64,
    descendant_vsize: u64,
    descendant_size: usize,
    /// This entry's key in `Mempool::roots`, while it is a root.
    root_key: Option<PackageKey>,
}

/// A root package in `Mempool::roots`: the root's txid and its package's
/// total fee and vsize (root plus every descendant). Ordered by package
/// fee rate, compared exactly (`fee_a * vsize_b` vs `fee_b * vsize_a`),
/// then by txid, so capacity eviction is deterministic.
#[derive(Clone, Copy, Debug)]
struct PackageKey {
    fee: u64,
    vsize: u64,
    txid: Txid,
}

impl PackageKey {
    /// Whether this package's fee rate is strictly below `fee / vsize`.
    fn rate_below(&self, fee: u64, vsize: u64) -> bool {
        rate_below(self.fee, self.vsize, fee, vsize)
    }
}

impl Ord for PackageKey {
    fn cmp(&self, other: &PackageKey) -> Ordering {
        let this = self.fee as u128 * other.vsize.max(1) as u128;
        let that = other.fee as u128 * self.vsize.max(1) as u128;
        this.cmp(&that).then(self.txid.cmp(&other.txid))
    }
}

impl PartialOrd for PackageKey {
    fn partial_cmp(&self, other: &PackageKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PackageKey {
    fn eq(&self, other: &PackageKey) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PackageKey {}

/// `fee_a / vsize_a < fee_b / vsize_b`, exactly.
fn rate_below(fee_a: u64, vsize_a: u64, fee_b: u64, vsize_b: u64) -> bool {
    (fee_a as u128 * vsize_b.max(1) as u128) < (fee_b as u128 * vsize_a.max(1) as u128)
}

/// Why a transaction left the mempool: Bitcoin Core's
/// `MemPoolRemovalReason`. A tx removed with its descendants passes the
/// reason on to them (`removeRecursive`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalReason {
    /// Mined in a connected block (`BLOCK`). Its descendants stay.
    Confirmed,
    /// Evicted by the accepted replacement with this txid, as a direct
    /// conflict or a descendant of one (`REPLACED`).
    ReplacedBy(Txid),
    /// Dropped with its package to keep the pool under its size cap
    /// (`SIZELIMIT`). Not invalid: it may be resubmitted.
    Evicted,
    /// Older than `MAX_TX_AGE`, or a descendant of such a tx (`EXPIRY`).
    Expired,
    /// It (or an ancestor) spent an outpoint that the connected block's
    /// transaction `by` spent: it can never confirm on this chain
    /// (`CONFLICT`).
    ConflictedByBlock { by: Txid },
    /// Removed through [`Mempool::remove_tx`], which the reorg path uses
    /// to clear the pool (`REORG`). Not invalid.
    Reorg,
}

impl RemovalReason {
    /// Whether the tx can never confirm on this chain once removed for
    /// this reason (its inputs are spent by a replacement or a block), so
    /// a wallet must settle it. The others may come back.
    pub fn is_final(&self) -> bool {
        matches!(self, RemovalReason::ReplacedBy(_) | RemovalReason::ConflictedByBlock { .. })
    }
}

/// One transaction leaving the mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolRemoval {
    pub txid: Txid,
    pub reason: RemovalReason,
}

/// What [`Mempool::drain_removals`] returns: every removal since the last
/// drain, in order, and how many older ones were dropped because the
/// queue was full (`MAX_QUEUED_REMOVALS`).
#[derive(Debug, Default)]
pub struct MempoolRemovals {
    pub removals: Vec<MempoolRemoval>,
    pub dropped: u64,
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
    /// Chain whose script-flag schedule applies to accepted transactions.
    params: &'static ChainParams,
    /// Median-time-past of the tip that admission last judged against:
    /// (height, header hash, MTP). Every relayed tx needs it, and it only
    /// changes with the tip; keyed by hash so a reorg can't serve a stale
    /// value.
    tip_mtp_cache: Option<(u32, [u8; 32], i64)>,
    /// Root packages, cheapest package fee rate first: the order capacity
    /// eviction takes them in. Kept in step with every entry's
    /// `root_key` by `reindex` / `unlink`.
    roots: BTreeSet<PackageKey>,
    /// Core's `rollingMinimumFeeRate` (sat/kvB): raised to an evicted
    /// package's rate plus the incremental relay fee, decayed once blocks
    /// arrive. See [`Mempool::mempool_min_fee_rate`].
    rolling_min_fee: f64,
    last_rolling_fee_update: Instant,
    block_since_last_rolling_fee_bump: bool,
    /// Removal events not yet drained (`drain_removals`).
    removals: VecDeque<MempoolRemoval>,
    removals_dropped: u64,
}

impl Mempool {
    /// Create a new mainnet mempool with the default 50 MB size cap.
    /// Test-only — production builds go through [`Mempool::with_params`].
    #[cfg(test)]
    pub fn new() -> Mempool {
        Mempool::with_params(ChainParams::mainnet())
    }

    /// Create a mempool for `params` with the default 50 MB size cap.
    pub fn with_params(params: &'static ChainParams) -> Mempool {
        Mempool {
            txs: HashMap::new(),
            spends: HashMap::new(),
            total_size: 0,
            max_size: DEFAULT_MAX_SIZE,
            params,
            tip_mtp_cache: None,
            roots: BTreeSet::new(),
            rolling_min_fee: 0.0,
            last_rolling_fee_update: Instant::now(),
            block_since_last_rolling_fee_bump: false,
            removals: VecDeque::new(),
            removals_dropped: 0,
        }
    }

    /// Create a new mempool with a custom size cap. Test-only — production
    /// callers use [`Mempool::new`].
    #[cfg(test)]
    pub(crate) fn with_max_size(max_size: usize) -> Mempool {
        Mempool { max_size, ..Mempool::with_params(ChainParams::mainnet()) }
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
    /// 3. Relay policy (018, relay only), standard sigops, script
    ///    validation (`script_verify`), value math, fee rate floor and
    ///    rolling minimum, absurd-fee guardrail (own txs only).
    /// 4. RBF: no new unconfirmed inputs, BIP 125 fee rules (only if
    ///    conflicts is non-empty).
    /// 5. Ancestor closure + 25-ancestor / 101 kvB limit checks.
    /// 6. Descendant-limit check on each ancestor.
    /// 7. **Capacity admission (inline label "Phase 6.5")** — without
    ///    mutating state, pick the cheaper packages to evict for room
    ///    (`plan_capacity_eviction`), or reject so we never destroy
    ///    innocent txs on a doomed accept.
    /// 8. Mutate (inline label "Phase 7"): evict the conflict set, insert
    ///    the new entry, update ancestors' descendant sets and the roots
    ///    index, and evict exactly the planned packages. The new tx's own
    ///    package is never evicted, so `Ok(txid)` means it is in the pool.
    ///
    /// Every removal is recorded for [`Mempool::drain_removals`].
    ///
    /// `current_height` is the chain tip height as understood by the
    /// caller, and `times` gives the header timestamps of that chain (the
    /// header store): finality and BIP 68 are judged for a block at
    /// `current_height + 1` whose parent's median-time-past is the tip's,
    /// as Core's `CheckFinalTxAtTip` / `CheckSequenceLocksAtTip` do.
    /// There is a small staleness window (one block at most)
    /// between when the caller reads the height and when this function
    /// runs under the mempool lock; the consequence is at worst a
    /// spurious `NonFinal` or `ImmatureCoinbase` rejection of one tx,
    /// which the peer can resubmit. Closing the window properly requires
    /// either (a) plumbing the height through an Arc<AtomicU32> shared
    /// with block validation, or (b) holding both header-store and
    /// mempool locks atomically — left for a follow-up.
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        times: &dyn HeaderTimes,
    ) -> Result<Txid, MempoolError> {
        self.accept_tx_internal(tx, utxo_set, current_height, times, AcceptMode::Relay)
    }

    /// Accept one of the **user's own** transactions (ticket 033).
    ///
    /// Same consensus checks as [`Mempool::accept_tx`] (inputs, scripts,
    /// maturity, finality, value math), and the same network-standardness
    /// and safety checks that decide whether *other* nodes will relay it:
    /// dust, weight, minimum relay fee, absurd-fee guard, RBF rules,
    /// ancestor/descendant limits, mempool capacity.
    ///
    /// What it skips is **our local relay policy** (ticket 018): the
    /// Knots-style filters in `relay_policy::check_relay_policy`, the
    /// 83-byte OP_RETURN cap, and the exclusion of bare P2PK / bare
    /// multisig outputs. Those say what we choose to relay *for others*;
    /// they must never stop the user broadcasting a consensus-valid
    /// transaction they signed (018 amendment). Use
    /// [`Mempool::local_policy_violation`] to warn about them instead.
    pub fn accept_own_tx(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        times: &dyn HeaderTimes,
    ) -> Result<Txid, MempoolError> {
        self.accept_tx_internal(tx, utxo_set, current_height, times, AcceptMode::Own)
    }

    /// [`Mempool::accept_own_tx`] for a fresh submission, which must also
    /// clear what our peers will take: if `tx`'s fee is below
    /// `network_floor_per_kvb` (sat/kvB, the lowest `feefilter` among our
    /// peers), no peer would be sent it (Core's `SendMessages` skips a tx
    /// whose fee is below `filterrate.GetFee(vsize)`), so it is refused
    /// with [`MempoolError::BelowNetworkMinimum`] before anything changes,
    /// instead of sitting here "pending" while nobody hears of it (ticket
    /// 053). 0 means no peer filters.
    pub fn accept_own_tx_for_network(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        times: &dyn HeaderTimes,
        network_floor_per_kvb: u64,
    ) -> Result<Txid, MempoolError> {
        let floor = FeeFloor::Network { per_kvb: network_floor_per_kvb };
        self.accept_tx_with(tx, utxo_set, current_height, times, AcceptMode::Own, floor)
    }

    /// Put back an own transaction that a reorg disconnected: it was mined,
    /// so it already paid its way. As Core's `MaybeUpdateMempoolForReorg`
    /// (`AcceptToMemoryPool` with `bypass_limits`), no fee-rate floor
    /// applies (not the minimum relay fee, not the rolling minimum, and not
    /// the absurd-fee cap, which in Core is the sending RPC's alone); every
    /// other check does. Capacity still applies: where Core admits it and
    /// trims the pool once the reorg is done, the admission plan evicts
    /// cheaper packages now, or refuses it if it is itself the cheapest,
    /// which is what that trim would have done.
    ///
    /// Only own transactions come back this way for now; ticket 025
    /// re-adds every disconnected transaction through the same floor.
    pub fn accept_disconnected_own_tx(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        times: &dyn HeaderTimes,
    ) -> Result<Txid, MempoolError> {
        self.accept_tx_with(tx, utxo_set, current_height, times, AcceptMode::Own, FeeFloor::Bypass)
    }

    /// Why our local relay policy (018) would refuse `tx` from a peer, if
    /// it would. Used to warn the user that an own transaction might
    /// propagate poorly among similarly-filtering nodes; never blocks it.
    pub fn local_policy_violation(tx: &Transaction) -> Option<String> {
        for (i, output) in tx.output.iter().enumerate() {
            if !is_relay_standard_script(&output.script_pubkey) {
                return Some(format!(
                    "output {} uses a script type this node does not relay for others \
                     (bare P2PK/multisig, or OP_RETURN over {} bytes)",
                    i, MAX_OP_RETURN_SIZE
                ));
            }
        }
        crate::relay_policy::check_relay_policy(tx)
            .err()
            .map(|r| format!("matches local relay filter: {:?}", r))
    }

    /// Mempool transactions that spend any of `tx`'s inputs (direct
    /// conflicts only — what a replacement would evict first).
    pub fn conflicting_txids(&self, tx: &Transaction) -> Vec<Txid> {
        let mut out: Vec<Txid> = Vec::new();
        for input in &tx.input {
            let key = (input.previous_output.txid, input.previous_output.vout);
            if let Some(c) = self.spends.get(&key) {
                if !out.contains(c) {
                    out.push(*c);
                }
            }
        }
        out
    }

    /// Test-only accept entry point that skips consensus script
    /// validation and the standard-script-type check. Lets unit tests
    /// exercise the graph state, fee math, RBF, and CPFP paths using
    /// trivial anyone-can-spend script_pubkeys instead of crafting valid
    /// signatures. Production callers must always go through `accept_tx`.
    ///
    /// Header times are synthetic (`tests::synthetic_times`); tests of the
    /// time-based rules use [`Mempool::accept_tx_test_with_times`].
    #[cfg(test)]
    pub(crate) fn accept_tx_test(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
    ) -> Result<Txid, MempoolError> {
        let times = tests::synthetic_times;
        self.accept_tx_internal(tx, utxo_set, current_height, &times, AcceptMode::SkipConsensus)
    }

    /// `accept_tx_test` with caller-supplied header timestamps.
    #[cfg(test)]
    pub(crate) fn accept_tx_test_with_times(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        times: &dyn HeaderTimes,
    ) -> Result<Txid, MempoolError> {
        self.accept_tx_internal(tx, utxo_set, current_height, times, AcceptMode::SkipConsensus)
    }

    /// Median-time-past at `height` (the tip admission judges against),
    /// cached per tip header hash. Sources that can't identify the header
    /// (`header_id_at` = None) are read every time.
    fn tip_mtp(&mut self, height: u32, times: &dyn HeaderTimes) -> Result<i64, MempoolError> {
        let id = times.header_id_at(height);
        if let (Some(id), Some((h, cached_id, mtp))) = (id, self.tip_mtp_cache) {
            if h == height && cached_id == id {
                return Ok(mtp);
            }
        }
        let mtp = median_time_past(times, height).map_err(MempoolError::ChainContext)?;
        // Headers can be replaced while we read them (a reorg on the sync
        // thread). Cache only if the tip is the same header after the read,
        // so a value computed across the switch is never keyed to either.
        let after = times.header_id_at(height);
        self.tip_mtp_cache = match (id, after) {
            (Some(id), Some(after)) if id == after => Some((height, id, mtp)),
            _ => None,
        };
        Ok(mtp)
    }

    /// Shared accept implementation with the standard fee floors. See
    /// [`AcceptMode`] for what each mode checks.
    fn accept_tx_internal(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        times: &dyn HeaderTimes,
        mode: AcceptMode,
    ) -> Result<Txid, MempoolError> {
        self.accept_tx_with(tx, utxo_set, current_height, times, mode, FeeFloor::Standard)
    }

    /// [`Mempool::accept_tx_internal`] with the fee floors `floor` names.
    fn accept_tx_with(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
        times: &dyn HeaderTimes,
        mode: AcceptMode,
        floor: FeeFloor,
    ) -> Result<Txid, MempoolError> {
        let skip_consensus = matches!(mode, AcceptMode::SkipConsensus);
        let txid = tx.compute_txid();

        // ── Phase 0: trivial rejections ─────────────────────────────────

        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseTx);
        }

        if tx.input.is_empty() || tx.output.is_empty() {
            return Err(MempoolError::MalformedTx);
        }

        // The rest of Core's CheckTransaction: no outpoint spent twice
        // (`bad-txns-inputs-duplicate`) and every output, and their total,
        // within MAX_MONEY (`bad-txns-vout-toolarge`,
        // `bad-txns-txouttotal-toolarge`). The script check below verifies
        // inputs one at a time, so without this a tx spending one coin
        // twice would have that coin's value counted twice and be relayed
        // to peers that treat it as consensus-invalid.
        let mut outpoints = HashSet::with_capacity(tx.input.len());
        for (input_index, input) in tx.input.iter().enumerate() {
            if !outpoints.insert(input.previous_output) {
                return Err(MempoolError::DuplicateInput { input_index });
            }
        }
        let mut output_total: u64 = 0;
        for output in &tx.output {
            let amount = output.value.to_sat();
            if amount > MAX_MONEY {
                return Err(MempoolError::ValueOutOfRange { what: "output", amount });
            }
            // Both terms are at most MAX_MONEY here: no overflow.
            output_total += amount;
            if output_total > MAX_MONEY {
                return Err(MempoolError::ValueOutOfRange { what: "output total", amount: output_total });
            }
        }

        if self.txs.contains_key(&txid) {
            return Err(MempoolError::AlreadyInMempool);
        }

        // Finality (nLockTime), as Core's `CheckFinalTxAtTip`: could `tx`
        // be mined in the next block? Height locks are judged against
        // `current_height + 1`, time locks against the tip's median-time-
        // past (BIP 113), never the wall clock. Same `IsFinalTx` port as
        // block validation (contextual_checks).
        let tip_mtp = self.tip_mtp(current_height, times)?;
        let mut mtp = MedianTimes::new(times);
        let next_height = current_height.saturating_add(1);
        if !is_final_tx(&tx, next_height, tip_mtp) {
            return Err(MempoolError::NonFinal {
                lock_time: tx.lock_time.to_consensus_u32(),
                current_height,
            });
        }

        let weight = tx.weight().to_wu();
        if weight > MAX_TX_WEIGHT {
            return Err(MempoolError::OversizedTx { weight });
        }
        // The rest of Core's `IsStandardTx` that doesn't depend on output
        // types: version, and scriptSigs that are small and push-only
        // (anything else in a scriptSig is malleable by third parties).
        let version = tx.version.0;
        if !(1..=TX_MAX_STANDARD_VERSION).contains(&version) {
            return Err(MempoolError::NonStandardVersion { version });
        }
        for (input_index, input) in tx.input.iter().enumerate() {
            if input.script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
                return Err(MempoolError::NonStandardScriptSig { input_index, reason: "scriptsig-size" });
            }
            if !is_push_only(&input.script_sig) {
                return Err(MempoolError::NonStandardScriptSig { input_index, reason: "scriptsig-not-pushonly" });
            }
        }

        // Virtual size = ceil(weight / 4). All policy decisions (fee rate,
        // ancestor / descendant limits, package rate) use this — never the
        // raw serialized byte length. The bitcoin crate's `Transaction::vsize`
        // already does the round-up correctly.
        let vsize: u64 = tx.vsize() as u64;

        // Core's `IsDust` per output (IsStandardTx, `dust`). Core 29+
        // allows one dust output in a zero-fee tx (ephemeral dust), which
        // only package relay can get mined; without package relay a
        // zero-fee tx fails the minimum relay fee anyway, so any dust
        // output is a rejection here.
        for (i, output) in tx.output.iter().enumerate() {
            let threshold = dust_threshold(output);
            if output.value.to_sat() < threshold {
                return Err(MempoolError::DustOutput {
                    index: i,
                    amount: output.value.to_sat(),
                    threshold,
                });
            }
        }

        match mode {
            AcceptMode::Relay => {
                for (i, output) in tx.output.iter().enumerate() {
                    if !is_relay_standard_script(&output.script_pubkey) {
                        return Err(MempoolError::NonStandardScript { index: i });
                    }
                }
                // The 018 witness filters run once the spent outputs are
                // known (after Phase 2).
            }
            AcceptMode::Own => {
                // Network standardness only: an output type other nodes
                // won't relay would just strand the tx. Local relay
                // policy is deliberately not applied (see accept_own_tx).
                for (i, output) in tx.output.iter().enumerate() {
                    if !is_network_standard_script(&output.script_pubkey) {
                        return Err(MempoolError::NonStandardScript { index: i });
                    }
                }
            }
            AcceptMode::SkipConsensus => {}
        }

        // Core's PreChecks `tx-size-small`, right after IsStandardTx. The
        // test mode skips it with the output-type checks: its fixtures pay
        // to 1-byte scripts.
        let base_size = tx.base_size();
        if mode != AcceptMode::SkipConsensus && base_size < MIN_STANDARD_TX_NONWITNESS_SIZE {
            return Err(MempoolError::TxSizeSmall { size: base_size });
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
        //
        // Resolution and script verification are split into two phases so
        // that script verification can see *all* spent outputs up-front
        // (BIP 341 sighash commits to every spent output, not just the one
        // being verified).
        let serialized_tx = serialize(&tx);
        let flags = self.params.script_flags(current_height);
        let mut input_sum: u64 = 0;
        let mut parents: HashSet<Txid> = HashSet::new();
        let mut spent: Vec<(u64, Vec<u8>)> = Vec::with_capacity(tx.input.len());
        // Height of each spent coin for BIP 68; a mempool parent counts as
        // confirming in the next block (Core's `CalculatePrevHeights`).
        let mut prev_heights: Vec<u32> = Vec::with_capacity(tx.input.len());

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
                        height: next_height,
                        is_coinbase: false,
                    }
                }
            };

            // Coinbase maturity (only confirmed coinbases can be flagged
            // here; mempool parents synthesize is_coinbase=false above),
            // judged for the next block like finality and BIP 68: Core's
            // CheckTxInputs gets spend height = tip + 1, and block
            // validation allows the spend at coin height + 100.
            if utxo.is_coinbase && next_height.saturating_sub(utxo.height) < COINBASE_MATURITY {
                return Err(MempoolError::ImmatureCoinbase {
                    input_index: input_idx,
                    coinbase_height: utxo.height,
                });
            }

            input_sum = input_sum
                .checked_add(utxo.amount)
                .ok_or(MempoolError::MathOverflow)?;
            prev_heights.push(utxo.height);
            spent.push((utxo.amount, utxo.script_pubkey));
        }
        // CheckTxInputs `bad-txns-inputvalues-outofrange`.
        if input_sum > MAX_MONEY {
            return Err(MempoolError::ValueOutOfRange { what: "input total", amount: input_sum });
        }

        // BIP 68 relative lock-times for the next block, as Core's
        // `CalculateLockPointsAtTip` + `CheckSequenceLocksAtTip`. Policy
        // always enforces them (STANDARD_LOCKTIME_VERIFY_FLAGS); on mainnet
        // CSV has been active since 419,328 anyway.
        let lock = calculate_sequence_locks(&tx, true, &prev_heights, &mut mtp)
            .map_err(MempoolError::ChainContext)?;
        if !evaluate_sequence_locks(next_height, tip_mtp, lock) {
            return Err(MempoolError::NonBip68Final {
                min_height: lock.min_height,
                min_time: lock.min_time,
                current_height,
            });
        }

        // Standard sigop cost (MemPoolAccept::PreChecks,
        // `bad-txns-too-many-sigops`): legacy + P2SH + witness sigops,
        // counted as `GetTransactionSigOpCost` does with the standard
        // flags, before any script runs.
        let spent_spks: Vec<&[u8]> = spent.iter().map(|(_, spk)| spk.as_slice()).collect();

        // What the inputs spend, and their witnesses, must be standard too
        // (Core's `ValidateInputsStandardness` and `IsWitnessStandard`,
        // network standardness, so own txs as well). The script-type-free
        // test mode skips them, as it skips output types.
        if mode != AcceptMode::SkipConsensus {
            validate_inputs_standardness(&tx, &spent_spks)?;
            is_witness_standard(&tx, &spent_spks)?;
        }

        // Knots-aligned relay policy (018): reject inscriptions, token
        // protocols, data injection, and parasitic patterns. Needs the
        // spent scriptPubKeys to know which witness element is a script.
        if mode == AcceptMode::Relay {
            crate::relay_policy::check_relay_policy_with_spent(&tx, &spent_spks)
                .map_err(MempoolError::PolicyRejection)?;
        }

        let sigop_cost = crate::contextual_checks::transaction_sigop_cost(
            &tx,
            &spent_spks,
            crate::chain_params::SCRIPT_VERIFY_P2SH | crate::chain_params::SCRIPT_VERIFY_WITNESS,
        );
        if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
            return Err(MempoolError::TooManySigops { cost: sigop_cost, limit: MAX_STANDARD_TX_SIGOPS_COST });
        }

        // ── Phase 3: value math + fee bounds ────────────────────────────
        let output_sum: u64 = tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or(MempoolError::MathOverflow)?;

        if input_sum < output_sum {
            return Err(MempoolError::Inflation);
        }

        let fee = input_sum - output_sum;

        // Absurd-fee guardrail, own transactions only (see
        // ABSURD_FEE_THRESHOLD), and not for one a block already mined.
        if mode == AcceptMode::Own && floor != FeeFloor::Bypass && fee > ABSURD_FEE_THRESHOLD {
            return Err(MempoolError::AbsurdFee {
                fee,
                limit: ABSURD_FEE_THRESHOLD,
            });
        }

        let fee_rate = fee as f64 / vsize as f64;
        if floor != FeeFloor::Bypass {
            if fee_rate < MIN_RELAY_FEE_RATE {
                return Err(MempoolError::InsufficientFee {
                    fee_rate,
                    min_rate: MIN_RELAY_FEE_RATE,
                });
            }
            // The rolling minimum (Core's CheckFeeRate, `mempool min fee
            // not met`): while the pool has recently been full, a tx must
            // beat what eviction last threw out, plus the incremental
            // relay fee.
            let min_fee_per_kvb = self.min_fee_per_kvb(Instant::now());
            if min_fee_per_kvb > 0 && fee < (min_fee_per_kvb * vsize).div_ceil(1000) {
                return Err(MempoolError::MempoolMinFeeNotMet {
                    fee_rate,
                    min_rate: min_fee_per_kvb as f64 / 1000.0,
                });
            }
        }
        // Our peers' floor, compared as each peer compares it before
        // announcing a tx to us (`fee < filterrate.GetFee(vsize)`, rounded
        // up). Reported with the rate that clears every floor we know of.
        if let FeeFloor::Network { per_kvb } = floor {
            if per_kvb > 0 && fee < (per_kvb * vsize).div_ceil(1000) {
                let ours = self.min_fee_per_kvb(Instant::now()).max((MIN_RELAY_FEE_RATE * 1000.0) as u64);
                return Err(MempoolError::BelowNetworkMinimum {
                    fee_rate,
                    min_rate: per_kvb.max(ours) as f64 / 1000.0,
                });
            }
        }

        let size = serialized_tx.len();

        // ── Phase 4: BIP 125 RBF enforcement ────────────────────────────
        if !direct_conflicts.is_empty() {
            self.check_bip125(&tx, fee, vsize, &direct_conflicts, &to_evict)?;
        }

        // ── Phase 5: ancestor closure + limit enforcement ───────────────
        //
        // Walk the parent chain breadth-first; the diamond case (same
        // ancestor reachable via multiple paths) is naturally deduplicated
        // by the visited HashSet. We accumulate fees and *vsizes* (not raw
        // bytes) to compare against MAX_ANCESTOR_VBYTES, which is in
        // virtual bytes per Bitcoin Core's DEFAULT_ANCESTOR_SIZE_LIMIT.
        let mut ancestors: HashSet<Txid> = HashSet::new();
        let mut ancestor_fee: u64 = 0;
        let mut ancestor_vsize: u64 = 0;
        let mut frontier: VecDeque<Txid> = parents.iter().copied().collect();

        while let Some(parent_txid) = frontier.pop_front() {
            if !ancestors.insert(parent_txid) {
                continue;
            }
            let parent = self
                .txs
                .get(&parent_txid)
                .expect("parent must exist — phase 2 just looked it up");
            ancestor_fee = ancestor_fee
                .checked_add(parent.fee)
                .ok_or(MempoolError::MathOverflow)?;
            ancestor_vsize = ancestor_vsize
                .checked_add(parent.vsize)
                .ok_or(MempoolError::MathOverflow)?;
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
        let pkg_vsize = ancestor_vsize
            .checked_add(vsize)
            .ok_or(MempoolError::MathOverflow)?;
        if pkg_vsize > MAX_ANCESTOR_VBYTES as u64 {
            return Err(MempoolError::AncestorSetTooLarge {
                vbytes: pkg_vsize,
                limit: MAX_ANCESTOR_VBYTES as u64,
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

        // ── Phase 6.5: capacity admission (collateral-eviction guard) ───
        //
        // Before *any* mutation, pick the packages capacity eviction will
        // drop to make room. Each must pay a strictly lower fee rate than
        // the package the new tx joins, and the new tx's own package is
        // never a candidate. If that can't free enough space, reject here.
        // Core inserts first and trims after (`LimitMempoolSize`), which
        // can evict innocent packages and then the new tx itself; planning
        // first means a failed accept changes nothing, and `Ok` always
        // means the tx is in the pool.
        let victims = match self.plan_capacity_eviction(size, fee, vsize, &ancestors, &to_evict) {
            Ok(victims) => victims,
            Err((new_pkg, cheapest_other)) => {
                // Core would have trimmed the new package straight back
                // out, raising the rolling minimum past it.
                self.track_package_removed(new_pkg.0, new_pkg.1);
                return Err(MempoolError::MempoolFull {
                    new_fee_rate: new_pkg.0 as f64 / new_pkg.1.max(1) as f64,
                    min_pkg_fee_rate: cheapest_other.map_or(0.0, |(f, v)| f as f64 / v.max(1) as f64),
                });
            }
        };

        // ── Phase 6.6: scripts ──────────────────────────────────────────
        //
        // Last, as Core's PreChecks → PolicyScriptChecks →
        // ConsensusScriptChecks: every cheap check above runs before any
        // signature is checked, so a tx that fails on fees, RBF or limits
        // costs no script work (ticket 053).
        //
        // Policy first: Core's STANDARD_SCRIPT_VERIFY_FLAGS (low-S, strict
        // encoding, NULLFAIL, CLEANSTACK, MINIMALIF, minimal pushes,
        // discouraged upgradable NOPs / witness programs / taproot leaf
        // versions / OP_SUCCESS / pubkey types, ...), which peers enforce
        // for relay. Where it fails, the mandatory (all consensus) flags
        // decide what to tell the user, as Core up to 29 classified it
        // (`mandatory-script-verify-flag-failed`): still failing is
        // invalid (`ScriptFailure`); passing is only non-standard (Core 30+
        // reports both as `mempool-script-verify-flag-failed`, and neither
        // costs the peer anything here). Then the consensus check proper,
        // with this build's consensus backend and the tip's flags.
        if !skip_consensus {
            if let Err(policy) = script_verify::verify_transaction_policy(&tx, &spent) {
                script_verify::verify_transaction(&tx, &spent, script_verify::SCRIPT_VERIFY_ALL_CONSENSUS)
                    .map_err(MempoolError::from_script_verify)?;
                return Err(MempoolError::from_policy_script_verify(policy));
            }
            script_verify::verify_transaction(&tx, &spent, flags)
                .map_err(MempoolError::from_script_verify)?;
        }

        // ── Phase 7: mutate ─────────────────────────────────────────────
        //
        // Every check that could fail has run. Mutations in order:
        //   1. Evict the BIP 125 conflict set (cascade).
        //   2. Insert the new entry, wire its spends index, and update
        //      every ancestor's descendant set and package sums.
        //   3. Evict the packages Phase 6.5 picked, raising the rolling
        //      minimum fee past each.

        if !to_evict.is_empty() {
            // Evict each top-level direct conflict; cascade handles the
            // rest. Skip txs already removed by an earlier cascade.
            for top_level in &direct_conflicts {
                if self.txs.contains_key(top_level) {
                    self.evict_with_descendants(top_level, RemovalReason::ReplacedBy(txid));
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
            vsize,
            added_at: Instant::now(),
            parents: parents.clone(),
            ancestors: ancestors.clone(),
            descendants: HashSet::new(),
            ancestor_fee,
            ancestor_vsize,
            descendant_fee: 0,
            descendant_vsize: 0,
            descendant_size: 0,
            root_key: None,
        };
        self.txs.insert(txid, entry);
        self.reindex(&txid);

        // Wire `txid` into every ancestor's descendant set and sums. This
        // is the *only* place ancestor.descendants grows; symmetrically,
        // the only place it shrinks is `unlink`.
        for ancestor_txid in &ancestors {
            if let Some(ancestor) = self.txs.get_mut(ancestor_txid) {
                ancestor.descendants.insert(txid);
                ancestor.descendant_fee += fee;
                ancestor.descendant_vsize += vsize;
                ancestor.descendant_size += size;
            }
            self.reindex(ancestor_txid);
        }

        debug!(
            "Mempool: accepted tx {} (fee_rate={:.1} sat/vB, size={}, parents={}, ancestors={})",
            txid,
            fee_rate,
            size,
            parents.len(),
            ancestors.len()
        );

        for victim in &victims {
            self.evict_package(victim);
        }
        // The plan frees enough by construction; this only guards the cap
        // if the accounting were ever off, still never touching the new
        // tx's package.
        while self.total_size > self.max_size {
            let Some(victim) = self
                .roots
                .iter()
                .map(|k| k.txid)
                .find(|t| *t != txid && !ancestors.contains(t))
            else {
                break;
            };
            warn!("Mempool: over capacity after a planned eviction; evicting {}", victim);
            self.evict_package(&victim);
        }
        if !self.txs.contains_key(&txid) {
            // Unreachable: nothing above removes the new tx's package.
            return Err(MempoolError::MempoolFull { new_fee_rate: fee_rate, min_pkg_fee_rate: 0.0 });
        }

        Ok(txid)
    }

    /// Capacity admission plan (Phase 6.5): the root packages to evict,
    /// cheapest first, so that the pool fits once `to_evict` is gone and
    /// the new tx (`new_size` bytes, `new_fee` over `new_vsize`) is in.
    ///
    /// The new tx joins the package of every root among `our_ancestors`
    /// (or is a root itself); the cheapest of those, after insertion, is
    /// the rate a victim must be strictly below. Ties keep the incumbent,
    /// as Core's descendant-score order evicts the newer entry first.
    /// Packages containing the new tx are never victims, and members
    /// already in `to_evict` or freed by an earlier victim aren't counted
    /// again, so a descendant shared by two roots is freed once and the
    /// second root is judged by what it has left.
    ///
    /// Walks `roots` from the cheapest end and stops at the first package
    /// that isn't cheaper than the new one, so the work is proportional to
    /// the packages evicted (plus at most the protected and conflicting
    /// roots skipped), not to the pool. Conservative: a package that only
    /// becomes cheaper once a shared descendant is gone isn't considered.
    ///
    /// `Err` carries the new package's (fee, vsize) and the cheapest
    /// package it would have had to displace.
    #[allow(clippy::type_complexity)]
    fn plan_capacity_eviction(
        &self,
        new_size: usize,
        new_fee: u64,
        new_vsize: u64,
        our_ancestors: &HashSet<Txid>,
        to_evict: &HashSet<Txid>,
    ) -> Result<Vec<Txid>, ((u64, u64), Option<(u64, u64)>)> {
        let evicted_size: usize = to_evict.iter().filter_map(|t| self.txs.get(t)).map(|e| e.size).sum();
        let total = self.total_size.saturating_sub(evicted_size).saturating_add(new_size);
        // Fast path: insertion fits without eviction.
        if total <= self.max_size {
            return Ok(Vec::new());
        }
        let mut needed = total - self.max_size;

        // The new tx's package rate: the cheapest root package it joins.
        let mut new_pkg = (new_fee, new_vsize);
        let mut joined = false;
        for root in our_ancestors.iter().filter_map(|a| self.txs.get(a)).filter(|e| e.ancestors.is_empty()) {
            let (mut f, mut v) = (root.fee + root.descendant_fee + new_fee, root.vsize + root.descendant_vsize + new_vsize);
            for gone in root.descendants.iter().filter(|d| to_evict.contains(*d)).filter_map(|d| self.txs.get(d)) {
                f -= gone.fee;
                v -= gone.vsize;
            }
            if !joined || rate_below(f, v, new_pkg.0, new_pkg.1) {
                new_pkg = (f, v);
                joined = true;
            }
        }

        let protected = |t: &Txid| to_evict.contains(t) || our_ancestors.contains(t);
        let mut victims = Vec::new();
        let mut freed: HashSet<Txid> = HashSet::new();
        for key in &self.roots {
            if needed == 0 || !key.rate_below(new_pkg.0, new_pkg.1) {
                break;
            }
            if protected(&key.txid) {
                continue;
            }
            let root = &self.txs[&key.txid];
            let members: Vec<&Txid> = std::iter::once(&key.txid)
                .chain(root.descendants.iter())
                .filter(|t| !to_evict.contains(*t) && !freed.contains(*t))
                .collect();
            let (mut f, mut v, mut s) = (0u64, 0u64, 0usize);
            for e in members.iter().filter_map(|t| self.txs.get(*t)) {
                f += e.fee;
                v += e.vsize;
                s += e.size;
            }
            if s == 0 || !rate_below(f, v, new_pkg.0, new_pkg.1) {
                continue;
            }
            freed.extend(members.into_iter().copied());
            victims.push(key.txid);
            needed = needed.saturating_sub(s);
        }
        if needed > 0 {
            let cheapest_other = self.roots.iter().find(|k| !protected(&k.txid)).map(|k| (k.fee, k.vsize));
            return Err((new_pkg, cheapest_other));
        }
        Ok(victims)
    }

    /// Evict root `txid` with its descendants for capacity, raising the
    /// rolling minimum fee past the package (`TrimToSize`).
    fn evict_package(&mut self, txid: &Txid) {
        let Some(e) = self.txs.get(txid) else { return };
        let (fee, vsize) = (e.fee + e.descendant_fee, e.vsize + e.descendant_vsize);
        debug!("Mempool: evicting package of {} for capacity", txid);
        self.evict_with_descendants(txid, RemovalReason::Evicted);
        self.track_package_removed(fee, vsize);
    }

    /// Core's `CTxMemPool::trackPackageRemoved`: the rolling minimum rises
    /// to a removed package's rate (sat/kvB, `CFeeRate`'s truncating
    /// division) plus the incremental relay fee.
    fn track_package_removed(&mut self, fee: u64, vsize: u64) {
        let rate = (fee.saturating_mul(1000) / vsize.max(1)) as f64 + INCREMENTAL_RELAY_FEE_PER_KVB;
        if rate > self.rolling_min_fee {
            self.rolling_min_fee = rate;
            self.block_since_last_rolling_fee_bump = false;
        }
    }

    /// Core's `CTxMemPool::GetMinFee` in sat/kvB: 0 until the pool has
    /// had to evict for space; then the rolling minimum, at least the
    /// incremental relay fee. Once a block arrives after the last rise it
    /// halves every `ROLLING_FEE_HALFLIFE` (faster while the pool is under
    /// half or a quarter full), checked at most every 10 seconds, and
    /// drops to 0 below half the incremental relay fee.
    fn min_fee_per_kvb(&mut self, now: Instant) -> u64 {
        if !self.block_since_last_rolling_fee_bump || self.rolling_min_fee == 0.0 {
            return self.rolling_min_fee.round() as u64;
        }
        let elapsed = now.saturating_duration_since(self.last_rolling_fee_update);
        if elapsed > Duration::from_secs(10) {
            let mut halflife = ROLLING_FEE_HALFLIFE.as_secs_f64();
            if self.total_size < self.max_size / 4 {
                halflife /= 4.0;
            } else if self.total_size < self.max_size / 2 {
                halflife /= 2.0;
            }
            self.rolling_min_fee /= 2f64.powf(elapsed.as_secs() as f64 / halflife);
            self.last_rolling_fee_update = now;
            if self.rolling_min_fee < INCREMENTAL_RELAY_FEE_PER_KVB / 2.0 {
                self.rolling_min_fee = 0.0;
                return 0;
            }
        }
        (self.rolling_min_fee.round() as u64).max(INCREMENTAL_RELAY_FEE_PER_KVB as u64)
    }

    /// The fee rate (sat/vB) a transaction must pay to get in right now
    /// beyond the 1 sat/vB relay floor: Core's `GetMinFee`, which is also
    /// what Core advertises in `feefilter`. 0.0 unless the pool has been
    /// full recently.
    #[cfg_attr(not(test), allow(dead_code))] // for our own feefilter, not sent yet
    pub fn mempool_min_fee_rate(&mut self) -> f64 {
        self.min_fee_per_kvb(Instant::now()) as f64 / 1000.0
    }

    /// Point `txid`'s `roots` entry at its current package, adding or
    /// removing it as it becomes or stops being a root. Called after any
    /// change to an entry's ancestors or descendant sums.
    fn reindex(&mut self, txid: &Txid) {
        let Some(e) = self.txs.get_mut(txid) else { return };
        if let Some(key) = e.root_key.take() {
            self.roots.remove(&key);
        }
        if e.ancestors.is_empty() {
            let key = PackageKey { fee: e.fee + e.descendant_fee, vsize: e.vsize + e.descendant_vsize, txid: *txid };
            self.roots.insert(key);
            e.root_key = Some(key);
        }
    }

    /// Every removal since the last call, oldest first: the mempool event
    /// stream (ticket 053; ticket 040's wallet view consumes it too).
    /// Drain after each call that can remove transactions — `accept_tx` /
    /// `accept_own_tx` (replacements, capacity eviction), `remove_confirmed`,
    /// `expire_old`, `remove_tx` — and hand the result to
    /// `OwnTxStore::on_mempool_removals`.
    pub fn drain_removals(&mut self) -> MempoolRemovals {
        MempoolRemovals {
            removals: self.removals.drain(..).collect(),
            dropped: std::mem::take(&mut self.removals_dropped),
        }
    }

    fn record_removal(&mut self, txid: Txid, reason: RemovalReason) {
        if self.removals.len() >= MAX_QUEUED_REMOVALS {
            // Drop the oldest event that settles nothing; if every queued
            // event is final, keep them all (see MAX_QUEUED_REMOVALS). The
            // scan past the front only runs once final events have piled
            // up undrained.
            if self.removals.front().is_some_and(|r| !r.reason.is_final()) {
                self.removals.pop_front();
                self.removals_dropped += 1;
            } else if let Some(i) = self.removals.iter().position(|r| !r.reason.is_final()) {
                self.removals.remove(i);
                self.removals_dropped += 1;
            } else if !reason.is_final() {
                self.removals_dropped += 1;
                return;
            }
        }
        self.removals.push_back(MempoolRemoval { txid, reason });
    }

    /// Walk the descendant graph of every txid in `roots` and return the
    /// union (roots ∪ all transitive descendants). Used by RBF to compute
    /// the set of mempool txs a replacement would evict.
    ///
    /// Early-terminates once the union exceeds `MAX_REPLACEMENT_EVICTIONS`
    /// — past that point, the caller is going to reject anyway, and
    /// continuing the walk is a wasted attack surface for crafted-deep
    /// descendant graphs.
    fn collect_eviction_set(&self, roots: &HashSet<Txid>) -> HashSet<Txid> {
        let mut out: HashSet<Txid> = HashSet::new();
        let mut frontier: VecDeque<Txid> = roots.iter().copied().collect();
        while let Some(txid) = frontier.pop_front() {
            if !out.insert(txid) {
                continue;
            }
            // Early-exit. The caller checks `out.len() > MAX_REPLACEMENT_EVICTIONS`
            // and rejects, so the additional walk work is wasted. Bound
            // it explicitly so an adversary can't force unbounded BFS by
            // crafting a wide descendant graph.
            if out.len() > MAX_REPLACEMENT_EVICTIONS {
                return out;
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

    /// Core's `MemPoolAccept::ReplacementChecks`, in its order. Signaling
    /// (BIP 125 rule 1) is intentionally omitted — we follow Bitcoin Core
    /// v28+ full RBF semantics. The eviction count (rule 5) is enforced
    /// before this is called, and Phase 2 rejects a replacement spending
    /// an output of a tx it replaces (`MissingInput`).
    ///
    /// * No new unconfirmed inputs (BIP 125 rule 2, Core ≤ 30's
    ///   `HasNoNewUnconfirmed`, `replacement-adds-unconfirmed`; Knots
    ///   keeps it): every input that spends a mempool tx must spend one
    ///   the directly-conflicting txs already spent from. Otherwise a fee
    ///   bump could hang on low-fee junk that has to be mined first, and
    ///   Knots / older Core peers drop it while we keep it.
    /// * Fee rate (Core's `PaysMoreThanConflicts`) — replacement fee_rate
    ///   (sat/vB) must be strictly higher than every directly-conflicting
    ///   tx's fee_rate. Both sides use *vsize* (virtual bytes), never raw
    ///   serialized bytes — mixing the two ranks SegWit txs incorrectly.
    /// * Rule 3/4 (`PaysForRBF`) — replacement absolute fee must cover the
    ///   originals' fees *plus* a relay-cost surcharge:
    ///   `replacement_vsize * incremental_relay_fee`.
    fn check_bip125(
        &self,
        tx: &Transaction,
        replacement_fee: u64,
        replacement_vsize: u64,
        direct_conflicts: &HashSet<Txid>,
        to_evict: &HashSet<Txid>,
    ) -> Result<(), MempoolError> {
        // Txids the conflicts spend from, confirmed or not, as Core
        // collects them (`parents_of_conflicts`).
        let parents_of_conflicts: HashSet<Txid> = direct_conflicts
            .iter()
            .filter_map(|t| self.txs.get(t))
            .flat_map(|e| e.tx.input.iter().map(|i| i.previous_output.txid))
            .collect();
        for (input_index, input) in tx.input.iter().enumerate() {
            let parent = input.previous_output.txid;
            if !parents_of_conflicts.contains(&parent) && self.txs.contains_key(&parent) {
                return Err(MempoolError::ReplacementAddsUnconfirmed { input_index, parent });
            }
        }

        // Rule 2 — replacement fee_rate strictly greater than each direct
        // conflict's individual fee_rate. Both sides use sat/vB so SegWit
        // discount is applied symmetrically.
        let replacement_fee_rate = replacement_fee as f64 / replacement_vsize as f64;
        for txid in direct_conflicts {
            let entry = self.txs.get(txid).expect("direct conflict must exist");
            let conflict_rate = entry.fee as f64 / entry.vsize as f64;
            if replacement_fee_rate <= conflict_rate {
                return Err(MempoolError::ReplacementFeeTooLow {
                    replacement: replacement_fee_rate,
                    conflict: conflict_rate,
                });
            }
        }

        // Rule 3 — total fee must cover the *entire* eviction set's fees
        // plus the relay cost of the replacement. Surcharge uses vsize
        // (the same denomination Bitcoin Core's incremental_relay_feerate
        // is expressed in).
        let mut evicted_fee_total: u64 = 0;
        for t in to_evict {
            if let Some(e) = self.txs.get(t) {
                evicted_fee_total = evicted_fee_total
                    .checked_add(e.fee)
                    .ok_or(MempoolError::MathOverflow)?;
            }
        }
        let relay_surcharge =
            (replacement_vsize as f64 * INCREMENTAL_RELAY_FEE_RATE).ceil() as u64;
        let required_fee = evicted_fee_total
            .checked_add(relay_surcharge)
            .ok_or(MempoolError::MathOverflow)?;
        if replacement_fee < required_fee {
            return Err(MempoolError::ReplacementFeeInsufficient {
                provided: replacement_fee,
                required: required_fee,
                evicted_fee_total,
                relay_surcharge,
            });
        }

        Ok(())
    }

    /// Drop everything in the mempool that's been resolved by a new block.
    ///
    /// Two distinct cases per block tx:
    ///
    /// * **The confirmed tx itself was in the mempool.** It leaves alone
    ///   (`RemovalReason::Confirmed`); descendants stay in place — their
    ///   inputs now resolve against the on-disk UTXO set, and `unlink`'s
    ///   graph maintenance drops the parent from each descendant's
    ///   ancestor closure and `parents` set.
    ///
    /// * **A different mempool tx double-spent the same inputs.** That tx
    ///   has been permanently invalidated by the chain — its descendants
    ///   reference outputs that will never exist. The whole package goes
    ///   (`RemovalReason::ConflictedByBlock`), as Core's `removeConflicts`.
    ///
    /// Also starts the rolling minimum fee's decay, as Core's
    /// `removeForBlock` does.
    pub fn remove_confirmed(&mut self, block: &Block) {
        let mut removed = 0;

        for tx in &block.txdata {
            let txid = tx.compute_txid();

            // Case 1: confirmed tx itself.
            if self.unlink(&txid, RemovalReason::Confirmed) {
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
                        removed += self.evict_with_descendants(
                            &conflicting_txid,
                            RemovalReason::ConflictedByBlock { by: txid },
                        );
                    }
                }
            }
        }

        self.last_rolling_fee_update = Instant::now();
        self.block_since_last_rolling_fee_bump = true;

        if removed > 0 {
            info!(
                "Mempool: removed {} txs after block, {} remaining",
                removed,
                self.txs.len()
            );
        }
    }

    /// Remove a single transaction by txid from outside the mempool's own
    /// rules: the reorg path clears the pool with it. Reported as
    /// `RemovalReason::Reorg`. Does **not** cascade: descendants stay in
    /// the mempool (see `unlink`).
    ///
    /// Returns `true` if the tx was present.
    pub fn remove_tx(&mut self, txid: &Txid) -> bool {
        self.unlink(txid, RemovalReason::Reorg)
    }

    /// Remove a single transaction, updating graph state and the roots
    /// index, and record its removal with `reason`.
    ///
    /// Does **not** cascade: descendants stay in the mempool. Used by:
    /// * `remove_confirmed` — a parent that just got mined leaves the
    ///   mempool but its children stay (their inputs now resolve against
    ///   the on-disk UTXO set).
    /// * `evict_with_descendants` — the cascade walks bottom-up and calls
    ///   this for each visited node.
    /// * `remove_tx`.
    ///
    /// Graph maintenance: drop self from every ancestor's `descendants`
    /// (and its descendant sums), drop self from every descendant's
    /// `ancestors`, and decrement each descendant's running ancestor
    /// totals by self's contribution. The "diamond" case (descendant has
    /// another path to the same ancestor) is not affected because each tx
    /// still has a single `parents` set pointing at its direct parents.
    fn unlink(&mut self, txid: &Txid, reason: RemovalReason) -> bool {
        let entry = match self.txs.remove(txid) {
            Some(e) => e,
            None => return false,
        };
        if let Some(key) = entry.root_key {
            self.roots.remove(&key);
        }

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

        // Drop self from each ancestor's descendants set and sums.
        for ancestor_txid in &entry.ancestors {
            if let Some(ancestor) = self.txs.get_mut(ancestor_txid) {
                if ancestor.descendants.remove(txid) {
                    ancestor.descendant_fee = ancestor.descendant_fee.saturating_sub(entry.fee);
                    ancestor.descendant_vsize = ancestor.descendant_vsize.saturating_sub(entry.vsize);
                    ancestor.descendant_size = ancestor.descendant_size.saturating_sub(entry.size);
                }
            }
            self.reindex(ancestor_txid);
        }

        // Drop self from each descendant's ancestors set, and adjust their
        // running ancestor totals. Each descendant counted `entry` exactly
        // once in its ancestor closure, so the decrement is unconditional.
        // The descendant's `parents` set may also reference us — clear that
        // too, since we're no longer in the mempool. A descendant left with
        // no ancestors becomes a root.
        for descendant_txid in &entry.descendants {
            if let Some(descendant) = self.txs.get_mut(descendant_txid) {
                if descendant.ancestors.remove(txid) {
                    descendant.ancestor_fee =
                        descendant.ancestor_fee.saturating_sub(entry.fee);
                    descendant.ancestor_vsize =
                        descendant.ancestor_vsize.saturating_sub(entry.vsize);
                }
                descendant.parents.remove(txid);
            }
            self.reindex(descendant_txid);
        }

        self.record_removal(*txid, reason);
        true
    }

    /// Remove `txid` and every transaction transitively descended from it,
    /// all with `reason`. Used by RBF (replaced txs and their packages
    /// must go), block conflicts, expiry and capacity eviction (packages
    /// are evicted as a unit).
    ///
    /// Removal proceeds deepest-first so each `unlink` call sees a
    /// well-formed graph and the descendant decrements terminate. Returns
    /// the number of transactions actually removed.
    fn evict_with_descendants(&mut self, txid: &Txid, reason: RemovalReason) -> usize {
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

        // Order by descending ancestor count so descendants come first,
        // then by txid so the event order is deterministic.
        to_remove.sort_by_key(|t| {
            (std::cmp::Reverse(self.txs.get(t).map(|e| e.ancestors.len()).unwrap_or(0)), *t)
        });

        let mut removed = 0;
        for t in &to_remove {
            if self.unlink(t, reason.clone()) {
                removed += 1;
            }
        }
        removed
    }

    /// Every mempool transaction that descends from `txid` (empty if it
    /// isn't in the pool or has none).
    pub fn descendants(&self, txid: &Txid) -> Vec<Txid> {
        self.txs.get(txid).map(|e| e.descendants.iter().copied().collect()).unwrap_or_default()
    }

    /// Test hook: make `txid` look older than `MAX_TX_AGE`.
    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self, txid: &Txid) {
        if let Some(e) = self.txs.get_mut(txid) {
            e.added_at = Instant::now().checked_sub(MAX_TX_AGE + Duration::from_secs(1)).unwrap();
        }
    }

    /// Test hook: set the rolling minimum fee (sat/kvB), as an eviction
    /// would.
    #[cfg(test)]
    pub(crate) fn set_rolling_min_fee_for_test(&mut self, per_kvb: f64) {
        self.rolling_min_fee = per_kvb;
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
    ///
    /// Cascades through descendants: an expired tx's children depend on
    /// outputs that no longer exist anywhere, so they cannot survive
    /// independently. Without the cascade we'd leave orphaned children
    /// in the pool whose `parents` set references a vanished entry,
    /// breaking graph invariants and any future replacement attempt.
    pub fn expire_old(&mut self) {
        let expired_roots: Vec<Txid> = self
            .txs
            .iter()
            .filter(|(_, e)| e.added_at.elapsed() > MAX_TX_AGE)
            .map(|(txid, _)| *txid)
            .collect();

        let mut total_removed = 0usize;
        for txid in &expired_roots {
            // An earlier iteration's cascade may have already removed
            // this tx. Skip silently in that case.
            if self.txs.contains_key(txid) {
                total_removed += self.evict_with_descendants(txid, RemovalReason::Expired);
            }
        }
        if total_removed > 0 {
            info!(
                "Mempool: expired {} txs ({} expired roots, {} cascaded descendants)",
                total_removed,
                expired_roots.len(),
                total_removed - expired_roots.len().min(total_removed),
            );
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

    // ── Wallet RPC accessors (ticket 014) ────────────────────────────

    /// Get detailed information about a mempool entry for the wallet RPC.
    pub fn get_entry_info(&self, txid: &Txid) -> Option<MempoolEntryInfo> {
        let e = self.txs.get(txid)?;
        Some(MempoolEntryInfo {
            fee: e.fee,
            vsize: e.vsize,
            fee_rate: e.fee_rate,
            ancestor_count: e.ancestors.len() as u32 + 1, // include self
            descendant_count: e.descendants.len() as u32 + 1,
            ancestor_fee: e.ancestor_fee,
            ancestor_vsize: e.ancestor_vsize,
        })
    }

    /// Estimate fee rates for various confirmation targets by analyzing the
    /// mempool fee distribution. Returns (1-block, 6-block, 144-block) in sat/vB.
    ///
    /// Approach: sort all entries by fee rate descending, then estimate which
    /// fee rate puts you at the Nth block boundary assuming 4M weight units
    /// per block. Simple and correct enough for v1 — real-world miners have
    /// slightly different selection algorithms, but this is what wallet users
    /// need: a rough estimate, not a guarantee.
    pub fn estimate_fee_rates(&self) -> FeeEstimates {
        if self.txs.is_empty() {
            return FeeEstimates {
                one_block: 1.0,
                six_blocks: 1.0,
                twelve_blocks: 1.0,
                twenty_four_blocks: 1.0,
                one_forty_four_blocks: 1.0,
            };
        }

        // Collect (fee_rate, weight) pairs and sort by fee rate descending.
        let mut entries: Vec<(f64, u64)> = self
            .txs
            .values()
            .map(|e| (e.fee_rate, e.vsize * 4)) // vsize * 4 = weight
            .collect();
        entries.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

        let fee_at_block = |target_blocks: u64| -> f64 {
            let capacity = MAX_BLOCK_WEIGHT * target_blocks;
            let mut cumulative_weight: u64 = 0;
            let mut last_rate = 1.0_f64;
            for &(rate, weight) in &entries {
                cumulative_weight = cumulative_weight.saturating_add(weight);
                last_rate = rate;
                if cumulative_weight >= capacity {
                    return rate.max(1.0);
                }
            }
            // Mempool fits in fewer than target_blocks — minimum relay fee.
            last_rate.max(1.0)
        };

        FeeEstimates {
            one_block: fee_at_block(1),
            six_blocks: fee_at_block(6),
            twelve_blocks: fee_at_block(12),
            twenty_four_blocks: fee_at_block(24),
            one_forty_four_blocks: fee_at_block(144),
        }
    }
}

/// Bitcoin Core's `GetDustThreshold` at `DUST_RELAY_FEE_PER_KVB`: an
/// output is dust if it is worth less than the fee to create *and later
/// spend* it. The spend is costed at a typical input for the output's
/// type: 32 + 4 + 1 + 107 + 4 = 148 bytes for a legacy (P2PKH-sized)
/// input, or 32 + 4 + 1 + 107 / 4 + 4 = 67 vbytes for a witness program,
/// whose signature and key sit in the discounted witness. Unspendable
/// outputs (`CScript::IsUnspendable`: OP_RETURN, or over
/// `MAX_SCRIPT_SIZE`) are never dust.
///
/// At 3,000 sat/kvB that gives P2WPKH 294, P2TR and P2WSH 330, P2SH 540
/// and P2PKH 546 sats. Core's fee is `ceil(rate * bytes / 1000)`
/// (`CFeeRate::GetFee`).
pub(crate) fn dust_threshold(output: &bitcoin::TxOut) -> u64 {
    let spk = &output.script_pubkey;
    if spk.is_op_return() || spk.len() > MAX_SCRIPT_SIZE {
        return 0;
    }
    // Serialized txout: 8-byte value, compact-size script length, script.
    let txout_size = 8 + bitcoin::VarInt(spk.len() as u64).size() as u64 + spk.len() as u64;
    let spend_size = if spk.is_witness_program() { 32 + 4 + 1 + 107 / 4 + 4 } else { 32 + 4 + 1 + 107 + 4 };
    (DUST_RELAY_FEE_PER_KVB * (txout_size + spend_size)).div_ceil(1000)
}

/// Mempool entry information exposed to the wallet RPC.
#[derive(Debug, Clone)]
pub struct MempoolEntryInfo {
    pub fee: u64,
    pub vsize: u64,
    pub fee_rate: f64,
    pub ancestor_count: u32,
    pub descendant_count: u32,
    pub ancestor_fee: u64,
    pub ancestor_vsize: u64,
}

/// Fee rate estimates for various confirmation targets.
#[derive(Debug, Clone)]
pub struct FeeEstimates {
    pub one_block: f64,
    pub six_blocks: f64,
    pub twelve_blocks: f64,
    pub twenty_four_blocks: f64,
    pub one_forty_four_blocks: f64,
}

/// Which checks `accept_tx_internal` runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptMode {
    /// A transaction relayed to us by a peer: consensus + standardness +
    /// local relay policy (018).
    Relay,
    /// The user's own transaction (033): consensus + network standardness,
    /// no local relay policy.
    Own,
    /// Test-only: skips script verification and all script-type checks.
    #[cfg_attr(not(test), allow(dead_code))]
    SkipConsensus,
}

/// Which fee-rate floors admission applies (Core's `CheckFeeRate` and
/// where it is skipped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FeeFloor {
    /// The minimum relay fee and the rolling minimum.
    Standard,
    /// Those, and our peers' lowest `feefilter` (sat/kvB): a fresh own
    /// submission ([`Mempool::accept_own_tx_for_network`]).
    Network { per_kvb: u64 },
    /// None, nor the absurd-fee cap: a tx from a disconnected block
    /// (Core's `bypass_limits`; [`Mempool::accept_disconnected_own_tx`]).
    Bypass,
}

/// Output script types this node relays for others (local policy, 018).
/// Bare P2PK and bare multisig are intentionally excluded: P2PK is
/// obsolete (no modern wallet generates it), and bare multisig is the
/// primary vector for Stamps/SRC-20 data embedding. Wrapped versions
/// (P2SH, P2WSH) remain standard via is_p2sh() and is_witness_program().
fn is_relay_standard_script(spk: &bitcoin::Script) -> bool {
    spk.is_p2pkh()
        || spk.is_p2sh()
        || spk.is_witness_program()
        || (spk.is_op_return() && spk.len() <= MAX_OP_RETURN_SIZE)
}

/// Output script types the wider network relays (Bitcoin Core v30-like
/// standardness): adds bare P2PK, bare multisig and OP_RETURN of any size
/// (the whole tx is still bounded by `MAX_TX_WEIGHT`). Used for own txs.
fn is_network_standard_script(spk: &bitcoin::Script) -> bool {
    spk.is_p2pkh()
        || spk.is_p2sh()
        || spk.is_witness_program()
        || spk.is_p2pk()
        || is_standard_bare_multisig(spk)
        || spk.is_op_return()
}

/// Bare multisig as Bitcoin Core's `Solver` + `IsStandard` accept it:
/// `OP_m <key>... OP_n OP_CHECKMULTISIG` with 1 <= m <= n <= 3, where each
/// key push is a well-sized pubkey (33 bytes with an 0x02/0x03 prefix, or
/// 65 bytes with 0x04, or the hybrid 0x06/0x07 that `CPubKey::ValidSize`
/// also admits). `Script::is_multisig` is looser (any n up to 20, any key
/// bytes), and peers would refuse to relay those.
fn is_standard_bare_multisig(spk: &bitcoin::Script) -> bool {
    use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_3};
    use bitcoin::script::Instruction;

    let small_int = |ins: &Instruction| match ins {
        Instruction::Op(op)
            if op.to_u8() >= OP_PUSHNUM_1.to_u8() && op.to_u8() <= OP_PUSHNUM_3.to_u8() =>
        {
            Some((op.to_u8() - OP_PUSHNUM_1.to_u8() + 1) as usize)
        }
        _ => None,
    };
    let Ok(ins) = spk.instructions().collect::<Result<Vec<_>, _>>() else {
        return false;
    };
    // m, at least one key, n, OP_CHECKMULTISIG.
    if ins.len() < 4 || ins.last() != Some(&Instruction::Op(OP_CHECKMULTISIG)) {
        return false;
    }
    let (Some(m), Some(n)) = (small_int(&ins[0]), small_int(&ins[ins.len() - 2])) else {
        return false;
    };
    let keys = &ins[1..ins.len() - 2];
    let valid_key = |ins: &Instruction| match ins {
        Instruction::PushBytes(b) => {
            let b = b.as_bytes();
            match b.first() {
                Some(0x02) | Some(0x03) => b.len() == 33,
                Some(0x04) | Some(0x06) | Some(0x07) => b.len() == 65,
                _ => false,
            }
        }
        _ => false,
    };
    m <= n && keys.len() == n && keys.iter().all(valid_key)
}

// ── Input and witness standardness (policy/policy.cpp) ──────────────────

/// What Core's `Solver` makes of a spent scriptPubKey, as far as
/// `ValidateInputsStandardness` cares.
#[derive(Debug, PartialEq, Eq)]
enum SpentType {
    ScriptHash,
    /// A witness program of a version we don't know (`WITNESS_UNKNOWN`).
    WitnessUnknown,
    NonStandard,
    /// Any other type `Solver` recognizes: PUBKEY, PUBKEYHASH, MULTISIG,
    /// NULL_DATA, P2WPKH, P2WSH, P2TR, ANCHOR.
    Known,
}

/// Core's `CPubKey::ValidSize`: the length the first byte implies.
fn pubkey_valid_size(key: &[u8]) -> bool {
    match key.first() {
        Some(0x02) | Some(0x03) => key.len() == 33,
        Some(0x04) | Some(0x06) | Some(0x07) => key.len() == 65,
        _ => false,
    }
}

/// Core's `CheckMinimalPush` for a push opcode (`opcode <= OP_PUSHDATA4`).
fn is_minimal_push(data: &[u8], opcode: u8) -> bool {
    match data.len() {
        0 => opcode == 0x00,
        // 1..=16 and -1 have their own OP_N opcodes, which aren't pushes.
        1 if (1..=16).contains(&data[0]) || data[0] == 0x81 => false,
        n if n <= 75 => opcode as usize == n,
        n if n <= 255 => opcode == 0x4c,
        n if n <= 65_535 => opcode == 0x4d,
        _ => true,
    }
}

/// `Solver`'s `GetScriptNumber`: `OP_1..OP_16`, or a minimal push of a
/// minimally encoded `CScriptNum` of at most 4 bytes, within `min..=max`.
fn solver_script_number(opcode: u8, data: &[u8], min: i64, max: i64) -> Option<i64> {
    let n = if (0x51..=0x60).contains(&opcode) {
        (opcode - 0x50) as i64
    } else if opcode <= 0x4e {
        if !is_minimal_push(data, opcode) || data.len() > 4 {
            return None;
        }
        if let Some(&last) = data.last() {
            if last & 0x7f == 0 && (data.len() <= 1 || data[data.len() - 2] & 0x80 == 0) {
                return None; // not minimally encoded
            }
        }
        let mut v: i64 = 0;
        for (i, b) in data.iter().enumerate() {
            v |= (*b as i64) << (8 * i);
        }
        match data.last() {
            Some(&last) if last & 0x80 != 0 => -(v & !(0x80i64 << (8 * (data.len() - 1)))),
            _ => v,
        }
    } else {
        return None;
    };
    (min..=max).contains(&n).then_some(n)
}

/// `Solver`'s `MatchMultisig`: `<m> <key>... <n> OP_CHECKMULTISIG`, any
/// `1 <= m <= n <= 20` (not only what `IsStandard` relays as an output).
fn solver_is_multisig(spk: &[u8]) -> bool {
    use crate::contextual_checks::get_op;
    if spk.last() != Some(&0xae) {
        return false;
    }
    let mut pc = 0;
    let Some((op, data)) = get_op(spk, &mut pc) else { return false };
    let Some(m) = solver_script_number(op, data, 1, 20) else { return false };
    let mut keys = 0i64;
    let (op, data) = loop {
        match get_op(spk, &mut pc) {
            Some((_, data)) if pubkey_valid_size(data) => keys += 1,
            Some(last) => break last,
            // Core's GetOp leaves OP_INVALIDOPCODE on failure.
            None => break (0xff, &[][..]),
        }
    };
    let Some(n) = solver_script_number(op, data, m, 20) else { return false };
    keys == n && pc + 1 == spk.len()
}

/// Core's `Solver`, reduced to [`SpentType`], in its order.
fn solver_type(spk: &[u8]) -> SpentType {
    use crate::contextual_checks::{is_p2sh, witness_program};
    if is_p2sh(spk) {
        return SpentType::ScriptHash;
    }
    if let Some((version, program)) = witness_program(spk) {
        return match (version, program.len()) {
            (0, 20) | (0, 32) | (1, 32) => SpentType::Known,
            (1, 2) if program == [0x4e, 0x73] => SpentType::Known, // ANCHOR (P2A)
            (0, _) => SpentType::NonStandard,
            _ => SpentType::WitnessUnknown,
        };
    }
    if spk.first() == Some(&0x6a) && is_push_only(bitcoin::Script::from_bytes(&spk[1..])) {
        return SpentType::Known; // NULL_DATA
    }
    let p2pk = match spk.len() {
        67 => spk[0] == 65,
        35 => spk[0] == 33,
        _ => false,
    } && spk.last() == Some(&0xac)
        && pubkey_valid_size(&spk[1..spk.len() - 1]);
    let p2pkh = spk.len() == 25
        && spk[..3] == [0x76, 0xa9, 0x14]
        && spk[23..] == [0x88, 0xac];
    if p2pk || p2pkh || solver_is_multisig(spk) {
        SpentType::Known
    } else {
        SpentType::NonStandard
    }
}

/// The stack a push-only scriptSig leaves (`EvalScript` with
/// `SCRIPT_VERIFY_NONE`, as the policy checks run it to find a redeem
/// script), or the reason `EvalScript` fails: a push over 520 bytes,
/// `OP_RESERVED`, more than 1000 items, or a parse error. The caller has
/// already required push-only (`scriptsig-not-pushonly`).
fn eval_push_only(script_sig: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    use crate::contextual_checks::get_op;
    // OP_N's values, for OP_1NEGATE (0x4f) to OP_16 (0x60).
    const SMALL: [u8; 18] = [0x81, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut stack = Vec::new();
    let mut pc = 0;
    while pc < script_sig.len() {
        let (op, data) = get_op(script_sig, &mut pc).ok_or("bad opcode")?;
        if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err("push size");
        }
        match op {
            0x00..=0x4e => stack.push(data),
            0x4f | 0x51..=0x60 => stack.push(std::slice::from_ref(&SMALL[(op - 0x4f) as usize])),
            _ => return Err("bad opcode"), // OP_RESERVED, or not push-only
        }
        if stack.len() > MAX_STACK_SIZE {
            return Err("stack size");
        }
    }
    Ok(stack)
}

/// Core's `ValidateInputsStandardness` (`bad-txns-nonstandard-inputs`):
/// at most `MAX_TX_LEGACY_SIGOPS` legacy sigops (BIP 54), no spend of a
/// NONSTANDARD or unknown-witness-version output, and P2SH redeem scripts
/// that parse and have at most `MAX_P2SH_SIGOPS` sigops. `spent[i]` is the
/// scriptPubKey input `i` spends.
fn validate_inputs_standardness(tx: &Transaction, spent: &[&[u8]]) -> Result<(), MempoolError> {
    use crate::contextual_checks::{is_p2sh, p2sh_redeem_sigop_count, script_sigop_count};
    let nonstandard = |input_index: Option<usize>, reason: String| {
        Err(MempoolError::NonStandardInputs { input_index, reason })
    };

    // CheckSigopsBIP54: sigops counted where they execute, i.e. in the
    // scriptSig and in the spent scriptPubKey (or its redeem script),
    // accurately (`GetSigOpCount(true)` / `GetSigOpCount(scriptSig)`).
    let mut legacy: u64 = 0;
    for (txin, spk) in tx.input.iter().zip(spent) {
        let script_sig = txin.script_sig.as_bytes();
        legacy += script_sigop_count(script_sig, true);
        legacy += if is_p2sh(spk) { p2sh_redeem_sigop_count(script_sig) } else { script_sigop_count(spk, true) };
        if legacy > MAX_TX_LEGACY_SIGOPS {
            return nonstandard(None, "non-witness sigops exceed bip54 limit".into());
        }
    }

    for (i, (txin, spk)) in tx.input.iter().zip(spent).enumerate() {
        match solver_type(spk) {
            SpentType::NonStandard => return nonstandard(Some(i), "script unknown".into()),
            SpentType::WitnessUnknown => {
                return nonstandard(Some(i), "witness program is undefined".into())
            }
            SpentType::ScriptHash => {
                let stack = match eval_push_only(txin.script_sig.as_bytes()) {
                    Ok(stack) => stack,
                    Err(e) => return nonstandard(Some(i), format!("p2sh scriptsig malformed ({})", e)),
                };
                let Some(redeem) = stack.last() else {
                    return nonstandard(Some(i), "P2SH redeemscript missing".into());
                };
                let sigops = script_sigop_count(redeem, true);
                if sigops > MAX_P2SH_SIGOPS {
                    return nonstandard(
                        Some(i),
                        format!("p2sh redeemscript sigops exceed limit ({} > {})", sigops, MAX_P2SH_SIGOPS),
                    );
                }
            }
            SpentType::Known => {}
        }
    }
    Ok(())
}

/// Core's `IsWitnessStandard` (`bad-witness-nonstandard`): a witness only
/// on a witness program (native or P2SH-wrapped) other than P2A, P2WSH
/// within the script-size and stack limits, and Taproot with no annex and,
/// for a tapscript leaf, stack items of at most 80 bytes.
fn is_witness_standard(tx: &Transaction, spent: &[&[u8]]) -> Result<(), MempoolError> {
    use crate::contextual_checks::{is_p2sh, witness_program};
    for (i, (txin, spk)) in tx.input.iter().zip(spent).enumerate() {
        let fail = |reason| Err(MempoolError::NonStandardWitness { input_index: i, reason });
        let witness = &txin.witness;
        if witness.is_empty() {
            // An empty witness can't be bloated; an invalid spend without
            // one fails script verification.
            continue;
        }
        if *spk == [0x51, 0x02, 0x4e, 0x73] {
            return fail("witness stuffing on a pay-to-anchor spend");
        }
        let mut script: &[u8] = spk;
        let mut p2sh = false;
        if is_p2sh(spk) {
            let stack = match eval_push_only(txin.script_sig.as_bytes()) {
                Ok(stack) => stack,
                Err(_) => return fail("P2SH scriptSig does not evaluate"),
            };
            let Some(redeem) = stack.last() else { return fail("P2SH redeem script missing") };
            script = redeem;
            p2sh = true;
        }
        let Some((version, program)) = witness_program(script) else {
            return fail("witness on a non-witness-program spend");
        };
        let items: Vec<&[u8]> = witness.iter().collect();
        if version == 0 && program.len() == 32 {
            let (witness_script, stack) = items.split_last().expect("witness is not empty");
            if witness_script.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
                return fail("P2WSH witness script too large");
            }
            if stack.len() > MAX_STANDARD_P2WSH_STACK_ITEMS {
                return fail("P2WSH witness stack has too many items");
            }
            if stack.iter().any(|item| item.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE) {
                return fail("P2WSH witness stack item too large");
            }
        }
        if version == 1 && program.len() == 32 && !p2sh {
            if items.len() >= 2 && items.last().is_some_and(|a| a.first() == Some(&0x50)) {
                return fail("taproot annex");
            }
            if items.len() >= 2 {
                // Script path: control block last, then the leaf script.
                let control_block = items[items.len() - 1];
                if control_block.is_empty() {
                    return fail("empty taproot control block");
                }
                if control_block[0] & 0xfe == 0xc0
                    && items[..items.len() - 2]
                        .iter()
                        .any(|item| item.len() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE)
                {
                    return fail("tapscript stack item too large");
                }
            }
            // One item is a key-path spend: no policy limits.
        }
    }
    Ok(())
}

/// Core's `CScript::IsPushOnly`: the script parses, and every opcode is a
/// push or a small-number opcode up to OP_16 (which counts OP_1NEGATE and
/// OP_RESERVED, as Core does).
fn is_push_only(script: &bitcoin::Script) -> bool {
    use bitcoin::opcodes::all::OP_PUSHNUM_16;
    use bitcoin::script::Instruction;
    script.instructions().all(|ins| match ins {
        Ok(Instruction::PushBytes(_)) => true,
        Ok(Instruction::Op(op)) => op.to_u8() <= OP_PUSHNUM_16.to_u8(),
        Err(_) => false,
    })
}

/// Errors from mempool transaction validation.
#[derive(Debug)]
pub enum MempoolError {
    CoinbaseTx,
    MalformedTx,
    /// Two inputs spend the same outpoint (CheckTransaction,
    /// `bad-txns-inputs-duplicate`). Consensus-invalid.
    DuplicateInput { input_index: usize },
    /// An output, the output total or the input total exceeds MAX_MONEY
    /// (`bad-txns-vout-toolarge`, `bad-txns-txouttotal-toolarge`,
    /// `bad-txns-inputvalues-outofrange`). Consensus-invalid.
    ValueOutOfRange { what: &'static str, amount: u64 },
    AlreadyInMempool,
    MissingInput { txid: Txid, vout: u32 },
    ImmatureCoinbase { input_index: usize, coinbase_height: u32 },
    ScriptFailure { input_index: usize, error: String },
    Inflation,
    /// Arithmetic overflow during fee/size accounting. Distinct from
    /// `Inflation` (outputs > inputs) — this is a checked-arithmetic
    /// failure that can only occur for adversarial or malformed values.
    MathOverflow,
    InsufficientFee { fee_rate: f64, min_rate: f64 },
    /// Absolute fee exceeds the wallet-safety ceiling (`ABSURD_FEE_THRESHOLD`).
    AbsurdFee { fee: u64, limit: u64 },
    /// Mempool is at capacity and evicting packages cheaper than the one
    /// the incoming tx joins can't make room for it (Core's `mempool
    /// full`). Rejected pre-mutation by the Phase 6.5 admission plan, so
    /// nothing was evicted. `new_fee_rate` is that package's rate;
    /// `min_pkg_fee_rate` is the lowest package rate it would have had to
    /// beat to displace something else.
    MempoolFull { new_fee_rate: f64, min_pkg_fee_rate: f64 },
    /// Fee rate below the rolling minimum a recently full pool demands
    /// (Core's `mempool min fee not met`; see `mempool_min_fee_rate`).
    MempoolMinFeeNotMet { fee_rate: f64, min_rate: f64 },
    /// An own tx's fee is below every connected peer's `feefilter`, so no
    /// peer would be sent it (`accept_own_tx_for_network`). `min_rate`
    /// (sat/vB) clears our own floors and that one.
    BelowNetworkMinimum { fee_rate: f64, min_rate: f64 },
    /// Serialized without witness, under `MIN_STANDARD_TX_NONWITNESS_SIZE`
    /// bytes (`tx-size-small`).
    TxSizeSmall { size: usize },
    /// A spent output's type or a P2SH redeem script fails Core's
    /// `ValidateInputsStandardness` (`bad-txns-nonstandard-inputs`).
    /// `reason` is Core's detail string; `input_index` is None for the
    /// whole-tx BIP 54 legacy sigop limit.
    NonStandardInputs { input_index: Option<usize>, reason: String },
    /// A witness fails Core's `IsWitnessStandard` (`bad-witness-nonstandard`).
    NonStandardWitness { input_index: usize, reason: &'static str },
    /// The scripts pass the consensus flags but not Core's
    /// STANDARD_SCRIPT_VERIFY_FLAGS (`mempool-script-verify-flag-failed`):
    /// valid, but no peer relays it. `error` is Core's ScriptError string.
    NonStandardScriptFlags { input_index: usize, error: String },
    OversizedTx { weight: u64 },
    /// An output worth less than its type's `dust_threshold`.
    DustOutput { index: usize, amount: u64, threshold: u64 },
    NonStandardScript { index: usize },
    /// Version outside 1..=`TX_MAX_STANDARD_VERSION` (IsStandardTx, `version`).
    NonStandardVersion { version: i32 },
    /// A scriptSig over `MAX_STANDARD_SCRIPTSIG_SIZE` (`scriptsig-size`) or
    /// with non-push opcodes (`scriptsig-not-pushonly`); `reason` is
    /// Core's reject string.
    NonStandardScriptSig { input_index: usize, reason: &'static str },
    /// Sigop cost over `MAX_STANDARD_TX_SIGOPS_COST` (`bad-txns-too-many-sigops`).
    TooManySigops { cost: u64, limit: u64 },
    /// Transaction rejected by Knots-aligned relay policy (spam filters).
    PolicyRejection(crate::relay_policy::PolicyRejection),
    NonFinal { lock_time: u32, current_height: u32 },
    /// A BIP 68 relative lock isn't satisfied in the next block (Core's
    /// `non-BIP68-final`). Lock points are the last invalid height/MTP.
    NonBip68Final { min_height: i64, min_time: i64, current_height: u32 },
    UtxoLookup(String),
    /// Header timestamps for median-time-past were unavailable (local).
    ChainContext(String),
    /// The script verifier itself failed (bad flags, mismatched spent
    /// outputs, a tx it could not parse back, a kernel/FFI fault): our
    /// fault, not proof the transaction is invalid. See `from_script_verify`.
    ScriptVerifierError { input_index: usize, error: String },
    // CPFP / ancestor tracking (ticket 010)
    TooManyAncestors { count: usize, limit: usize },
    AncestorSetTooLarge { vbytes: u64, limit: u64 },
    TooManyDescendants { ancestor: Txid, count: usize, limit: usize },
    // BIP 125 RBF (ticket 009)
    TooManyReplacements { evicted: usize, limit: usize },
    /// A replacement spends from unconfirmed `parent`, which none of the
    /// txs it replaces spent from (`replacement-adds-unconfirmed`).
    ReplacementAddsUnconfirmed { input_index: usize, parent: Txid },
    ReplacementFeeTooLow { replacement: f64, conflict: f64 },
    ReplacementFeeInsufficient {
        provided: u64,
        required: u64,
        evicted_fee_total: u64,
        relay_surcharge: u64,
    },
}

impl MempoolError {
    /// Invalid on its face, with no chain state involved: a loose coinbase
    /// or a failure of Core's context-free `CheckTransaction` (no inputs or
    /// outputs, a duplicate input, a value out of range). No honest node
    /// relays one, so `handle_tx` disconnects the sender (ticket 053).
    /// Script and input-value failures are left out on purpose: they depend
    /// on the coins and flags we judge with, and Core 30+ no longer
    /// punishes any tx rejection (its mempool reports script failures as
    /// `TX_NOT_STANDARD`).
    pub fn is_invalid_on_its_face(&self) -> bool {
        matches!(
            self,
            MempoolError::CoinbaseTx
                | MempoolError::MalformedTx
                | MempoolError::DuplicateInput { .. }
                | MempoolError::ValueOutOfRange { .. }
        )
    }

    /// Classify a failure of the policy-flag script pass that the
    /// consensus flags then passed: non-standard (Core's
    /// `mempool-script-verify-flag-failed`), or our verifier's own fault.
    fn from_policy_script_verify(f: script_verify::PolicyScriptFailure) -> MempoolError {
        match f.error {
            script_verify::ScriptVerifyError::ScriptFailed => MempoolError::NonStandardScriptFlags {
                input_index: f.input_index,
                error: f.script_error,
            },
            other => MempoolError::ScriptVerifierError { input_index: f.input_index, error: other.to_string() },
        }
    }

    /// Classify a script-verifier failure, as `block_validation::script_error`
    /// does for blocks (ticket 024): only a script that evaluated to false
    /// is `ScriptFailure`. Exhaustive so a new `ScriptVerifyError` must be
    /// classified here.
    fn from_script_verify(f: script_verify::ScriptVerifyFailure) -> MempoolError {
        use script_verify::ScriptVerifyError as E;
        let script_verify::ScriptVerifyFailure { input_index, error } = f;
        match error {
            E::ScriptFailed => MempoolError::ScriptFailure {
                input_index,
                error: error.to_string(),
            },
            E::InvalidFlags(_)
            | E::SpentOutputsMismatch { .. }
            | E::NoInputs
            | E::TxDeserialize
            | E::Library(_) => MempoolError::ScriptVerifierError {
                input_index,
                error: error.to_string(),
            },
        }
    }
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::CoinbaseTx => write!(f, "coinbase transactions are not allowed in mempool"),
            MempoolError::MalformedTx => write!(f, "transaction has empty inputs or outputs"),
            MempoolError::DuplicateInput { input_index } => {
                write!(f, "input {} spends an outpoint an earlier input already spends", input_index)
            }
            MempoolError::ValueOutOfRange { what, amount } => {
                write!(f, "{} of {} sats exceeds MAX_MONEY", what, amount)
            }
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
            MempoolError::MathOverflow => {
                write!(f, "arithmetic overflow in fee or size accounting")
            }
            MempoolError::InsufficientFee { fee_rate, min_rate } => {
                write!(
                    f,
                    "fee rate {:.2} sat/vB below minimum {:.2}",
                    fee_rate, min_rate
                )
            }
            MempoolError::AbsurdFee { fee, limit } => {
                write!(
                    f,
                    "absolute fee {} sats exceeds safety ceiling {} sats",
                    fee, limit
                )
            }
            MempoolError::MempoolFull {
                new_fee_rate,
                min_pkg_fee_rate,
            } => {
                write!(
                    f,
                    "mempool full: tx fee rate {:.2} sat/vB does not exceed lowest surviving package rate {:.2} sat/vB",
                    new_fee_rate, min_pkg_fee_rate
                )
            }
            MempoolError::MempoolMinFeeNotMet { fee_rate, min_rate } => {
                write!(
                    f,
                    "fee rate {:.2} sat/vB below the mempool's rolling minimum {:.2} sat/vB",
                    fee_rate, min_rate
                )
            }
            MempoolError::BelowNetworkMinimum { fee_rate, min_rate } => {
                write!(
                    f,
                    "fee rate {:.2} sat/vB is below what every connected peer accepts ({:.2} sat/vB)",
                    fee_rate, min_rate
                )
            }
            MempoolError::TxSizeSmall { size } => {
                write!(
                    f,
                    "transaction is {} bytes without witness, under the standard minimum {}",
                    size, MIN_STANDARD_TX_NONWITNESS_SIZE
                )
            }
            MempoolError::NonStandardInputs { input_index: Some(i), reason } => {
                write!(f, "input {} is non-standard: {}", i, reason)
            }
            MempoolError::NonStandardInputs { input_index: None, reason } => {
                write!(f, "non-standard inputs: {}", reason)
            }
            MempoolError::NonStandardWitness { input_index, reason } => {
                write!(f, "input {} has a non-standard witness: {}", input_index, reason)
            }
            MempoolError::NonStandardScriptFlags { input_index, error } => {
                write!(f, "input {} script is non-standard: {}", input_index, error)
            }
            MempoolError::OversizedTx { weight } => {
                write!(f, "transaction weight {} exceeds limit {}", weight, MAX_TX_WEIGHT)
            }
            MempoolError::DustOutput { index, amount, threshold } => {
                write!(
                    f,
                    "output {} is dust ({} sats, min {} for its type)",
                    index, amount, threshold
                )
            }
            MempoolError::NonStandardScript { index } => {
                write!(f, "output {} has non-standard script type", index)
            }
            MempoolError::NonStandardVersion { version } => {
                write!(f, "transaction version {} is non-standard", version)
            }
            MempoolError::NonStandardScriptSig { input_index, reason } => {
                write!(f, "input {} scriptSig is non-standard ({})", input_index, reason)
            }
            MempoolError::TooManySigops { cost, limit } => {
                write!(f, "sigop cost {} exceeds standard limit {}", cost, limit)
            }
            MempoolError::PolicyRejection(ref r) => {
                write!(f, "relay policy: {:?}", r)
            }
            MempoolError::NonFinal { lock_time, current_height } => {
                write!(
                    f,
                    "transaction not final (locktime={}, current_height={})",
                    lock_time, current_height
                )
            }
            MempoolError::NonBip68Final { min_height, min_time, current_height } => {
                write!(
                    f,
                    "transaction not BIP 68 final (needs height > {} and median time > {}, -1 = no lock; current_height={})",
                    min_height, min_time, current_height
                )
            }
            MempoolError::UtxoLookup(e) => write!(f, "UTXO lookup error: {}", e),
            MempoolError::ChainContext(e) => write!(f, "header context unavailable: {}", e),
            MempoolError::ScriptVerifierError { input_index, error } => {
                write!(f, "script verifier error on input {}: {}", input_index, error)
            }
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
            MempoolError::ReplacementAddsUnconfirmed { input_index, parent } => {
                write!(
                    f,
                    "replacement input {} spends unconfirmed {}, which no replaced tx spent from",
                    input_index, parent
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
        }
    }
}

impl std::error::Error for MempoolError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_multisig_standardness_matches_core() {
        use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1, OP_PUSHNUM_2, OP_PUSHNUM_3, OP_PUSHNUM_4};
        use bitcoin::opcodes::Opcode;
        use bitcoin::script::{Builder, PushBytesBuf};
        let key = |prefix: u8, len: usize| {
            let mut k = vec![0x11u8; len];
            k[0] = prefix;
            PushBytesBuf::try_from(k).unwrap()
        };
        let ms = |m: Opcode, keys: Vec<PushBytesBuf>, n: Opcode| {
            let mut b = Builder::new().push_opcode(m);
            for k in keys {
                b = b.push_slice(k);
            }
            b.push_opcode(n).push_opcode(OP_CHECKMULTISIG).into_script()
        };
        let c = || key(0x02, 33);
        let ok = |s: &bitcoin::Script| is_network_standard_script(s);

        assert!(ok(&ms(OP_PUSHNUM_1, vec![c()], OP_PUSHNUM_1)));
        assert!(ok(&ms(OP_PUSHNUM_2, vec![c(), key(0x03, 33), key(0x04, 65)], OP_PUSHNUM_3)));
        assert!(ok(&ms(OP_PUSHNUM_1, vec![key(0x06, 65), key(0x07, 65)], OP_PUSHNUM_2)));
        // n > 3.
        assert!(!ok(&ms(OP_PUSHNUM_1, vec![c(), c(), c(), c()], OP_PUSHNUM_4)));
        // m > n.
        assert!(!ok(&ms(OP_PUSHNUM_3, vec![c(), c()], OP_PUSHNUM_2)));
        // Key count disagrees with n.
        assert!(!ok(&ms(OP_PUSHNUM_1, vec![c(), c()], OP_PUSHNUM_3)));
        // Key pushes that aren't pubkeys (data-carrying "multisig").
        assert!(!ok(&ms(OP_PUSHNUM_1, vec![key(0x02, 65)], OP_PUSHNUM_1)));
        assert!(!ok(&ms(OP_PUSHNUM_1, vec![key(0x04, 33)], OP_PUSHNUM_1)));
        assert!(!ok(&ms(OP_PUSHNUM_1, vec![key(0x05, 33)], OP_PUSHNUM_1)));
        assert!(!ok(&ms(OP_PUSHNUM_1, vec![key(0x02, 32)], OP_PUSHNUM_1)));
        // m = 0.
        let zero = Builder::new()
            .push_int(0)
            .push_slice(c())
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert!(!ok(&zero));
    }
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
    // script verification and the standard-script-type check; every
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
        assert_eq!(child_entry.ancestor_vsize, parent_entry.vsize);
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
        // ancestor_fee/vsize sums each ancestor once.
        assert_eq!(
            d_entry.ancestor_fee,
            a_entry.fee + b_entry.fee + c_entry.fee
        );
        assert_eq!(
            d_entry.ancestor_vsize,
            a_entry.vsize + b_entry.vsize + c_entry.vsize
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
        //
        // Sizing note: keep A's fee comfortably below ABSURD_FEE_THRESHOLD
        // (10 BTC). Outputs sum to ~75 M sats; root UTXO is sized to make
        // A's fee a tidy 10 k sats.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 75_010_000);

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
        let b_vsize = pool.txs.get(&b_txid).unwrap().vsize;
        let original_ancestor_fee = c_before.ancestor_fee;
        let original_ancestor_vsize = c_before.ancestor_vsize;

        assert!(pool.remove_tx(&b_txid));

        // C should still exist
        assert!(pool.contains(&c_txid));
        let c_after = pool.txs.get(&c_txid).unwrap();
        assert!(!c_after.ancestors.contains(&b_txid));
        assert!(c_after.ancestors.contains(&a_txid));
        assert!(!c_after.parents.contains(&b_txid));
        assert_eq!(c_after.ancestor_fee, original_ancestor_fee - b_fee);
        assert_eq!(c_after.ancestor_vsize, original_ancestor_vsize - b_vsize);

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

        let removed = pool.evict_with_descendants(&b_txid, RemovalReason::Evicted);
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
        assert_eq!(b_entry.ancestor_vsize, 0);
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
    fn rbf_allows_replacement_with_existing_mempool_parent() {
        // BIP 125 rule 2 as Knots and Core ≤ 30 enforce it
        // (`replacement-adds-unconfirmed`, owner decision on ticket 053):
        // a replacement may spend unconfirmed outputs only of txs the
        // conflicts already spent from. It used to be relaxed here, so a
        // fee bump accepted locally died on Knots peers.
        //
        // Setup: P1, P2 both in mempool. A spends P1.0 only. A' spends
        // P1.0 (the conflict) and P2.0 (in the mempool, but not a parent
        // of A): rejected. A'' spends P1.0 and P1.1 (P1 already a parent
        // of A): accepted.
        let (utxo, _dir) = fresh_utxo();
        let r1 = seed_txid(1);
        let r2 = seed_txid(2);
        seed_utxo(&utxo, r1, 0, 1_000_000);
        seed_utxo(&utxo, r2, 0, 1_000_000);

        let mut pool = Mempool::new();
        // P1 has two outputs so we can spend one (in A) and the other
        // (left untouched, just to ensure P1 stays in the mempool).
        let p1 = make_tx(&[(r1, 0)], &[400_000, 400_000]);
        let p1_txid = pool.accept_tx_test(p1, &utxo, TEST_HEIGHT).unwrap();
        let p2 = make_tx(&[(r2, 0)], &[990_000]);
        let p2_txid = pool.accept_tx_test(p2, &utxo, TEST_HEIGHT).unwrap();

        // A spends P1.0 only.
        let a = make_tx_marked(&[(p1_txid, 0)], &[390_000], 0xa);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();

        // A' spends P1.0 (RBF conflict with A) AND P2.0 (a mempool tx A
        // didn't spend from). It pays a much higher absolute fee, but
        // that doesn't matter.
        let a_prime = make_tx_marked(&[(p1_txid, 0), (p2_txid, 0)], &[1_300_000], 0xb);
        let err = pool.accept_tx_test(a_prime, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(
            matches!(err, MempoolError::ReplacementAddsUnconfirmed { input_index: 1, parent } if parent == p2_txid),
            "{:?}",
            err
        );
        assert!(pool.contains(&a_txid));

        // A'' adds P1.1: P1 is already a parent of A, so nothing new.
        let a_second = make_tx_marked(&[(p1_txid, 0), (p1_txid, 1)], &[700_000], 0xc);
        let a_second_txid = pool.accept_tx_test(a_second, &utxo, TEST_HEIGHT).unwrap();
        assert!(pool.contains(&a_second_txid));
        assert!(!pool.contains(&a_txid));
        assert!(pool.txs[&a_second_txid].parents.contains(&p1_txid));
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

    // ── Code-review fixes (Phase 6.5 admission, absurd fee, expire cascade) ──

    #[test]
    fn absurd_fee_rejected_for_own_txs_only() {
        // Burning the entire input as fees should trip the anti-foot-shoot
        // ceiling (0.1 BTC) on the user's own send; a relayed tx paying
        // that much is someone else's business, as in Core.
        let (utxo, _dir) = fresh_utxo();
        let coin = seed_op_true(&utxo, 1, 20 * 100_000_000, 1, false); // 20 BTC

        // Output of 1000 sats; fee = 20 BTC - 1000 sats.
        let tx = spend_ops(&[coin], vec![p2wpkh_out(1000)]);
        let err = accept_in(&mut Mempool::new(), tx.clone(), &utxo, TEST_HEIGHT, AcceptMode::Own).unwrap_err();
        assert!(matches!(
            err,
            MempoolError::AbsurdFee { fee, limit }
                if fee > limit && limit == 10_000_000
        ));
        for mode in [AcceptMode::Relay, AcceptMode::SkipConsensus] {
            accept_in(&mut Mempool::new(), tx.clone(), &utxo, TEST_HEIGHT, mode)
                .unwrap_or_else(|e| panic!("{:?}: {:?}", mode, e));
        }
    }

    #[test]
    fn capacity_admission_rejects_low_fee_tx_at_full_pool() {
        // Pool is at capacity with a high-rate tx. A low-rate tx that
        // would force eviction must be rejected by Phase 6.5 admission
        // *before* the high-rate tx is touched. The bug being guarded
        // against: pre-Phase-6.5 the post-mutation eviction loop would
        // sometimes evict the new tx and return Err, but if any innocent
        // package was evicted in an earlier loop iteration first, that
        // damage was permanent.
        let (utxo, _dir) = fresh_utxo();
        let r1 = seed_txid(1);
        let r2 = seed_txid(2);
        seed_utxo(&utxo, r1, 0, 1_000_000);
        seed_utxo(&utxo, r2, 0, 1_000_000);

        // Tight cap that fits exactly one ~62-byte tx.
        let mut pool = Mempool::with_max_size(70);

        // High-rate incumbent: low output → high fee per byte.
        let high = make_tx_marked(&[(r1, 0)], &[100_000], 0xa);
        let high_txid = pool.accept_tx_test(high, &utxo, TEST_HEIGHT).unwrap();
        assert!(pool.contains(&high_txid));

        // Low-rate intruder: high output → low fee per byte. Total size
        // after insertion exceeds cap, so the eviction loop has to drop
        // something. Phase 6.5 should detect that the intruder is the
        // worst-rate package and reject pre-mutation.
        let low = make_tx_marked(&[(r2, 0)], &[990_000], 0xb);
        let err = pool.accept_tx_test(low, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(
            matches!(err, MempoolError::MempoolFull { .. }),
            "expected MempoolFull, got {:?}",
            err
        );

        // Innocent high-rate tx must be untouched. This is the
        // "no collateral damage" guarantee.
        assert!(pool.contains(&high_txid));
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn capacity_admission_accepts_high_fee_tx_at_full_pool() {
        // Mirror of the above: a high-rate intruder *should* displace a
        // low-rate incumbent. Phase 6.5 must NOT reject in this case.
        let (utxo, _dir) = fresh_utxo();
        let r1 = seed_txid(1);
        let r2 = seed_txid(2);
        seed_utxo(&utxo, r1, 0, 1_000_000);
        seed_utxo(&utxo, r2, 0, 1_000_000);

        let mut pool = Mempool::with_max_size(70);

        // Low-rate incumbent.
        let low = make_tx_marked(&[(r1, 0)], &[990_000], 0xa);
        let low_txid = pool.accept_tx_test(low, &utxo, TEST_HEIGHT).unwrap();

        // High-rate intruder.
        let high = make_tx_marked(&[(r2, 0)], &[100_000], 0xb);
        let high_txid = pool.accept_tx_test(high, &utxo, TEST_HEIGHT).unwrap();

        assert!(pool.contains(&high_txid));
        assert!(!pool.contains(&low_txid));
    }

    #[test]
    fn expire_old_cascades_to_descendants() {
        // A → B → C in mempool. Manually age A past MAX_TX_AGE; expire_old
        // should cascade and remove B and C as well, since they depend on
        // A's outputs which would otherwise dangle.
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
        assert_eq!(pool.count(), 3);

        // Forge A's added_at to be older than the expiry window.
        let stale = Instant::now()
            .checked_sub(MAX_TX_AGE + std::time::Duration::from_secs(60))
            .expect("test machine clock should be far enough into uptime");
        pool.txs.get_mut(&a_txid).unwrap().added_at = stale;

        pool.expire_old();

        // The cascade should have removed all three.
        assert!(!pool.contains(&a_txid));
        assert!(!pool.contains(&b_txid));
        assert!(!pool.contains(&c_txid));
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn vsize_used_for_fee_rate_not_raw_bytes() {
        // Sanity check that fee_rate is computed against vsize. Our test
        // helper builds non-witness txs, so vsize == size, but the
        // semantics are: fee_rate = fee / vsize. Confirm the stored
        // fee_rate matches that math.
        let (utxo, _dir) = fresh_utxo();
        let parent = seed_txid(1);
        seed_utxo(&utxo, parent, 0, 100_000);

        let mut pool = Mempool::new();
        let tx = make_tx(&[(parent, 0)], &[90_000]);
        let txid = pool.accept_tx_test(tx, &utxo, TEST_HEIGHT).unwrap();
        let entry = pool.txs.get(&txid).unwrap();
        let expected_rate = entry.fee as f64 / entry.vsize as f64;
        assert!(
            (entry.fee_rate - expected_rate).abs() < 1e-9,
            "fee_rate should be fee/vsize: got {} expected {}",
            entry.fee_rate,
            expected_rate
        );
    }

    #[test]
    fn missing_input_when_parent_in_evict_set() {
        // RBF setup where the replacement tries to spend an output of
        // the very tx it's replacing — must be MissingInput, not a
        // successful chained spend. This was already correct behavior
        // but is worth pinning down with a regression test now that the
        // accept loop is in flux.
        let (utxo, _dir) = fresh_utxo();
        let root = seed_txid(1);
        seed_utxo(&utxo, root, 0, 1_000_000);

        let mut pool = Mempool::new();
        // Original A spends `root`, produces an output.
        let a = make_tx_marked(&[(root, 0)], &[900_000], 0xa);
        let a_txid = pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();

        // Replacement A' spends `root` (RBF conflict with A) and *also*
        // tries to spend a.0 — but A is in `to_evict`, so a.0 should
        // resolve as MissingInput rather than as a chained mempool spend.
        let a_prime = make_tx_marked(&[(root, 0), (a_txid, 0)], &[1_700_000], 0xb);
        let err = pool.accept_tx_test(a_prime, &utxo, TEST_HEIGHT).unwrap_err();
        assert!(
            matches!(err, MempoolError::MissingInput { txid, .. } if txid == a_txid),
            "expected MissingInput on a_txid, got {:?}",
            err
        );

        // A is still in the mempool — the rejection happened pre-mutation.
        assert!(pool.contains(&a_txid));
    }

    // ── Ticket 026: finality and BIP 68 at the tip ──────────────────────

    /// Synthetic header timestamps for `accept_tx_test`: 600 s apart from
    /// 1,600,000,000, so MTP(h) = 1,600,000,000 + 600·(h − 5) for h ≥ 10.
    pub(super) fn synthetic_times(height: u32) -> Result<u32, String> {
        Ok(1_600_000_000 + 600 * height)
    }

    fn tip_mtp() -> u32 {
        crate::contextual_checks::median_time_past(&synthetic_times, TEST_HEIGHT).unwrap() as u32
    }

    fn locked_tx(lock_time: u32, sequence: u32) -> (UtxoSet, TempDir, Transaction) {
        let (utxo, dir) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 100_000);
        let mut tx = make_tx(&[(seed_txid(1), 0)], &[90_000]);
        tx.lock_time = LockTime::from_consensus(lock_time);
        tx.input[0].sequence = Sequence(sequence);
        (utxo, dir, tx)
    }

    /// Header source that counts reads and names its tip, for the tip-MTP
    /// cache.
    struct CountingTimes {
        reads: std::cell::Cell<u32>,
        tip_id: std::cell::Cell<[u8; 32]>,
    }

    impl HeaderTimes for CountingTimes {
        fn timestamp_at(&self, height: u32) -> Result<u32, String> {
            self.reads.set(self.reads.get() + 1);
            synthetic_times(height)
        }
        fn header_id_at(&self, _height: u32) -> Option<[u8; 32]> {
            Some(self.tip_id.get())
        }
    }

    /// The tip's MTP is read once per tip, not once per relayed tx, and a
    /// different header at the same height (a reorg) is never served the
    /// old value.
    #[test]
    fn tip_mtp_is_cached_per_tip_hash() {
        let times = CountingTimes {
            reads: 0.into(),
            tip_id: [1; 32].into(),
        };
        let mut pool = Mempool::new();
        let (utxo, _d, tx) = locked_tx(tip_mtp() - 1, 0xffff_fffe);
        pool.accept_tx_test_with_times(tx, &utxo, TEST_HEIGHT, &times).unwrap();
        let first = times.reads.get();
        assert!(first > 0);

        let (utxo, _d, mut tx) = locked_tx(tip_mtp() - 1, 0xffff_fffe);
        tx.output[0].value = Amount::from_sat(80_000);
        pool.accept_tx_test_with_times(tx, &utxo, TEST_HEIGHT, &times).unwrap();
        assert_eq!(times.reads.get(), first, "same tip: MTP not re-read");

        // A cached MTP 1,000 s later, for a different header at this
        // height (the branch we reorged away from). Served, it would make
        // this locktime final; recomputed for the new tip, it is not.
        times.tip_id.set([2; 32]);
        let mut pool = Mempool::new();
        pool.tip_mtp_cache = Some((TEST_HEIGHT, [1; 32], tip_mtp() as i64 + 1_000));
        let (utxo, _d, tx) = locked_tx(tip_mtp() + 500, 0xffff_fffe);
        assert!(matches!(
            pool.accept_tx_test_with_times(tx, &utxo, TEST_HEIGHT, &times),
            Err(MempoolError::NonFinal { .. })
        ));
    }

    #[test]
    fn height_locktime_judged_for_next_block() {
        // CheckFinalTxAtTip: nLockTime < tip + 1. Core's anti-fee-sniping
        // value (the tip height) is accepted; tip + 1 is not.
        let (utxo, _d, tx) = locked_tx(TEST_HEIGHT, 0xffff_fffe);
        assert!(Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT).is_ok());
        let (utxo, _d, tx) = locked_tx(TEST_HEIGHT + 1, 0xffff_fffe);
        assert!(matches!(
            Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT),
            Err(MempoolError::NonFinal { lock_time, .. }) if lock_time == TEST_HEIGHT + 1
        ));
        // Final sequences opt out.
        let (utxo, _d, tx) = locked_tx(TEST_HEIGHT + 100, 0xffff_ffff);
        assert!(Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT).is_ok());
    }

    #[test]
    fn time_locktime_uses_tip_mtp_not_wall_clock() {
        // BIP 113: nLockTime < MTP(tip). The synthetic chain is in 2020,
        // so a wall-clock check would accept both of these.
        let (utxo, _d, tx) = locked_tx(tip_mtp() - 1, 0xffff_fffe);
        assert!(Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT).is_ok());
        let (utxo, _d, tx) = locked_tx(tip_mtp(), 0xffff_fffe);
        assert!(matches!(
            Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT),
            Err(MempoolError::NonFinal { .. })
        ));
    }

    #[test]
    fn bip68_height_lock_on_confirmed_input() {
        // Seeded coins are at height 1: a relative lock of N is met in the
        // next block (TEST_HEIGHT + 1) iff 1 + N − 1 < TEST_HEIGHT + 1.
        let (utxo, _d, tx) = locked_tx(0, TEST_HEIGHT);
        assert!(Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT).is_ok());
        let (utxo, _d, tx) = locked_tx(0, TEST_HEIGHT + 1);
        assert!(matches!(
            Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT),
            Err(MempoolError::NonBip68Final { .. })
        ));
        // Disable flag: not a lock.
        let (utxo, _d, tx) = locked_tx(0, (1 << 31) | 0xffff);
        assert!(Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT).is_ok());
        // Version 1: BIP 68 doesn't apply.
        let (utxo, _d, mut tx) = locked_tx(0, 0xffff);
        tx.version = Version::ONE;
        assert!(Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT).is_ok());
    }

    #[test]
    fn bip68_time_lock_on_confirmed_input() {
        // Coin at height 1: lock measured from MTP(0) = 1,600,000,000.
        // Met iff MTP(0) + 512·N − 1 < MTP(tip), i.e. 512·N ≤ span.
        let span = tip_mtp() - 1_600_000_000;
        let ok_units = span / 512;
        let (utxo, _d, tx) = locked_tx(0, (1 << 22) | ok_units);
        assert!(Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT).is_ok());
        let (utxo, _d, tx) = locked_tx(0, (1 << 22) | (ok_units + 1));
        assert!(matches!(
            Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT),
            Err(MempoolError::NonBip68Final { .. })
        ));
    }

    #[test]
    fn bip68_mempool_parent_counts_as_next_block() {
        // A child of an unconfirmed parent can only carry a zero lock
        // (Core assumes the parent confirms at tip + 1).
        let (utxo, _dir) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 100_000);
        let mut pool = Mempool::new();
        let parent = make_tx(&[(seed_txid(1), 0)], &[90_000]);
        let parent_txid = pool.accept_tx_test(parent, &utxo, TEST_HEIGHT).unwrap();

        let mut child = make_tx(&[(parent_txid, 0)], &[80_000]);
        child.input[0].sequence = Sequence(1);
        assert!(matches!(
            pool.accept_tx_test(child.clone(), &utxo, TEST_HEIGHT),
            Err(MempoolError::NonBip68Final { .. })
        ));
        child.input[0].sequence = Sequence(0);
        assert!(pool.accept_tx_test(child, &utxo, TEST_HEIGHT).is_ok());
    }

    #[test]
    fn missing_header_times_reject_without_panicking() {
        let (utxo, _d, tx) = locked_tx(0, 0xffff_ffff);
        let none = |h: u32| -> Result<u32, String> { Err(format!("no header at {}", h)) };
        assert!(matches!(
            Mempool::new().accept_tx_test_with_times(tx, &utxo, TEST_HEIGHT, &none),
            Err(MempoolError::ChainContext(_))
        ));
    }

    /// Ticket 047 review: only a script evaluating to false rejects the tx
    /// as a script failure; every verifier fault is local.
    #[test]
    fn only_script_failed_is_a_mempool_script_failure() {
        use crate::script_verify::{ScriptVerifyError as E, ScriptVerifyFailure};
        let fail = |error| ScriptVerifyFailure { input_index: 1, error };
        assert!(matches!(
            MempoolError::from_script_verify(fail(E::ScriptFailed)),
            MempoolError::ScriptFailure { input_index: 1, .. }
        ));
        for other in [
            E::InvalidFlags(0xffff_ffff),
            E::SpentOutputsMismatch { inputs: 2, spent: 1 },
            E::NoInputs,
            E::TxDeserialize,
            E::Library("btck_script_pubkey_verify status 2".into()),
        ] {
            let e = MempoolError::from_script_verify(fail(other));
            assert!(
                matches!(e, MempoolError::ScriptVerifierError { input_index: 1, .. }),
                "{:?}",
                e
            );
        }
    }

    // ── Data-path pass: CheckTransaction parity, exact policy boundaries,
    //    capacity eviction and graph invariants ─────────────────────────

    const ALL_MODES: [AcceptMode; 3] = [AcceptMode::Relay, AcceptMode::Own, AcceptMode::SkipConsensus];

    fn accept_in(
        pool: &mut Mempool,
        tx: Transaction,
        utxo: &UtxoSet,
        height: u32,
        mode: AcceptMode,
    ) -> Result<Txid, MempoolError> {
        pool.accept_tx_internal(tx, utxo, height, &synthetic_times, mode)
    }

    /// A P2WSH(`OP_TRUE`) coin: spendable with the witness script alone
    /// (`spend_ops`), so the real script check (`Relay` / `Own` modes,
    /// policy flags included) passes without signatures. A bare `OP_TRUE`
    /// coin would be a non-standard input (`ValidateInputsStandardness`).
    fn seed_op_true(utxo: &UtxoSet, id: u8, amount: u64, height: u32, coinbase: bool) -> OutPoint {
        utxo.test_insert_utxo(
            [id; 32],
            0,
            UtxoEntry { amount, script_pubkey: p2wsh_op_true().into_bytes(), height, is_coinbase: coinbase },
        )
        .unwrap();
        OutPoint { txid: seed_txid(id), vout: 0 }
    }

    fn p2wsh_op_true() -> ScriptBuf {
        ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(vec![0x51]).wscript_hash())
    }

    fn p2wpkh_out(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7; 20])),
        }
    }

    /// Spends `inputs` as `seed_op_true` coins: the witness is the
    /// `OP_TRUE` witness script.
    fn spend_ops(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|op| TxIn {
                    previous_output: *op,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[[0x51]]),
                })
                .collect(),
            output: outputs,
        }
    }

    /// A spend of `input` paying `value`, padded with an OP_RETURN output
    /// (4 WU per byte) and, for weights that aren't a multiple of 4, one
    /// witness item (1 WU per byte), to a weight of exactly `target`.
    fn tx_with_weight(input: (Txid, u32), value: u64, target: u64) -> Transaction {
        let build = |pad: usize, witness: Option<usize>| {
            let mut tx = make_tx(&[input], &[value]);
            let mut script = vec![0x6a];
            script.resize(1 + pad, 0);
            tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(script) });
            if let Some(len) = witness {
                tx.input[0].witness = Witness::from_slice(&[vec![0u8; len]]);
            }
            tx
        };
        let w0 = |pad| build(pad, None).weight().to_wu();
        let mut pad = (target.saturating_sub(w0(0)) / 4).saturating_sub(80) as usize;
        loop {
            let base = w0(pad);
            assert!(base <= target, "overshot weight {}", target);
            let tx = if (target - base) % 4 == 0 && target - base < 4 {
                Some(build(pad, None))
            } else if target - base >= 4 && target - base - 4 <= 252 {
                // Marker + flag + item count + item length = 4 WU.
                Some(build(pad, Some((target - base - 4) as usize)))
            } else {
                None
            };
            if let Some(tx) = tx {
                assert_eq!(tx.weight().to_wu(), target);
                return tx;
            }
            pad += 1;
        }
    }

    /// Bitcoin Core's CheckTransaction `bad-txns-inputs-duplicate`: a tx
    /// spending one coin twice is consensus-invalid. Accepting it would
    /// count the coin's value twice and relay a tx Core peers punish us for.
    #[test]
    fn duplicate_input_is_rejected_in_every_mode() {
        for mode in ALL_MODES {
            let (utxo, _d) = fresh_utxo();
            let coin = seed_op_true(&utxo, 1, 100_000, 1, false);
            // Pays more than the coin is worth: only valid if counted twice.
            let tx = spend_ops(&[coin, coin], vec![p2wpkh_out(150_000)]);
            let err = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode).unwrap_err();
            assert!(matches!(err, MempoolError::DuplicateInput { input_index: 1 }), "{:?}: {:?}", mode, err);
        }
    }

    /// CheckTransaction's MoneyRange checks: each output and the output
    /// total at most MAX_MONEY (`bad-txns-vout-toolarge`,
    /// `bad-txns-txouttotal-toolarge`), and CheckTxInputs' input total
    /// (`bad-txns-inputvalues-outofrange`).
    #[test]
    fn value_ranges_match_check_transaction() {
        const MAX_MONEY: u64 = 21_000_000 * 100_000_000;
        for mode in ALL_MODES {
            let (utxo, _d) = fresh_utxo();
            let a = seed_op_true(&utxo, 1, MAX_MONEY, 1, false);
            let b = seed_op_true(&utxo, 2, MAX_MONEY, 1, false);
            let c = seed_op_true(&utxo, 3, 1_000_000, 1, false);
            let cases = [
                ("one output above MAX_MONEY", vec![p2wpkh_out(MAX_MONEY + 1), p2wpkh_out(MAX_MONEY - 51_000)]),
                ("outputs totalling above MAX_MONEY", vec![p2wpkh_out(MAX_MONEY), p2wpkh_out(MAX_MONEY - 50_000)]),
            ];
            for (what, outputs) in cases {
                let tx = spend_ops(&[a, b], outputs);
                let err = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode).unwrap_err();
                assert!(matches!(err, MempoolError::ValueOutOfRange { .. }), "{:?} {}: {:?}", mode, what, err);
            }
            // Inputs above MAX_MONEY in total, outputs fine.
            let tx = spend_ops(&[a, c], vec![p2wpkh_out(MAX_MONEY), p2wpkh_out(950_000)]);
            let err = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode).unwrap_err();
            assert!(matches!(err, MempoolError::ValueOutOfRange { .. }), "{:?} input total: {:?}", mode, err);
            // Exactly MAX_MONEY in and out (less the fee) is fine.
            let tx = spend_ops(&[a], vec![p2wpkh_out(MAX_MONEY - 50_000)]);
            accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode).unwrap();
        }
    }

    /// Core's mempool judges maturity for the next block (spend height =
    /// tip + 1), exactly as block validation would: a coinbase from height
    /// 100 can be mined at 200, so it is accepted with the tip at 199.
    #[test]
    fn coinbase_spend_is_judged_for_the_next_block() {
        for mode in ALL_MODES {
            let (utxo, _d) = fresh_utxo();
            let coin = seed_op_true(&utxo, 1, 100_000, 100, true);
            let tx = spend_ops(&[coin], vec![p2wpkh_out(90_000)]);
            let err = accept_in(&mut Mempool::new(), tx.clone(), &utxo, 198, mode).unwrap_err();
            assert!(
                matches!(err, MempoolError::ImmatureCoinbase { coinbase_height: 100, .. }),
                "{:?}: {:?}",
                mode,
                err
            );
            accept_in(&mut Mempool::new(), tx, &utxo, 199, mode)
                .unwrap_or_else(|e| panic!("{:?}: mature in block 200, rejected at tip 199: {:?}", mode, e));
        }
    }

    #[test]
    fn min_relay_fee_boundary_is_one_sat_per_vbyte() {
        let (utxo, _d) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
        let vsize = make_tx(&[(seed_txid(1), 0)], &[0]).vsize() as u64;
        let short = make_tx(&[(seed_txid(1), 0)], &[1_000_000 - (vsize - 1)]);
        assert!(matches!(
            Mempool::new().accept_tx_test(short, &utxo, TEST_HEIGHT),
            Err(MempoolError::InsufficientFee { .. })
        ));
        let exact = make_tx(&[(seed_txid(1), 0)], &[1_000_000 - vsize]);
        Mempool::new().accept_tx_test(exact, &utxo, TEST_HEIGHT).unwrap();
    }

    #[test]
    fn absurd_fee_boundary_is_inclusive() {
        let (utxo, _d) = fresh_utxo();
        let coin = seed_op_true(&utxo, 1, 100_000_000, 1, false);
        let at = spend_ops(&[coin], vec![p2wpkh_out(100_000_000 - ABSURD_FEE_THRESHOLD)]);
        accept_in(&mut Mempool::new(), at, &utxo, TEST_HEIGHT, AcceptMode::Own).unwrap();
        let over = spend_ops(&[coin], vec![p2wpkh_out(100_000_000 - ABSURD_FEE_THRESHOLD - 1)]);
        assert!(matches!(
            accept_in(&mut Mempool::new(), over, &utxo, TEST_HEIGHT, AcceptMode::Own),
            Err(MempoolError::AbsurdFee { fee, .. }) if fee == ABSURD_FEE_THRESHOLD + 1
        ));
    }

    /// The 018 witness filters read the spent output's type: a P2WSH
    /// witnessScript with an inscription envelope is refused relay (and
    /// still accepted as an own tx), while the same bytes as a stack item
    /// of a P2WPKH spend are not scanned.
    #[test]
    fn relay_policy_scans_the_witness_script_of_the_spent_output_type() {
        let ws = ScriptBuf::from_bytes(vec![0x51, 0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68]);
        let seed = |utxo: &UtxoSet, spk: ScriptBuf| {
            utxo.test_insert_utxo(
                [5; 32],
                0,
                UtxoEntry { amount: 1_000_000, script_pubkey: spk.into_bytes(), height: 1, is_coinbase: false },
            )
            .unwrap();
            OutPoint { txid: seed_txid(5), vout: 0 }
        };
        let (utxo, _d) = fresh_utxo();
        let coin = seed(&utxo, ScriptBuf::new_p2wsh(&ws.wscript_hash()));
        let mut tx = spend_ops(&[coin], vec![p2wpkh_out(900_000)]);
        tx.input[0].witness = Witness::from_slice(&[ws.as_bytes()]);
        assert!(matches!(
            accept_in(&mut Mempool::new(), tx.clone(), &utxo, TEST_HEIGHT, AcceptMode::Relay),
            Err(MempoolError::PolicyRejection(crate::relay_policy::PolicyRejection::InscriptionEnvelope { .. }))
        ));
        accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Own).unwrap();

        // As a P2WPKH spend the same bytes are a signature-shaped stack
        // item, which the filter doesn't scan. (Without a real key the
        // script check refuses it afterwards: the policy flags apply the
        // witness rules at any height, ticket 053.)
        let (utxo, _d) = fresh_utxo();
        let coin = seed(&utxo, ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([3; 20])));
        let mut tx = spend_ops(&[coin], vec![p2wpkh_out(900_000)]);
        tx.input[0].witness = Witness::from_slice(&[ws.as_bytes(), &[0x51]]);
        let err = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Relay).unwrap_err();
        assert!(matches!(err, MempoolError::ScriptFailure { .. }), "{:?}", err);
    }

    /// IsStandardTx's version rule: 1 and 2 are standard, 0, 3 (TRUC,
    /// which we don't implement) and above are not, in every mode.
    #[test]
    fn version_standardness_both_sides() {
        for mode in ALL_MODES {
            for (version, ok) in [(0, false), (1, true), (2, true), (3, false), (-1, false), (i32::MAX, false)] {
                let (utxo, _d) = fresh_utxo();
                let coin = seed_op_true(&utxo, 1, 1_000_000, 1, false);
                let mut tx = spend_ops(&[coin], vec![p2wpkh_out(900_000)]);
                tx.version = Version(version);
                let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode);
                if ok {
                    r.unwrap_or_else(|e| panic!("{:?} v{}: {:?}", mode, version, e));
                } else {
                    assert!(matches!(r, Err(MempoolError::NonStandardVersion { version: v }) if v == version), "{:?} v{}: {:?}", mode, version, r);
                }
            }
        }
    }

    /// IsStandardTx's scriptSig rules: push-only (`scriptsig-not-pushonly`,
    /// where OP_1NEGATE..OP_16 and OP_RESERVED count as pushes) and at most
    /// 1,650 bytes (`scriptsig-size`).
    #[test]
    fn scriptsig_standardness_both_sides() {
        let push = |len: usize| {
            let mut b = bitcoin::script::Builder::new();
            b = b.push_slice(<&bitcoin::script::PushBytes>::try_from(&vec![0x11u8; len][..]).unwrap());
            b.into_script()
        };
        // A pushdata2 of n bytes is n + 3 bytes of script.
        let cases: Vec<(ScriptBuf, Option<&str>)> = vec![
            (ScriptBuf::from_bytes(vec![0x00, 0x4f, 0x50, 0x51, 0x60]), None), // OP_0 OP_1NEGATE OP_RESERVED OP_1 OP_16
            (push(1_647), None),                                               // exactly 1,650 bytes
            (push(1_648), Some("scriptsig-size")),
            (ScriptBuf::from_bytes(vec![0x51, 0x61]), Some("scriptsig-not-pushonly")), // OP_NOP
            (ScriptBuf::from_bytes(vec![0x51, 0x75]), Some("scriptsig-not-pushonly")), // OP_DROP
            (ScriptBuf::from_bytes(vec![0x4c]), Some("scriptsig-not-pushonly")),       // truncated push
        ];
        assert_eq!(push(1_647).len(), MAX_STANDARD_SCRIPTSIG_SIZE);
        for (script_sig, expected) in cases {
            // SkipConsensus: a scriptSig in front of OP_TRUE would leave
            // extra stack items; the standardness rule is what's tested.
            let (utxo, _d) = fresh_utxo();
            seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
            let mut tx = make_tx(&[(seed_txid(1), 0)], &[900_000]);
            tx.input[0].script_sig = script_sig.clone();
            let r = Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT);
            match expected {
                None => {
                    r.unwrap_or_else(|e| panic!("{:?}: {:?}", script_sig, e));
                }
                Some(reason) => assert!(
                    matches!(r, Err(MempoolError::NonStandardScriptSig { input_index: 0, reason: got }) if got == reason),
                    "{:?}: {:?}",
                    script_sig,
                    r
                ),
            }
        }
    }

    /// The standard sigop cost limit (16,000) counts legacy sigops in
    /// outputs (x4) and P2SH redeem-script sigops (x4) as
    /// `GetTransactionSigOpCost` does.
    #[test]
    fn sigop_cost_limit_both_sides() {
        // Each 0xac (OP_CHECKSIG) output script costs 4; 0xae
        // (OP_CHECKMULTISIG, inaccurate count) costs 20 * 4 = 80.
        let with_outputs = |checksigs: usize| {
            let mut spk = vec![0xae; checksigs / 20];
            spk.extend(vec![0xac; checksigs % 20]);
            spk
        };
        for (sigops, ok) in [(4_000usize, true), (4_001, false)] {
            let (utxo, _d) = fresh_utxo();
            seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
            let mut tx = make_tx(&[(seed_txid(1), 0)], &[900_000]);
            tx.output[0].script_pubkey = ScriptBuf::from_bytes(with_outputs(sigops));
            let r = Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT);
            if ok {
                r.unwrap();
            } else {
                assert!(matches!(r, Err(MempoolError::TooManySigops { cost: 16_004, limit: 16_000 })), "{:?}", r);
            }
        }

        // P2SH: the redeem script's sigops count (accurately) against the
        // spending tx: 16 x OP_CHECKSIG is 16 sigops.
        let redeem = ScriptBuf::from_bytes(vec![0xac; 16]);
        let (utxo, _d) = fresh_utxo();
        utxo.test_insert_utxo(
            [2; 32],
            0,
            UtxoEntry {
                amount: 1_000_000,
                script_pubkey: ScriptBuf::new_p2sh(&redeem.script_hash()).into_bytes(),
                height: 1,
                is_coinbase: false,
            },
        )
        .unwrap();
        let mut tx = make_tx(&[(seed_txid(2), 0)], &[900_000]);
        tx.input[0].script_sig = bitcoin::script::Builder::new()
            .push_slice(<&bitcoin::script::PushBytes>::try_from(redeem.as_bytes()).unwrap())
            .into_script();
        // Outputs: 3,980 legacy sigops + 16 P2SH = 3,996 x 4 = 15,984: ok.
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(with_outputs(3_980));
        Mempool::new().accept_tx_test(tx.clone(), &utxo, TEST_HEIGHT).unwrap();
        // 3,985 + 16 = 4,001: over.
        tx.output[0].script_pubkey = ScriptBuf::from_bytes(with_outputs(3_985));
        assert!(matches!(
            Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT),
            Err(MempoolError::TooManySigops { cost: 16_004, .. })
        ));
    }

    /// `GetDustThreshold` for scripts that aren't one of the standard
    /// types follows the same formula (legacy-spend sized); OP_RETURN and
    /// over-long (unspendable) scripts are exempt.
    #[test]
    fn dust_threshold_formula_covers_other_scripts_and_exempts_unspendable() {
        let out = |spk: Vec<u8>| TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) };
        // 0xac: (8 + 1 + 1 + 148) * 3 = 474.
        assert_eq!(dust_threshold(&out(vec![0xac])), 474);
        // A 2-of-3 bare multisig (105-byte script): (8 + 1 + 105 + 148) * 3.
        assert_eq!(dust_threshold(&out(vec![0x51; 105])), 786);
        // Unknown witness version 2, 32-byte program: witness-sized spend.
        let mut v2 = vec![0x52, 0x20];
        v2.extend([7u8; 32]);
        assert_eq!(dust_threshold(&out(v2)), 330);
        assert_eq!(dust_threshold(&out(vec![0x6a, 0x01, 0x00])), 0);
        assert_eq!(dust_threshold(&out(vec![0x51; MAX_SCRIPT_SIZE])), (8 + 3 + 10_000 + 148) * 3);
        assert_eq!(dust_threshold(&out(vec![0x51; MAX_SCRIPT_SIZE + 1])), 0);

        let (utxo, _d) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
        let at = make_tx(&[(seed_txid(1), 0)], &[474, 900_000]);
        Mempool::new().accept_tx_test(at, &utxo, TEST_HEIGHT).unwrap();
        let below = make_tx(&[(seed_txid(1), 0)], &[473, 900_000]);
        assert!(matches!(
            Mempool::new().accept_tx_test(below, &utxo, TEST_HEIGHT),
            Err(MempoolError::DustOutput { index: 0, amount: 473, threshold: 474 })
        ));
        let mut op_return = make_tx(&[(seed_txid(1), 0)], &[0, 900_000]);
        op_return.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]);
        Mempool::new().accept_tx_test(op_return, &utxo, TEST_HEIGHT).unwrap();
    }

    /// The boundaries the ticket names, in every accept mode: P2WPKH
    /// 293/294, P2TR and P2WSH 329/330, P2SH 539/540, P2PKH 545/546.
    #[test]
    fn dust_boundaries_per_output_type_in_every_mode() {
        let xonly = bitcoin::key::XOnlyPublicKey::from_slice(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .unwrap();
        let p2tr = ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly));
        let cases = [
            (ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([1; 20])), 293u64),
            (p2tr, 329),
            (ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([1; 32])), 329),
            (ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array([1; 20])), 539),
            (ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array([1; 20])), 545),
        ];
        for mode in ALL_MODES {
            for (spk, below) in &cases {
                for (value, ok) in [(*below, false), (below + 1, true)] {
                    let (utxo, _d) = fresh_utxo();
                    let coin = seed_op_true(&utxo, 1, 1_000_000, 1, false);
                    let tx = spend_ops(&[coin], vec![TxOut { value: Amount::from_sat(value), script_pubkey: spk.clone() }, p2wpkh_out(900_000)]);
                    let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode);
                    if ok {
                        r.unwrap_or_else(|e| panic!("{:?} {} sats to {}: {:?}", mode, value, spk, e));
                    } else {
                        assert!(
                            matches!(r, Err(MempoolError::DustOutput { index: 0, amount, threshold }) if amount == value && threshold == value + 1),
                            "{:?} {} sats to {}: {:?}",
                            mode,
                            value,
                            spk,
                            r
                        );
                    }
                }
            }
        }
    }

    /// Core's `GetDustThreshold` at the default 3 sat/vB dust relay fee is
    /// per output type; a flat 546 refuses outputs the network relays
    /// (e.g. a 330-sat P2TR output, common for Lightning anchors and
    /// ordinals-free taproot change).
    #[test]
    fn dust_threshold_is_per_output_type_like_core() {
        use bitcoin::key::XOnlyPublicKey;
        let xonly = XOnlyPublicKey::from_slice(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ])
        .unwrap();
        let scripts: [(&str, ScriptBuf, u64); 5] = [
            ("p2wpkh", ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([1; 20])), 294),
            ("p2tr", ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly)), 330),
            ("p2wsh", ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_byte_array([1; 32])), 330),
            ("p2sh", ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array([1; 20])), 540),
            ("p2pkh", ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array([1; 20])), 546),
        ];
        for (what, spk, threshold) in scripts {
            for (value, ok) in [(threshold - 1, false), (threshold, true)] {
                let (utxo, _d) = fresh_utxo();
                seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
                let mut tx = make_tx(&[(seed_txid(1), 0)], &[value, 900_000]);
                tx.output[0].script_pubkey = spk.clone();
                let r = Mempool::new().accept_tx_test(tx, &utxo, TEST_HEIGHT);
                assert_eq!(r.is_ok(), ok, "{} output of {} sats: {:?}", what, value, r);
            }
        }
    }

    /// MAX_TX_WEIGHT is inclusive, judged in weight units (not vbytes).
    #[test]
    fn weight_limit_is_exactly_400000_wu() {
        let (utxo, _d) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 10_000_000);
        let at = tx_with_weight((seed_txid(1), 0), 9_800_000, MAX_TX_WEIGHT);
        Mempool::new().accept_tx_test(at, &utxo, TEST_HEIGHT).unwrap();
        let over = tx_with_weight((seed_txid(1), 0), 9_800_000, MAX_TX_WEIGHT + 1);
        assert!(matches!(
            Mempool::new().accept_tx_test(over, &utxo, TEST_HEIGHT),
            Err(MempoolError::OversizedTx { weight }) if weight == MAX_TX_WEIGHT + 1
        ));
    }

    /// vsize is ceil(weight / 4): a child of weight 8,000 (2,000 vB) fits
    /// a 99,000 vB parent's 101,000 vB package; 8,001 WU rounds up to
    /// 2,001 vB and doesn't.
    #[test]
    fn ancestor_package_vsize_limit_is_exact_and_rounds_vsize_up() {
        for (child_weight, ok) in [(8_000u64, true), (8_001, false)] {
            let (utxo, _d) = fresh_utxo();
            seed_utxo(&utxo, seed_txid(1), 0, 10_000_000);
            let mut pool = Mempool::new();
            let parent = tx_with_weight((seed_txid(1), 0), 9_800_000, 396_000);
            assert_eq!(parent.vsize(), 99_000);
            let parent_txid = pool.accept_tx_test(parent, &utxo, TEST_HEIGHT).unwrap();
            let child = tx_with_weight((parent_txid, 0), 9_700_000, child_weight);
            let r = pool.accept_tx_test(child, &utxo, TEST_HEIGHT);
            if ok {
                let txid = r.unwrap();
                assert_eq!(pool.get_entry_info(&txid).unwrap().vsize, 2_000);
                assert_eq!(pool.get_entry_info(&txid).unwrap().ancestor_vsize, 99_000);
            } else {
                assert!(
                    matches!(r, Err(MempoolError::AncestorSetTooLarge { vbytes: 101_001, .. })),
                    "{:?}",
                    r
                );
            }
        }
    }

    /// BIP 125 rule 3 at its exact boundary: the replacement must pay the
    /// evicted fees plus its own vsize at the incremental relay fee.
    #[test]
    fn rbf_absolute_fee_boundary_is_exact() {
        let r = seed_txid(1);
        let setup = || {
            let (utxo, d) = fresh_utxo();
            seed_utxo(&utxo, r, 0, 1_000_000);
            let mut pool = Mempool::new();
            pool.accept_tx_test(make_tx_marked(&[(r, 0)], &[990_000], 0xa), &utxo, TEST_HEIGHT).unwrap();
            (utxo, d, pool)
        };
        let vsize = make_tx_marked(&[(r, 0)], &[0], 0xb).vsize() as u64;
        let required = 10_000 + vsize;

        let (utxo, _d, mut pool) = setup();
        let short = make_tx_marked(&[(r, 0)], &[1_000_000 - (required - 1)], 0xb);
        assert!(matches!(
            pool.accept_tx_test(short, &utxo, TEST_HEIGHT),
            Err(MempoolError::ReplacementFeeInsufficient { provided, required: req, .. })
                if provided == required - 1 && req == required
        ));
        assert_eq!(pool.count(), 1);

        let (utxo, _d, mut pool) = setup();
        let exact = make_tx_marked(&[(r, 0)], &[1_000_000 - required], 0xb);
        let txid = pool.accept_tx_test(exact, &utxo, TEST_HEIGHT).unwrap();
        assert_eq!(pool.get_all_txids(), vec![txid]);
    }

    /// BIP 125 rule 5 (Core's MAX_REPLACEMENT_CANDIDATES): a replacement
    /// may evict 100 transactions, not 101.
    #[test]
    fn rbf_eviction_limit_is_exactly_100() {
        for (extra_child, ok) in [(false, true), (true, false)] {
            let (utxo, _d) = fresh_utxo();
            let mut pool = Mempool::new();
            let mut roots_inputs = vec![];
            // 5 roots x (1 + 19 fan-out children) = 100 transactions.
            for i in 0..5u8 {
                let coin = seed_txid(10 + i);
                seed_utxo(&utxo, coin, 0, 1_000_000);
                roots_inputs.push((coin, 0));
                let children = if extra_child && i == 0 { 20 } else { 19 };
                let mut outs: Vec<u64> = vec![10_000; children];
                outs.push(1_000_000 - children as u64 * 10_000 - 1_000);
                let root = pool.accept_tx_test(make_tx(&[(coin, 0)], &outs), &utxo, TEST_HEIGHT).unwrap();
                for v in 0..children as u32 {
                    pool.accept_tx_test(make_tx(&[(root, v)], &[9_000]), &utxo, TEST_HEIGHT).unwrap();
                }
            }
            let before = pool.count();
            let replacement = make_tx_marked(&roots_inputs, &[4_700_000], 0xee);
            let r = pool.accept_tx_test(replacement, &utxo, TEST_HEIGHT);
            if ok {
                assert_eq!(before, 100);
                let txid = r.unwrap();
                assert_eq!(pool.get_all_txids(), vec![txid]);
            } else {
                assert_eq!(before, 101);
                assert!(
                    matches!(r, Err(MempoolError::TooManyReplacements { evicted: 101, limit: 100 })),
                    "{:?}",
                    r
                );
                assert_eq!(pool.count(), 101, "a refused replacement evicts nothing");
            }
        }
    }

    /// Core (and Knots) refuse a replacement that spends an unconfirmed
    /// output none of the originals spent (`replacement-adds-unconfirmed`,
    /// BIP 125 rule 2), and so do we (owner decision, ticket 053).
    #[test]
    fn rbf_replacement_adding_new_unconfirmed_input_is_rejected_like_core() {
        let (utxo, _d) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
        seed_utxo(&utxo, seed_txid(2), 0, 1_000_000);
        let mut pool = Mempool::new();
        let a = pool.accept_tx_test(make_tx_marked(&[(seed_txid(1), 0)], &[990_000], 1), &utxo, TEST_HEIGHT).unwrap();
        let p = pool.accept_tx_test(make_tx(&[(seed_txid(2), 0)], &[990_000]), &utxo, TEST_HEIGHT).unwrap();
        let repl = make_tx_marked(&[(seed_txid(1), 0), (p, 0)], &[1_900_000], 2);
        assert!(pool.accept_tx_test(repl, &utxo, TEST_HEIGHT).is_err());
        assert!(pool.contains(&a));
    }

    /// A block confirming a tx that conflicts with a mempool tx evicts the
    /// mempool tx and its whole package, and nothing else.
    #[test]
    fn confirmed_conflict_evicts_the_losing_package_only() {
        let (utxo, _d) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
        seed_utxo(&utxo, seed_txid(2), 0, 1_000_000);
        let mut pool = Mempool::new();
        let a = pool.accept_tx_test(make_tx(&[(seed_txid(1), 0)], &[990_000]), &utxo, TEST_HEIGHT).unwrap();
        let a_child = pool.accept_tx_test(make_tx(&[(a, 0)], &[980_000]), &utxo, TEST_HEIGHT).unwrap();
        let other = pool.accept_tx_test(make_tx(&[(seed_txid(2), 0)], &[990_000]), &utxo, TEST_HEIGHT).unwrap();
        let rival = make_tx_marked(&[(seed_txid(1), 0)], &[500_000], 0x77);
        let block = Block {
            header: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
            txdata: vec![rival],
        };
        pool.remove_confirmed(&block);
        assert!(!pool.contains(&a) && !pool.contains(&a_child));
        assert_eq!(pool.get_all_txids(), vec![other]);
        assert!(pool.spends.len() == 1 && pool.total_size == pool.txs[&other].size);
    }

    #[test]
    fn entry_info_counts_include_self() {
        let (utxo, _d) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
        let mut pool = Mempool::new();
        let a = pool.accept_tx_test(make_tx(&[(seed_txid(1), 0)], &[990_000]), &utxo, TEST_HEIGHT).unwrap();
        let b = pool.accept_tx_test(make_tx(&[(a, 0)], &[980_000]), &utxo, TEST_HEIGHT).unwrap();
        let ia = pool.get_entry_info(&a).unwrap();
        let ib = pool.get_entry_info(&b).unwrap();
        assert_eq!((ia.ancestor_count, ia.descendant_count), (1, 2));
        assert_eq!((ib.ancestor_count, ib.descendant_count), (2, 1));
        assert_eq!((ib.ancestor_fee, ib.ancestor_vsize), (ia.fee, ia.vsize));
        assert_eq!(ia.fee, 10_000);
        assert!(pool.get_entry_info(&seed_txid(9)).is_none());
        assert_eq!(pool.min_fee_rate(), ia.fee_rate.min(ib.fee_rate));
    }

    #[test]
    fn fee_estimates_are_floored_and_monotone_in_target() {
        assert_eq!(Mempool::new().estimate_fee_rates().one_block, 1.0);
        let (utxo, _d) = fresh_utxo();
        let mut pool = Mempool::new();
        // 40 txs of ~99 kvB each: ~1 block of weight per 10 txs, at fee
        // rates 2..=41 sat/vB.
        for i in 0..40u8 {
            seed_utxo(&utxo, seed_txid(i), 0, 10_000_000);
            let probe = tx_with_weight((seed_txid(i), 0), 0, 396_000);
            let fee = probe.vsize() as u64 * (2 + i as u64);
            pool.accept_tx_test(tx_with_weight((seed_txid(i), 0), 10_000_000 - fee, 396_000), &utxo, TEST_HEIGHT)
                .unwrap();
        }
        let e = pool.estimate_fee_rates();
        let all = [e.one_block, e.six_blocks, e.twelve_blocks, e.twenty_four_blocks, e.one_forty_four_blocks];
        assert!(all.windows(2).all(|w| w[0] >= w[1]), "{:?}", all);
        assert!(all.iter().all(|r| *r >= 1.0));
        // The first block fills at the 11th-best rate (10 x 396k WU < 4M WU,
        // 11 x 396k > 4M): rate 41 - 10 = 31.
        assert!((e.one_block - 31.0).abs() < 0.01, "{}", e.one_block);
        // Everything fits in 6 blocks: the floor of the cheapest tx's rate.
        assert!((e.six_blocks - 2.0).abs() < 0.01, "{}", e.six_blocks);
    }

    /// Capacity eviction must never evict the transaction `accept_tx` just
    /// accepted (the Phase 6.5 promise; only a `debug_assert` backs it).
    /// Regression: with two packages at the same fee rate the admission
    /// check assumed the incumbent goes, while the real loop took
    /// whichever root HashMap iteration reached first.
    #[test]
    fn full_pool_fee_rate_tie_never_evicts_the_accepted_tx() {
        for round in 0..64 {
            let (utxo, _d) = fresh_utxo();
            seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
            seed_utxo(&utxo, seed_txid(2), 0, 1_000_000);
            let a = make_tx_marked(&[(seed_txid(1), 0)], &[990_000], 0xa);
            let size = serialize(&a).len();
            let mut pool = Mempool::with_max_size(size + size / 2);
            pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
            let b = make_tx_marked(&[(seed_txid(2), 0)], &[990_000], 0xb);
            if let Ok(txid) = pool.accept_tx_test(b, &utxo, TEST_HEIGHT) {
                assert!(pool.contains(&txid), "round {}: accepted then evicted", round);
            }
            assert!(pool.size() <= pool.max_size);
        }
    }

    /// Same promise with a descendant shared by two roots. Regression: the
    /// admission check counted the shared child once per root package, so
    /// it thought two evictions freed more than they do (and never
    /// re-ranked the second root after it lost the child).
    #[test]
    fn full_pool_shared_descendant_never_evicts_the_accepted_tx() {
        for round in 0..16 {
            let (utxo, _d) = fresh_utxo();
            for i in 1..=3u8 {
                seed_utxo(&utxo, seed_txid(i), 0, 10_000_000);
            }
            let vs = |t: &Transaction| t.vsize() as u64;
            // R1 at 1 sat/vB, R2 at 10 sat/vB, D (spends both) at 1 sat/vB,
            // N (unrelated, large) at 5 sat/vB.
            let r1_v = vs(&make_tx(&[(seed_txid(1), 0)], &[0]));
            let r1 = make_tx(&[(seed_txid(1), 0)], &[10_000_000 - r1_v]);
            let r2 = make_tx(&[(seed_txid(2), 0)], &[10_000_000 - 10 * r1_v]);
            let (r1_id, r2_id) = (r1.compute_txid(), r2.compute_txid());
            let d_v = vs(&make_tx(&[(r1_id, 0), (r2_id, 0)], &[0]));
            let d = make_tx(&[(r1_id, 0), (r2_id, 0)], &[20_000_000 - 11 * r1_v - d_v]);
            let n_v = vs(&tx_with_weight((seed_txid(3), 0), 0, 1_400));
            let n = tx_with_weight((seed_txid(3), 0), 10_000_000 - 5 * n_v, 1_400);
            let sz = |t: &Transaction| serialize(t).len();
            // Big enough for R1+R2+D; after N arrives, evicting R1's package
            // (R1+D) is not enough, but the simulation subtracts D again
            // with R2's package and concludes N fits.
            let cap = sz(&n) - sz(&d) + 2;
            assert!(cap >= sz(&r1) + sz(&r2) + sz(&d) && cap < sz(&r2) + sz(&n), "scenario setup");
            let mut pool = Mempool::with_max_size(cap);
            for tx in [r1.clone(), r2.clone(), d.clone()] {
                pool.accept_tx_test(tx, &utxo, TEST_HEIGHT).unwrap();
            }
            // Package rates: R1+D < R2+D < N < R2 alone.
            let pkg = |a: &Transaction, fee_a: u64| (fee_a + d_v) as f64 / (vs(a) + d_v) as f64;
            assert!(pkg(&r1, r1_v) < pkg(&r2, 10 * r1_v) && pkg(&r2, 10 * r1_v) < 5.0);
            assert!(pool.fee_rate(&r2_id).unwrap() > 5.0);
            if let Ok(txid) = pool.accept_tx_test(n, &utxo, TEST_HEIGHT) {
                assert!(pool.contains(&txid), "round {}: accepted then evicted", round);
            }
            assert!(pool.size() <= pool.max_size);
        }
    }

    // ── Ticket 053: rolling minimum fee, capacity plan, event stream ───

    /// A one-in, one-out spend of `coin` (worth `value`) at exactly
    /// `rate` sat/vB, made distinct by `marker`.
    fn at_rate(coin: (Txid, u32), value: u64, rate: u64, marker: u8) -> Transaction {
        let vsize = make_tx_marked(&[coin], &[0], marker).vsize() as u64;
        make_tx_marked(&[coin], &[value - rate * vsize], marker)
    }

    fn block_with(txs: Vec<Transaction>) -> Block {
        Block {
            header: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
            txdata: txs,
        }
    }

    fn ago(d: Duration) -> Instant {
        Instant::now().checked_sub(d).expect("test machine clock should be far enough into uptime")
    }

    /// Core's rolling minimum fee: eviction raises it to the evicted
    /// package's rate plus the incremental relay fee (1 sat/vB); a tx below
    /// it is refused even when there is room; it doesn't decay until a block
    /// arrives, then halves every 12 h (6 h under half full, 3 h under a
    /// quarter) and resets below half the incremental fee.
    #[test]
    fn rolling_min_fee_rises_when_full_and_decays_after_blocks() {
        let (utxo, _d) = fresh_utxo();
        for i in 1..=4u8 {
            seed_utxo(&utxo, seed_txid(i), 0, 1_000_000);
        }
        let low = at_rate((seed_txid(1), 0), 1_000_000, 100, 1);
        let size = serialize(&low).len();
        let vsize = low.vsize() as u64;
        let mut pool = Mempool::with_max_size(size + size / 2);
        assert_eq!(pool.mempool_min_fee_rate(), 0.0, "an empty pool has no rolling minimum");
        pool.accept_tx_test(low, &utxo, TEST_HEIGHT).unwrap();
        let high = at_rate((seed_txid(2), 0), 1_000_000, 1_000, 2);
        pool.accept_tx_test(high.clone(), &utxo, TEST_HEIGHT).unwrap();
        assert_eq!(pool.mempool_min_fee_rate(), 101.0, "evicted 100 sat/vB + 1");

        // No block yet: no decay, however long.
        pool.last_rolling_fee_update = ago(Duration::from_secs(48 * 3600));
        assert_eq!(pool.mempool_min_fee_rate(), 101.0);

        // A block (confirming `high`) empties the pool and starts the clock.
        pool.remove_confirmed(&block_with(vec![high]));
        assert_eq!(pool.count(), 0);
        assert_eq!(pool.mempool_min_fee_rate(), 101.0, "within 10 s of the block");

        // Room in the pool, but below the rolling minimum: refused. At it: in.
        let short = make_tx_marked(&[(seed_txid(3), 0)], &[1_000_000 - (101 * vsize - 1)], 3);
        assert!(matches!(
            pool.accept_tx_test(short, &utxo, TEST_HEIGHT),
            Err(MempoolError::MempoolMinFeeNotMet { min_rate, .. }) if min_rate == 101.0
        ));
        let exact = make_tx_marked(&[(seed_txid(3), 0)], &[1_000_000 - 101 * vsize], 3);
        let exact_id = pool.accept_tx_test(exact, &utxo, TEST_HEIGHT).unwrap();

        // Over half full: 12 h half-life.
        pool.last_rolling_fee_update = ago(Duration::from_secs(12 * 3600));
        assert!((pool.mempool_min_fee_rate() - 50.5).abs() < 0.01, "{}", pool.mempool_min_fee_rate());
        // Empty (under a quarter full): 3 h half-life, 12 h = four halvings.
        pool.remove_tx(&exact_id);
        pool.last_rolling_fee_update = ago(Duration::from_secs(12 * 3600));
        assert!((pool.mempool_min_fee_rate() - 3.156).abs() < 0.01, "{}", pool.mempool_min_fee_rate());
        // Under half the incremental relay fee: back to no minimum.
        pool.last_rolling_fee_update = ago(Duration::from_secs(48 * 3600));
        assert_eq!(pool.mempool_min_fee_rate(), 0.0);
        assert_eq!(pool.rolling_min_fee, 0.0);
        pool.accept_tx_test(at_rate((seed_txid(4), 0), 1_000_000, 1, 4), &utxo, TEST_HEIGHT).unwrap();
    }

    /// A refused accept at a full pool also raises the rolling minimum
    /// past the refused package, as Core's trim of it would.
    #[test]
    fn rolling_min_fee_rises_past_a_refused_package() {
        let (utxo, _d) = fresh_utxo();
        seed_utxo(&utxo, seed_txid(1), 0, 1_000_000);
        seed_utxo(&utxo, seed_txid(2), 0, 1_000_000);
        let high = at_rate((seed_txid(1), 0), 1_000_000, 50, 1);
        let size = serialize(&high).len();
        let mut pool = Mempool::with_max_size(size + size / 2);
        pool.accept_tx_test(high, &utxo, TEST_HEIGHT).unwrap();
        let low = at_rate((seed_txid(2), 0), 1_000_000, 20, 2);
        assert!(matches!(pool.accept_tx_test(low, &utxo, TEST_HEIGHT), Err(MempoolError::MempoolFull { .. })));
        assert_eq!(pool.mempool_min_fee_rate(), 21.0);
        assert!(pool.drain_removals().removals.is_empty(), "nothing was evicted");
    }

    /// Ties keep the incumbent (Core's descendant-score order evicts the
    /// newer entry first). The refused tie raised the rolling minimum to
    /// its rate plus 1 sat/vB, so the next tx must pay that: just above
    /// the incumbent isn't enough, the rolling minimum is. `Ok` always
    /// means the tx is in the pool.
    #[test]
    fn full_pool_tie_keeps_the_incumbent_and_ok_implies_contains() {
        let (utxo, _d) = fresh_utxo();
        for i in 1..=4u8 {
            seed_utxo(&utxo, seed_txid(i), 0, 1_000_000);
        }
        let a = at_rate((seed_txid(1), 0), 1_000_000, 10, 1);
        let a_id = a.compute_txid();
        let size = serialize(&a).len();
        let mut pool = Mempool::with_max_size(size + size / 2);
        pool.accept_tx_test(a, &utxo, TEST_HEIGHT).unwrap();
        let tie = at_rate((seed_txid(2), 0), 1_000_000, 10, 2);
        assert!(matches!(pool.accept_tx_test(tie, &utxo, TEST_HEIGHT), Err(MempoolError::MempoolFull { .. })));
        assert_eq!(pool.get_all_txids(), vec![a_id]);
        assert_eq!(pool.mempool_min_fee_rate(), 11.0);
        let vsize = make_tx_marked(&[(seed_txid(3), 0)], &[0], 3).vsize() as u64;
        let more = make_tx_marked(&[(seed_txid(3), 0)], &[1_000_000 - 10 * vsize - 1], 3);
        assert!(matches!(pool.accept_tx_test(more, &utxo, TEST_HEIGHT), Err(MempoolError::MempoolMinFeeNotMet { .. })));
        let id = pool.accept_tx_test(at_rate((seed_txid(4), 0), 1_000_000, 11, 4), &utxo, TEST_HEIGHT).unwrap();
        assert!(pool.contains(&id));
        assert_eq!(pool.get_all_txids(), vec![id]);
    }

    /// The package a new child joins is never evicted to make room for it:
    /// a CPFP child whose package beats the cheapest other package
    /// displaces that one; a child whose package doesn't is refused, with
    /// its cheap parent (and everything else) left alone.
    #[test]
    fn full_pool_never_evicts_the_new_txs_own_package() {
        for (child_rate, ok) in [(40u64, true), (3, false)] {
            let (utxo, _d) = fresh_utxo();
            for i in 1..=3u8 {
                seed_utxo(&utxo, seed_txid(i), 0, 1_000_000);
            }
            let parent = at_rate((seed_txid(1), 0), 1_000_000, 1, 1);
            let parent_id = parent.compute_txid();
            let parent_value = parent.output[0].value.to_sat();
            let other = at_rate((seed_txid(2), 0), 1_000_000, 5, 2);
            let other_id = other.compute_txid();
            let child = at_rate((parent_id, 0), parent_value, child_rate, 3);
            let child_id = child.compute_txid();
            let (sp, so, sc) = (serialize(&parent).len(), serialize(&other).len(), serialize(&child).len());
            // Parent and other fit; the child needs one of them gone.
            let mut pool = Mempool::with_max_size(sp + so + sc - 1);
            pool.accept_tx_test(parent, &utxo, TEST_HEIGHT).unwrap();
            pool.accept_tx_test(other, &utxo, TEST_HEIGHT).unwrap();
            // The parent alone is the cheapest root package (1 sat/vB), so a
            // "drop the cheapest package" loop would take the new child's.
            assert_eq!(pool.roots.iter().next().unwrap().txid, parent_id);
            let r = pool.accept_tx_test(child, &utxo, TEST_HEIGHT);
            if ok {
                // Package (1 + 40) / 2 ≈ 20 sat/vB > 5: `other` goes.
                assert_eq!(r.unwrap(), child_id);
                assert!(pool.contains(&parent_id) && pool.contains(&child_id) && !pool.contains(&other_id));
                let ev = pool.drain_removals().removals;
                assert_eq!(ev, vec![MempoolRemoval { txid: other_id, reason: RemovalReason::Evicted }]);
            } else {
                // Package (1 + 3) / 2 = 2 sat/vB < 5: refused, nothing moved.
                assert!(matches!(r, Err(MempoolError::MempoolFull { min_pkg_fee_rate, .. }) if (min_pkg_fee_rate - 5.0).abs() < 1e-9), "{:?}", r);
                assert!(pool.contains(&parent_id) && pool.contains(&other_id) && !pool.contains(&child_id));
                assert!(pool.drain_removals().removals.is_empty());
            }
        }
    }

    /// Every removal reason, with descendants inheriting their package's.
    #[test]
    fn removal_events_for_every_reason() {
        let (utxo, _d) = fresh_utxo();
        for i in 1..=8u8 {
            seed_utxo(&utxo, seed_txid(i), 0, 1_000_000);
        }
        let mut pool = Mempool::new();
        let accept = |pool: &mut Mempool, tx: Transaction| pool.accept_tx_test(tx, &utxo, TEST_HEIGHT).unwrap();
        let ev = |pool: &mut Mempool| {
            let d = pool.drain_removals();
            assert_eq!(d.dropped, 0);
            d.removals.into_iter().map(|r| (r.txid, r.reason)).collect::<Vec<_>>()
        };

        // Confirmed: only the mined tx; its child stays.
        let a = make_tx(&[(seed_txid(1), 0)], &[990_000]);
        let a_id = accept(&mut pool, a.clone());
        let a_child = accept(&mut pool, make_tx(&[(a_id, 0)], &[980_000]));
        assert!(ev(&mut pool).is_empty(), "accepting removes nothing");
        pool.remove_confirmed(&block_with(vec![a]));
        assert_eq!(ev(&mut pool), vec![(a_id, RemovalReason::Confirmed)]);
        assert!(pool.contains(&a_child));

        // ConflictedByBlock: a rival of B confirms; B and its child go.
        let b_id = accept(&mut pool, make_tx(&[(seed_txid(2), 0)], &[990_000]));
        let b_child = accept(&mut pool, make_tx(&[(b_id, 0)], &[980_000]));
        let rival = make_tx_marked(&[(seed_txid(2), 0)], &[900_000], 0x77);
        let by = rival.compute_txid();
        pool.remove_confirmed(&block_with(vec![rival]));
        assert_eq!(
            ev(&mut pool),
            vec![(b_child, RemovalReason::ConflictedByBlock { by }), (b_id, RemovalReason::ConflictedByBlock { by })],
            "deepest first"
        );

        // ReplacedBy: C and its child, by the replacement.
        let c_id = accept(&mut pool, make_tx_marked(&[(seed_txid(3), 0)], &[990_000], 1));
        let c_child = accept(&mut pool, make_tx(&[(c_id, 0)], &[980_000]));
        let repl = accept(&mut pool, make_tx_marked(&[(seed_txid(3), 0)], &[900_000], 2));
        assert_eq!(
            ev(&mut pool),
            vec![(c_child, RemovalReason::ReplacedBy(repl)), (c_id, RemovalReason::ReplacedBy(repl))]
        );

        // Expired: D and its child.
        let d_id = accept(&mut pool, make_tx(&[(seed_txid(4), 0)], &[990_000]));
        let d_child = accept(&mut pool, make_tx(&[(d_id, 0)], &[980_000]));
        pool.txs.get_mut(&d_id).unwrap().added_at = ago(MAX_TX_AGE + Duration::from_secs(1));
        pool.expire_old();
        assert_eq!(ev(&mut pool), vec![(d_child, RemovalReason::Expired), (d_id, RemovalReason::Expired)]);

        // Reorg: remove_tx.
        assert!(pool.remove_tx(&repl));
        assert!(!pool.remove_tx(&repl));
        assert_eq!(ev(&mut pool), vec![(repl, RemovalReason::Reorg)]);

        // Evicted: a cheap package for a better tx at a full pool.
        pool.max_size = pool.size() + 1; // `rich` has a 1-byte longer script
        let cheap = pool.get_all_txids();
        assert_eq!(cheap, vec![a_child]);
        let rich = accept(&mut pool, at_rate((seed_txid(5), 0), 1_000_000, 500, 5));
        assert_eq!(ev(&mut pool), vec![(a_child, RemovalReason::Evicted)]);
        assert_eq!(pool.get_all_txids(), vec![rich]);
    }

    /// Undrained events are capped; the oldest go first and are counted.
    #[test]
    fn removal_queue_is_bounded_and_counts_what_it_drops() {
        let mut pool = Mempool::new();
        for i in 0..MAX_QUEUED_REMOVALS + 3 {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            pool.record_removal(Txid::from_byte_array(id), RemovalReason::Evicted);
        }
        let d = pool.drain_removals();
        assert_eq!((d.removals.len(), d.dropped), (MAX_QUEUED_REMOVALS, 3));
        assert_eq!(d.removals[0].txid.to_byte_array()[0], 3, "oldest dropped");
        let d = pool.drain_removals();
        assert_eq!((d.removals.len(), d.dropped), (0, 0));
    }

    /// Accepting into a full 10,000-tx pool costs work proportional to
    /// what it evicts, not to the pool: the admission check walks the
    /// ordered roots index instead of copying the graph. 1,000 accepts,
    /// each displacing one tx, take ~30 ms in a debug build; the bound is
    /// deliberately generous (CI runs tests in parallel). A per-accept
    /// copy of the graph would be 10 million entry copies here.
    #[test]
    fn accept_into_a_full_10k_pool_does_bounded_work() {
        const POOL: usize = 10_000;
        const INCOMING: usize = 1_000;
        let (utxo, _d) = fresh_utxo();
        // One block funds every coin in one write.
        let mut funding = unique_coinbase(1);
        funding.output = (0..POOL + INCOMING)
            .map(|_| TxOut { value: Amount::from_sat(1_000_000), script_pubkey: ScriptBuf::from_bytes(vec![0xac]) })
            .collect();
        let fund = funding.compute_txid();
        utxo.apply_block(&block_with(vec![funding]), 1).unwrap();

        let mut pool = Mempool::new();
        for i in 0..POOL {
            // Rates 2..=51 sat/vB.
            let tx = at_rate((fund, i as u32), 1_000_000, 2 + (i % 50) as u64, 0);
            pool.accept_tx_test(tx, &utxo, TEST_HEIGHT).unwrap();
        }
        pool.max_size = pool.size();
        let started = Instant::now();
        for i in 0..INCOMING {
            let tx = at_rate((fund, (POOL + i) as u32), 1_000_000, 100, 0);
            let txid = pool.accept_tx_test(tx, &utxo, TEST_HEIGHT).unwrap();
            assert!(pool.contains(&txid));
        }
        let elapsed = started.elapsed();
        assert_eq!(pool.count(), POOL);
        assert!(pool.size() <= pool.max_size);
        assert_eq!(pool.drain_removals().removals.len(), INCOMING);
        // The cheapest went first: every 2 sat/vB tx (200 of them), then 3...
        assert!(pool.mempool_min_fee_rate() > 2.0);
        assert!(elapsed < Duration::from_secs(2), "{} accepts into a full {}-tx pool took {:?}", INCOMING, POOL, elapsed);
    }

    /// A coinbase whose txid is unique per height (scriptSig = height).
    fn unique_coinbase(height: u32) -> Transaction {
        let mut cb = make_tx(&[(seed_txid(0), 0)], &[1]);
        cb.input[0].previous_output = OutPoint::null();
        cb.input[0].script_sig = ScriptBuf::from_bytes(height.to_le_bytes().to_vec());
        cb
    }

    /// Every graph field `accept_tx`, RBF, `remove_confirmed`, capacity
    /// eviction and expiry maintain incrementally must equal what a full
    /// recomputation from the pool's transactions gives, after every step
    /// of random operation sequences.
    fn assert_graph_invariants(pool: &Mempool, utxo: &UtxoSet) {
        let total: usize = pool.txs.values().map(|e| e.size).sum();
        assert_eq!(pool.total_size, total, "total_size");
        assert!(pool.total_size <= pool.max_size, "over capacity");
        let mut spends: HashMap<(Txid, u32), Txid> = HashMap::new();
        for (txid, e) in &pool.txs {
            assert_eq!(e.tx.compute_txid(), *txid);
            assert_eq!(e.size, serialize(&e.tx).len());
            assert_eq!(e.vsize, e.tx.vsize() as u64);
            let parents: HashSet<Txid> = e
                .tx
                .input
                .iter()
                .map(|i| i.previous_output.txid)
                .filter(|t| pool.txs.contains_key(t))
                .collect();
            assert_eq!(e.parents, parents, "parents of {}", txid);
            for i in &e.tx.input {
                let op = (i.previous_output.txid, i.previous_output.vout);
                assert!(spends.insert(op, *txid).is_none(), "two pool txs spend {:?}", op);
                let from_pool = pool
                    .txs
                    .get(&op.0)
                    .is_some_and(|p| (op.1 as usize) < p.tx.output.len());
                let confirmed = utxo.get(&op.0, op.1).unwrap().is_some();
                assert!(from_pool || confirmed, "{} has an orphaned input {:?}", txid, op);
            }
            let mut ancestors = HashSet::new();
            let mut stack: Vec<Txid> = parents.into_iter().collect();
            while let Some(t) = stack.pop() {
                if ancestors.insert(t) {
                    stack.extend(pool.txs[&t].parents.iter().copied());
                }
            }
            assert_eq!(e.ancestors, ancestors, "ancestors of {}", txid);
            assert_eq!(e.ancestor_fee, ancestors.iter().map(|t| pool.txs[t].fee).sum::<u64>());
            assert_eq!(e.ancestor_vsize, ancestors.iter().map(|t| pool.txs[t].vsize).sum::<u64>());
            let descendants: HashSet<Txid> =
                pool.txs.iter().filter(|(_, d)| d.ancestors.contains(txid)).map(|(t, _)| *t).collect();
            assert_eq!(e.descendants, descendants, "descendants of {}", txid);
            assert_eq!(e.descendant_fee, descendants.iter().map(|t| pool.txs[t].fee).sum::<u64>());
            assert_eq!(e.descendant_vsize, descendants.iter().map(|t| pool.txs[t].vsize).sum::<u64>());
            assert_eq!(e.descendant_size, descendants.iter().map(|t| pool.txs[t].size).sum::<usize>());
            let key = e.root_key.map(|k| (k.txid, k.fee, k.vsize));
            let expected_key = e.ancestors.is_empty().then(|| (*txid, e.fee + e.descendant_fee, e.vsize + e.descendant_vsize));
            assert_eq!(key, expected_key, "root key of {}", txid);
            assert!(e.ancestors.len() < MAX_ANCESTORS && e.descendants.len() < MAX_DESCENDANTS);
        }
        // The roots index holds exactly every root's current key, in
        // package-rate order.
        let mut indexed: Vec<(Txid, u64, u64)> = pool.roots.iter().map(|k| (k.txid, k.fee, k.vsize)).collect();
        assert!(indexed.windows(2).all(|w| !rate_below(w[1].1, w[1].2, w[0].1, w[0].2)), "roots out of order");
        indexed.sort();
        let mut expected: Vec<(Txid, u64, u64)> = pool.txs.values().filter_map(|e| e.root_key).map(|k| (k.txid, k.fee, k.vsize)).collect();
        expected.sort();
        assert_eq!(indexed, expected, "roots index");
        assert_eq!(pool.spends, spends, "spends index");
    }

    #[test]
    fn graph_state_matches_recomputation_after_random_operations() {
        use proptest::test_runner::{Config, TestRunner};
        let mut runner = TestRunner::new(Config { cases: 48, ..Config::default() });
        runner
            .run(&(proptest::prelude::any::<u64>(), 1500usize..6000), |(seed, cap)| {
                let mut rng = seed;
                let mut next = move |n: u64| {
                    rng = rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
                    let mut z = rng;
                    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                    (z ^ (z >> 31)) % n.max(1)
                };
                let (utxo, _d) = fresh_utxo();
                for i in 0..16u8 {
                    seed_utxo(&utxo, seed_txid(i), 0, 1_000_000);
                }
                let mut pool = Mempool::with_max_size(cap);
                let mut height = TEST_HEIGHT;
                for step in 0..60 {
                    // Candidate coins: confirmed seeds and every pool output.
                    let mut coins: Vec<(Txid, u32, u64)> = (0..16u8)
                        .filter_map(|i| utxo.get(&seed_txid(i), 0).unwrap().map(|u| (seed_txid(i), 0, u.amount)))
                        .collect();
                    let mut ids: Vec<Txid> = pool.txs.keys().copied().collect();
                    ids.sort();
                    for t in &ids {
                        for (v, o) in pool.txs[t].tx.output.iter().enumerate() {
                            coins.push((*t, v as u32, o.value.to_sat()));
                        }
                    }
                    let before: HashSet<Txid> = pool.txs.keys().copied().collect();
                    match next(10) {
                        0..=6 if !coins.is_empty() => {
                            // New tx (may double-spend: exercises RBF).
                            let n_in = 1 + next(2) as usize;
                            let mut ins = vec![];
                            for _ in 0..n_in {
                                let c = coins[next(coins.len() as u64) as usize];
                                if !ins.iter().any(|x: &(Txid, u32, u64)| x.0 == c.0 && x.1 == c.1) {
                                    ins.push(c);
                                }
                            }
                            let value: u64 = ins.iter().map(|c| c.2).sum();
                            let n_out = 1 + next(3);
                            let fee = 200 + next(20_000);
                            if value < fee + n_out * 1_000 {
                                continue;
                            }
                            let each = (value - fee) / n_out;
                            let outs: Vec<u64> = (0..n_out).map(|_| each).collect();
                            let inputs: Vec<(Txid, u32)> = ins.iter().map(|c| (c.0, c.1)).collect();
                            let tx = make_tx_marked(&inputs, &outs, step as u8);
                            if let Ok(txid) = pool.accept_tx_test(tx, &utxo, height) {
                                assert!(pool.contains(&txid));
                            }
                        }
                        7 if !ids.is_empty() => {
                            // Confirm a random root (block also lands in the UTXO set).
                            let roots: Vec<Txid> =
                                ids.iter().copied().filter(|t| pool.txs[t].ancestors.is_empty()).collect();
                            let root = roots[next(roots.len() as u64) as usize];
                            let tx = pool.txs[&root].tx.clone();
                            height += 1;
                            let block = Block {
                                header: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
                                txdata: vec![unique_coinbase(height), tx],
                            };
                            utxo.apply_block(&block, height).unwrap();
                            pool.remove_confirmed(&block);
                        }
                        8 if !ids.is_empty() => {
                            // A rival spend of a random pool tx's confirmed input confirms.
                            let victim = &pool.txs[&ids[next(ids.len() as u64) as usize]].tx;
                            let Some(confirmed) = victim
                                .input
                                .iter()
                                .find(|i| utxo.get(&i.previous_output.txid, i.previous_output.vout).unwrap().is_some())
                            else {
                                continue;
                            };
                            let rival = make_tx_marked(
                                &[(confirmed.previous_output.txid, confirmed.previous_output.vout)],
                                &[1_000],
                                0xfe,
                            );
                            height += 1;
                            let block = Block {
                                header: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
                                txdata: vec![unique_coinbase(height), rival],
                            };
                            utxo.apply_block(&block, height).unwrap();
                            pool.remove_confirmed(&block);
                        }
                        9 if !ids.is_empty() => {
                            let t = ids[next(ids.len() as u64) as usize];
                            pool.txs.get_mut(&t).unwrap().added_at = Instant::now()
                                .checked_sub(MAX_TX_AGE + std::time::Duration::from_secs(1))
                                .unwrap();
                            pool.expire_old();
                        }
                        _ => {}
                    }
                    assert_graph_invariants(&pool, &utxo);
                    // Every tx that left is reported, once, and nothing else.
                    let drained = pool.drain_removals();
                    assert_eq!(drained.dropped, 0);
                    let reported: Vec<Txid> = drained.removals.iter().map(|r| r.txid).collect();
                    let gone: HashSet<Txid> = before.iter().filter(|t| !pool.contains(t)).copied().collect();
                    assert_eq!(reported.len(), gone.len(), "{:?}", drained.removals);
                    assert_eq!(reported.into_iter().collect::<HashSet<_>>(), gone);
                }
                Ok(())
            })
            .unwrap();
    }

    // ── Ticket 053 part 2: input / witness standardness, size, policy
    //    script flags, fee floors ────────────────────────────────────────

    fn seed_spk(utxo: &UtxoSet, id: u8, vout: u32, amount: u64, spk: &ScriptBuf) -> OutPoint {
        utxo.test_insert_utxo(
            [id; 32],
            vout,
            UtxoEntry { amount, script_pubkey: spk.to_bytes(), height: 1, is_coinbase: false },
        )
        .unwrap();
        OutPoint { txid: seed_txid(id), vout }
    }

    fn with_input(mut tx: Transaction, i: usize, script_sig: Vec<u8>, witness: &[Vec<u8>]) -> Transaction {
        tx.input[i].script_sig = ScriptBuf::from_bytes(script_sig);
        tx.input[i].witness = Witness::from_slice(witness);
        tx
    }

    /// A single push of `data` (direct, PUSHDATA1 or PUSHDATA2, minimal).
    fn push(data: &[u8]) -> Vec<u8> {
        let mut out = match data.len() {
            n @ 0..=75 => vec![n as u8],
            n @ 76..=255 => vec![0x4c, n as u8],
            n => vec![0x4d, n as u8, (n >> 8) as u8],
        };
        out.extend_from_slice(data);
        out
    }

    /// A valid, policy-clean witness script of exactly `len` (>= 1) bytes:
    /// pushes of non-small bytes dropped again, then OP_1.
    fn filler_script(len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut r = len - 1;
        while r > 0 {
            // A piece is <push n> OP_DROP: n + 2 bytes, n in 1..=75.
            let piece = if r >= 80 { 77 } else if r > 77 { r - 3 } else { r };
            assert!(piece >= 3, "{} left", r);
            out.extend(push(&vec![0xaa; piece - 2]));
            out.push(0x75);
            r -= piece;
        }
        out.push(0x51);
        assert_eq!(out.len(), len);
        out
    }

    fn standard_modes() -> [AcceptMode; 2] {
        [AcceptMode::Relay, AcceptMode::Own]
    }

    /// Core's `tx-size-small`: 64 bytes without witness is refused, 65 is
    /// not (CVE-2017-12842), whatever the witness adds.
    #[test]
    fn tx_size_small_boundary_is_65_non_witness_bytes() {
        for (data_len, ok) in [(2usize, false), (3, true)] {
            for mode in standard_modes() {
                let (utxo, _d) = fresh_utxo();
                let coin = seed_op_true(&utxo, 1, 10_000, 1, false);
                let mut spk = vec![0x6a];
                spk.extend(push(&vec![0xaa; data_len]));
                let tx = spend_ops(
                    &[coin],
                    vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(spk) }],
                );
                assert_eq!(tx.base_size(), 62 + data_len);
                let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode);
                if ok {
                    r.unwrap();
                } else {
                    assert!(matches!(r, Err(MempoolError::TxSizeSmall { size: 64 })), "{:?}", r);
                }
            }
        }
    }

    /// `ValidateInputsStandardness`: a NONSTANDARD or unknown-witness
    /// spent output is refused, as relay and as an own send; the test-only
    /// mode skips it. The ticket 053 reviewer's reproducer: an own tx
    /// spending OP_2 <32 bytes> with an empty witness was accepted.
    #[test]
    fn spends_of_nonstandard_outputs_are_refused() {
        let mut v2 = vec![0x52, 0x20];
        v2.extend([7u8; 32]);
        let mut v0_25 = vec![0x00, 25];
        v0_25.extend([7u8; 25]);
        for (spk, reason) in [
            (vec![0x51], "script unknown"),
            (v0_25, "script unknown"),
            (v2, "witness program is undefined"),
        ] {
            let spk = ScriptBuf::from_bytes(spk);
            for mode in standard_modes() {
                let (utxo, _d) = fresh_utxo();
                let coin = seed_spk(&utxo, 1, 0, 100_000, &spk);
                let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, vec![], &[]);
                match accept_in(&mut Mempool::new(), tx.clone(), &utxo, TEST_HEIGHT, mode) {
                    Err(MempoolError::NonStandardInputs { input_index: Some(0), reason: r }) => {
                        assert!(r.contains(reason), "{} vs {}", r, reason)
                    }
                    other => panic!("{:?} {}: {:?}", mode, spk, other),
                }
                let (utxo, _d) = fresh_utxo();
                let coin = seed_spk(&utxo, 1, 0, 100_000, &spk);
                let _ = coin;
                accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::SkipConsensus).unwrap();
            }
        }
    }

    /// A P2SH redeem script `OP_0 OP_IF <n x OP_CHECKSIG> OP_ENDIF OP_1`
    /// (the CHECKSIGs never run, but count).
    fn p2sh_sigops_redeem(n: usize) -> Vec<u8> {
        let mut r = vec![0x00, 0x63];
        r.extend(std::iter::repeat_n(0xac, n));
        r.extend([0x68, 0x51]);
        r
    }

    /// `MAX_P2SH_SIGOPS`: 15 redeem-script sigops pass, 16 don't.
    #[test]
    fn p2sh_redeem_sigops_boundary_is_15() {
        for (n, ok) in [(15, true), (16, false)] {
            for mode in standard_modes() {
                let redeem = ScriptBuf::from_bytes(p2sh_sigops_redeem(n));
                let (utxo, _d) = fresh_utxo();
                let coin = seed_spk(&utxo, 1, 0, 100_000, &ScriptBuf::new_p2sh(&redeem.script_hash()));
                let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, push(redeem.as_bytes()), &[]);
                let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode);
                if ok {
                    r.unwrap();
                } else {
                    assert!(
                        matches!(&r, Err(MempoolError::NonStandardInputs { reason, .. }) if reason.contains("16 > 15")),
                        "{:?}",
                        r
                    );
                }
            }
        }
    }

    /// BIP 54 (`MAX_TX_LEGACY_SIGOPS`): 2500 legacy sigops across the
    /// inputs pass, 2510 don't.
    #[test]
    fn bip54_legacy_sigop_limit_is_2500() {
        for (inputs, ok) in [(250u32, true), (251, false)] {
            let redeem = ScriptBuf::from_bytes(p2sh_sigops_redeem(10));
            let spk = ScriptBuf::new_p2sh(&redeem.script_hash());
            let (utxo, _d) = fresh_utxo();
            let coins: Vec<OutPoint> = (0..inputs).map(|v| seed_spk(&utxo, 1, v, 10_000, &spk)).collect();
            let mut tx = spend_ops(&coins, vec![p2wpkh_out(10_000 * inputs as u64 - 200_000)]);
            for i in 0..tx.input.len() {
                tx = with_input(tx, i, push(redeem.as_bytes()), &[]);
            }
            let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Own);
            if ok {
                r.unwrap();
            } else {
                assert!(
                    matches!(&r, Err(MempoolError::NonStandardInputs { input_index: None, reason }) if reason.contains("bip54")),
                    "{:?}",
                    r
                );
            }
        }
    }

    /// A P2SH scriptSig that `EvalScript` can't run (a 521-byte push) is a
    /// malformed P2SH spend.
    #[test]
    fn p2sh_scriptsig_with_an_oversized_push_is_nonstandard() {
        let redeem = ScriptBuf::from_bytes(p2sh_sigops_redeem(0));
        let (utxo, _d) = fresh_utxo();
        let coin = seed_spk(&utxo, 1, 0, 100_000, &ScriptBuf::new_p2sh(&redeem.script_hash()));
        let mut sig = push(&[0xaa; 521]);
        sig.extend(push(redeem.as_bytes()));
        let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, sig, &[]);
        let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Own);
        assert!(
            matches!(&r, Err(MempoolError::NonStandardInputs { reason, .. }) if reason.contains("push size")),
            "{:?}",
            r
        );
    }

    /// `IsWitnessStandard`'s P2WSH limits, at their boundaries: witness
    /// script 3600 / 3601 bytes, 100 / 101 stack items, 80 / 81-byte items.
    /// As own txs: our 018 relay filter caps witness items lower.
    #[test]
    fn p2wsh_witness_limits_match_core() {
        let run = |ws: Vec<u8>, items: Vec<Vec<u8>>| {
            let script = ScriptBuf::from_bytes(ws.clone());
            let (utxo, _d) = fresh_utxo();
            let coin = seed_spk(&utxo, 1, 0, 100_000, &ScriptBuf::new_p2wsh(&script.wscript_hash()));
            let mut witness = items;
            witness.push(ws);
            let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, vec![], &witness);
            accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Own)
        };
        let nonstandard = |r: Result<Txid, MempoolError>, what: &str| {
            assert!(
                matches!(&r, Err(MempoolError::NonStandardWitness { reason, .. }) if reason.contains(what)),
                "{:?}",
                r
            )
        };
        run(filler_script(3600), vec![]).unwrap();
        nonstandard(run(filler_script(3601), vec![]), "too large");
        // n items, the bottom one true, dropped down to it.
        let stack = |n: usize| {
            let mut items = vec![vec![]; n];
            items[0] = vec![0x01];
            (vec![0x75; n - 1], items)
        };
        let (ws, items) = stack(100);
        run(ws, items).unwrap();
        let (ws, items) = stack(101);
        nonstandard(run(ws, items), "too many items");
        run(vec![0x75, 0x51], vec![vec![0xaa; 80]]).unwrap();
        nonstandard(run(vec![0x75, 0x51], vec![vec![0xaa; 81]]), "item too large");
    }

    /// `IsWitnessStandard`: a witness on a P2PKH or P2A spend, a Taproot
    /// annex and an 81-byte tapscript stack item are refused before any
    /// script runs.
    #[test]
    fn witness_on_the_wrong_spend_type_and_taproot_rules() {
        let cases: Vec<(ScriptBuf, Vec<Vec<u8>>, &str)> = vec![
            (ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array([1; 20])), vec![vec![1]], "non-witness-program"),
            (ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]), vec![vec![1]], "pay-to-anchor"),
            (ScriptBuf::from_bytes([&[0x51, 0x20][..], &[9; 32]].concat()), vec![vec![0; 64], vec![0x50, 1]], "annex"),
            (
                ScriptBuf::from_bytes([&[0x51, 0x20][..], &[9; 32]].concat()),
                vec![vec![0xaa; 81], vec![0x51], [&[0xc0][..], &[2; 32]].concat()],
                "tapscript stack item",
            ),
        ];
        for (spk, witness, what) in cases {
            for mode in standard_modes() {
                let (utxo, _d) = fresh_utxo();
                let coin = seed_spk(&utxo, 1, 0, 100_000, &spk);
                let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, vec![], &witness);
                let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode);
                assert!(
                    matches!(&r, Err(MempoolError::NonStandardWitness { reason, .. }) if reason.contains(what)),
                    "{}: {:?}",
                    what,
                    r
                );
            }
        }
    }

    /// A native pay-to-anchor spend with an empty witness is standard (Core
    /// 28+), though the policy pass's v26 interpreter predates P2A.
    #[test]
    fn pay_to_anchor_spend_is_standard() {
        let (utxo, _d) = fresh_utxo();
        let coin = seed_spk(&utxo, 1, 0, 100_000, &ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]));
        let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, vec![], &[]);
        accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Relay).unwrap();
    }

    /// The policy script pass (Core's STANDARD_SCRIPT_VERIFY_FLAGS) refuses
    /// what only policy forbids, as non-standard, in both modes:
    /// - a P2SH-wrapped witness v2 program (DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
    ///   the reviewer's case, wrapped so input standardness lets it through);
    /// - an OP_NOP4 (DISCOURAGE_UPGRADABLE_NOPS);
    /// - a P2SH redeem script leaving two items (CLEANSTACK);
    /// - an OP_IF on a non-minimal argument (MINIMALIF).
    ///
    /// A script that fails the consensus flags too is `ScriptFailure`.
    #[test]
    #[allow(clippy::type_complexity)]
    fn policy_script_flags_refuse_what_core_does_not_relay() {
        let mut v2 = vec![0x52, 0x20];
        v2.extend([7u8; 32]);
        let wrapped = ScriptBuf::from_bytes(v2);
        let p2wsh = |ws: &[u8]| ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(ws.to_vec()).wscript_hash());
        let cases: Vec<(ScriptBuf, Vec<u8>, Vec<Vec<u8>>, &str)> = vec![
            (ScriptBuf::new_p2sh(&wrapped.script_hash()), push(wrapped.as_bytes()), vec![], "soft-fork upgrades"),
            (p2wsh(&[0xb3, 0x51]), vec![], vec![vec![0xb3, 0x51]], "NOPx"),
            // Legacy P2SH: for witness scripts a clean stack is consensus.
            (
                ScriptBuf::new_p2sh(&ScriptBuf::from_bytes(vec![0x51, 0x51]).script_hash()),
                push(&[0x51, 0x51]),
                vec![],
                "exactly one",
            ),
            (p2wsh(&[0x63, 0x51, 0x68]), vec![], vec![vec![0x02], vec![0x63, 0x51, 0x68]], "OP_IF"),
        ];
        for (spk, script_sig, witness, what) in cases {
            for mode in standard_modes() {
                let (utxo, _d) = fresh_utxo();
                let coin = seed_spk(&utxo, 1, 0, 100_000, &spk);
                let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, script_sig.clone(), &witness);
                let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, mode);
                assert!(
                    matches!(&r, Err(MempoolError::NonStandardScriptFlags { error, .. }) if error.contains(what)),
                    "{}: {:?}",
                    what,
                    r
                );
            }
        }
        // P2WSH(OP_FALSE) spent with OP_TRUE fails consensus too.
        let (utxo, _d) = fresh_utxo();
        let coin = seed_spk(&utxo, 1, 0, 100_000, &p2wsh(&[0x00]));
        let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(90_000)]), 0, vec![], &[vec![0x51]]);
        let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Own);
        assert!(matches!(r, Err(MempoolError::ScriptFailure { .. })), "{:?}", r);
    }

    /// Scripts run last, after fees and limits (Core's PreChecks before
    /// PolicyScriptChecks): a tx with a failing script and too low a fee
    /// is refused for the fee.
    #[test]
    fn fee_checks_run_before_scripts() {
        let (utxo, _d) = fresh_utxo();
        let ws = ScriptBuf::from_bytes(vec![0x00]);
        let coin = seed_spk(&utxo, 1, 0, 100_000, &ScriptBuf::new_p2wsh(&ws.wscript_hash()));
        let tx = with_input(spend_ops(&[coin], vec![p2wpkh_out(99_990)]), 0, vec![], &[vec![0x00]]);
        let r = accept_in(&mut Mempool::new(), tx, &utxo, TEST_HEIGHT, AcceptMode::Relay);
        assert!(matches!(r, Err(MempoolError::InsufficientFee { .. })), "{:?}", r);
    }

    /// The submit floor: below the peers' feefilter (Core's comparison,
    /// `fee < ceil(filter * vsize / 1000)`) an own tx is refused and the
    /// pool is unchanged; at it, accepted. 0 means no floor.
    #[test]
    fn network_floor_refuses_an_own_tx_below_every_peer_filter() {
        let (utxo, _d) = fresh_utxo();
        let coin = seed_op_true(&utxo, 1, 100_000, 1, false);
        let tx = spend_ops(&[coin], vec![p2wpkh_out(100_000 - 1_000)]);
        let vsize = tx.vsize() as u64;
        // The filter at which 1000 sats is exactly enough.
        let at = 1_000 * 1000 / vsize;
        let mut pool = Mempool::new();
        let r = pool.accept_own_tx_for_network(tx.clone(), &utxo, TEST_HEIGHT, &synthetic_times, at + 10);
        assert!(matches!(r, Err(MempoolError::BelowNetworkMinimum { .. })), "{:?}", r);
        assert_eq!(pool.count(), 0);
        assert!(pool.drain_removals().removals.is_empty());
        pool.accept_own_tx_for_network(tx, &utxo, TEST_HEIGHT, &synthetic_times, at).unwrap();
        let (utxo, _d) = fresh_utxo();
        let coin = seed_op_true(&utxo, 1, 100_000, 1, false);
        let tx = spend_ops(&[coin], vec![p2wpkh_out(100_000 - 1_000)]);
        Mempool::new().accept_own_tx_for_network(tx, &utxo, TEST_HEIGHT, &synthetic_times, 0).unwrap();
    }

    /// A disconnected own tx comes back with no fee floor (Core's
    /// `bypass_limits`): below the rolling minimum, below 1 sat/vB, and
    /// over the absurd-fee cap.
    #[test]
    fn disconnected_own_tx_bypasses_the_fee_floors() {
        let (utxo, _d) = fresh_utxo();
        let cheap_coin = seed_op_true(&utxo, 1, 100_000, 1, false);
        let cheap = spend_ops(&[cheap_coin], vec![p2wpkh_out(100_000 - 10)]);
        let mut pool = Mempool::new();
        pool.rolling_min_fee = 50_000.0; // 50 sat/vB, as after an eviction
        assert!(matches!(
            pool.accept_own_tx(cheap.clone(), &utxo, TEST_HEIGHT, &synthetic_times),
            Err(MempoolError::InsufficientFee { .. })
        ));
        pool.accept_disconnected_own_tx(cheap, &utxo, TEST_HEIGHT, &synthetic_times).unwrap();
        let rich_coin = seed_op_true(&utxo, 2, 100_000_000, 1, false);
        let absurd = spend_ops(&[rich_coin], vec![p2wpkh_out(1_000)]);
        pool.accept_disconnected_own_tx(absurd, &utxo, TEST_HEIGHT, &synthetic_times).unwrap();
    }

    /// Past the cap only non-final events are dropped: replacements and
    /// block conflicts, which settle own txs, are always kept.
    #[test]
    fn removal_queue_never_drops_final_events() {
        let mut pool = Mempool::new();
        let id = |i: u64| {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&i.to_le_bytes());
            Txid::from_byte_array(b)
        };
        let by = id(u64::MAX);
        for i in 0..MAX_QUEUED_REMOVALS as u64 {
            pool.record_removal(id(i), RemovalReason::ReplacedBy(by));
        }
        pool.record_removal(id(1 << 40), RemovalReason::Evicted);
        pool.record_removal(id(1 << 41), RemovalReason::ConflictedByBlock { by });
        let d = pool.drain_removals();
        assert_eq!((d.removals.len(), d.dropped), (MAX_QUEUED_REMOVALS + 1, 1));
        assert!(d.removals.iter().all(|r| r.reason.is_final()));
    }
}
