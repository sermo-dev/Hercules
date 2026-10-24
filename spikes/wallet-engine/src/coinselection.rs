//! Port of Bitcoin Core's coin selection: Branch-and-Bound (`SelectCoinsBnB`), CoinGrinder,
//! the waste metric (`SelectionResult::RecalculateWaste`) and the supporting
//! `COutput` / `OutputGroup` / `SelectionResult` / `CFeeRate::GetFee` semantics.
//!
//! Source: bitcoin/bitcoin @ a773e1e33b349dc819b5a0edc1c7a4839dc73b48
//!   src/wallet/coinselection.cpp, src/wallet/coinselection.h, src/policy/feerate.cpp
//!
//! The port is intentionally line-for-line (same variable names, same control flow, same
//! tie-breaks, same attempt counting) so Core's tests, including their exact
//! `GetSelectionsEvaluated()` counts, can be reused as a regression oracle.
//! Amounts are `i64` satoshis (Core's `CAmount`) because effective values and waste can be
//! negative.

pub type CAmount = i64;

pub const COIN: CAmount = 100_000_000;
pub const CENT: CAmount = 1_000_000;
pub const MAX_MONEY: CAmount = 21_000_000 * COIN;
pub const WITNESS_SCALE_FACTOR: i32 = 4;
/// policy/policy.h
pub const MAX_STANDARD_TX_WEIGHT: i32 = 400_000;
/// coinselection.h: lower/upper bound for randomly-chosen target change amount
pub const CHANGE_LOWER: CAmount = 50_000;
pub const CHANGE_UPPER: CAmount = 1_000_000;
/// coinselection.cpp
pub const TOTAL_TRIES: usize = 100_000;

/// `CFeeRate`: satoshis per 1000 virtual bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRate(pub CAmount);

impl FeeRate {
    /// `CFeeRate::GetFee`: `FeeFrac::EvaluateFeeUp` (round toward +inf), with Core's special
    /// case that a negative rate never rounds to zero.
    pub fn get_fee(&self, virtual_bytes: i32) -> CAmount {
        debug_assert!(virtual_bytes >= 0);
        if self.0 == 0 {
            return 0;
        }
        let num = self.0 * virtual_bytes as CAmount;
        let fee = if num >= 0 { (num + 999) / 1000 } else { num / 1000 };
        if fee == 0 && virtual_bytes != 0 && self.0 < 0 {
            return -1;
        }
        fee
    }
}

/// `COutput`: one UTXO under consideration. `id` is an opaque handle back to the caller's
/// coin (outpoint, descriptor, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct COutput {
    pub id: usize,
    pub value: CAmount,
    /// Estimated size of the fully-signed input in vbytes; -1 if unknown.
    pub input_bytes: i32,
    fee: CAmount,
    effective_value: CAmount,
    pub long_term_fee: CAmount,
}

impl COutput {
    /// Core ctor with `std::optional<CFeeRate> feerate`.
    pub fn with_feerate(id: usize, value: CAmount, input_bytes: i32, feerate: FeeRate) -> Self {
        let fee = if input_bytes < 0 { 0 } else { feerate.get_fee(input_bytes) };
        COutput { id, value, input_bytes, fee, effective_value: value - fee, long_term_fee: 0 }
    }
    /// Core ctor with explicit `CAmount fees`.
    pub fn with_fee(id: usize, value: CAmount, input_bytes: i32, fees: CAmount) -> Self {
        assert!((input_bytes < 0 && fees == 0) || (input_bytes > 0 && fees >= 0));
        COutput { id, value, input_bytes, fee: fees, effective_value: value - fees, long_term_fee: 0 }
    }
    pub fn fee(&self) -> CAmount {
        self.fee
    }
    pub fn effective_value(&self) -> CAmount {
        self.effective_value
    }
}

/// `OutputGroup`.
#[derive(Clone, Debug)]
pub struct OutputGroup {
    pub outputs: Vec<COutput>,
    pub value: CAmount,
    pub effective_value: CAmount,
    pub fee: CAmount,
    pub long_term_fee: CAmount,
    pub weight: i32,
    pub long_term_feerate: FeeRate,
    pub subtract_fee_outputs: bool,
}

impl OutputGroup {
    pub fn new(long_term_feerate: FeeRate, subtract_fee_outputs: bool) -> Self {
        OutputGroup {
            outputs: vec![],
            value: 0,
            effective_value: 0,
            fee: 0,
            long_term_fee: 0,
            weight: 0,
            long_term_feerate,
            subtract_fee_outputs,
        }
    }

    /// `OutputGroup::Insert` (ancestor/cluster/depth bookkeeping omitted: the spike has no
    /// mempool-ancestry model yet).
    pub fn insert(&mut self, mut coin: COutput) {
        self.fee += coin.fee;
        coin.long_term_fee =
            if coin.input_bytes < 0 { 0 } else { self.long_term_feerate.get_fee(coin.input_bytes) };
        self.long_term_fee += coin.long_term_fee;
        self.effective_value += coin.effective_value;
        self.value += coin.value;
        if coin.input_bytes > 0 {
            self.weight += coin.input_bytes * WITNESS_SCALE_FACTOR;
        }
        self.outputs.push(coin);
    }

    pub fn selection_amount(&self) -> CAmount {
        if self.subtract_fee_outputs { self.value } else { self.effective_value }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionAlgorithm {
    Bnb,
    CoinGrinder,
    Manual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionError {
    /// Core: empty `util::Error()`.
    InsufficientFunds,
    /// Core: "The inputs size exceeds the maximum weight..."
    MaxWeightExceeded,
}

/// `SelectionResult`.
#[derive(Clone, Debug)]
pub struct SelectionResult {
    pub target: CAmount,
    pub algo: SelectionAlgorithm,
    pub inputs: Vec<COutput>,
    pub use_effective: bool,
    pub weight: i32,
    pub selections_evaluated: usize,
    pub algo_completed: bool,
    pub waste: Option<CAmount>,
    pub bump_fee_group_discount: CAmount,
}

impl SelectionResult {
    pub fn new(target: CAmount, algo: SelectionAlgorithm) -> Self {
        SelectionResult {
            target,
            algo,
            inputs: vec![],
            use_effective: false,
            weight: 0,
            selections_evaluated: 0,
            algo_completed: false,
            waste: None,
            bump_fee_group_discount: 0,
        }
    }

    pub fn add_input(&mut self, group: &OutputGroup) {
        self.inputs.extend(group.outputs.iter().cloned());
        self.use_effective = !group.subtract_fee_outputs;
        self.weight += group.weight;
    }

    pub fn selected_value(&self) -> CAmount {
        self.inputs.iter().map(|c| c.value).sum()
    }

    pub fn selected_effective_value(&self) -> CAmount {
        self.inputs.iter().map(|c| c.effective_value).sum::<CAmount>() + self.bump_fee_group_discount
    }

    /// `SelectionResult::GetChange`
    pub fn get_change(&self, min_viable_change: CAmount, change_fee: CAmount) -> CAmount {
        let change = if self.use_effective {
            self.selected_effective_value() - self.target - change_fee
        } else {
            self.selected_value() - self.target
        };
        if change < min_viable_change { 0 } else { change }
    }

    /// `SelectionResult::RecalculateWaste`:
    ///   waste = Σ(fee - long_term_fee) [- bump discount] + (change ? change_cost : excess)
    pub fn recalculate_waste(&mut self, min_viable_change: CAmount, change_cost: CAmount, change_fee: CAmount) {
        assert!(!self.inputs.is_empty());
        let mut waste: CAmount = self.inputs.iter().map(|c| c.fee - c.long_term_fee).sum();
        waste -= self.bump_fee_group_discount;
        if self.get_change(min_viable_change, change_fee) != 0 {
            waste += change_cost;
        } else {
            let selected =
                if self.use_effective { self.selected_effective_value() } else { self.selected_value() };
            assert!(selected >= self.target);
            waste += selected - self.target;
        }
        self.waste = Some(waste);
    }
}

/// Core's `descending` comparator: by selection amount desc, then lower waste first.
fn descending(a: &OutputGroup, b: &OutputGroup) -> std::cmp::Ordering {
    b.selection_amount()
        .cmp(&a.selection_amount())
        .then_with(|| (a.fee - a.long_term_fee).cmp(&(b.fee - b.long_term_fee)))
}

/// Core's `descending_effval_weight` comparator: by selection amount desc, then lower weight.
fn descending_effval_weight(a: &OutputGroup, b: &OutputGroup) -> std::cmp::Ordering {
    b.selection_amount().cmp(&a.selection_amount()).then_with(|| a.weight.cmp(&b.weight))
}

/// `SelectCoinsBnB`: search for a changeless input set with
/// `selection_target <= Σ eff_value <= selection_target + cost_of_change`, minimising waste.
pub fn select_coins_bnb(
    utxo_pool: &mut [OutputGroup],
    selection_target: CAmount,
    cost_of_change: CAmount,
    max_selection_weight: i32,
) -> Result<SelectionResult, SelectionError> {
    utxo_pool.sort_by(descending);
    // lookahead[i] = Σ(UTXO[i+1..].amount)
    let mut lookahead = vec![0 as CAmount; utxo_pool.len()];
    let mut total_available: CAmount = 0;
    for index in (0..utxo_pool.len()).rev() {
        lookahead[index] = total_available;
        debug_assert!(utxo_pool[index].selection_amount() > 0);
        total_available += utxo_pool[index].selection_amount();
    }
    if utxo_pool.is_empty() || total_available < selection_target {
        return Err(SelectionError::InsufficientFunds);
    }

    let mut curr_selection: Vec<usize> = vec![];
    let mut best_selection: Vec<usize> = vec![];
    let mut curr_amount: CAmount = 0;
    let mut curr_selection_waste: CAmount = 0;
    let mut best_waste: CAmount = MAX_MONEY;
    let mut curr_weight: i32 = 0;
    let mut max_tx_weight_exceeded = false;
    let mut next_utxo: usize = 0;

    let mut curr_try: usize = 0;
    let mut result = SelectionResult::new(selection_target, SelectionAlgorithm::Bnb);
    let mut is_done = false;
    // fee : long_term_fee :: feerate : LTFRE
    let is_feerate_high = utxo_pool[0].fee > utxo_pool[0].long_term_fee;

    macro_rules! deselect_last {
        () => {{
            let u = &utxo_pool[*curr_selection.last().unwrap()];
            curr_amount -= u.selection_amount();
            curr_weight -= u.weight;
            curr_selection_waste -= u.fee - u.long_term_fee;
            curr_selection.pop();
        }};
    }

    while !is_done {
        let mut should_shift = false;
        let mut should_cut = false;
        // Select `next_utxo`
        {
            let u = &utxo_pool[next_utxo];
            curr_amount += u.selection_amount();
            curr_weight += u.weight;
            curr_selection_waste += u.fee - u.long_term_fee;
        }
        curr_selection.push(next_utxo);
        next_utxo += 1;
        curr_try += 1;

        // EVALUATE
        if curr_amount + lookahead[*curr_selection.last().unwrap()] < selection_target {
            should_cut = true; // insufficient funds with lookahead: CUT
        } else if curr_weight > max_selection_weight {
            max_tx_weight_exceeded = true;
            should_shift = true;
        } else if curr_amount > selection_target + cost_of_change {
            should_shift = true; // overshot target range
        } else if is_feerate_high && curr_selection_waste > best_waste {
            should_shift = true; // more inputs only add waste at high feerates
        } else if curr_amount >= selection_target {
            should_shift = true; // in target window: candidate
            let curr_excess = curr_amount - selection_target;
            let curr_waste = curr_selection_waste + curr_excess;
            if curr_waste <= best_waste {
                best_selection = curr_selection.clone();
                best_waste = curr_waste;
            }
        }

        if curr_try >= TOTAL_TRIES {
            result.algo_completed = false;
            break;
        }

        if next_utxo == utxo_pool.len() {
            should_cut = true;
        }

        if should_cut {
            deselect_last!();
            should_shift = true;
        }

        while should_shift {
            if curr_selection.is_empty() {
                is_done = true;
                result.algo_completed = true;
                break;
            }
            next_utxo = curr_selection.last().unwrap() + 1;
            deselect_last!();
            should_shift = false;

            debug_assert!(next_utxo < utxo_pool.len());
            // Skip clones / equal-amount-but-more-wasteful successors of the omitted UTXO.
            while utxo_pool[next_utxo - 1].selection_amount() == utxo_pool[next_utxo].selection_amount() {
                if next_utxo >= utxo_pool.len() - 1 {
                    should_shift = true;
                    break;
                }
                next_utxo += 1;
            }
        }
    }

    result.selections_evaluated = curr_try;

    if best_selection.is_empty() {
        return Err(if max_tx_weight_exceeded {
            SelectionError::MaxWeightExceeded
        } else {
            SelectionError::InsufficientFunds
        });
    }
    for &i in &best_selection {
        result.add_input(&utxo_pool[i]);
    }
    Ok(result)
}

/// `CoinGrinder`: deterministic DFS for the minimum-weight input set funding
/// `selection_target + change_target` (i.e. a transaction *with* change).
pub fn coin_grinder(
    utxo_pool: &mut [OutputGroup],
    selection_target: CAmount,
    change_target: CAmount,
    max_selection_weight: i32,
) -> Result<SelectionResult, SelectionError> {
    utxo_pool.sort_by(descending_effval_weight);
    let n = utxo_pool.len();
    let mut lookahead = vec![0 as CAmount; n];
    let mut min_tail_weight = vec![0i32; n];

    let mut total_available: CAmount = 0;
    let mut min_group_weight = i32::MAX;
    for index in (0..n).rev() {
        lookahead[index] = total_available;
        min_tail_weight[index] = min_group_weight;
        debug_assert!(utxo_pool[index].selection_amount() > 0);
        total_available += utxo_pool[index].selection_amount();
        min_group_weight = min_group_weight.min(utxo_pool[index].weight);
    }

    let total_target = selection_target + change_target;
    if n == 0 || total_available < total_target {
        return Err(SelectionError::InsufficientFunds);
    }

    let mut curr_selection: Vec<usize> = vec![];
    let mut best_selection: Vec<usize> = vec![];
    let mut curr_amount: CAmount = 0;
    let mut best_selection_amount: CAmount = MAX_MONEY;
    let mut curr_weight: i32 = 0;
    let mut best_selection_weight: i32 = max_selection_weight; // tie fine: prefer lower amount
    let mut max_tx_weight_exceeded = false;
    let mut next_utxo: usize = 0;

    macro_rules! deselect_last {
        () => {{
            let u = &utxo_pool[*curr_selection.last().unwrap()];
            curr_amount -= u.selection_amount();
            curr_weight -= u.weight;
            curr_selection.pop();
        }};
    }

    let mut result = SelectionResult::new(selection_target, SelectionAlgorithm::CoinGrinder);
    let mut is_done = false;
    let mut curr_try: usize = 0;
    while !is_done {
        let mut should_shift = false;
        let mut should_cut = false;
        {
            let u = &utxo_pool[next_utxo];
            curr_amount += u.selection_amount();
            curr_weight += u.weight;
        }
        curr_selection.push(next_utxo);
        next_utxo += 1;
        curr_try += 1;

        let curr_tail = *curr_selection.last().unwrap();
        if curr_amount + lookahead[curr_tail] < total_target {
            should_cut = true;
        } else if curr_weight > best_selection_weight {
            if curr_weight > max_selection_weight {
                max_tx_weight_exceeded = true;
            }
            if utxo_pool[curr_tail].weight <= min_tail_weight[curr_tail] {
                should_cut = true;
            } else {
                should_shift = true;
            }
        } else if curr_amount >= total_target {
            should_shift = true;
            if curr_weight < best_selection_weight
                || (curr_weight == best_selection_weight && curr_amount < best_selection_amount)
            {
                best_selection = curr_selection.clone();
                best_selection_weight = curr_weight;
                best_selection_amount = curr_amount;
            }
        } else if !best_selection.is_empty() && {
            let tail_amt = utxo_pool[curr_tail].selection_amount();
            // ceil((total_target - curr_amount) / tail_amt) more UTXOs of at least min_tail_weight
            let needed = (total_target - curr_amount + tail_amt - 1) / tail_amt;
            curr_weight as i64 + min_tail_weight[curr_tail] as i64 * needed > best_selection_weight as i64
        } {
            if utxo_pool[curr_tail].weight <= min_tail_weight[curr_tail] {
                should_cut = true;
            } else {
                should_shift = true;
            }
        }

        if curr_try >= TOTAL_TRIES {
            result.algo_completed = false;
            break;
        }

        if next_utxo == n {
            should_cut = true;
        }

        if should_cut {
            deselect_last!();
            should_shift = true;
        }

        while should_shift {
            if curr_selection.is_empty() {
                is_done = true;
                result.algo_completed = true;
                break;
            }
            next_utxo = curr_selection.last().unwrap() + 1;
            deselect_last!();
            should_shift = false;

            while utxo_pool[next_utxo - 1].selection_amount() == utxo_pool[next_utxo].selection_amount() {
                if next_utxo >= n - 1 {
                    should_shift = true;
                    break;
                }
                next_utxo += 1;
            }
        }
    }

    result.selections_evaluated = curr_try;

    if best_selection.is_empty() {
        return Err(if max_tx_weight_exceeded {
            SelectionError::MaxWeightExceeded
        } else {
            SelectionError::InsufficientFunds
        });
    }
    for &i in &best_selection {
        result.add_input(&utxo_pool[i]);
    }
    Ok(result)
}

/// Spike-level stand-in for Core's `ChooseSelectionResult`: run BnB, and CoinGrinder when
/// the feerate is high (Core: `effective_feerate > 3 * long_term_feerate`), recompute waste
/// for each and keep the least wasteful (Core breaks waste ties by preferring more inputs;
/// ported here as well). Knapsack/SRD are not ported in the spike.
pub struct ChooseParams {
    pub effective_feerate: FeeRate,
    pub long_term_feerate: FeeRate,
    pub cost_of_change: CAmount,
    pub min_change_target: CAmount,
    pub min_viable_change: CAmount,
    pub change_fee: CAmount,
    pub max_selection_weight: i32,
}

pub fn choose(
    pool: &[OutputGroup],
    selection_target: CAmount,
    p: &ChooseParams,
) -> Result<SelectionResult, SelectionError> {
    let positive: Vec<OutputGroup> =
        pool.iter().filter(|g| g.selection_amount() > 0).cloned().collect();
    let mut results = vec![];
    let mut errors = vec![];
    match select_coins_bnb(&mut positive.clone(), selection_target, p.cost_of_change, p.max_selection_weight) {
        Ok(r) => results.push(r),
        Err(e) => errors.push(e),
    }
    if p.effective_feerate.0 > 3 * p.long_term_feerate.0 {
        match coin_grinder(&mut positive.clone(), selection_target, p.min_change_target, p.max_selection_weight) {
            Ok(r) => results.push(r),
            Err(e) => errors.push(e),
        }
    }
    for r in results.iter_mut() {
        r.recalculate_waste(p.min_viable_change, p.cost_of_change, p.change_fee);
    }
    results
        .into_iter()
        .min_by(|a, b| a.waste.cmp(&b.waste).then_with(|| b.inputs.len().cmp(&a.inputs.len())))
        .ok_or_else(|| {
            if errors.contains(&SelectionError::MaxWeightExceeded) {
                SelectionError::MaxWeightExceeded
            } else {
                SelectionError::InsufficientFunds
            }
        })
}
