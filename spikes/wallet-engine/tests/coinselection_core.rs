//! Spike step 5: Bitcoin Core's own coin-selection unit tests, ported 1:1.
//!
//! Source: bitcoin/bitcoin @ a773e1e33b349dc819b5a0edc1c7a4839dc73b48
//!   src/wallet/test/coinselection_tests.cpp: bnb_test, bnb_exhaustion_with_solution_test,
//!                                           bnb_feerate_sensitivity_test
//!   src/wallet/test/coinselector_tests.cpp:  coin_grinder_tests (cases 1-8), waste_test
//!
//! Expected input sets AND expected attempt counts (`GetSelectionsEvaluated()`) are copied
//! verbatim, so these tests check that the port walks the search tree exactly like Core.

use wallet_engine_spike::coinselection::*;

const P2WPKH_INPUT_VSIZE: i32 = 68;
const P2WPKH_OUTPUT_VSIZE: i32 = 31;
const FEERATES: [CAmount; 10] = [0, 1, 99, 100, 315, 1_000, 2_345, 10_292, 59_764, 1_500_000];

// ---------------------------------------------------------------------------------------
// coinselection_tests.cpp fixtures
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct CsParams {
    effective_feerate: FeeRate,
    long_term_feerate: FeeRate,
    change_fee: CAmount,
    min_viable_change: CAmount,
    cost_of_change: CAmount,
}

fn init_cs_params(eff_feerate: CAmount) -> CsParams {
    let effective_feerate = FeeRate(eff_feerate);
    let long_term_feerate = FeeRate(10_000);
    let discard_feerate = FeeRate(3000);
    let change_fee = effective_feerate.get_fee(P2WPKH_OUTPUT_VSIZE);
    let min_viable_change = discard_feerate.get_fee(P2WPKH_INPUT_VSIZE);
    CsParams { effective_feerate, long_term_feerate, change_fee, min_viable_change, cost_of_change: min_viable_change + change_fee }
}

fn default_cs_params() -> CsParams {
    init_cs_params(5000)
}

static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn next_id() -> usize {
    NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// `MakeCoin`: one OutputGroup with a single UTXO whose *effective value* is `amount`.
fn make_coin(amount: CAmount, is_eff_value: bool, cs: CsParams, vsize: i32) -> OutputGroup {
    let fees = cs.effective_feerate.get_fee(vsize);
    let value = amount + if is_eff_value { fees } else { 0 };
    let mut g = OutputGroup::new(cs.long_term_feerate, false);
    g.insert(COutput::with_fee(next_id(), value, vsize, fees));
    g
}

fn add_coins(pool: &mut Vec<OutputGroup>, coins: &[CAmount], cs: CsParams) {
    for &c in coins {
        pool.push(make_coin(c, true, cs, P2WPKH_INPUT_VSIZE));
    }
}

fn add_duplicate_coins(pool: &mut Vec<OutputGroup>, count: usize, amount: CAmount, cs: CsParams) {
    for _ in 0..count {
        pool.push(make_coin(amount, true, cs, P2WPKH_INPUT_VSIZE));
    }
}

fn sorted_values(r: &SelectionResult) -> Vec<CAmount> {
    let mut v: Vec<_> = r.inputs.iter().map(|c| c.value).collect();
    v.sort();
    v
}

#[allow(clippy::too_many_arguments)]
fn test_bnb_success(
    title: &str,
    pool: &mut Vec<OutputGroup>,
    selection_target: CAmount,
    expected_input_amounts: &[CAmount],
    expected_attempts: usize,
    cs: CsParams,
    custom_spending_vsize: i32,
    max_selection_weight: i32,
) {
    let mut expected: Vec<CAmount> = expected_input_amounts
        .iter()
        .map(|&a| make_coin(a, true, cs, custom_spending_vsize).value)
        .collect();
    expected.sort();
    let expected_amount: CAmount = expected.iter().sum();

    let r = select_coins_bnb(pool, selection_target, cs.cost_of_change, max_selection_weight)
        .unwrap_or_else(|e| panic!("Falsy result in BnB-Success: {title} ({e:?}) @feerate {:?}", cs.effective_feerate));
    assert_eq!(sorted_values(&r), expected, "Result mismatch in BnB-Success: {title}");
    assert_eq!(r.selected_value(), expected_amount, "{title}");
    assert!(r.weight <= max_selection_weight, "{title}");
    assert_eq!(r.selections_evaluated, expected_attempts, "Unexpected number of attempts in BnB-Success: {title} @feerate {:?}", cs.effective_feerate);
}

fn bnb_ok(title: &str, pool: &mut Vec<OutputGroup>, target: CAmount, exp: &[CAmount], attempts: usize, cs: CsParams) {
    test_bnb_success(title, pool, target, exp, attempts, cs, P2WPKH_INPUT_VSIZE, MAX_STANDARD_TX_WEIGHT);
}

fn test_bnb_fail(title: &str, pool: &mut Vec<OutputGroup>, target: CAmount, cs: CsParams, max_w: i32, expect_max_weight_exceeded: bool) {
    let r = select_coins_bnb(pool, target, cs.cost_of_change, max_w);
    assert!(r.is_err(), "BnB-Fail: {title}");
    assert_eq!(r.unwrap_err() == SelectionError::MaxWeightExceeded, expect_max_weight_exceeded, "{title}");
}

fn bnb_fail(title: &str, pool: &mut Vec<OutputGroup>, target: CAmount, cs: CsParams) {
    test_bnb_fail(title, pool, target, cs, MAX_STANDARD_TX_WEIGHT, false);
}

#[test]
fn cfeerate_getfee_rounds_up_like_core() {
    // Comments in init_cs_params: 155 sats change_fee and 204 sats min_viable_change at 5 s/vB.
    let cs = default_cs_params();
    assert_eq!(cs.change_fee, 155);
    assert_eq!(cs.min_viable_change, 204);
    assert_eq!(cs.cost_of_change, 359); // "cost_of_change (359 sats)" in the doppelganger comment
    assert_eq!(FeeRate(1).get_fee(31), 1); // EvaluateFeeUp: never rounds a positive fee to 0
    assert_eq!(FeeRate(315).get_fee(68), 22); // 21.42 -> 22
    assert_eq!(FeeRate(-1).get_fee(31), -1);
    assert_eq!(FeeRate(0).get_fee(100), 0);
}

#[test]
fn bnb_test() {
    for feerate in FEERATES {
        let cs = init_cs_params(feerate);
        let mut utxo_pool = vec![];

        bnb_fail("Empty UTXO pool", &mut utxo_pool, CENT, cs);

        add_coins(&mut utxo_pool, &[CENT, 3 * CENT, 5 * CENT], cs);

        // Simple success cases
        bnb_ok("Select smallest UTXO", &mut utxo_pool, CENT, &[CENT], 3, cs);
        bnb_ok("Select middle UTXO", &mut utxo_pool, 3 * CENT, &[3 * CENT], 3, cs);
        bnb_ok("Select biggest UTXO", &mut utxo_pool, 5 * CENT, &[5 * CENT], 2, cs);
        bnb_ok("Select two UTXOs", &mut utxo_pool, 4 * CENT, &[CENT, 3 * CENT], 4, cs);
        bnb_ok("Select all UTXOs", &mut utxo_pool, 9 * CENT, &[CENT, 3 * CENT, 5 * CENT], 5, cs);

        // BnB finds changeless solution while overshooting by up to cost_of_change
        bnb_ok("Select upper bound", &mut utxo_pool, 4 * CENT - cs.cost_of_change, &[CENT, 3 * CENT], 4, cs);
        // ...and fails when overshooting by cost_of_change + 1 sat
        bnb_fail("Overshoot upper bound", &mut utxo_pool, 4 * CENT - cs.cost_of_change - 1, cs);

        test_bnb_success("Select max weight", &mut utxo_pool, 4 * CENT, &[CENT, 3 * CENT], 4, cs, P2WPKH_INPUT_VSIZE, 4 * 2 * P2WPKH_INPUT_VSIZE);
        test_bnb_fail("Exceed max weight", &mut utxo_pool, 4 * CENT, cs, 4 * 2 * P2WPKH_INPUT_VSIZE - 1, true);

        // Simple cases without BnB solution
        bnb_fail("Smallest combination too big", &mut utxo_pool, CENT / 2, cs);
        bnb_fail("No UTXO combination in target window", &mut utxo_pool, 7 * CENT, cs);
        bnb_fail("Select more than available", &mut utxo_pool, 10 * CENT, cs);

        // Skipping of equivalent input sets
        let mut clone_pool = vec![];
        add_coins(&mut clone_pool, &[2 * CENT, 7 * CENT, 7 * CENT], cs);
        add_duplicate_coins(&mut clone_pool, 50_000, 5 * CENT, cs);
        bnb_ok("Skip equivalent input sets", &mut clone_pool, 16 * CENT, &[2 * CENT, 7 * CENT, 7 * CENT], 16, cs);

        // Attempt limit (TOTAL_TRIES): 8 smallest of 17/18 near-identical UTXOs
        let mut doppelganger_pool = vec![];
        let mut doppelgangers = vec![];
        let mut expected_inputs = vec![];
        for i in 0..17 {
            if i < 8 {
                doppelgangers.push(CENT + i);
                expected_inputs.push(CENT + i);
            } else {
                doppelgangers.push(CENT + cs.cost_of_change + i);
            }
        }
        add_coins(&mut doppelganger_pool, &doppelgangers, cs);
        bnb_ok("Combine smallest 8 of 17 unique UTXOs", &mut doppelganger_pool, 8 * CENT, &expected_inputs, 51_765, cs);

        add_coins(&mut doppelganger_pool, &[CENT + cs.cost_of_change + 17], cs);
        bnb_ok("Combine smallest 8 of 18 unique UTXOs", &mut doppelganger_pool, 8 * CENT, &expected_inputs, 87_957, cs);

        add_coins(&mut doppelganger_pool, &[CENT + cs.cost_of_change + 18], cs);
        bnb_fail("Exhaust looking for smallest 8 of 19 unique UTXOs", &mut doppelganger_pool, 8 * CENT, cs);
    }
}

#[test]
fn bnb_exhaustion_with_solution_test() {
    let cs = default_cs_params();
    let selection_target: CAmount = 800_000;
    let mut utxo_pool: Vec<_> = (0..19).map(|i| make_coin(100_000 + i, true, cs, P2WPKH_INPUT_VSIZE)).collect();
    let r = select_coins_bnb(&mut utxo_pool, selection_target, cs.cost_of_change, MAX_STANDARD_TX_WEIGHT)
        .expect("Exhaust with early solution");
    assert!(r.selected_effective_value() > selection_target + 28);
    assert_eq!(r.inputs.len(), 8);
    assert_eq!(r.selections_evaluated, 100_000);
    assert!(!r.algo_completed);
}

#[test]
fn bnb_feerate_sensitivity_test() {
    let cs = default_cs_params();
    let mut low = vec![]; // 5 sat/vB < LTFRE 10 sat/vB
    add_coins(&mut low, &[2 * CENT, 3 * CENT, 5 * CENT, 10 * CENT], cs);
    bnb_ok("Select many inputs at low feerates", &mut low, 10 * CENT, &[2 * CENT, 3 * CENT, 5 * CENT], 6, cs);

    let high_cs = init_cs_params(25_000);
    let mut high = vec![];
    add_coins(&mut high, &[2 * CENT, 3 * CENT, 5 * CENT, 10 * CENT], high_cs);
    bnb_ok("Select one input at high feerates", &mut high, 10 * CENT, &[10 * CENT], 5, high_cs);

    low.push(make_coin(6 * CENT, true, cs, 500));
    low.push(make_coin(7 * CENT, true, cs, 500));
    test_bnb_success("Prefer two heavy inputs over two light inputs at low feerates", &mut low, 13 * CENT, &[6 * CENT, 7 * CENT], 18, cs, 500, MAX_STANDARD_TX_WEIGHT);

    high.push(make_coin(6 * CENT, true, high_cs, 500));
    high.push(make_coin(7 * CENT, true, high_cs, 500));
    bnb_ok("Prefer two light inputs over two heavy inputs at high feerates", &mut high, 13 * CENT, &[3 * CENT, 10 * CENT], 9, high_cs);
}

// ---------------------------------------------------------------------------------------
// coinselector_tests.cpp: coin_grinder_tests
// ---------------------------------------------------------------------------------------

/// `add_coin(available_coins, wallet, nValue, feerate, nAge, fIsFromMe, nInput, spendable,
/// custom_size)`: input_bytes = custom_size, else the max signed size of a fresh BECH32
/// (P2WPKH) address = 68 when spendable, else -1 (unsolvable empty script).
fn cg_coin(value: CAmount, feerate: CAmount, spendable: bool, custom_size: i32) -> COutput {
    let input_bytes = if custom_size != 0 { custom_size } else if spendable { 68 } else { -1 };
    COutput::with_feerate(next_id(), value, input_bytes, FeeRate(feerate))
}

/// Test helper `CoinGrinder(target, cs_params, ...)`: GroupOutputs (no partial-spend
/// avoidance => one group per coin; LTFRE = 2000 s/kvB), keep positive groups, run.
fn run_cg(target: CAmount, min_change_target: CAmount, max_w: i32, coins: Vec<COutput>) -> Result<SelectionResult, SelectionError> {
    let mut groups: Vec<OutputGroup> = coins
        .into_iter()
        .map(|c| {
            let mut g = OutputGroup::new(FeeRate(2000), false);
            g.insert(c);
            g
        })
        .filter(|g| g.selection_amount() > 0)
        .collect();
    coin_grinder(&mut groups, target, min_change_target, max_w)
}

fn cg_expect(r: &SelectionResult, expected: &[CAmount], attempts: usize) {
    let mut e = expected.to_vec();
    e.sort();
    assert_eq!(sorted_values(r), e);
    assert_eq!(r.selections_evaluated, attempts, "Expected {attempts} attempts");
}

#[test]
fn coin_grinder_tests() {
    // 1) Insufficient funds, select all provided coins and fail
    {
        let mut coins = vec![];
        for _ in 0..10 {
            coins.push(cg_coin(COIN, 0, false, 0));
            coins.push(cg_coin(2 * COIN, 0, false, 0));
        }
        let r = run_cg(4_950_000_000, CENT, 10_000, coins);
        assert_eq!(r.unwrap_err(), SelectionError::InsufficientFunds);
    }
    // 2) Max weight exceeded
    {
        let mut coins = vec![];
        for _ in 0..10 {
            coins.push(cg_coin(COIN, 5000, true, 0));
            coins.push(cg_coin(2 * COIN, 5000, true, 0));
        }
        let r = run_cg(2_950_000_000, CENT, 3000, coins);
        assert_eq!(r.unwrap_err(), SelectionError::MaxWeightExceeded);
    }
    // 3) Lowest-weight solution when some combinations would exceed the allowed weight
    {
        let mut coins = vec![];
        for _ in 0..60 {
            coins.push(cg_coin(33_000_000, 5000, true, 0));
        }
        for _ in 0..10 {
            coins.push(cg_coin(2 * COIN, 5000, true, 0));
        }
        let r = run_cg(2_533_000_000, CENT, 10_000, coins).unwrap();
        let mut exp = vec![2 * COIN; 10];
        exp.extend(std::iter::repeat_n(33_000_000, 17));
        cg_expect(&r, &exp, 37);
    }
    // 4) Two less valuable UTXOs with lower combined weight beat one heavier, more valuable UTXO
    {
        let coins = vec![cg_coin(2 * COIN, 5000, true, 148), cg_coin(COIN, 5000, true, 68), cg_coin(COIN, 5000, true, 68)];
        let r = run_cg(190_000_000, CENT, 400_000, coins).unwrap();
        cg_expect(&r, &[COIN, COIN], 3);
    }
    // 5) Mixed weights
    {
        let mut coins = vec![];
        for j in 0..5 {
            coins.push(cg_coin((3 + 3 * j) * COIN, 5000, true, 350));
            coins.push(cg_coin((2 + 3 * j) * COIN, 5000, true, 250));
            coins.push(cg_coin((1 + 3 * j) * COIN, 5000, true, 150));
        }
        let r = run_cg(30 * COIN, CENT, 400_000, coins).unwrap();
        cg_expect(&r, &[14 * COIN, 13 * COIN, 4 * COIN], 92);
    }
    // 6) Lightest solution among many clones
    {
        let mut coins = vec![
            cg_coin(4 * COIN, 5000, true, 100),
            cg_coin(3 * COIN, 5000, true, 100),
            cg_coin(2 * COIN, 5000, true, 100),
            cg_coin(COIN, 5000, true, 100),
        ];
        for (v, w) in [(8, 1000), (7, 800), (6, 600), (5, 400)] {
            for _ in 0..100 {
                coins.push(cg_coin(v * COIN, 5000, true, w));
            }
        }
        let r = run_cg(990_000_000, CENT, 400_000, coins).unwrap();
        cg_expect(&r, &[4 * COIN, 3 * COIN, 2 * COIN, COIN], 38);
    }
    // 7) Lots of tiny UTXOs skipped when too heavy while lookahead has enough funds
    {
        let mut coins = vec![cg_coin(180_000_000, 5000, true, 2500), cg_coin(COIN, 5000, true, 1000), cg_coin(COIN, 5000, true, 1000)];
        for j in 0..100 {
            coins.push(cg_coin(CENT + j, 5000, true, 110));
        }
        let r = run_cg(190_000_000, CENT, 40_000, coins).unwrap();
        cg_expect(&r, &[COIN, COIN], 7);
    }
    // 8) Solution found just before / not found after the attempt limit
    {
        let mk = |n: i64| (0..n).map(|i| cg_coin(COIN + i, 0, true, 96 + i as i32)).collect::<Vec<_>>();
        let a = run_cg(8 * COIN, 0, 3200, mk(18)).unwrap();
        let exp: Vec<CAmount> = (0..8).map(|i| COIN + i).collect();
        cg_expect(&a, &exp, 87_525);
        assert!(run_cg(8 * COIN, 0, 3200, mk(19)).is_err());
    }
}

// ---------------------------------------------------------------------------------------
// coinselector_tests.cpp: waste_test
// ---------------------------------------------------------------------------------------

fn waste_coin(value: CAmount, sel: &mut SelectionResult, fee: CAmount, long_term_fee: CAmount) {
    let mut g = OutputGroup::new(FeeRate(0), false);
    g.insert(COutput::with_fee(next_id(), value, 148, fee));
    g.outputs[0].long_term_fee = long_term_fee; // Insert() overwrites it; set afterwards (as Core's test does)
    sel.add_input(&g);
}

fn waste_of(target: CAmount, fee: CAmount, ltf: CAmount, mvc: CAmount, change_cost: CAmount, change_fee: CAmount) -> CAmount {
    let mut s = SelectionResult::new(target, SelectionAlgorithm::Manual);
    waste_coin(COIN, &mut s, fee, ltf);
    waste_coin(2 * COIN, &mut s, fee, ltf);
    s.recalculate_waste(mvc, change_cost, change_fee);
    s.waste.unwrap()
}

#[test]
fn waste_test() {
    let fee: CAmount = 100;
    let min_viable_change: CAmount = 300;
    let change_cost: CAmount = 125;
    let change_fee: CAmount = 30;
    let fee_diff: CAmount = 40;
    let in_amt: CAmount = 3 * COIN;
    let target: CAmount = 2 * COIN;
    let excess: CAmount = 80;
    let exact_target = in_amt - fee * 2;
    let w = |t, f, l, cc| waste_of(t, f, l, min_viable_change, cc, change_fee);

    // With change: change cost + Σ(fee - ltf)
    let s1 = w(target, fee, fee - fee_diff, change_cost);
    assert_eq!(s1, fee_diff * 2 + change_cost);
    assert!(w(target, fee * 2, fee - fee_diff, change_cost) > s1);
    let s3 = w(target, fee, fee + fee_diff, change_cost);
    assert_eq!(s3, fee_diff * -2 + change_cost);
    assert!(s3 < s1);

    // Without change: excess + Σ(fee - ltf)
    let n1 = w(exact_target - excess, fee, fee - fee_diff, change_cost);
    assert_eq!(n1, fee_diff * 2 + excess);
    let n2 = w(exact_target - excess, fee, fee + fee_diff, change_cost);
    assert_eq!(n2, fee_diff * -2 + excess);
    assert!(n2 < n1);

    assert_eq!(w(target, fee, fee, change_cost), change_cost);
    assert_eq!(w(exact_target - excess, fee, fee, change_cost), excess);
    assert_eq!(w(exact_target, fee, fee, change_cost), 0);
    assert_eq!(w(target, fee, fee + fee_diff, fee_diff * 2), 0);
    assert_eq!(w(exact_target - fee_diff * 2, fee, fee + fee_diff, change_cost), 0);
    assert_eq!(w(exact_target, fee, fee + fee_diff, change_cost), -2 * fee_diff);
    let large_fee_diff = 90;
    assert_eq!(w(target, fee, fee + large_fee_diff, change_cost), -55);
}
