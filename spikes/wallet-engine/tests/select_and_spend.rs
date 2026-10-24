//! Glue check: ported Core coin selection feeding the miniscript/rust-bitcoin spend path.
//! Input sizes come from the descriptors (`max_weight_to_satisfy`), the selected coins are
//! spent, and the result must meet the target feerate and verify under libbitcoinconsensus.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};
use wallet_engine_spike::coinselection::*;
use wallet_engine_spike::keys::{master_from_mnemonic, Account, Purpose};
use wallet_engine_spike::spend::*;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn run(values: &[u64], payment_sats: u64, feerate: CAmount, purpose: Purpose) -> (SelectionResult, bitcoin::Transaction, Vec<TxOut>) {
    let secp = Secp256k1::new();
    let master = master_from_mnemonic(MNEMONIC, "", Network::Bitcoin);
    let acct = Account::new(&secp, master, purpose, 0);
    let coins: Vec<OwnedCoin> = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let d = acct.at(0, i as u32);
            OwnedCoin {
                outpoint: OutPoint { txid: Txid::from_byte_array([i as u8 + 1; 32]), vout: 0 },
                txout: TxOut { value: Amount::from_sat(v), script_pubkey: d.script_pubkey() },
                descriptor: d,
                parent_tx: None,
            }
        })
        .collect();

    let eff = FeeRate(feerate);
    let ltfre = FeeRate(10_000);
    let change_desc = acct.at(1, 0);
    let change_out_vsize = TxOut { value: Amount::ZERO, script_pubkey: change_desc.script_pubkey() }.size() as i32;
    let change_spend_vsize = (utxo_weight(&change_desc) + 3) / 4;
    let change_fee = eff.get_fee(change_out_vsize);
    let min_viable_change = FeeRate(3000).get_fee(change_spend_vsize);
    let cost_of_change = min_viable_change + change_fee;

    let payment = TxOut { value: Amount::from_sat(payment_sats), script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([9; 20])) };
    // Core's tx_noinputs_size: version+locktime+counts (10) + segwit marker/flag (rounded) + outputs
    let tx_noinputs_size = 11 + payment.size() as i32;
    let selection_target = payment_sats as CAmount + eff.get_fee(tx_noinputs_size);

    let pool: Vec<OutputGroup> = coins
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut g = OutputGroup::new(ltfre, false);
            let vbytes = c.max_input_weight().div_ceil(4) as i32;
            g.insert(COutput::with_feerate(i, c.txout.value.to_sat() as CAmount, vbytes, eff));
            g
        })
        .collect();
    let params = ChooseParams {
        effective_feerate: eff,
        long_term_feerate: ltfre,
        cost_of_change,
        min_change_target: CHANGE_LOWER,
        min_viable_change,
        change_fee,
        max_selection_weight: MAX_STANDARD_TX_WEIGHT,
    };
    let sel = choose(&pool, selection_target, &params).expect("selection");
    let chosen: Vec<OwnedCoin> = sel.inputs.iter().map(|c| coins[c.id].clone()).collect();
    let change = sel.get_change(min_viable_change, change_fee);
    let mut psbt = build_psbt(
        &chosen,
        &[payment],
        (change > 0).then(|| (Amount::from_sat(change as u64), &change_desc)),
    )
    .unwrap();
    sign(&mut psbt, &master, &secp).unwrap();
    let tx = finalize_and_extract(psbt, &secp).unwrap();
    let prevouts: Vec<TxOut> = chosen.iter().map(|c| c.txout.clone()).collect();
    common::verify_tx(&tx, &prevouts).unwrap();

    let fee = prevouts.iter().map(|p| p.value.to_sat()).sum::<u64>() - tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
    let vsize = tx.vsize() as u64;
    assert!(fee * 1000 >= feerate as u64 * vsize, "fee {fee} sat for {vsize} vB below {feerate} s/kvB");
    eprintln!("{:?} {:?}: {} in, change {change}, fee {fee} sat / {vsize} vB = {:.3} s/vB (target {:.3})",
        purpose, sel.algo, tx.input.len(), fee as f64 / vsize as f64, feerate as f64 / 1000.0);
    (sel, tx, prevouts)
}

fn utxo_weight(d: &miniscript::Descriptor<miniscript::DefiniteDescriptorKey>) -> i32 {
    OwnedCoin {
        outpoint: OutPoint::null(),
        txout: TxOut { value: Amount::ZERO, script_pubkey: d.script_pubkey() },
        descriptor: d.clone(),
        parent_tx: None,
    }
    .max_input_weight() as i32
}

#[test]
fn bnb_changeless_spend_p2wpkh() {
    // Two coins sum to just above payment + fees: BnB should find a changeless solution.
    let (sel, tx, _) = run(&[30_000, 50_000, 120_000, 71_000, 9_000], 100_000, 5_000, Purpose::Bip84);
    assert_eq!(sel.algo, SelectionAlgorithm::Bnb);
    assert_eq!(tx.output.len(), 1, "changeless");
}

#[test]
fn coingrinder_with_change_at_high_feerate_p2tr() {
    // 60 s/vB > 3x LTFRE: CoinGrinder runs; no changeless window exists, so it wins.
    let (sel, tx, _) = run(&[400_000, 250_000, 260_000, 1_000_000, 90_000], 600_000, 60_000, Purpose::Bip86);
    assert_eq!(sel.algo, SelectionAlgorithm::CoinGrinder);
    assert_eq!(tx.output.len(), 2, "payment + change");
    assert_eq!(tx.input.len(), 1, "min-weight: the single 1M coin");
}
