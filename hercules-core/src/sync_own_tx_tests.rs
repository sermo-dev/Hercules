//! Ticket 033: own-transaction submission, tracking, rebroadcast and relay.
//!
//! Transactions here spend `OP_TRUE` outputs seeded straight into the UTXO
//! set, so they pass real libbitcoinconsensus script verification without
//! signatures, and pay to P2WPKH so they are network-standard.

use super::*;
use crate::own_tx_store::{OwnTxStatus, SubmitError};
use crate::p2p::tests::{loopback_peer_pair, read_one_message, write_message};
use crate::utxo::UtxoEntry;
use bitcoin::absolute::LockTime;
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, WPubkeyHash, Witness};
use tempfile::TempDir;

const OP_TRUE: u8 = 0x51;
const VALIDATED: u32 = 200;

fn fresh(dir: &TempDir) -> HeaderSync {
    let db = dir.path().join("headers.sqlite3");
    let hs = HeaderSync::new(db.to_str().unwrap(), None).unwrap();
    hs.store.set_validated_height(VALIDATED).unwrap();
    hs
}

fn seed(hs: &HeaderSync, id: u8, script: u8, height: u32, coinbase: bool) -> OutPoint {
    let txid = Txid::from_byte_array([id; 32]);
    hs.utxo
        .test_insert_utxo(
            txid.to_byte_array(),
            0,
            UtxoEntry {
                amount: 100_000,
                script_pubkey: vec![script],
                height,
                is_coinbase: coinbase,
            },
        )
        .unwrap();
    OutPoint { txid, vout: 0 }
}

fn spend(prev: OutPoint, out_value: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_value),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([1; 20])),
        }],
    }
}

fn raw(tx: &Transaction) -> Vec<u8> {
    bitcoin::consensus::serialize(tx)
}

fn block_with(txs: Vec<Transaction>) -> bitcoin::Block {
    let mut b = crate::p2p::tests::synthetic_block(7);
    b.txdata.extend(txs);
    b
}

/// Pop the own-tx entries currently queued for relay.
fn queued_own(hs: &HeaderSync) -> Vec<Txid> {
    hs.relay_queue
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.from_peer.is_none())
        .map(|e| e.txid)
        .collect()
}

#[test]
fn accepted_own_tx_is_tracked_and_queued_for_immediate_relay() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);

    let receipt = hs.submit_own_tx(&raw(&tx)).unwrap();
    assert_eq!(receipt.txid, tx.compute_txid());
    assert!(receipt.warnings.is_empty());
    assert!(hs.mempool.lock().unwrap().contains(&receipt.txid));

    // Immediate (not Poisson) and not attributed to any peer.
    let queue = hs.relay_queue.lock().unwrap();
    assert_eq!(queue.len(), 1);
    assert!(queue[0].from_peer.is_none());
    assert!(queue[0].relay_at <= Instant::now());
    drop(queue);

    let rec = hs.own_tx_status(&receipt.txid).unwrap().unwrap();
    assert_eq!(rec.status, OwnTxStatus::Pending);
    assert_eq!(rec.attempts, 1);
}

#[test]
fn resubmission_is_already_known_but_still_tracked() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let txid = tx.compute_txid();
    // Arrives from a peer first (not tracked), then the user submits it.
    hs.handle_tx("1.2.3.4:8333", tx.clone()).unwrap();
    assert!(hs.own_tx_status(&txid).unwrap().is_none());

    assert_eq!(
        hs.submit_own_tx(&raw(&tx)).unwrap_err(),
        SubmitError::AlreadyKnown { txid }
    );
    assert!(hs.own_txs.is_active(&txid));
    assert_eq!(queued_own(&hs), vec![txid], "re-announced");
}

#[test]
fn consensus_rejects_are_classified() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);

    // OP_FALSE output: script verification fails.
    let bad_script = spend(seed(&hs, 1, 0x00, 1, false), 90_000);
    assert!(matches!(
        hs.submit_own_tx(&raw(&bad_script)),
        Err(SubmitError::Consensus(_))
    ));

    // Unknown input (UTXO set caught up to headers): consensus.
    let missing = spend(OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 }, 90_000);
    assert!(matches!(hs.submit_own_tx(&raw(&missing)), Err(SubmitError::Consensus(_))));

    // Outputs exceed inputs.
    let inflate = spend(seed(&hs, 2, OP_TRUE, 1, false), 200_000);
    assert!(matches!(hs.submit_own_tx(&raw(&inflate)), Err(SubmitError::Consensus(_))));

    // Garbage bytes.
    assert!(matches!(hs.submit_own_tx(&[0xde, 0xad]), Err(SubmitError::Decode(_))));

    // Standardness / fee rejects are distinct from consensus.
    let dust = spend(seed(&hs, 3, OP_TRUE, 1, false), 100);
    assert!(matches!(hs.submit_own_tx(&raw(&dust)), Err(SubmitError::NonStandard(_))));
    let no_fee = spend(seed(&hs, 4, OP_TRUE, 1, false), 100_000);
    assert!(matches!(hs.submit_own_tx(&raw(&no_fee)), Err(SubmitError::FeeTooLow { .. })));

    assert!(hs.list_own_txs().unwrap().is_empty(), "rejects are not tracked");
    assert!(queued_own(&hs).is_empty());
}

#[test]
fn not_synced_without_utxo_set() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    hs.store.set_validated_height(0).unwrap();
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    assert!(matches!(
        hs.submit_own_tx(&raw(&tx)),
        Err(SubmitError::NotSynced { .. })
    ));
}

#[test]
fn coinbase_maturity_uses_validated_height_not_header_tip() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    // Headers reach 300, the UTXO set only 150. A coinbase from height 100
    // is mature at the header tip (300) but not at validated height (150).
    let headers: Vec<Header> = {
        let mut prev = genesis_header().block_hash();
        (1..=300u32)
            .map(|i| {
                let h = Header {
                    version: bitcoin::block::Version::ONE,
                    prev_blockhash: prev,
                    merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                    time: 1_231_006_505 + i * 600,
                    bits: bitcoin::pow::CompactTarget::from_consensus(0x207fffff),
                    nonce: i,
                };
                prev = h.block_hash();
                h
            })
            .collect()
    };
    hs.store.store_headers(&headers, 1).unwrap();
    hs.store.set_validated_height(150).unwrap();

    let tx = spend(seed(&hs, 1, OP_TRUE, 100, true), 90_000);
    match hs.submit_own_tx(&raw(&tx)) {
        Err(SubmitError::Consensus(msg)) => assert!(msg.contains("immature coinbase"), "{}", msg),
        other => panic!("expected consensus reject, got {:?}", other),
    }

    // While lagging, an input we haven't validated yet is NotSynced.
    let unknown = spend(OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 }, 90_000);
    assert!(matches!(
        hs.submit_own_tx(&raw(&unknown)),
        Err(SubmitError::NotSynced { validated_height: 150, tip_height: 300 })
    ));
}

#[test]
fn local_relay_policy_does_not_block_own_tx() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let mut tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(PushBytesBuf::try_from(vec![0xab; 200]).unwrap()),
    });

    // From a peer, our 018 policy rejects it...
    let mut other = Mempool::new();
    assert!(matches!(
        other.accept_tx(tx.clone(), &hs.utxo, VALIDATED),
        Err(crate::mempool::MempoolError::NonStandardScript { index: 1 })
    ));
    hs.handle_tx("1.2.3.4:8333", tx.clone()).unwrap();
    assert!(!hs.mempool.lock().unwrap().contains(&tx.compute_txid()));

    // ...as the user's own tx it is accepted, with a warning, and queued.
    let receipt = hs.submit_own_tx(&raw(&tx)).unwrap();
    assert_eq!(receipt.warnings.len(), 1, "{:?}", receipt.warnings);
    assert_eq!(queued_own(&hs), vec![receipt.txid]);
}

#[test]
fn own_rbf_marks_original_replaced() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let prev = seed(&hs, 1, OP_TRUE, 1, false);
    let a = hs.submit_own_tx(&raw(&spend(prev, 95_000))).unwrap().txid;
    let b = hs.submit_own_tx(&raw(&spend(prev, 90_000))).unwrap().txid;
    assert_eq!(
        hs.own_tx_status(&a).unwrap().unwrap().status,
        OwnTxStatus::Replaced { by: b }
    );
    assert!(hs.own_txs.is_active(&b));

    // A replacement that doesn't pay enough is a Conflict naming `b`.
    match hs.submit_own_tx(&raw(&spend(prev, 89_990))) {
        Err(SubmitError::Conflict { conflicts, .. }) => assert_eq!(conflicts, vec![b]),
        other => panic!("expected conflict, got {:?}", other),
    }
}

#[test]
fn tracking_survives_restart_and_is_rebroadcast() {
    let dir = TempDir::new().unwrap();
    let txid = {
        let hs = fresh(&dir);
        let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
        hs.submit_own_tx(&raw(&tx)).unwrap().txid
    }; // app killed: mempool and relay queue gone

    let hs = fresh(&dir);
    assert!(!hs.mempool.lock().unwrap().contains(&txid));
    assert!(hs.own_txs.is_active(&txid));
    assert_eq!(hs.list_own_txs().unwrap().len(), 1);

    hs.begin_own_tx_session();
    assert!(hs.mempool.lock().unwrap().contains(&txid), "re-added to mempool");
    assert_eq!(queued_own(&hs), vec![txid], "re-announced");
    let rec = hs.own_tx_status(&txid).unwrap().unwrap();
    assert_eq!(rec.attempts, 2);

    // Not due again until the backoff elapses.
    hs.relay_queue.lock().unwrap().clear();
    let now = unix_now_u32() as u64;
    hs.rebroadcast_due_own_txs(now);
    assert!(queued_own(&hs).is_empty());
    hs.rebroadcast_due_own_txs(now + crate::own_tx_store::REBROADCAST_MAX_SECS);
    assert_eq!(queued_own(&hs), vec![txid]);
}

#[test]
fn confirmation_stops_tracking_and_conflict_drops() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;
    let tx2 = spend(seed(&hs, 2, OP_TRUE, 1, false), 90_000);
    let txid2 = hs.submit_own_tx(&raw(&tx2)).unwrap().txid;

    // Block confirms tx, and a different spend of tx2's input.
    let double_spend = spend(tx2.input[0].previous_output, 80_000);
    hs.on_block_connected(&block_with(vec![tx.clone(), double_spend.clone()]), VALIDATED + 1);

    assert!(!hs.mempool.lock().unwrap().contains(&txid));
    assert!(!hs.mempool.lock().unwrap().contains(&txid2));
    assert_eq!(
        hs.own_tx_status(&txid).unwrap().unwrap().status,
        OwnTxStatus::Confirmed { height: VALIDATED + 1 }
    );
    assert_eq!(
        hs.own_tx_status(&txid2).unwrap().unwrap().status,
        OwnTxStatus::Conflicted { by: double_spend.compute_txid() }
    );
    assert!(!hs.own_txs.is_active(&txid));
    hs.relay_queue.lock().unwrap().clear();
    hs.rebroadcast_due_own_txs(unix_now_u32() as u64 + 100_000);
    assert!(queued_own(&hs).is_empty(), "no rebroadcast after confirmation");

    // Reorg below the confirmation: back to pending.
    hs.own_txs.demote_confirmed_above(VALIDATED, unix_now_u32() as u64).unwrap();
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Pending);
}

#[test]
fn broadcast_sends_inv_then_tx_to_peer() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);

    let mut pool = PeerPool::new_for_test();
    let (peer, mut server) = loopback_peer_pair();
    assert!(pool.add_inbound_peer(peer));

    // The 014 wallet RPC path.
    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;
    let started = Instant::now();
    hs.drain_relay_queue(&pool);

    match read_one_message(&mut server) {
        NetworkMessage::Inv(inv) => assert_eq!(inv, vec![Inventory::Transaction(txid)]),
        other => panic!("expected inv, got {}", msg_name(&other)),
    }
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(hs.relay_queue.lock().unwrap().is_empty());

    // Peer asks for it; we serve the transaction.
    write_message(&mut server, NetworkMessage::GetData(vec![Inventory::WitnessTransaction(txid)]));
    hs.service_peer_messages(&mut pool);
    match read_one_message(&mut server) {
        NetworkMessage::Tx(got) => assert_eq!(got.compute_txid(), txid),
        other => panic!("expected tx, got {}", msg_name(&other)),
    }

    // Another peer announcing it back counts as propagation.
    write_message(&mut server, NetworkMessage::Inv(vec![Inventory::Transaction(txid)]));
    hs.service_peer_messages(&mut pool);
    let rec = hs.own_tx_status(&txid).unwrap().unwrap();
    assert_eq!(rec.status, OwnTxStatus::Propagated);
    assert_eq!(rec.seen_from_peers, 1);
}

#[test]
fn private_broadcast_hook_replaces_peer_announcement() {
    struct Recorder(Mutex<Vec<Txid>>);
    impl crate::own_tx_store::PrivateBroadcast for Recorder {
        fn broadcast(&self, tx: &Transaction) -> Result<usize, String> {
            self.0.lock().unwrap().push(tx.compute_txid());
            Ok(2)
        }
    }
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let rec = Arc::new(Recorder(Mutex::new(Vec::new())));
    hs.set_private_broadcast(Some(rec.clone()));
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;
    assert_eq!(*rec.0.lock().unwrap(), vec![txid]);
    assert!(queued_own(&hs).is_empty(), "not announced on regular peers");
}
