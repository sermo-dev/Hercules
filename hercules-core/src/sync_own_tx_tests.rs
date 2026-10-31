//! Ticket 033: own-transaction submission, tracking, rebroadcast and relay.
//!
//! Transactions here spend `OP_TRUE` outputs seeded straight into the UTXO
//! set, so they pass real (`script_verify`) script verification without
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

/// A node in Tor mode (regular peers over Tor), without a real TorManager.
fn fresh(dir: &TempDir) -> HeaderSync {
    let db = dir.path().join("headers.sqlite3");
    let mut hs = HeaderSync::new(db.to_str().unwrap(), None).unwrap();
    hs.regular_peers_over_tor = true;
    hs.own_tx_trickle_mean_secs = 0.0;
    // Headers up to the validated height, so mempool finality / BIP 68
    // (ticket 026) can read the tip's median-time-past. Contents only
    // need distinct hashes and increasing timestamps.
    let genesis = hs.store.tip().unwrap().unwrap().2;
    let headers: Vec<bitcoin::block::Header> = (1..=VALIDATED)
        .map(|h| bitcoin::block::Header {
            nonce: h,
            time: genesis.time + 600 * h,
            ..genesis
        })
        .collect();
    hs.store.store_headers(&headers, 1).unwrap();
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

/// Ticket 026 review: a timelocked own tx is "not valid yet", not
/// consensus-invalid. It isn't tracked or sent, and once the lock is
/// reached the same bytes are accepted.
#[test]
fn timelocked_own_tx_is_not_yet_final_then_accepted() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);

    let mut tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    tx.input[0].sequence = bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF;
    tx.lock_time = bitcoin::absolute::LockTime::from_consensus(VALIDATED + 1);
    match hs.submit_own_tx(&raw(&tx)) {
        Err(e @ SubmitError::NotYetFinal { .. }) => {
            assert_eq!(e.kind(), "not_yet_final");
            assert!(!e.to_string().contains("consensus"), "{}", e);
        }
        other => panic!("expected NotYetFinal, got {:?}", other),
    }
    assert!(hs.list_own_txs().unwrap().is_empty(), "timelocked tx not tracked");
    assert!(queued_own(&hs).is_empty());

    // One more validated block: nLockTime VALIDATED+1 < next height.
    let genesis = hs.store.tip().unwrap().unwrap().2;
    let next = bitcoin::block::Header { nonce: VALIDATED + 1, time: genesis.time + 600 * (VALIDATED + 1), ..genesis };
    hs.store.store_headers(&[next], VALIDATED + 1).unwrap();
    hs.store.set_validated_height(VALIDATED + 1).unwrap();
    hs.submit_own_tx(&raw(&tx)).expect("final now");
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

/// Regtest-difficulty headers for heights `from..=to` on top of `prev`;
/// `salt` makes a competing branch.
fn headers_on(mut prev: BlockHash, from: u32, to: u32, salt: u32) -> Vec<Header> {
    (from..=to)
        .map(|i| {
            let h = Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1_231_006_505 + i * 600 + salt,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207fffff),
                nonce: i + salt,
            };
            prev = h.block_hash();
            h
        })
        .collect()
}

/// Store headers 1..=`tip` on top of genesis.
/// End to end, from the user and from a peer: a tx spending one coin twice
/// is consensus-invalid (Core `bad-txns-inputs-duplicate`). Before the
/// mempool checked this, it was accepted with the coin counted twice and
/// relayed to peers that discourage the sender for it.
#[test]
fn duplicate_input_tx_is_refused_from_user_and_peers() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let coin = seed(&hs, 1, OP_TRUE, 1, false);
    // Pays more than the coin holds: only "valid" if counted twice.
    let mut tx = spend(coin, 150_000);
    tx.input.push(tx.input[0].clone());
    match hs.submit_own_tx(&raw(&tx)) {
        Err(SubmitError::Consensus(msg)) => assert!(msg.contains("already spends"), "{}", msg),
        other => panic!("expected a consensus reject, got {:?}", other),
    }
    hs.handle_tx("1.2.3.4:8333", tx.clone()).unwrap();
    assert!(!hs.mempool.lock().unwrap().contains(&tx.compute_txid()));
    assert!(hs.list_own_txs().unwrap().is_empty());
    assert!(hs.relay_queue.lock().unwrap().is_empty());
}

/// Own coinbase spends are judged for the next block, as block validation
/// will judge them: with the UTXO set at 200, a coinbase from 101 can be
/// mined in block 201 and is accepted; one from 102 can't yet.
#[test]
fn own_coinbase_spend_is_judged_for_the_next_block() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let immature = spend(seed(&hs, 2, OP_TRUE, VALIDATED - 98, true), 90_000);
    match hs.submit_own_tx(&raw(&immature)) {
        Err(SubmitError::Consensus(msg)) => assert!(msg.contains("immature coinbase"), "{}", msg),
        other => panic!("expected immature, got {:?}", other),
    }
    let mature = spend(seed(&hs, 1, OP_TRUE, VALIDATED - 99, true), 90_000);
    hs.submit_own_tx(&raw(&mature)).expect("spendable in block VALIDATED + 1");
}

fn store_headers_to(hs: &HeaderSync, tip: u32) {
    let headers = headers_on(genesis_header().block_hash(), 1, tip, 0);
    hs.store.store_headers(&headers, 1).unwrap();
}

/// Read one message if the peer sends one within a short wait.
fn try_read(server: &mut std::net::TcpStream) -> Option<NetworkMessage> {
    server.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let mut b = [0u8; 1];
    let got = server.peek(&mut b).map(|n| n > 0).unwrap_or(false);
    server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    got.then(|| read_one_message(server))
}

#[test]
fn coinbase_maturity_uses_validated_height_not_header_tip() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    // Headers reach 300, the UTXO set only 150. A coinbase from height 100
    // is mature at the header tip (300) but not at validated height (150).
    store_headers_to(&hs, 300);
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
        other.accept_tx(tx.clone(), &hs.utxo, VALIDATED, &hs.store),
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
    pool.add_outbound_peer_for_test(peer);

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

    // Ticket 052: the peer we sent it to echoing it back proves nothing
    // (a censoring peer would, to fake delivery); nor does an inbound one.
    write_message(&mut server, NetworkMessage::Inv(vec![Inventory::Transaction(txid)]));
    hs.service_peer_messages(&mut pool);
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Pending, "echo counted");
    let (inbound, mut in_server) = loopback_peer_pair();
    assert!(pool.add_inbound_peer(inbound));
    write_message(&mut in_server, NetworkMessage::Inv(vec![Inventory::Transaction(txid)]));
    hs.service_peer_messages(&mut pool);
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Pending, "inbound counted");

    // Another outbound peer, one we never sent it to, announcing it back
    // counts as propagation.
    let (other, mut other_server) = loopback_peer_pair();
    pool.add_outbound_peer_for_test(other);
    write_message(&mut other_server, NetworkMessage::Inv(vec![Inventory::Transaction(txid)]));
    hs.service_peer_messages(&mut pool);
    let rec = hs.own_tx_status(&txid).unwrap().unwrap();
    assert_eq!(rec.status, OwnTxStatus::Propagated);
    assert_eq!(rec.seen_from_peers, 1);
}

/// Ticket 052's verification: a tx announced by three peers is downloaded
/// once, whether it is then accepted or rejected; a rejected one isn't
/// fetched again until the next block, and a request that runs out (or is
/// answered `notfound`) goes to the next announcer.
#[test]
fn announced_txs_are_downloaded_once() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let mut pool = PeerPool::new_for_test();
    let mut servers = Vec::new();
    for _ in 0..3 {
        let (p, s) = loopback_peer_pair();
        pool.add_outbound_peer_for_test(p);
        servers.push(s);
    }
    let getdatas = |servers: &mut Vec<std::net::TcpStream>| -> Vec<usize> {
        (0..servers.len())
            .filter(|&i| matches!(try_read(&mut servers[i]), Some(NetworkMessage::GetData(_))))
            .collect()
    };

    // Accepted: everyone announces at once, one is asked.
    let good = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let inv = |tx: &Transaction| NetworkMessage::Inv(vec![Inventory::Transaction(tx.compute_txid())]);
    for s in servers.iter_mut() {
        write_message(s, inv(&good));
    }
    hs.service_peer_messages(&mut pool);
    let asked = getdatas(&mut servers);
    assert_eq!(asked.len(), 1, "asked {:?}", asked);
    write_message(&mut servers[asked[0]], NetworkMessage::Tx(good.clone()));
    hs.service_peer_messages(&mut pool);
    assert!(hs.mempool.lock().unwrap().contains(&good.compute_txid()));

    // Rejected (a dust output, decided by what the txid commits to): asked
    // once, then never again from the others.
    let dust = spend(seed(&hs, 2, OP_TRUE, 1, false), 100);
    write_message(&mut servers[0], inv(&dust));
    hs.service_peer_messages(&mut pool);
    assert_eq!(getdatas(&mut servers), vec![0]);
    write_message(&mut servers[0], NetworkMessage::Tx(dust.clone()));
    hs.service_peer_messages(&mut pool);
    assert!(!hs.mempool.lock().unwrap().contains(&dust.compute_txid()));
    for s in servers[1..].iter_mut() {
        write_message(s, inv(&dust));
    }
    hs.service_peer_messages(&mut pool);
    assert!(getdatas(&mut servers).is_empty(), "rejected tx fetched again");

    // A block later the verdict is forgotten (Core resets on a new tip).
    hs.store.set_validated_height(VALIDATED + 1).ok();
    write_message(&mut servers[1], inv(&dust));
    hs.service_peer_messages(&mut pool);
    assert_eq!(getdatas(&mut servers), vec![1]);
    hs.store.set_validated_height(VALIDATED).ok();

    // `notfound` hands the request to the next announcer at once.
    let third = spend(seed(&hs, 3, OP_TRUE, 1, false), 90_000);
    write_message(&mut servers[0], inv(&third));
    hs.service_peer_messages(&mut pool);
    assert_eq!(getdatas(&mut servers), vec![0]);
    write_message(&mut servers[2], inv(&third));
    hs.service_peer_messages(&mut pool);
    assert!(getdatas(&mut servers).is_empty(), "asked a second announcer while in flight");
    write_message(&mut servers[0], NetworkMessage::NotFound(vec![Inventory::WitnessTransaction(third.compute_txid())]));
    hs.service_peer_messages(&mut pool);
    hs.retry_tx_requests(&pool);
    assert_eq!(getdatas(&mut servers), vec![2]);
}

/// Ticket 052's Tor-mode stopgap: an own tx is announced only to outbound
/// peers never told our onion, after a Poisson delay, and served only to
/// those; an inbound peer (it dialed our onion) and a self-advertised one
/// get neither, even after announcing it to us.
#[test]
fn own_tx_never_reaches_onion_aware_peers() {
    let dir = TempDir::new().unwrap();
    let mut hs = fresh(&dir);
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let mut pool = PeerPool::new_for_test();
    let (clean, mut clean_s) = loopback_peer_pair();
    let (advertised, mut adv_s) = loopback_peer_pair();
    let (inbound, mut in_s) = loopback_peer_pair();
    pool.add_outbound_peer_for_test(clean);
    pool.add_self_advertised_peer_for_test(advertised);
    assert!(pool.add_inbound_peer(inbound));

    // The trickle: with Core's 2 s mean nothing is due at once.
    hs.own_tx_trickle_mean_secs = 3600.0;
    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;
    hs.drain_relay_queue(&pool);
    assert!(try_read(&mut clean_s).is_none(), "announced before its delay");
    hs.relay_queue.lock().unwrap().iter_mut().for_each(|e| e.relay_at = Instant::now());
    hs.drain_relay_queue(&pool);
    assert!(matches!(read_one_message(&mut clean_s), NetworkMessage::Inv(_)));
    assert!(try_read(&mut adv_s).is_none(), "own tx announced to a self-advertised peer");
    assert!(try_read(&mut in_s).is_none(), "own tx announced to an inbound peer");

    // They announce it to us (they got it elsewhere) and ask for it: not
    // served, so they can't learn that we have it.
    for s in [&mut adv_s, &mut in_s] {
        write_message(s, NetworkMessage::Inv(vec![Inventory::Transaction(txid)]));
    }
    hs.service_peer_messages(&mut pool);
    for s in [&mut adv_s, &mut in_s] {
        write_message(s, NetworkMessage::GetData(vec![Inventory::WitnessTransaction(txid)]));
    }
    hs.service_peer_messages(&mut pool);
    for s in [&mut adv_s, &mut in_s] {
        assert!(matches!(read_one_message(s), NetworkMessage::NotFound(_)));
    }
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

#[test]
fn clearnet_without_transport_waits_for_private_broadcast() {
    let dir = TempDir::new().unwrap();
    let mut hs = fresh(&dir);
    hs.regular_peers_over_tor = false;
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);

    // Accepted and tracked, but not announced on clearnet peers.
    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;
    assert!(queued_own(&hs).is_empty());
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Pending);
    hs.begin_own_tx_session();
    assert!(queued_own(&hs).is_empty(), "rebroadcast waits too");

    // Once someone else has put it on the network, announcing it on our
    // clearnet peers no longer makes us the source.
    hs.own_txs.record_seen(&txid, "5.6.7.8:8333", unix_now_u32() as u64).unwrap();
    hs.rebroadcast_due_own_txs(unix_now_u32() as u64 + 2 * 24 * 3600);
    assert_eq!(queued_own(&hs), vec![txid]);
}

#[test]
fn announced_and_announcing_peers_are_not_reannounced_to() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let mut pool = PeerPool::new_for_test();
    let (p1, mut s1) = loopback_peer_pair();
    let (p2, mut s2) = loopback_peer_pair();
    let (a1, a2) = (p1.addr().to_string(), p2.addr().to_string());
    pool.add_outbound_peer_for_test(p1);
    pool.add_outbound_peer_for_test(p2);

    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;
    hs.drain_relay_queue(&pool);
    for s in [&mut s1, &mut s2] {
        assert!(matches!(read_one_message(s), NetworkMessage::Inv(_)));
    }
    {
        let state = hs.relay_state.lock().unwrap();
        for a in [&a1, &a2] {
            assert!(state[a].known_txids.contains(&txid), "sent inv recorded for {}", a);
            assert!(state[a].own_txids.contains(&txid));
        }
    }

    // A rebroadcast goes only to peers that don't have it: a new peer.
    let (p3, mut s3) = loopback_peer_pair();
    pool.add_outbound_peer_for_test(p3);
    hs.rebroadcast_due_own_txs(unix_now_u32() as u64 + crate::own_tx_store::REBROADCAST_MAX_SECS);
    assert_eq!(queued_own(&hs), vec![txid]);
    hs.drain_relay_queue(&pool);
    assert!(matches!(read_one_message(&mut s3), NetworkMessage::Inv(_)));
    assert!(try_read(&mut s1).is_none(), "p1 already knows it");
    assert!(try_read(&mut s2).is_none(), "p2 already knows it");

    // A peer announcing a tx we already have is recorded too.
    let other = spend(seed(&hs, 2, OP_TRUE, 1, false), 90_000);
    let other_id = other.compute_txid();
    hs.handle_tx("9.9.9.9:8333", other).unwrap();
    write_message(&mut s1, NetworkMessage::Inv(vec![Inventory::Transaction(other_id)]));
    hs.service_peer_messages(&mut pool);
    assert!(hs.relay_state.lock().unwrap()[&a1].known_txids.contains(&other_id));
    assert!(try_read(&mut s1).is_none(), "no getdata for a tx we have");
}

#[test]
fn pending_own_tx_is_hidden_from_unsolicited_getdata() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let mut pool = PeerPool::new_for_test();
    let (peer, mut server) = loopback_peer_pair();
    let addr = peer.addr().to_string();
    pool.add_outbound_peer_for_test(peer);

    let own = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let txid = hs.submit_own_tx(&raw(&own)).unwrap().txid;
    // Not drained: this peer has not been told about it.
    let getdata = || NetworkMessage::GetData(vec![Inventory::WitnessTransaction(txid)]);
    write_message(&mut server, getdata());
    hs.service_peer_messages(&mut pool);
    assert!(matches!(read_one_message(&mut server), NetworkMessage::NotFound(_)));

    // Propagated (someone else announced it), but neither to nor by this
    // peer: asking is still a probe.
    hs.own_txs.record_seen(&txid, "5.6.7.8:8333", unix_now_u32() as u64).unwrap();
    write_message(&mut server, getdata());
    hs.service_peer_messages(&mut pool);
    assert!(matches!(read_one_message(&mut server), NetworkMessage::NotFound(_)));

    // Once it has announced the tx to us, it may fetch it.
    write_message(&mut server, NetworkMessage::Inv(vec![Inventory::Transaction(txid)]));
    hs.service_peer_messages(&mut pool);
    assert!(hs.peer_knows_own_tx(&addr, &txid));
    write_message(&mut server, getdata());
    hs.service_peer_messages(&mut pool);
    assert!(matches!(read_one_message(&mut server), NetworkMessage::Tx(_)));
}

#[test]
fn mempool_request_disconnects_like_a_default_core_node() {
    // Ticket 049: BIP 35 `mempool` is answered as Core answers it without
    // NODE_BLOOM (which we never advertise): a disconnect, never a list
    // (which would also put our own txs in front of a probe).
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let relayed = spend(seed(&hs, 2, OP_TRUE, 1, false), 90_000);
    hs.handle_tx("9.9.9.9:8333", relayed).unwrap();
    let mut pool = PeerPool::new_for_test();
    let (peer, mut server) = loopback_peer_pair();
    assert!(pool.add_inbound_peer(peer));

    write_message(&mut server, NetworkMessage::MemPool);
    hs.service_peer_messages(&mut pool);
    assert_eq!(pool.count(), 0, "peer asking for our mempool still connected");
    assert!(try_read(&mut server).is_none(), "mempool answered");
}

#[test]
fn expiry_waits_until_utxo_set_catches_up() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    store_headers_to(&hs, 300);
    hs.store.set_validated_height(150).unwrap();
    let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;

    // Long past expiry, but blocks 151..300 may confirm it.
    let later = unix_now_u32() as u64 + crate::own_tx_store::PENDING_EXPIRY_SECS + 10;
    hs.rebroadcast_due_own_txs(later);
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Pending);

    hs.store.set_validated_height(300).unwrap();
    hs.rebroadcast_due_own_txs(later);
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Expired);
}

#[test]
fn replaced_original_confirming_conflicts_the_replacement() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    let prev = seed(&hs, 1, OP_TRUE, 1, false);
    let a_tx = spend(prev, 95_000);
    let a = hs.submit_own_tx(&raw(&a_tx)).unwrap().txid;
    let b = hs.submit_own_tx(&raw(&spend(prev, 90_000))).unwrap().txid;
    assert_eq!(hs.own_tx_status(&a).unwrap().unwrap().status, OwnTxStatus::Replaced { by: b });

    hs.on_block_connected(&block_with(vec![a_tx]), VALIDATED + 1);
    assert_eq!(
        hs.own_tx_status(&a).unwrap().unwrap().status,
        OwnTxStatus::Confirmed { height: VALIDATED + 1 }
    );
    assert_eq!(hs.own_tx_status(&b).unwrap().unwrap().status, OwnTxStatus::Conflicted { by: a });
    assert!(!hs.own_txs.is_active(&b));
}

#[test]
fn open_undoes_settlements_above_validated_height() {
    // Crash after a block hook ran (or mid-reorg) but before the validated
    // height moved: on reopen the tx is unsettled, ready to be settled
    // again when the block is re-applied.
    let dir = TempDir::new().unwrap();
    let tx = {
        let hs = fresh(&dir);
        let tx = spend(seed(&hs, 1, OP_TRUE, 1, false), 90_000);
        hs.submit_own_tx(&raw(&tx)).unwrap();
        hs.on_block_connected(&block_with(vec![tx.clone()]), VALIDATED + 1);
        // ...crash here, before set_validated_height(VALIDATED + 1).
        tx
    };
    let txid = tx.compute_txid();
    let hs = fresh(&dir);
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Pending);
    // Re-applying the block (crash-recovery path) settles it again.
    hs.on_block_connected(&block_with(vec![tx]), VALIDATED + 1);
    hs.store.set_validated_height(VALIDATED + 1).unwrap();
    drop(hs);
    // Opened with the validated height caught up: left alone.
    let hs = fresh(&dir);
    assert_eq!(
        hs.own_tx_status(&txid).unwrap().unwrap().status,
        OwnTxStatus::Confirmed { height: VALIDATED + 1 }
    );
}

#[test]
fn reorg_path_unsettles_and_rebroadcasts_own_tx() {
    let dir = TempDir::new().unwrap();
    let hs = fresh(&dir);
    store_headers_to(&hs, VALIDATED + 1);
    let prev = seed(&hs, 1, OP_TRUE, 1, false);
    let tx = spend(prev, 90_000);
    let txid = hs.submit_own_tx(&raw(&tx)).unwrap().txid;

    // Block VALIDATED+1 confirms it, through the same steps the sync loop
    // takes (UTXO apply, block hook, validated height).
    let block = block_with(vec![tx]);
    hs.utxo.apply_block(&block, VALIDATED + 1).unwrap();
    hs.on_block_connected(&block, VALIDATED + 1);
    hs.store.set_validated_height(VALIDATED + 1).unwrap();
    assert_eq!(
        hs.own_tx_status(&txid).unwrap().unwrap().status,
        OwnTxStatus::Confirmed { height: VALIDATED + 1 }
    );
    assert!(hs.utxo.get(&prev.txid, prev.vout).unwrap().is_none());

    // A heavier branch from VALIDATED replaces that block.
    let fork_hash = hs.store.get_hash_at_height(VALIDATED).unwrap().unwrap();
    let branch = headers_on(fork_hash, VALIDATED + 1, VALIDATED + 2, 7);
    let (new_tip, new_validated) = hs.apply_reorg(VALIDATED, &branch).unwrap();
    assert_eq!((new_tip, new_validated), (VALIDATED + 2, VALIDATED));
    assert!(hs.utxo.get(&prev.txid, prev.vout).unwrap().is_some(), "input unspent again");
    assert_eq!(hs.own_tx_status(&txid).unwrap().unwrap().status, OwnTxStatus::Pending);

    // The next rebroadcast puts it back in the mempool and announces it.
    hs.relay_queue.lock().unwrap().clear();
    hs.rebroadcast_due_own_txs(unix_now_u32() as u64);
    assert!(hs.mempool.lock().unwrap().contains(&txid));
    assert_eq!(queued_own(&hs), vec![txid]);
}
