//! Ticket 054: a wake doesn't take one peer's word for the tip, and doesn't
//! run before the node is set up. Against the real `HeaderSync` and mock
//! peers.
//!
//! Mounted as `sync::wake_agreement_tests`, beside `integration_tests`,
//! whose harness (`Node`, `presync`) it reuses.

use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;

use super::integration_tests::{presync, Node};
use super::*;
use crate::testkit::{Behavior, FixtureChain, MockPeer};

/// A fresh peer's reputation (`SCORE_DEFAULT`).
const FRESH_SCORE: i32 = 100;

fn chain(n: u32) -> FixtureChain {
    let mut c = FixtureChain::new();
    c.mine(n);
    c
}

/// Give `addr` a persisted reputation below a fresh peer's, so a wake asks
/// the fresh peers first (`wake_header_peer` ranks by weight).
fn demote(node: &Node, addr: &str, score: i32) {
    node.peer_store().save_score(addr, score).unwrap();
}

// ── The agreement rule ───────────────────────────────────────────────

#[test]
fn tip_needs_two_peers_or_one_on_a_recent_tip_with_min_work() {
    let now = 2_000_000_000;
    let recent = now - WAKE_RECENT_TIP_SECS;
    let stale = now - WAKE_RECENT_TIP_SECS - 1;
    assert!(wake_tip_confirmed(2, false, stale, now), "two independent peers always do");
    assert!(wake_tip_confirmed(3, false, 0, now));
    assert!(wake_tip_confirmed(1, true, recent, now));
    assert!(wake_tip_confirmed(1, true, now + 3_600, now), "a tip ahead of our clock is recent");
    assert!(!wake_tip_confirmed(1, true, stale, now), "one peer on an old tip");
    assert!(!wake_tip_confirmed(1, false, recent, now), "one peer below minimum work");
    assert!(!wake_tip_confirmed(0, true, now, now), "nobody vouched for it");
}

#[test]
fn block_share_leaves_time_for_another_peer_unless_none_is_left() {
    let s = Duration::from_secs;
    assert_eq!(wake_block_share(s(20), 3), s(10));
    assert_eq!(wake_block_share(s(20), 2), s(10));
    assert_eq!(wake_block_share(s(8), 2), WAKE_BLOCK_MIN_SHARE, "never below the floor");
    assert_eq!(wake_block_share(s(3), 2), s(3), "never above what is left");
    assert_eq!(wake_block_share(s(20), 1), s(20), "the last peer gets it all");
    assert_eq!(wake_block_share(s(20), 0), s(20));
}

// ── Withholding and lone peers ───────────────────────────────────────

/// Verification: an inflated-height peer that withholds headers, alone,
/// never gets the wake to say "caught up".
#[test]
fn lone_inflated_withholder_leaves_the_tip_unconfirmed() {
    let c = chain(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &c);
    let liar = MockPeer::spawn(&c, vec![Behavior::WithholdHeaders, Behavior::InflatedHeight(25)]);
    node.use_peers(&[&liar]);

    let status = node.hs.catch_up_blocks(10, 10).unwrap();
    assert!(!status.caught_up, "{:?}", status);
    assert!(!status.tip_confirmed, "{:?}", status);
    assert!(status.error.is_none() && !status.tip_disagreement, "{:?}", status);
    assert_eq!(status.target_height, 20);
}

/// Verification: the withholding peer is asked first, says there's
/// nothing new; the second opinion shows five new headers. They're
/// stored and validated, the withholder loses score, and with only the
/// honest peer vouching for the new tip (on an old fixture chain) the
/// tip stays unconfirmed.
#[test]
fn withholding_peer_is_outvoted_and_charged() {
    let c = chain(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(15));
    let withholder = MockPeer::spawn(&c, vec![Behavior::WithholdHeaders]);
    let honest = MockPeer::spawn(&c, vec![]);
    demote(&node, &honest.addr(), 80);
    node.use_peers(&[&withholder, &honest]);

    let status = node.hs.catch_up_blocks(10, 15).unwrap();
    assert_eq!(status.target_height, 20, "{:?}", status);
    assert_eq!(status.blocks_validated, 5, "{:?}", status);
    assert!(!status.tip_confirmed && !status.caught_up, "{:?}", status);
    let score = node.score(&withholder.addr()).expect("score persisted");
    assert!(score < FRESH_SCORE, "withholder not charged: {}", score);
    assert!(!node.is_banned(&withholder.addr()));
    assert!(node.score(&honest.addr()).unwrap() >= 80);
}

/// With a third (honest) peer the new tip gets its second opinion.
#[test]
fn withheld_headers_found_and_confirmed_by_two_peers() {
    let c = chain(20);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(15));
    let withholder = MockPeer::spawn(&c, vec![Behavior::WithholdHeaders]);
    let (a, b) = (MockPeer::spawn(&c, vec![]), MockPeer::spawn(&c, vec![]));
    demote(&node, &a.addr(), 80);
    demote(&node, &b.addr(), 80);
    node.use_peers(&[&withholder, &a, &b]);

    let status = node.hs.catch_up_blocks(10, 15).unwrap();
    assert!(status.caught_up && status.tip_confirmed, "{:?}", status);
    assert_eq!(node.validated(), 20);
    assert!(node.score(&withholder.addr()).unwrap() < FRESH_SCORE);
}

/// Verification: one honest peer is all the wake finds. Its tip is too
/// old (and, second round, below minimum work) to take on its word.
#[test]
fn single_peer_never_reports_caught_up_on_an_old_or_low_work_tip() {
    let c = chain(12);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(8));
    let only = MockPeer::spawn(&c, vec![]);
    node.use_peers(&[&only]);

    let status = node.hs.catch_up_blocks(10, 10).unwrap();
    assert_eq!(status.blocks_validated, 4, "{:?}", status);
    assert!(!status.caught_up && !status.tip_confirmed, "{:?}", status);

    let headers: Vec<Header> = c.blocks().iter().map(|b| b.header).collect();
    let mut one = [0u8; 32];
    one[0] = 1;
    node.hs.min_chain_work = u256_add(chainwork_for_headers(&headers), one);
    let status = node.hs.catch_up_blocks(10, 10).unwrap();
    assert!(!status.caught_up && !status.tip_confirmed, "{:?}", status);
}

/// Two honest peers that agree there is nothing new: caught up.
#[test]
fn two_peers_agreeing_on_no_news_is_caught_up() {
    let c = chain(10);
    let mut node = Node::new(&[]);
    presync(&mut node, &c);
    let (a, b) = (MockPeer::spawn(&c, vec![]), MockPeer::spawn(&c, vec![]));
    node.use_peers(&[&a, &b]);

    let status = node.hs.catch_up_blocks(10, 10).unwrap();
    assert!(status.caught_up && status.tip_confirmed, "{:?}", status);
    assert_eq!(status.blocks_validated, 0);
}

// ── Retry ────────────────────────────────────────────────────────────

/// Verification: the first peer asked fails; the wake carries on with the
/// next one inside the budget instead of failing.
#[test]
fn failed_first_peer_is_retried_on_the_next() {
    let c = chain(14);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(10));
    let broken = MockPeer::spawn(&c, vec![Behavior::SendGarbage]);
    let (a, b) = (MockPeer::spawn(&c, vec![]), MockPeer::spawn(&c, vec![]));
    demote(&node, &a.addr(), 80);
    demote(&node, &b.addr(), 80);
    node.use_peers(&[&broken, &a, &b]);

    let status = node.hs.catch_up_blocks(10, 15).unwrap();
    assert!(status.caught_up, "{:?}", status);
    assert_eq!(node.validated(), 14);
    // The broken peer was asked (and failed) before the others.
    assert!(broken.log().iter().any(|m| matches!(m, NetworkMessage::GetHeaders(_))));
}

// ── Block requests rotate (ticket 054 review) ────────────────────────

/// The highest-weighted peer never serves blocks. It is asked once, is
/// dropped for the wake, and the others serve the backlog: before, the
/// first slot's peer was asked for every block, and its failure ended the
/// wake (or, slow enough, used the whole budget: `wake_block_share` above
/// bounds that, since tests' 3 s block timeout fires first here).
#[test]
fn a_peer_sitting_on_block_requests_costs_one_share_not_the_wake() {
    let c = chain(14);
    let mut node = Node::new(&[]);
    presync(&mut node, &c.prefix(10));
    let sitter = MockPeer::spawn(&c, (11..=14).map(Behavior::WithholdBlock).collect());
    let (a, b) = (MockPeer::spawn(&c, vec![]), MockPeer::spawn(&c, vec![]));
    demote(&node, &a.addr(), 80);
    demote(&node, &b.addr(), 80);
    node.use_peers(&[&sitter, &a, &b]);

    let start = Instant::now();
    let status = node.hs.catch_up_blocks(10, 20).unwrap();
    assert_eq!(status.blocks_validated, 4, "{:?}", status);
    assert!(status.caught_up, "{:?}", status);
    // One share (about half the budget), not all of it.
    assert!(start.elapsed() < Duration::from_secs(16), "{:?}", start.elapsed());
    assert_eq!(sitter.block_requests().len(), 1, "the sitter was asked again");
    // Our deadline, not the peer's fault.
    assert!(!node.is_banned(&sitter.addr()));
}

// ── Setup gate ───────────────────────────────────────────────────────

/// An AssumeUTXO anchor at `height` of `c`, with no snapshot loaded.
fn anchor_at(node: &mut Node, c: &FixtureChain, height: u32) {
    node.hs.anchor = SnapshotAnchor {
        height,
        block_hash: c.hash_at(height).to_byte_array(),
        utxo_hash: [0u8; 32],
        utxo_count: 0,
    };
}

/// Verification: in AssumeUTXO mode with no snapshot, a wake whose
/// headers pass the anchor syncs them and validates nothing: no genesis
/// sync by the back door, and `needs_snapshot` stays true.
#[test]
fn snapshot_pending_wake_syncs_headers_only() {
    let c = chain(20);
    let (a, b) = (MockPeer::spawn(&c, vec![]), MockPeer::spawn(&c, vec![]));
    let mut node = Node::new(&[&a, &b]);
    anchor_at(&mut node, &c, 10);
    assert_eq!(node.hs.set_validation_mode(NodeMode::AssumeUtxo).unwrap(), NodeMode::AssumeUtxo);
    assert!(node.hs.needs_snapshot().unwrap());

    let status = node.hs.catch_up_blocks(10, 15).unwrap();
    assert_eq!(status.target_height, 20, "{:?}", status);
    assert_eq!(status.blocks_validated, 0, "{:?}", status);
    assert!(status.awaiting_snapshot && !status.caught_up, "{:?}", status);
    assert_eq!(node.validated(), 0);
    assert!(node.hs.needs_snapshot().unwrap(), "snapshot no longer needed");
    assert!(!node.hs.activate_pending_snapshot().unwrap());
    assert!(a.block_requests().is_empty() && b.block_requests().is_empty());

    // The foreground loop holds to it too.
    let _ = node.sync_for(Duration::from_secs(3));
    assert_eq!(node.validated(), 0);
}

/// The same chain in genesis mode validates from genesis, as before.
#[test]
fn genesis_mode_validates_without_a_snapshot() {
    let c = chain(12);
    let (a, b) = (MockPeer::spawn(&c, vec![]), MockPeer::spawn(&c, vec![]));
    let mut node = Node::new(&[&a, &b]);
    anchor_at(&mut node, &c, 6);
    node.hs.set_validation_mode(NodeMode::Genesis).unwrap();
    assert!(!node.hs.needs_snapshot().unwrap());

    let status = node.hs.catch_up_blocks(20, 15).unwrap();
    assert!(status.caught_up && !status.awaiting_snapshot, "{:?}", status);
    assert_eq!(node.validated(), 12);
}

/// The recorded mode is the node's: a different request later is ignored,
/// and it survives a restart.
#[test]
fn recorded_mode_wins_and_survives_restart() {
    let mut node = Node::new(&[]);
    assert_eq!(node.hs.mode().unwrap(), None);
    assert_eq!(node.hs.set_validation_mode(NodeMode::AssumeUtxo).unwrap(), NodeMode::AssumeUtxo);
    assert_eq!(node.hs.set_validation_mode(NodeMode::Genesis).unwrap(), NodeMode::AssumeUtxo);
    node = node.restart(&[]);
    assert_eq!(node.hs.mode().unwrap(), Some(NodeMode::AssumeUtxo));
}

/// A database the old bug already turned into a genesis sync (no
/// snapshot, blocks validated) is recorded as what it is.
#[test]
fn already_converted_database_is_recorded_as_genesis() {
    let c = chain(5);
    let mut node = Node::new(&[]);
    presync(&mut node, &c);
    assert_eq!(node.validated(), 5);
    assert_eq!(node.hs.set_validation_mode(NodeMode::AssumeUtxo).unwrap(), NodeMode::Genesis);
    assert!(!node.hs.needs_snapshot().unwrap());
}
