# Ticket 058: Serving and Block-Fetch Liveness — What's Left of 049's Critical

## Summary

Ticket 049 put deadlines on every peer read and write, but deadlines are per message. A peer that stays just inside each deadline can still hold the single sync thread for hours. That can happen in two places: while we serve its requests, and while we fetch blocks from it. Found by the deep review of main at `d627836` (2026-10-31).

## Background

### 1. Serving: one `getdata` holds the sync thread for hours (critical)

- **The code:** `serve_getdata_step` (`sync.rs` ~4586) serves up to `GETDATA_ITEMS_PER_STEP = 1000` items per step, each one a blocking `send_tx` / `send_block` with its own fresh write deadline (20 s; 60 s over Tor). The queued list is not deduplicated.
- **The attack:**
  1. Any peer sends `getdata` listing one mempool txid 1,000 times. An inbound connection to our onion costs nothing.
  2. It then reads just enough bytes to finish each `tx` message inside its deadline.
- **Effect:** the step takes about 5.5 h (about 16 h over Tor). During that time there are no headers, no blocks, no chores and no `stop` check, and every wake returns `Busy`.
- **Same pattern, smaller scale:** block items (about 100–180 s each), relays in `for_each_peer`, and `drain_relay_queue`, which sends serially.

### 2. Block fetch: a slow first-slot peer paces all validation (medium-high)

- **The code:** `PeerPool::any_peer` (`peer_pool.rs` ~1168) always returns the first outbound slot. It is used for block fetches in the main loop (`sync.rs` ~3504 and ~3550) and in `fetch_requested_block`.
- **What happens:** a peer that answers each block just under the deadline (120 s; 300 s over Tor) is rewarded and asked again, because nothing detects a block stall.
- **Effect:** 144 blocks take about 5 h, or about 12 h over Tor.
- **Confirmed** by the reviewer's scratch test: all 8 blocks came from the slow peer, none from the fast honest one.
- The wake side of this went to the 054 agent.

## Proposed fix

1. **A per-step budget for serving.** Each serving step gets a time and byte budget, then yields back to the loop.
   - Deduplicate queued getdata items.
   - Measure each peer's overall serve rate, not just per-message deadlines, and drop peers below a floor (the 25 kB/s minimum from 049, applied across the whole step).
   - Longer term: non-blocking per-peer send buffers with back-pressure, as Core's `fPauseSend` does.
2. **The same budget for relay sends:** `for_each_peer` relays and `drain_relay_queue`.
3. **A block stall timeout**, like Core's `BLOCK_STALLING_TIMEOUT` and the header stall timeout from 049. A peer that is slow to deliver blocks is demoted and the request moves to another peer.
4. **Spread block requests:** rotate across peers, or download from several in parallel, instead of always asking the first slot.
5. **Check `stop` between items** in every serving loop.

## Verification

- A reproducer for each attack with a short test timeout: a duplicated-txid getdata against a slow reader, and a slow block server in the first slot. Both must finish within a bounded time, and `stop_sync` must return promptly.
- Honest slow peers (the trickle tests in `adversarial_sync.rs`) are still served and are not penalized.

## Roadmap position

Before the wallet ships sends. Goes after wave 2 (052 / 053 part 2 / 054), alongside 025 and 029.
