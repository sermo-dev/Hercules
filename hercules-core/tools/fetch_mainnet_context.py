#!/usr/bin/env python3
"""Fetch a mainnet block with everything the ticket-026 contextual rules
need: raw block, every prevout (value, scriptPubKey, confirmation height),
and the header timestamps for median-time-past at the block and at every
spent coin's height. Public chain data from mempool.space's Esplora API.
Feeds the ignored mainnet regression test in src/testkit/consensus_rules.rs:
    python3 -I tools/fetch_mainnet_context.py <height|tip-N> <out dir>
    HERCULES_MAINNET_CTX_DIR=<out dir> cargo test -- --ignored mainnet_blocks_pass"""
import hashlib, json, sys, time, urllib.request

API = "https://mempool.space/api"

def get(path, binary=False):
    for attempt in range(6):
        try:
            with urllib.request.urlopen(API + path, timeout=30) as r:
                d = r.read()
                return d if binary else d.decode()
        except Exception:
            time.sleep(2 * (attempt + 1))
    raise SystemExit("failed: " + path)

arg, out = sys.argv[1], sys.argv[2]
height = int(get("/blocks/tip/height")) - int(arg[4:]) if arg.startswith("tip-") else int(arg)
bhash = get(f"/block-height/{height}").strip()
raw = get(f"/block/{bhash}/raw", binary=True)
assert hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()[::-1].hex() == bhash
info = json.loads(get(f"/block/{bhash}"))
n = info["tx_count"]

txs = []
for start in range(0, n, 25):
    txs.extend(json.loads(get(f"/block/{bhash}/txs/{start}")))
    time.sleep(0.1)
assert len(txs) == n
in_block = {t["txid"] for t in txs}

# Prevout confirmation heights: only inputs BIP 68 can constrain need the
# real one (version >= 2 unsigned, disable bit clear); others get 0.
status_cache = {}
def coin_height(txid):
    if txid in in_block:
        return height
    if txid not in status_cache:
        st = json.loads(get(f"/tx/{txid}/status"))
        assert st["confirmed"], txid
        status_cache[txid] = st["block_height"]
        time.sleep(0.05)
    return status_cache[txid]

prevouts = []
relevant = 0
for t in txs:
    if t["vin"][0].get("is_coinbase"):
        continue
    v2 = (t["version"] & 0xffffffff) >= 2
    row = []
    for vin in t["vin"]:
        h = 0
        if v2 and not (vin["sequence"] & (1 << 31)):
            h = coin_height(vin["txid"])
            relevant += 1
        row.append([vin["prevout"]["value"], vin["prevout"]["scriptpubkey"], h, vin["txid"] in in_block])
    prevouts.append(row)

# Timestamps for MTP(height - 1) and MTP(coin_height - 1) windows.
need = set(range(max(0, height - 11), height))
for row in prevouts:
    for _, _, h, _ in row:
        if h:
            need.update(range(max(0, h - 11), h))
timestamps = {}
for h in sorted(need):
    bh = get(f"/block-height/{h}").strip()
    timestamps[h] = json.loads(get(f"/block/{bh}"))["timestamp"]
    time.sleep(0.05)

path = f"{out}/mainnet_ctx_{height}.json"
json.dump({"height": height, "hash": bhash, "block_hex": raw.hex(), "prevouts": prevouts,
           "timestamps": {str(k): v for k, v in timestamps.items()}}, open(path, "w"))
print(path, n, "txs", sum(len(p) for p in prevouts), "inputs", relevant, "bip68-relevant",
      len(timestamps), "timestamps")
