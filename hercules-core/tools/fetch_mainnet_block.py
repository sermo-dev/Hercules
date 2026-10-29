#!/usr/bin/env python3
"""Fetch one mainnet block + all its prevouts from a public Esplora API into
<out dir>/mainnet_block_<height>.json, for the script-verify benchmark in
src/script_verify/tests.rs (ticket 047). Usage:
    python3 -I tools/fetch_mainnet_block.py <height|tip-N> <out dir>
Data is public chain data; the block hash is checked against the header hash."""
import hashlib, json, sys, time, urllib.request

API = "https://mempool.space/api"

def get(path, binary=False):
    for attempt in range(6):
        try:
            with urllib.request.urlopen(API + path, timeout=30) as r:
                d = r.read()
                return d if binary else d.decode()
        except Exception as e:
            time.sleep(2 * (attempt + 1))
    raise SystemExit("failed: " + path)

arg, out = sys.argv[1], sys.argv[2]
height = int(get("/blocks/tip/height")) - int(arg[4:]) if arg.startswith("tip-") else int(arg)
bhash = get(f"/block-height/{height}").strip()
raw = get(f"/block/{bhash}/raw", binary=True)
assert hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()[::-1].hex() == bhash
info = json.loads(get(f"/block/{bhash}"))
n = info["tx_count"]
prevouts = []
for start in range(0, n, 25):
    for tx in json.loads(get(f"/block/{bhash}/txs/{start}")):
        if tx["vin"][0].get("is_coinbase"):
            continue
        prevouts.append([[v["prevout"]["value"], v["prevout"]["scriptpubkey"]] for v in tx["vin"]])
    time.sleep(0.15)
assert len(prevouts) == n - 1, (len(prevouts), n)
path = f"{out}/mainnet_block_{height}.json"
json.dump({"height": height, "hash": bhash, "block_hex": raw.hex(), "prevouts": prevouts}, open(path, "w"))
print(path, n, "txs", sum(len(p) for p in prevouts), "inputs", len(raw), "bytes")
