#!/bin/bash
# Ticket 047 Step 1: run identical script-verify cases through libbitcoinkernel
# and our patched libbitcoinconsensus v26 in SEPARATE binaries (linking both
# into one binary is an ODR violation, see src/lib.rs) and diff the outcomes.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="${CARGO_TARGET_DIR:-$HERE/../../spike-deps/target-spike}"
OUT="${1:-$T/step1}"
mkdir -p "$OUT"
cd "$HERE"
CARGO_TARGET_DIR="$T/kernel"    cargo build --release --bin verify-dump --no-default-features --features kernel
CARGO_TARGET_DIR="$T/consensus" cargo build --release --bin verify-dump --no-default-features --features consensus
"$T/kernel/release/verify-dump"    "$HERE/testdata" > "$OUT/kernel.tsv" 2> "$OUT/kernel.json"
"$T/consensus/release/verify-dump" "$HERE/testdata" > "$OUT/consensus.tsv" 2> "$OUT/consensus.json"
echo "cases: $(wc -l < "$OUT/kernel.tsv") kernel / $(wc -l < "$OUT/consensus.tsv") consensus"
if diff "$OUT/kernel.tsv" "$OUT/consensus.tsv" > "$OUT/diff.txt"; then
  echo "IDENTICAL outcomes for every case and input"
else
  echo "DIFFERENCES ($(grep -c '^<' "$OUT/diff.txt") lines):"; head -40 "$OUT/diff.txt"; exit 1
fi
for e in kernel consensus; do
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["engine"], "unexpected_vs_core:", len(d["unexpected_vs_core"]), "|", "; ".join("block %d: %d inputs, script verify ms %s" % (b["height"], b["inputs"], [round(t,1) for t in b["single_thread_script_verify_ms_per_run"]]) for b in d["mainnet_blocks"]))' "$OUT/$e.json"
done
