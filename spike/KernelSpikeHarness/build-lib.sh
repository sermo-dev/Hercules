#!/bin/bash
# Build libkernel_spike.a for iOS device + simulator and wrap it in an xcframework.
#   ENGINE=kernel (default) or ENGINE=consensus (our current libbitcoinconsensus v26,
#   for same-device comparison of script-verify timings).
# Needs: cmake, boost headers (brew install cmake boost), spike-deps/rust-bitcoinkernel
# with ../kernel-spike/build-rs-ios.patch applied.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENGINE="${ENGINE:-kernel}"
export BOOST_ROOT="${BOOST_ROOT:-$(brew --prefix boost)}"
export IPHONEOS_DEPLOYMENT_TARGET=17.0
T="$HERE/../../spike-deps/target-spike/harness-$ENGINE"
cd "$HERE/../kernel-spike"
for tgt in aarch64-apple-ios aarch64-apple-ios-sim; do
  CARGO_TARGET_DIR="$T" cargo build --release --lib --target "$tgt" --no-default-features --features "$ENGINE"
done
rm -rf "$HERE/build" && mkdir -p "$HERE/build/headers"
cp "$HERE/Sources/KernelSpike.h" "$HERE/build/headers/"
xcodebuild -create-xcframework \
  -library "$T/aarch64-apple-ios/release/libkernel_spike.a" -headers "$HERE/build/headers" \
  -library "$T/aarch64-apple-ios-sim/release/libkernel_spike.a" -headers "$HERE/build/headers" \
  -output "$HERE/build/KernelSpike.xcframework"
echo "built $ENGINE xcframework"
