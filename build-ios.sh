#!/bin/bash
set -e

# Build script for Hercules iOS
# Compiles Rust -> static lib + Swift bindings

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$SCRIPT_DIR/hercules-core"
BUILD_DIR="$SCRIPT_DIR/build"

echo "==> Cleaning build directory"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "==> Building Rust for iOS device (aarch64-apple-ios)"
cd "$RUST_DIR"
cargo build --release --target aarch64-apple-ios

echo "==> Building Rust for iOS simulator (aarch64-apple-ios-sim)"
cargo build --release --target aarch64-apple-ios-sim

echo "==> Generating UniFFI Swift bindings"
cargo run --bin uniffi-bindgen generate \
    --library target/aarch64-apple-ios/release/libhercules_core.a \
    --language swift \
    --out-dir "$BUILD_DIR"

echo "==> Creating XCFramework from static libraries"

# Create herculesFFI.xcframework directly from static libraries + headers
# This avoids framework module naming issues
mkdir -p "$BUILD_DIR/device-headers" "$BUILD_DIR/sim-headers"

# Copy header and modulemap to both
for DIR in "$BUILD_DIR/device-headers" "$BUILD_DIR/sim-headers"; do
    cp "$BUILD_DIR/herculesFFI.h" "$DIR/"
    cp "$BUILD_DIR/herculesFFI.modulemap" "$DIR/module.modulemap"
done

xcodebuild -create-xcframework \
    -library "$RUST_DIR/target/aarch64-apple-ios/release/libhercules_core.a" \
    -headers "$BUILD_DIR/device-headers" \
    -library "$RUST_DIR/target/aarch64-apple-ios-sim/release/libhercules_core.a" \
    -headers "$BUILD_DIR/sim-headers" \
    -output "$BUILD_DIR/herculesFFI.xcframework"

echo "==> Done!"
echo "    XCFramework: $BUILD_DIR/herculesFFI.xcframework"
echo "    Swift bindings: $BUILD_DIR/hercules.swift"
echo ""
echo "Add both to your Xcode project:"
echo "  1. herculesFFI.xcframework (as a linked framework)"
echo "  2. hercules.swift (as a source file)"
