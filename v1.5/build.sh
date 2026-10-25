#!/bin/bash

# Build script for Flowsta Signing DNA v1.5
#
# v1.5 is the Holochain 0.7 generation of v1.4 (same entry and link types
# plus the carried-record fields; new DNA hash, so a new network):
#   - validation written for the 0.7 action model
#   - a SignatureRecord, RevocationEntry or SignatureThumbnail may carry its
#     origin on the v1.4 network (author, time, action hash, signed action,
#     the witness that re-published it), and a CarriedIndex link maps the old
#     action hash to the new one so a carry is idempotent
#
# Prerequisites:
#   - hc CLI 0.7.1 (cargo install holochain_cli --version 0.7.1), reachable
#     as `hc-0.7` or named in $HC
#   - Rust 1.94 or newer with the wasm32 target (rust-toolchain.toml pins it)

set -e

echo "Building Flowsta Signing DNA v1.5"

if ! command -v ${HC:-hc-0.7} &> /dev/null; then
    echo "Error: Holochain CLI (hc) not found"
    echo "Install with: cargo install holochain_cli --version 0.7.1"
    exit 1
fi

mkdir -p workdir

echo "Building zomes..."
RUSTFLAGS='--cfg getrandom_backend="custom"' CARGO_TARGET_DIR=target \
    cargo build --release --target wasm32-unknown-unknown

echo "Copying WASM files..."
cp target/wasm32-unknown-unknown/release/signing_integrity.wasm workdir/
cp target/wasm32-unknown-unknown/release/signing_coordinator.wasm workdir/
cp dna.yaml workdir/
cp happ.yaml workdir/

echo "Packing DNA..."
${HC:-hc-0.7} dna pack workdir

echo "Packing hApp..."
${HC:-hc-0.7} app pack workdir

echo ""
echo "Build complete!"
echo "  - DNA: workdir/flowsta_signing_v1_5.dna"
echo "  - hApp: workdir/flowsta_signing_v1_5_happ.happ"
sha256sum workdir/flowsta_signing_v1_5_happ.happ
