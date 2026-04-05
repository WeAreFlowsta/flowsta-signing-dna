#!/bin/bash

# Build script for Flowsta Signing DNA v1.1

set -e

echo "Building Flowsta Signing DNA v1.1"

# Check if Holochain CLI is installed
if ! command -v hc &> /dev/null; then
    echo "Error: Holochain CLI (hc) not found"
    echo "Install with: cargo install holochain_cli --version 0.6.0"
    exit 1
fi

# Create workdir if it doesn't exist
mkdir -p workdir

# Build all zomes
echo "Building zomes..."
RUSTFLAGS='--cfg getrandom_backend="custom"' CARGO_TARGET_DIR=target cargo build --release --target wasm32-unknown-unknown

# Copy wasm files and manifests to workdir (manifest_version "0" expects flat paths)
echo "Copying WASM files and manifests..."
cp target/wasm32-unknown-unknown/release/signing_integrity.wasm workdir/
cp target/wasm32-unknown-unknown/release/signing_coordinator.wasm workdir/
cp dna.yaml workdir/
cp happ.yaml workdir/

# Pack the DNA
echo "Packing DNA..."
hc dna pack workdir

# Pack the hApp
echo "Packing hApp..."
hc app pack workdir

echo "Build complete!"
echo ""
echo "Outputs:"
echo "  - DNA: workdir/flowsta_signing_v1_0.dna"
echo "  - hApp: workdir/flowsta_signing_v1_0_happ.happ"
