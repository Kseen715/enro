#!/bin/bash
# Build script for ENRO on Linux/macOS

echo "🔨 Building ENRO - File Encryption & Randomness Observer"
echo ""

echo "Building with release optimizations..."
cargo build --release

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Build successful!"
    echo "Binary location: target/release/enro"
    echo ""
    echo "Run with: ./target/release/enro --help"
else
    echo ""
    echo "✗ Build failed!"
    exit 1
fi
