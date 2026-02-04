#!/bin/bash
# Build Drista CLI for testing
set -euo pipefail

DRISTA_ROOT="${DRISTA_ROOT:-/Users/sylvaincormier/QuantumVerseProtocols/drista}"

echo "=== Building Drista CLI ==="
cd "$DRISTA_ROOT"

# Build in release mode for performance
cargo build --release -p drista-cli

# Verify binary exists
if [ ! -f "$DRISTA_ROOT/target/release/drista" ]; then
    echo "ERROR: drista binary not found after build"
    exit 1
fi

echo "CLI version info:"
"$DRISTA_ROOT/target/release/drista" --help | head -5

echo "=== CLI Build Complete ==="
