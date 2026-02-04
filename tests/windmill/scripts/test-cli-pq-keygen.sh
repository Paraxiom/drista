#!/bin/bash
# Test CLI ML-KEM-1024 keygen command
set -euo pipefail

DRISTA="${DRISTA_CLI_PATH:-/Users/sylvaincormier/QuantumVerseProtocols/drista/target/release/drista}"

echo "=== Test: CLI PQ Keygen (ML-KEM-1024) ==="

# Generate a PQ keypair
output=$("$DRISTA" pq-keygen 2>&1)

# Verify output mentions ML-KEM-1024
if ! echo "$output" | grep -q "ML-KEM-1024"; then
    echo "ERROR: Should mention ML-KEM-1024"
    echo "$output"
    exit 1
fi

# Verify PQ public key is present
if ! echo "$output" | grep -q "PQ Public key"; then
    echo "ERROR: Missing PQ public key in output"
    echo "$output"
    exit 1
fi

# Extract the public key (it spans multiple lines or is very long)
# ML-KEM-1024 public key is 1568 bytes = ~2091 chars in base64
pq_pubkey=$(echo "$output" | grep -A1 "PQ Public key" | tail -1 | tr -d ' ')

# Base64 encoded 1568 bytes should be ~2091 characters
if [ ${#pq_pubkey} -lt 2000 ]; then
    echo "ERROR: PQ public key too short (${#pq_pubkey} chars, expected ~2091)"
    echo "Key: ${pq_pubkey:0:50}..."
    exit 1
fi

# Validate it's base64
if ! echo "$pq_pubkey" | grep -qE '^[A-Za-z0-9+/=]+$'; then
    echo "ERROR: PQ public key is not valid base64"
    exit 1
fi

echo "PQ public key: ${pq_pubkey:0:40}... (${#pq_pubkey} chars, valid)"
echo "=== Test PASSED ==="
