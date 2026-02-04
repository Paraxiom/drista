#!/bin/bash
# Test CLI Nostr keygen command
set -euo pipefail

DRISTA="${DRISTA_CLI_PATH:-/Users/sylvaincormier/QuantumVerseProtocols/drista/target/release/drista}"

echo "=== Test: CLI Keygen ==="

# Generate a keypair
output=$("$DRISTA" keygen 2>&1)

# Verify output contains private and public keys
if ! echo "$output" | grep -q "Private key:"; then
    echo "ERROR: Missing private key in output"
    echo "$output"
    exit 1
fi

if ! echo "$output" | grep -q "Public key:"; then
    echo "ERROR: Missing public key in output"
    echo "$output"
    exit 1
fi

# Extract and validate key format (64 hex chars)
privkey=$(echo "$output" | grep "Private key:" | awk '{print $NF}')
pubkey=$(echo "$output" | grep "Public key:" | awk '{print $NF}')

if [ ${#privkey} -ne 64 ]; then
    echo "ERROR: Private key should be 64 hex chars, got ${#privkey}"
    exit 1
fi

if [ ${#pubkey} -ne 64 ]; then
    echo "ERROR: Public key should be 64 hex chars, got ${#pubkey}"
    exit 1
fi

# Validate hex format
if ! echo "$privkey" | grep -qE '^[0-9a-f]{64}$'; then
    echo "ERROR: Private key is not valid hex"
    exit 1
fi

if ! echo "$pubkey" | grep -qE '^[0-9a-f]{64}$'; then
    echo "ERROR: Public key is not valid hex"
    exit 1
fi

echo "Private key: ${privkey:0:16}... (valid)"
echo "Public key:  ${pubkey:0:16}... (valid)"
echo "=== Test PASSED ==="
