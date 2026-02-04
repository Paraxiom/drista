#!/bin/bash
# Test NIP-04 encryption roundtrip via Rust unit tests
set -euo pipefail

DRISTA_ROOT="${DRISTA_ROOT:-/Users/sylvaincormier/QuantumVerseProtocols/drista}"

echo "=== Test: NIP-04 Encryption Roundtrip ==="

cd "$DRISTA_ROOT"

# Run the NIP-04 specific tests
cargo test -p drista-cli -- nip04 --nocapture 2>&1 | tee /tmp/nip04_test_output.txt

# Check for test failures
if grep -q "FAILED" /tmp/nip04_test_output.txt; then
    echo "ERROR: Some NIP-04 tests failed"
    exit 1
fi

# Verify all expected tests ran
expected_tests=(
    "test_encrypt_decrypt_nip04"
    "test_encrypt_decrypt_unicode"
    "test_iv_is_16_bytes"
)

for test in "${expected_tests[@]}"; do
    if ! grep -q "$test" /tmp/nip04_test_output.txt; then
        echo "WARNING: Expected test '$test' not found in output"
    fi
done

echo "=== Test PASSED ==="
