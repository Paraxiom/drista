#!/bin/bash
# Test PQ-DM (ML-KEM + AES-GCM) encryption roundtrip
set -euo pipefail

DRISTA_ROOT="${DRISTA_ROOT:-/Users/sylvaincormier/QuantumVerseProtocols/drista}"

echo "=== Test: PQ-DM Encryption Roundtrip ==="

cd "$DRISTA_ROOT"

# Run the PQ-DM specific tests from drista-cli
cargo test -p drista-cli -- pq --nocapture 2>&1 | tee /tmp/pqdm_test_output.txt

# Check for test failures
if grep -q "FAILED" /tmp/pqdm_test_output.txt; then
    echo "ERROR: Some PQ-DM tests failed"
    cat /tmp/pqdm_test_output.txt
    exit 1
fi

# Verify expected tests ran
if grep -q "test_pq_dm_roundtrip" /tmp/pqdm_test_output.txt; then
    echo "PQ-DM roundtrip test passed"
else
    echo "WARNING: test_pq_dm_roundtrip not found"
fi

if grep -q "test_pq_dm_unicode" /tmp/pqdm_test_output.txt; then
    echo "PQ-DM unicode test passed"
else
    echo "WARNING: test_pq_dm_unicode not found"
fi

echo "=== Test PASSED ==="
