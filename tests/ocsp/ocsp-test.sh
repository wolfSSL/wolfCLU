#!/bin/bash

# Consolidated OCSP interoperability test
# Runs all test combinations in series to avoid port conflicts

# Exit 77 to indicate test was skipped
# Exit 99 to indicate test failed
# Exit 0 to indicate test passed

echo "======================================"
echo "OCSP Interoperability Test Suite"
echo "======================================"

if ! ./wolfssl ocsp -help &> /dev/null; then
    echo "ocsp not supported, skipping test"
    exit 77
fi

# Track overall results
TOTAL=0
PASSED=0
SKIPPED=0
FAILED=0

run_test() {
    local client=$1
    local responder=$2
    local test_name="$client-$responder"
    
    echo ""
    echo "Running: $test_name"
    echo "--------------------------------------"
    
    TOTAL=$((TOTAL + 1))
    
    export OCSP_CLIENT="$client"
    export OCSP_RESPONDER="$responder"
    
    "$(dirname "$0")/ocsp-interop-test.sh"
    local result=$?
    
    if [ $result -eq 0 ]; then
        echo "✓ $test_name: PASSED"
        PASSED=$((PASSED + 1))
    elif [ $result -eq 77 ]; then
        echo "⊘ $test_name: SKIPPED"
        SKIPPED=$((SKIPPED + 1))
    else
        echo "✗ $test_name: FAILED (exit $result)"
        FAILED=$((FAILED + 1))
    fi
}

# Run all test combinations in series
run_test "./wolfssl" "openssl"
run_test "openssl" "./wolfssl"
run_test "./wolfssl" "./wolfssl"
# Running this config too to make sure the script works
run_test "openssl" "openssl"

# Print summary
echo ""
echo "======================================"
echo "Test Summary"
echo "======================================"
echo "Total:   $TOTAL"
echo "Passed:  $PASSED"
echo "Skipped: $SKIPPED"
echo "Failed:  $FAILED"
echo "======================================"

# Return appropriate exit code
if [ $FAILED -gt 0 ]; then
    exit 99
elif [ $PASSED -eq 0 ]; then
    # All tests were skipped
    exit 77
else
    exit 0
fi


