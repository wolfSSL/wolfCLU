#!/bin/bash

# Generic OCSP interoperability test
# Uses environment variables to determine which binaries to use:
#   OCSP_CLIENT - binary to use for OCSP client (wolfclu or openssl)
#   OCSP_RESPONDER - binary to use for OCSP responder (wolfclu or openssl)
#   KEEP_TEST_DIR - if set to 1, preserve test directory for debugging
#
# Test coverage:
#   - Positive tests: Valid certificate checks with various options
#   - Negative tests: Revoked certificates, missing parameters, invalid files
#   - Return code compatibility: Verifies wolfssl ocsp is compatible with openssl ocsp
#
# Exit codes:
#   0  - All tests passed
#   77 - Test skipped (filesystem disabled, OCSP not supported, etc.)
#   99 - Test failed

if [ ! -d ./certs/ ]; then
    echo "certs directory not found, skipping test"
    exit 77
fi

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]; then
    echo "Filesystem disabled, skipping test"
    exit 77
fi

# Determine client and responder binaries
if [ -z "$OCSP_CLIENT" ]; then
    echo "Client not specified"
    exit 99
fi

if [ -z "$OCSP_RESPONDER" ]; then
    echo "Responder not specified"
    exit 99
fi

echo "Testing OCSP interop: $OCSP_CLIENT (client) vs $OCSP_RESPONDER (responder)"

if ! $OCSP_CLIENT ocsp -help &> /dev/null; then
    echo "ocsp not supported on client side, skipping test"
    exit 77
fi
if ! $OCSP_RESPONDER ocsp -help &> /dev/null; then
    echo "ocsp not supported on responder side, skipping test"
    exit 77
fi

# Create a temporary directory for test files
TEST_DIR=$(mktemp -d)
if [ $? != 0 ]; then
    echo "Failed to create temp directory"
    exit 99
fi

cleanup() {
    EXIT_CODE=$?
    
    # Print logs on error
    if [ $EXIT_CODE != 0 ] && [ $EXIT_CODE != 77 ]; then
        echo "===================================="
        echo "Test failed with exit code: $EXIT_CODE"
        echo "===================================="
        
        for logfile in "$TEST_DIR"/*.log; do
            if [ -f "$logfile" ]; then
                echo "$(basename "$logfile"):"
                cat "$logfile"
                echo "------------------------------------"
            fi
        done
    fi
    
    # Kill the OCSP responder if still running
    if [ ! -z "$RESPONDER_PID" ]; then
        kill $RESPONDER_PID 2>/dev/null
        wait $RESPONDER_PID 2>/dev/null
    fi
    
    # Remove test directory unless KEEP_TEST_DIR is set
    if [ "$KEEP_TEST_DIR" = "1" ]; then
        echo "Test directory preserved: $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

# Create an OCSP index file for the test
# Format: status<TAB>expiration<TAB>revocation<TAB>serial<TAB>filename<TAB>DN
# V = valid, R = revoked, E = expired
# Use printf to ensure proper tab separators
printf "V\t991231235959Z\t\t01\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" > "$TEST_DIR/index.txt"

OCSP_PORT=6960

# Start OCSP responder in background
$OCSP_RESPONDER ocsp -port $OCSP_PORT \
    -index "$TEST_DIR/index.txt" \
    -CA certs/ca-cert.pem \
    -rsigner certs/ca-cert.pem \
    -rkey certs/ca-key.pem \
    -nrequest 10 \
    > "$TEST_DIR/ocsp-responder.log" 2>&1 &
RESPONDER_PID=$!

# Wait for responder to start
sleep 0.5

# Check if responder is still running
if ! kill -0 $RESPONDER_PID 2>/dev/null; then
    echo "OCSP responder failed to start"
    exit 99
fi

echo "OCSP responder started on port $OCSP_PORT (PID: $RESPONDER_PID)"

# Run client tests
# Test 1: Basic OCSP check with CA file and explicit URL
echo "Test 1: OCSP check with -CAfile and -url"

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert certs/server-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test1.log" 2>&1

RESULT=$?
if [ $RESULT != 0 ]; then
    echo "Test 1 failed: $OCSP_CLIENT OCSP check returned $RESULT"
    exit 99
fi

# Verify the output contains success indicator
grep -q "good" "$TEST_DIR/test1.log"
if [ $? != 0 ]; then
    echo "Test 1 failed: expected success indicator in output"
    exit 99
fi

echo "Test 1 passed"

# Test 2: OCSP check with -no_nonce
echo "Test 2: OCSP check with -no_nonce"

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert certs/server-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    -no_nonce \
    > "$TEST_DIR/test2.log" 2>&1

RESULT=$?
if [ $RESULT != 0 ]; then
    echo "Test 2 failed: $OCSP_CLIENT OCSP check with -no_nonce returned $RESULT"
    exit 99
fi

grep -q "good" "$TEST_DIR/test2.log"
if [ $? != 0 ]; then
    echo "Test 2 failed: expected success indicator in output"
    exit 99
fi

echo "Test 2 passed"

# Test 3: OCSP check for revoked certificate
echo "Test 3: OCSP check for revoked certificate (should show revoked status)"

# Note: OpenSSL OCSP returns exit code 0 even for revoked certificates, because
# the OCSP transaction itself succeeded. The revocation status is in the output.
# wolfssl OCSP responder currently has a limitation generating revoked responses.


# Update index.txt to include the revoked certificate (serial 02)
printf "V\t991231235959Z\t\t01\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" > "$TEST_DIR/index.txt"
printf "R\t991231235959Z\t240101000000Z\t02\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL_revoked/OU=Support_revoked/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" >> "$TEST_DIR/index.txt"

# Restart responder with new index
if [ ! -z "$RESPONDER_PID" ]; then
    kill $RESPONDER_PID 2>/dev/null
    wait $RESPONDER_PID 2>/dev/null
fi

$OCSP_RESPONDER ocsp -port $OCSP_PORT \
    -index "$TEST_DIR/index.txt" \
    -CA certs/ca-cert.pem \
    -rsigner certs/ca-cert.pem \
    -rkey certs/ca-key.pem \
    -nrequest 10 \
    > "$TEST_DIR/ocsp-responder2.log" 2>&1 &
RESPONDER_PID=$!

sleep 0.5

if ! kill -0 $RESPONDER_PID 2>/dev/null; then
    echo "Test 3 failed: OCSP responder failed to restart"
    exit 99
fi

# Check the revoked certificate
$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert certs/server-revoked-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test3.log" 2>&1

RESULT=$?

# OpenSSL returns 0 (success) even for revoked certs - the status is in output
# Check the output for revoked status indicator
if grep -qi "revoked" "$TEST_DIR/test3.log"; then
    # Found revoked status - this is correct
    echo "Test 3 passed"
else
    # Didn't find any revoked indicator
    echo "Test 3 failed: expected revoked status indicator in output"
    cat "$TEST_DIR/test3.log"
    exit 99
fi

# Test 4: Missing required parameter (-cert without -issuer)
echo "Test 4: Missing required parameter (no issuer)"

$OCSP_CLIENT ocsp \
    -cert certs/server-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test4.log" 2>&1

RESULT=$?
if [ $RESULT = 0 ]; then
    echo "Test 4 failed: $OCSP_CLIENT should have failed without -issuer"
    exit 99
fi

# Check for error message about missing issuer
grep -qi "issuer" "$TEST_DIR/test4.log"
if [ $? != 0 ]; then
    echo "Test 4 failed: expected error about missing issuer"
    exit 99
fi

echo "Test 4 passed"

# Test 5: Missing required parameter (-issuer without -cert)
echo "Test 5: Missing required parameter (no cert)"

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test5.log" 2>&1

RESULT=$?
if [ $RESULT = 0 ]; then
    echo "Test 5 failed: $OCSP_CLIENT should have failed without -cert"
    exit 99
fi

# Check for error message about missing cert or help output
# OpenSSL shows help usage, wolfssl shows an error
grep -qi "cert\|help\|usage" "$TEST_DIR/test5.log"
if [ $? != 0 ]; then
    echo "Test 5 failed: expected error about missing cert or help output"
    exit 99
fi

echo "Test 5 passed"

# Test 6: Invalid certificate file
echo "Test 6: Invalid certificate file"

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert /nonexistent/file.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test6.log" 2>&1

RESULT=$?
if [ $RESULT = 0 ]; then
    echo "Test 6 failed: $OCSP_CLIENT should have failed with invalid cert file"
    exit 99
fi

# Check for error message
grep -qi "fail\|error\|not found\|unable\|no such\|could not" "$TEST_DIR/test6.log"
if [ $? != 0 ]; then
    echo "Test 6 failed: expected error message about invalid file"
    exit 99
fi

echo "Test 6 passed"

# Test 7: Invalid issuer certificate file
echo "Test 7: Invalid issuer certificate file"

$OCSP_CLIENT ocsp \
    -issuer /nonexistent/issuer.pem \
    -cert certs/server-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test7.log" 2>&1

RESULT=$?
if [ $RESULT = 0 ]; then
    echo "Test 7 failed: $OCSP_CLIENT should have failed with invalid issuer file"
    exit 99
fi

# Check for error message
grep -qi "fail\|error\|unable\|issuer" "$TEST_DIR/test7.log"
if [ $? != 0 ]; then
    echo "Test 7 failed: expected error message about invalid issuer file"
    exit 99
fi

echo "Test 7 passed"

# --- Tests with delegated OCSP responder (ocsp-responder-cert.pem as -rsigner) ---

# Kill current responder and restart with delegated responder cert
if [ ! -z "$RESPONDER_PID" ]; then
    kill $RESPONDER_PID 2>/dev/null
    wait $RESPONDER_PID 2>/dev/null
    RESPONDER_PID=""
fi

# Reset index to valid-only for delegated responder tests
printf "V\t991231235959Z\t\t01\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" > "$TEST_DIR/index.txt"

$OCSP_RESPONDER ocsp -port $OCSP_PORT \
    -index "$TEST_DIR/index.txt" \
    -CA certs/ca-cert.pem \
    -rsigner certs/ocsp-responder-cert.pem \
    -rkey certs/ocsp-responder-key.pem \
    -nrequest 10 \
    > "$TEST_DIR/ocsp-responder-deleg.log" 2>&1 &
RESPONDER_PID=$!

sleep 0.5

if ! kill -0 $RESPONDER_PID 2>/dev/null; then
    echo "Delegated OCSP responder failed to start"
    exit 99
fi

echo "Delegated OCSP responder started on port $OCSP_PORT (PID: $RESPONDER_PID)"

# Test 8: Basic OCSP check with delegated responder
echo "Test 8: OCSP check with delegated responder (-rsigner ocsp-responder-cert.pem)"

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert certs/server-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test8.log" 2>&1

RESULT=$?
if [ $RESULT != 0 ]; then
    echo "Test 8 failed: $OCSP_CLIENT OCSP check with delegated responder returned $RESULT"
    exit 99
fi

grep -q "good" "$TEST_DIR/test8.log"
if [ $? != 0 ]; then
    echo "Test 8 failed: expected success indicator in output"
    exit 99
fi

echo "Test 8 passed"

# Test 9: OCSP check with delegated responder and -no_nonce
echo "Test 9: OCSP check with delegated responder and -no_nonce"

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert certs/server-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    -no_nonce \
    > "$TEST_DIR/test9.log" 2>&1

RESULT=$?
if [ $RESULT != 0 ]; then
    echo "Test 9 failed: $OCSP_CLIENT OCSP check with delegated responder and -no_nonce returned $RESULT"
    exit 99
fi

grep -q "good" "$TEST_DIR/test9.log"
if [ $? != 0 ]; then
    echo "Test 9 failed: expected success indicator in output"
    exit 99
fi

echo "Test 9 passed"

# Test 10: Revoked cert check with delegated responder
echo "Test 10: OCSP revoked cert check with delegated responder"

# Update index to include revoked certificate
printf "V\t991231235959Z\t\t01\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" > "$TEST_DIR/index.txt"
printf "R\t991231235959Z\t240101000000Z\t02\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL_revoked/OU=Support_revoked/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" >> "$TEST_DIR/index.txt"

# Restart delegated responder with updated index
if [ ! -z "$RESPONDER_PID" ]; then
    kill $RESPONDER_PID 2>/dev/null
    wait $RESPONDER_PID 2>/dev/null
fi

$OCSP_RESPONDER ocsp -port $OCSP_PORT \
    -index "$TEST_DIR/index.txt" \
    -CA certs/ca-cert.pem \
    -rsigner certs/ocsp-responder-cert.pem \
    -rkey certs/ocsp-responder-key.pem \
    -nrequest 10 \
    > "$TEST_DIR/ocsp-responder-deleg2.log" 2>&1 &
RESPONDER_PID=$!

sleep 0.5

if ! kill -0 $RESPONDER_PID 2>/dev/null; then
    echo "Test 10 failed: delegated OCSP responder failed to restart"
    exit 99
fi

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert certs/server-revoked-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test10.log" 2>&1

if grep -qi "revoked" "$TEST_DIR/test10.log"; then
    echo "Test 10 passed"
else
    echo "Test 10 failed: expected revoked status indicator in output"
    cat "$TEST_DIR/test10.log"
    exit 99
fi

# Test 11: Unreachable OCSP responder
echo "Test 11: Unreachable OCSP responder"

# Kill the responder temporarily
if [ ! -z "$RESPONDER_PID" ]; then
    kill $RESPONDER_PID 2>/dev/null
    wait $RESPONDER_PID 2>/dev/null
    RESPONDER_PID=""
fi

$OCSP_CLIENT ocsp \
    -issuer certs/ca-cert.pem \
    -cert certs/server-cert.pem \
    -CAfile certs/ca-cert.pem \
    -url http://127.0.0.1:$OCSP_PORT \
    > "$TEST_DIR/test11.log" 2>&1

RESULT=$?
if [ $RESULT = 0 ]; then
    echo "Test 11 failed: $OCSP_CLIENT should have failed with unreachable responder"
    exit 99
fi

# Check for connection/network error
grep -qi "fail\|error\|connect\|timeout\|refused" "$TEST_DIR/test11.log"
if [ $? != 0 ]; then
    echo "Test 11 failed: expected connection error message"
    exit 99
fi

echo "Test 11 passed"

# Verify graceful exit messages in responder logs (for wolfCLU responders only)
if [ "$OCSP_RESPONDER" = "./wolfssl" ]; then
    echo ""
    echo "Verifying graceful shutdown messages..."
    
    # Check each responder log file for the graceful exit message
    MISSING_LOGS=""
    LOG_COUNT=0
    
    for logfile in "$TEST_DIR"/ocsp-responder*.log; do
        if [ -f "$logfile" ]; then
            LOG_COUNT=$((LOG_COUNT + 1))
            if grep -q "wolfssl exiting gracefully" "$logfile"; then
                echo "✓ Found graceful exit message in $(basename "$logfile")"
            else
                echo "✗ Missing graceful exit message in $(basename "$logfile")"
                MISSING_LOGS="$MISSING_LOGS $(basename "$logfile")"
            fi
        fi
    done
    
    if [ $LOG_COUNT -eq 0 ]; then
        echo "ERROR: No responder log files found"
        exit 99
    fi
    
    if [ -n "$MISSING_LOGS" ]; then
        echo ""
        echo "ERROR: The following responder logs are missing graceful exit messages:"
        echo "$MISSING_LOGS"
        echo "All responders must shut down gracefully"
        exit 99
    fi
fi

echo "All OCSP interop tests passed"
exit 0
