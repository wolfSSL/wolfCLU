#!/bin/bash

# OCSP SCGI Integration Tests
# Tests wolfCLU OCSP SCGI mode with nginx proxying
#
# Usage: ocsp-scgi-test.sh [--keep-temp]
#
# Options:
#   --keep-temp  Don't delete temporary directory on exit (useful for debugging)
#
# Exit codes:
#   0  - All tests passed
#   77 - Tests skipped (missing dependencies)
#   99 - Tests failed

set -e

EXIT_SUCCESS=0
EXIT_FAILURE=99
EXIT_SKIP=77

# Track if tests failed (used in cleanup to print logs)
TESTS_FAILED=0

# Parse command line options
KEEP_TEMP=0
if [ "$1" = "--keep-temp" ]; then
    KEEP_TEMP=1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WOLFCLU_BIN="$REPO_ROOT/wolfssl"
CERTS_DIR="$REPO_ROOT/certs"

if ! $WOLFCLU_BIN ocsp -help &> /dev/null; then
    echo "ocsp not supported, skipping test"
    exit 77
fi

# Create temporary directory for test files
TEMP_DIR=$(mktemp -d -t wolfclu-ocsp-scgi-XXXXXX)
TEST_DIR="$TEMP_DIR"
LOG_DIR="$TEMP_DIR/logs"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    
    # Kill wolfCLU SCGI responder
    if [ -n "$WOLFCLU_PID" ] && kill -0 "$WOLFCLU_PID" 2>/dev/null; then
        echo "Stopping wolfCLU SCGI responder (PID: $WOLFCLU_PID)..."
        kill "$WOLFCLU_PID" 2>/dev/null || true
        wait "$WOLFCLU_PID" 2>/dev/null || true
    fi
    
    # Stop nginx
    if [ -n "$NGINX_PID" ] && kill -0 "$NGINX_PID" 2>/dev/null; then
        echo "Stopping nginx (PID: $NGINX_PID)..."
        kill "$NGINX_PID" 2>/dev/null || true
        wait "$NGINX_PID" 2>/dev/null || true
    fi
    
    # Print all logs if tests failed
    if [ "$TESTS_FAILED" = "1" ] && [ -d "$TEMP_DIR" ]; then
        echo ""
        echo "======================================"
        echo "Tests failed - dumping all logs:"
        echo "======================================"
        
        # Find all .log files in temp directory
        while IFS= read -r -d '' logfile; do
            if [ -s "$logfile" ]; then  # Only show non-empty log files
                echo ""
                echo "--- $logfile ---"
                cat "$logfile"
            fi
        done < <(find "$TEMP_DIR" -type f -name "*.log" -print0 2>/dev/null)
        
        echo ""
        echo "======================================"
    fi
    
    # Clean up temporary directory
    if [ "$KEEP_TEMP" = "1" ]; then
        echo ""
        echo "======================================"
        echo "Temporary directory preserved:"
        echo "$TEMP_DIR"
        echo "======================================"
        echo "Contents:"
        ls -lh "$TEMP_DIR"
        if [ -d "$LOG_DIR" ]; then
            echo ""
            echo "Logs:"
            ls -lh "$LOG_DIR"
        fi
    else
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

# Check prerequisites
echo "======================================"
echo "OCSP SCGI Integration Tests"
echo "======================================"

# Check for nginx
if ! command -v nginx &> /dev/null; then
    echo "nginx not found - skipping OCSP SCGI tests"
    echo "Install nginx to run these tests: sudo apt-get install nginx"
    exit $EXIT_SKIP
fi

# Check for openssl
if ! command -v openssl &> /dev/null; then
    echo "openssl not found - skipping OCSP SCGI tests"
    exit $EXIT_SKIP
fi

# Check for wolfCLU binary
if [ ! -x "$WOLFCLU_BIN" ]; then
    echo "wolfCLU binary not found or not executable: $WOLFCLU_BIN"
    echo "Build wolfCLU first: make"
    exit $EXIT_SKIP
fi

# Check for certificates
if [ ! -d "$CERTS_DIR" ]; then
    echo "Certificates directory not found: $CERTS_DIR"
    exit $EXIT_SKIP
fi

echo "Prerequisites check passed"
echo "wolfCLU: $WOLFCLU_BIN"
echo "Certificates: $CERTS_DIR"
echo "Temp directory: $TEMP_DIR"
echo "Logs: $LOG_DIR"
if [ "$KEEP_TEMP" = "1" ]; then
    echo "Keep temp: YES (will preserve on exit)"
fi
echo ""

# Create log directory
mkdir -p "$LOG_DIR"

# Create nginx temporary directories
mkdir -p "$TEMP_DIR/nginx_client_body"
mkdir -p "$TEMP_DIR/nginx_proxy"
mkdir -p "$TEMP_DIR/nginx_fastcgi"
mkdir -p "$TEMP_DIR/nginx_uwsgi"
mkdir -p "$TEMP_DIR/nginx_scgi"

# Generate nginx configuration with proper temp directory paths
cat > "$TEMP_DIR/nginx.conf" <<EOF
# nginx configuration for OCSP SCGI tests
# This config proxies HTTP OCSP requests to a wolfCLU SCGI backend

daemon off;
error_log $TEMP_DIR/nginx-error.log warn;
pid $TEMP_DIR/nginx.pid;

events {
    worker_connections 1024;
}

http {
    access_log $TEMP_DIR/nginx-access.log;
    
    # Temporary directories
    client_body_temp_path $TEMP_DIR/nginx_client_body;
    proxy_temp_path $TEMP_DIR/nginx_proxy;
    fastcgi_temp_path $TEMP_DIR/nginx_fastcgi;
    uwsgi_temp_path $TEMP_DIR/nginx_uwsgi;
    scgi_temp_path $TEMP_DIR/nginx_scgi;
    
    server {
        listen 8080;
        server_name localhost;
        
        location /ocsp {
            scgi_pass localhost:6961;
            include $SCRIPT_DIR/scgi_params;
            
            scgi_connect_timeout 5s;
            scgi_send_timeout 10s;
            scgi_read_timeout 10s;
        }
    }
}
EOF

# Test helper function to setup index file
setup_index() {
    local mode="$1"
    
    rm -f "$TEST_DIR/index.txt" "$TEST_DIR/index.txt.attr"
    
    case "$mode" in
        "valid")
            printf "V\t991231235959Z\t\t01\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" > "$TEST_DIR/index.txt"
            ;;
        "revoked")
            printf "R\t991231235959Z\t200101000000Z\t01\tunknown\t/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n" > "$TEST_DIR/index.txt"
            ;;
        "empty")
            touch "$TEST_DIR/index.txt"
            ;;
        *)
            echo "Unknown mode: $mode"
            return 1
            ;;
    esac
    
    echo "unique_subject = no" > "$TEST_DIR/index.txt.attr"
}

# Test helper function
# Usage: run_test <name> <index_setup> <expected_status> [rsigner] [rkey]
run_test() {
    local test_name="$1"
    local index_setup="$2"
    local expected_status="$3"
    local rsigner="${4:-$CERTS_DIR/ca-cert.pem}"
    local rkey="${5:-$CERTS_DIR/ca-key.pem}"
    
    echo ""
    echo "======================================"
    echo "Test: $test_name"
    echo "======================================"
    
    # Setup index file
    echo "Setting up index file..."
    setup_index "$index_setup"
    
    # Restart wolfCLU SCGI responder with new index
    if [ -n "$WOLFCLU_PID" ] && kill -0 "$WOLFCLU_PID" 2>/dev/null; then
        echo "Restarting wolfCLU SCGI responder..."
        kill "$WOLFCLU_PID"
        wait "$WOLFCLU_PID" 2>/dev/null || true
    fi
    
    # Start wolfCLU SCGI responder
    echo "Starting wolfCLU SCGI responder (rsigner: $(basename "$rsigner"))..."
    "$WOLFCLU_BIN" ocsp -scgi \
        -port 6961 \
        -index "$TEST_DIR/index.txt" \
        -rsigner "$rsigner" \
        -rkey "$rkey" \
        -CA "$CERTS_DIR/ca-cert.pem" \
        > "$LOG_DIR/wolfclu-scgi.log" 2>&1 &
    WOLFCLU_PID=$!
    
    # Wait for responder to start
    sleep 0.5
    
    if ! kill -0 "$WOLFCLU_PID" 2>/dev/null; then
        echo "ERROR: wolfCLU SCGI responder failed to start"
        cat "$LOG_DIR/wolfclu-scgi.log"
        return $EXIT_FAILURE
    fi
    
    echo "wolfCLU SCGI responder started (PID: $WOLFCLU_PID)"
    
    # Make OCSP request via nginx
    echo "Making OCSP request..."
    
    # Send OCSP request via HTTP to nginx (which forwards via SCGI to wolfCLU)
    # openssl ocsp handles the entire HTTP transaction
    OCSP_OUTPUT=$(openssl ocsp \
        -issuer "$CERTS_DIR/ca-cert.pem" \
        -cert "$CERTS_DIR/server-cert.pem" \
        -CAfile "$CERTS_DIR/ca-cert.pem" \
        -url http://localhost:8080/ocsp 2>&1)
    
    OCSP_EXIT_CODE=$?
    
    echo "$OCSP_OUTPUT"
    
    # Check if the request was successful
    if [ $OCSP_EXIT_CODE -eq 0 ]; then
        if echo "$OCSP_OUTPUT" | grep -q "$expected_status"; then
            echo "✓ Test PASSED: Found expected status '$expected_status'"
            return $EXIT_SUCCESS
        else
            echo "✗ Test FAILED: Expected '$expected_status' but got different status"
            return $EXIT_FAILURE
        fi
    else
        echo "✗ Test FAILED: OCSP request failed with exit code $OCSP_EXIT_CODE"
        return $EXIT_FAILURE
    fi
}

# Start nginx
echo "Starting nginx..."

nginx -c "$TEMP_DIR/nginx.conf" > "$LOG_DIR/nginx-startup.log" 2>&1 &
NGINX_PID=$!
sleep 0.5

if ! kill -0 "$NGINX_PID" 2>/dev/null; then
    echo "ERROR: nginx failed to start"
    cat "$LOG_DIR/nginx-startup.log"
    exit $EXIT_FAILURE
fi

echo "nginx started (PID: $NGINX_PID)"

# Run tests
FAILED_TESTS=0
PASSED_TESTS=0

# Test 1: Valid certificate
if run_test "Valid certificate (good status)" "valid" "good"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 2: Revoked certificate
if run_test "Revoked certificate" "revoked" "revoked"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 3: Valid certificate after revoked (stateless verification)
if run_test "Valid certificate again (stateless)" "valid" "good"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 4: Multiple requests to same responder
echo ""
echo "======================================"
echo "Test: Multiple sequential requests"
echo "======================================"

MULTI_REQUEST_SUCCESS=1
for i in 1 2 3; do
    echo "Request $i of 3..."
    
    # Send OCSP request via openssl (handles HTTP internally)
    if openssl ocsp \
        -issuer "$CERTS_DIR/ca-cert.pem" \
        -cert "$CERTS_DIR/server-cert.pem" \
        -CAfile "$CERTS_DIR/ca-cert.pem" \
        -url http://localhost:8080/ocsp > /dev/null 2>&1; then
        echo "✓ Request $i successful"
    else
        echo "✗ Request $i failed"
        MULTI_REQUEST_SUCCESS=0
        break
    fi
done

if [ "$MULTI_REQUEST_SUCCESS" = "1" ]; then
    echo "✓ Test PASSED: All 3 requests successful"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo "✗ Test FAILED: Not all requests successful"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# --- Tests with authorized/delegated OCSP responder ---

# Test 5: Valid certificate with authorized responder
if run_test "Valid certificate with authorized responder" "valid" "good" \
    "$CERTS_DIR/ocsp-responder-cert.pem" "$CERTS_DIR/ocsp-responder-key.pem"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 6: Revoked certificate with authorized responder
if run_test "Revoked certificate with authorized responder" "revoked" "revoked" \
    "$CERTS_DIR/ocsp-responder-cert.pem" "$CERTS_DIR/ocsp-responder-key.pem"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 7: Valid certificate after revoked with authorized responder (stateless)
if run_test "Valid certificate again with authorized responder (stateless)" "valid" "good" \
    "$CERTS_DIR/ocsp-responder-cert.pem" "$CERTS_DIR/ocsp-responder-key.pem"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 8: Multiple requests with authorized responder
echo ""
echo "======================================"
echo "Test: Multiple sequential requests with authorized responder"
echo "======================================"

setup_index "valid"

# Restart with authorized responder
if [ -n "$WOLFCLU_PID" ] && kill -0 "$WOLFCLU_PID" 2>/dev/null; then
    kill "$WOLFCLU_PID"
    wait "$WOLFCLU_PID" 2>/dev/null || true
fi

"$WOLFCLU_BIN" ocsp -scgi \
    -port 6961 \
    -index "$TEST_DIR/index.txt" \
    -rsigner "$CERTS_DIR/ocsp-responder-cert.pem" \
    -rkey "$CERTS_DIR/ocsp-responder-key.pem" \
    -CA "$CERTS_DIR/ca-cert.pem" \
    > "$LOG_DIR/wolfclu-scgi.log" 2>&1 &
WOLFCLU_PID=$!
sleep 0.5

if ! kill -0 "$WOLFCLU_PID" 2>/dev/null; then
    echo "ERROR: wolfCLU SCGI responder failed to start"
    cat "$LOG_DIR/wolfclu-scgi.log"
    FAILED_TESTS=$((FAILED_TESTS + 1))
else
    MULTI_REQUEST_SUCCESS=1
    for i in 1 2 3; do
        echo "Request $i of 3..."
        if openssl ocsp \
            -issuer "$CERTS_DIR/ca-cert.pem" \
            -cert "$CERTS_DIR/server-cert.pem" \
            -CAfile "$CERTS_DIR/ca-cert.pem" \
            -url http://localhost:8080/ocsp > /dev/null 2>&1; then
            echo "✓ Request $i successful"
        else
            echo "✗ Request $i failed"
            MULTI_REQUEST_SUCCESS=0
            break
        fi
    done

    if [ "$MULTI_REQUEST_SUCCESS" = "1" ]; then
        echo "✓ Test PASSED: All 3 requests successful"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "✗ Test FAILED: Not all requests successful"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
fi

# Stop the last responder and verify graceful shutdown
echo ""
echo "======================================"
echo "Verifying graceful shutdown"
echo "======================================"

if [ -n "$WOLFCLU_PID" ] && kill -0 "$WOLFCLU_PID" 2>/dev/null; then
    echo "Stopping wolfCLU SCGI responder..."
    kill "$WOLFCLU_PID" 2>/dev/null || true
    wait "$WOLFCLU_PID" 2>/dev/null || true
    WOLFCLU_PID=""
fi

# Check for graceful exit message in logs
if [ -f "$LOG_DIR/wolfclu-scgi.log" ]; then
    if grep -q "wolfssl exiting gracefully" "$LOG_DIR/wolfclu-scgi.log"; then
        echo "✓ Found graceful exit message in wolfclu-scgi.log"
    else
        echo "✗ ERROR: No 'wolfssl exiting gracefully' message found in wolfclu-scgi.log"
        echo "  The responder did not shut down gracefully"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "✗ ERROR: wolfclu-scgi.log not found"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Summary
echo ""
echo "======================================"
echo "Test Summary"
echo "======================================"
echo "Passed: $PASSED_TESTS"
echo "Failed: $FAILED_TESTS"
echo "======================================"

if [ "$FAILED_TESTS" -gt 0 ]; then
    TESTS_FAILED=1
    echo "Some tests failed. Check logs above."
    exit $EXIT_FAILURE
else
    echo "All tests passed!"
    exit $EXIT_SUCCESS
fi
