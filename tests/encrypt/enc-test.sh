#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]
then
    exit 77
fi

run() {
    RESULT=`./wolfssl $1 -k "$2"`
    if [ $? != 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1 -k "$2"`
    if [ $? == 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}


run "enc -d -aes-256-cbc -nosalt -in certs/crl.der.enc -out test-dec.der" ""
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption 1"
    exit 99
fi
rm -f test-dec.der

run "enc -base64 -d -aes-256-cbc -nosalt -in certs/crl.der.enc.base64 -out test-dec.der" ""
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption 2"
    exit 99
fi
rm -f test-dec.der


# check fail cases
run_fail "enc -base64 -d -aes-256-cbc -nosalt -in certs/file-does-not-exist -out test-dec.der" ""


# encrypt and then test decrypt
run "enc -base64 -aes-256-cbc -in certs/crl.der -out test-enc.der" "test password"
run_fail "enc -base64 -d -aes-256-cbc -in test-enc.der -out test-dec.der" "bad password"
run "enc -base64 -d -aes-256-cbc -in test-enc.der -out test-dec.der" "test password"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with decryption 3"
    exit 99
fi
rm -f test-dec.der
rm -f test-enc.der

run "enc -aes-128-cbc -in ./configure.ac -out ./configure.ac.enc" "test"
run "enc -d -aes-128-cbc -in ./configure.ac.enc -out ./configure.ac.dec" "test"
diff ./configure.ac ./configure.ac.dec
if [ $? != 0 ]; then
    echo "decrypted file does not match original file"
    exit 99
fi
rm -f configure.ac.dec
rm -f configure.ac.enc

# small file test
rm -rf enc_small.txt
echo " " > enc_small.txt
run "enc -aes-128-cbc -in ./enc_small.txt -out ./enc_small.txt.enc 'test'"
run "enc -d -aes-128-cbc -in ./enc_small.txt.enc -out ./enc_small.txt.dec 'test'"
diff ./enc_small.txt ./enc_small.txt.dec
if [ $? != 0 ]; then
    echo "enc_small decrypted file does not match original file"
    exit 99
fi
rm -f enc_small.txt
rm -f enc_small.txt.dec
rm -f enc_small.txt.enc

# interoperability testing
openssl enc --help &> /dev/null
if [ $? == 0 ]; then
    openssl enc -base64 -aes-256-cbc -k 'test password' -in certs/crl.der -out test-enc.der &> /dev/null
    run "enc -base64 -d -aes-256-cbc -in test-enc.der -out test-dec.der" "test password"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue openssl enc and wolfssl dec"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    run "enc -base64 -aes-256-cbc -in certs/crl.der -out test-enc.der" "test password"
    openssl enc -base64 -d -aes-256-cbc -k 'test password' -in test-enc.der -out test-dec.der &> /dev/null
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl enc and openssl dec"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    # now try with -pbkdf2
    openssl enc -base64 -pbkdf2 -aes-256-cbc -k 'long test password' -in certs/crl.der -out test-enc.der &> /dev/null
    run "enc -base64 -d -pbkdf2 -aes-256-cbc -in test-enc.der -out test-dec.der" "long test password"
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue openssl enc and wolfssl dec pbkdf2"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der

    run "enc -base64 -pbkdf2 -aes-256-cbc -in certs/crl.der -out test-enc.der" "long test password"
    openssl enc -base64 -d -pbkdf2 -aes-256-cbc -k 'long test password' -in test-enc.der -out test-dec.der &> /dev/null
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl enc and openssl dec pbkdf2"
        exit 99
    fi
    ./wolfssl enc -base64 -d -pbkdf2 -aes-256-cbc -pass 'pass:long test password' -in test-enc.der -out test-dec.der
    if [ $? != 0 ]; then
        echo "issue wolfssl decrypt using -pass"
        exit 99
    fi
    diff "./certs/crl.der" "./test-dec.der" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue wolfssl -pass decrypt mismatch"
        exit 99
    fi
    rm -f test-dec.der
    rm -f test-enc.der
fi

# test legacy algo names
run "enc -base64 -aes-cbc-256 -in certs/crl.der -out test-enc.der" "test password"
run "enc -base64 -d -aes-cbc-256 -in test-enc.der -out test-dec.der" "test password"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with legacy name aes-cbc-256 round trip"
    exit 99
fi
rm -f test-dec.der
rm -f test-enc.der

# encrypt with legacy name, decrypt with canonical name
run "enc -aes-cbc-256 -in certs/crl.der -out test-enc.der" "test password"
run "enc -d -aes-256-cbc -in test-enc.der -out test-dec.der" "test password"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with legacy enc / canonical dec"
    exit 99
fi
rm -f test-dec.der
rm -f test-enc.der

# encrypt with canonical name, decrypt with legacy name
run "enc -aes-256-cbc -in certs/crl.der -out test-enc.der" "test password"
run "enc -d -aes-cbc-256 -in test-enc.der -out test-dec.der" "test password"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with canonical enc / legacy dec"
    exit 99
fi
rm -f test-dec.der
rm -f test-enc.der

# test legacy name with aes-cbc-128
run "enc -aes-cbc-128 -in certs/crl.der -out test-enc.der" "test password"
run "enc -d -aes-cbc-128 -in test-enc.der -out test-dec.der" "test password"
diff "./certs/crl.der" "./test-dec.der" &> /dev/null
if [ $? != 0 ]; then
    echo "issue with legacy name aes-cbc-128 round trip"
    exit 99
fi
rm -f test-dec.der
rm -f test-enc.der

# camellia: decrypt file whose size is a multiple of MAX_LEN (2 x 1024 bytes)
# to ensure the exact-boundary read case is covered (non-EVP path)
if grep -q "HAVE_CAMELLIA" wolfssl/wolfssl/options.h 2>/dev/null; then
    dd if=/dev/urandom bs=2048 count=1 of=test_maxlen_camellia.bin 2>/dev/null
    ./wolfssl encrypt camellia-cbc-128 -pwd testpwd \
        -in test_maxlen_camellia.bin -out test_maxlen_camellia.enc
    if [ $? != 0 ]; then
        echo "failed to encrypt in MAX_LEN boundary test"
        exit 99
    fi
    ./wolfssl decrypt camellia-cbc-128 \
        -in test_maxlen_camellia.enc -out test_maxlen_camellia.dec -pwd testpwd
    if [ $? != 0 ]; then
        echo "failed to decrypt in MAX_LEN boundary test"
        exit 99
    fi
    diff test_maxlen_camellia.bin test_maxlen_camellia.dec &> /dev/null
    if [ $? != 0 ]; then
        echo "MAX_LEN boundary: decrypted file does not match original"
        exit 99
    fi
    rm -f test_maxlen_camellia.bin test_maxlen_camellia.enc test_maxlen_camellia.dec
fi

# Regression tests for stack buffer overflow fix (scanf -> fgets)

# Test: -in not provided, filename supplied via stdin to exercise the inName Path
rm -f test-stdin-in.enc test-stdin-in.dec
printf "certs/crl.der\n" | ./wolfssl enc -aes-128-cbc -out test-stdin-in.enc -k "testpass" > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Failed: enc with stdin input (no -in flag)"
    exit 99
fi
rm -f test-stdin-in.dec
./wolfssl enc -d -aes-128-cbc -in test-stdin-in.enc -out test-stdin-in.dec -k "testpass" > /dev/null 2>&1
diff certs/crl.der test-stdin-in.dec > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Failed: stdin enc/dec roundtrip mismatch"
    exit 99
fi
rm -f test-stdin-in.enc test-stdin-in.dec


# Test: outNameEnc/outNameDec via stdin (non-EVP path, Camellia)
./wolfssl enc -camellia-128-cbc -in certs/crl.der -out test-cam-probe.enc -k "testpass" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    # outNameEnc: -out omitted, filename supplied via stdin
    printf "test-cam-stdin.enc\n" | ./wolfssl enc -camellia-128-cbc -in certs/crl.der -k "testpass" > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: Camellia enc with stdin output name (no -out flag)"
        exit 99
    fi

    # outNameDec: -out omitted, filename supplied via stdin
    printf "test-cam-stdin.dec\n" | ./wolfssl enc -d -camellia-128-cbc -in test-cam-stdin.enc -k "testpass" > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: Camellia dec with stdin output name (no -out flag)"
        exit 99
    fi
    diff certs/crl.der test-cam-stdin.dec > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: Camellia stdin outName enc/dec roundtrip mismatch"
        exit 99
    fi

    rm -f test-cam-stdin.enc test-cam-stdin.dec
fi

rm -f test-cam-probe.enc

# Test: inName empty line is rejected, re-prompt accepts valid filename
printf "\ncerts/crl.der\n" | ./wolfssl enc -aes-128-cbc -out test-empty-in.enc -k "testpass" > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Failed: enc should accept filename after empty line on stdin (-in path)"
    exit 99
fi
./wolfssl enc -d -aes-128-cbc -in test-empty-in.enc -out test-empty-in.dec -k "testpass" > /dev/null 2>&1
diff certs/crl.der test-empty-in.dec > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Failed: enc/dec roundtrip mismatch after empty-line re-prompt (-in path)"
    exit 99
fi
rm -f test-empty-in.enc test-empty-in.dec

# Test: outNameEnc/outNameDec empty line is rejected (non-EVP path, Camellia)
./wolfssl enc -camellia-128-cbc -in certs/crl.der -out test-cam-probe2.enc -k "testpass" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    rm -f test-cam-probe2.enc

    # outNameEnc: empty line rejected, then valid output name accepted
    printf "\ntest-cam-empty.enc\n" | ./wolfssl enc -camellia-128-cbc -in certs/crl.der -k "testpass" > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: Camellia enc should accept output name after empty line (outNameEnc)"
        exit 99
    fi

    # outNameDec: empty line rejected, then valid output name accepted
    printf "\ntest-cam-empty.dec\n" | ./wolfssl enc -d -camellia-128-cbc -in test-cam-empty.enc -k "testpass" > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: Camellia dec should accept output name after empty line (outNameDec)"
        exit 99
    fi
    diff certs/crl.der test-cam-empty.dec > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: enc/dec roundtrip mismatch after empty-line re-prompt (outNameEnc/Dec)"
        exit 99
    fi
    rm -f test-cam-empty.enc test-cam-empty.dec
fi

# Test: 'input too long' path — inName buffer overflow prevention
# Pipe a 255-char line (no newline within fgets buffer), triggering the
# strchr(buf,'\n')==NULL flush branch, then supply a valid filename.
LONG_INPUT=$(printf '%255s' ' ')
printf "%s\ncerts/crl.der\n" "$LONG_INPUT" | \
    ./wolfssl enc -aes-128-cbc -out test-toolong-in.enc -k "testpass" > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Failed: enc should recover and accept filename after too-long input (-in path)"
    exit 99
fi
./wolfssl enc -d -aes-128-cbc -in test-toolong-in.enc -out test-toolong-in.dec -k "testpass" > /dev/null 2>&1
diff certs/crl.der test-toolong-in.dec > /dev/null 2>&1
if [ $? != 0 ]; then
    echo "Failed: enc/dec roundtrip mismatch after too-long re-prompt (-in path)"
    exit 99
fi
rm -f test-toolong-in.enc test-toolong-in.dec

# Test: 'input too long' path — outNameEnc/outNameDec (non-EVP path, Camellia)
./wolfssl enc -camellia-128-cbc -in certs/crl.der -out test-cam-probe3.enc -k "testpass" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    rm -f test-cam-probe3.enc

    # outNameEnc: too-long input flushed, then valid output name accepted
    printf "%s\ntest-cam-toolong.enc\n" "$LONG_INPUT" | \
        ./wolfssl enc -camellia-128-cbc -in certs/crl.der -k "testpass" > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: Camellia enc should recover after too-long output name (outNameEnc)"
        exit 99
    fi

    # outNameDec: too-long input flushed, then valid output name accepted
    printf "%s\ntest-cam-toolong.dec\n" "$LONG_INPUT" | \
        ./wolfssl enc -d -camellia-128-cbc -in test-cam-toolong.enc -k "testpass" > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: Camellia dec should recover after too-long output name (outNameDec)"
        exit 99
    fi
    diff certs/crl.der test-cam-toolong.dec > /dev/null 2>&1
    if [ $? != 0 ]; then
        echo "Failed: enc/dec roundtrip mismatch after too-long re-prompt (outNameEnc/Dec)"
        exit 99
    fi
    rm -f test-cam-toolong.enc test-cam-toolong.dec
fi

# Test encrypt with explicit hex IV and key (verifies XSTRLCPY size is correct)
echo "testing explicit hex IV and key" > enc_hex_test.txt
./wolfssl enc -aes-128-cbc -nosalt -in enc_hex_test.txt -out enc_hex_test.enc --key 00112233445566778899aabbccddeeff --iv 00112233445566778899aabb0011aab7
if [ $? != 0 ]; then
    echo "encrypt with explicit hex key/iv failed"
    rm -f enc_hex_test.txt enc_hex_test.enc
    exit 99
fi
rm -f enc_hex_test.txt enc_hex_test.enc

echo "Done"
exit 0
