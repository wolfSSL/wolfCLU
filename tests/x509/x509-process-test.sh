#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

test_case() {
    echo "testing: ./wolfssl -x509 $1"
    OUTPUT=$(./wolfssl -x509 $1)
    RESULT=$?
    if [ $RESULT != 0 ]; then
        echo "Failed when expected to pass"
        exit 99
    fi
}

fail_case() {
    echo "testing: ./wolfssl -x509 $1"
    OUTPUT=$(./wolfssl -x509 $1)
    RESULT=$?
    if [ $RESULT == 0 ]; then
        echo "Success when expected to fail"
        exit 99
    fi
}

cert_test_case() {
    echo "testing: ./wolfssl -x509 $1"
    OUTPUT=$(./wolfssl -x509 $1)
    RESULT=$?
    echo "RESULT: $RESULT"
    diff $2 $3
    RESULT=$?
    echo "RESULT OF DIFF: $RESULT"
    [ $RESULT != 0 ] && echo "DIFF FAILED" && exit 5
    echo ""
}

run1() {
    echo "TEST 1: VALID"
    echo "TEST 1.a"
    test_case "-inform pem -outform pem -in certs/ca-cert.pem -out test.pem"
    if [ ! -f test.pem ]; then
        echo "issue creating output file"
        exit 99
    fi

    echo "TEST 1.b"
    ./wolfssl x509 -in test.pem -text -noout -out test.pem
    ./wolfssl x509 -in certs/ca-cert.pem -text -noout -out ca-cert.pem
    diff "./ca-cert.pem" "./test.pem" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue with in pem out pem matching"
        exit 99
    fi
    rm -f ca-cert.pem
    rm -f test.pem

    echo "TEST 1.c"
    test_case "-inform pem -outform der -in certs/ca-cert.pem -out test.der"
    rm -f test.der

    echo "TEST 1.d"
    test_case "-inform der -outform pem -in certs/ca-cert.der"
    echo "TEST 1.e"
    test_case "-inform der -outform der -in certs/ca-cert.der -out test.der"
    rm -f test.der
    echo ""
    echo "TEST 1.f"
    test_case "-inform der -text -noout -in certs/ca-cert.der"
    echo ""
}

run2() {
    echo "TEST 2: INVALID INPUT"
    echo "TEST 2.a"
    fail_case "-inform pem -inform der"
    echo "TEST 2.b"
    fail_case "-outform pem -outform der"
    echo "TEST 2.c"
    fail_case "-inform -inform"
    echo "TEST 2.d"
    fail_case "-outform -outform"
    echo "TEST 2.e"
    fail_case "-inform pem -inform der -inform"
    echo "TEST 2.f"
    fail_case "-outform pem -outform der -outform"
    echo "TEST 2.g"
    fail_case "-inform pem -outform der -inform"
    echo "TEST 2.h"
    fail_case "-outform pem -inform der -outform"
    echo "TEST 2.i"
    fail_case "-inform"
    echo "TEST 2.j"
    fail_case "-outform"
    echo "TEST 2.k"
    fail_case "-outform pem -outform der -noout"
    echo "TEST 2.l"
    fail_case "-outform -outform -noout"
    echo "TEST 2.m"
    fail_case "-outform pem -outform der -outform -noout"
    echo "TEST 2.n"
    fail_case "-inform pem -outform der -inform -noout"
    echo "TEST 2.o"
    fail_case "-outform pem -inform der -outform -noout"
    echo "TEST 2.p"
    fail_case "-outform -noout"
    echo "TEST 2.q"
    fail_case "-inform pem -outform pem -noout"
}

run3() {
    echo "TEST3: VALID INPUT FILES"
    echo "TEST 3.a"
    #convert ca-cert.der to tmp.pem and compare to ca-cert.pem for valid transform
    ./wolfssl x509 -inform pem -in certs/ca-cert.pem -outform pem -out test.pem
    cert_test_case "-inform der -in certs/ca-cert.der -outform pem -out tmp.pem" \
                   test.pem tmp.pem
    rm -f test.pem tmp.pem
    echo "TEST 3.b"
    ./wolfssl x509 -inform pem -in certs/ca-cert.pem -outform der -out test.der
    cert_test_case "-inform pem -outform der -in certs/ca-cert.pem -out tmp.der" \
                    test.der tmp.der
    rm -f test.pem tmp.pem
}

run4() {
    echo "TEST4: INVALID INPUT FILES"
    echo "TEST 4.a"
    #convert ca-cert.der to tmp.pem and compare to ca-cert.pem for valid transform
    fail_case "-inform der -in certs/ca-cert.der
                    -in certs/ca-cert.der -outform pem -out tmp.pem"
    echo "TEST 4.b"
    fail_case "-inform der -in certs/ca-cert.der
                    -outform pem -out tmp.pem -out tmp.pem"

    echo "TEST 4.c"
    fail_case "-inform pem -outform der -in certs/ca-cert.pem
                    -out tmp.der -out tmp.der -in certs/ca-cert.pem"
    echo "TEST 4.d"
    rm -f test.der
    fail_case "-inform pem -in certs/ca-cert.der -outform der -out test.der"
    if [ -f test.der ]; then
        echo "./wolfssl x509 -inform pem -in certs/ca-cert.der -outform der -out test.der"
        echo "Should not have created output file in error case!"
        rm -f test.der
        exit 99
    fi
    rm -f test.der
    echo "TEST 4.e"
    fail_case "-inform der -in ca-cert.pem -outform der -out out.txt"
    echo "TEST 4.f"
    fail_case "-inform pem -in ca-cert.pem -outform pem -out out.txt"
}

run1
run2
run3
run4

rm -f out.txt
rm -f tmp.pem
rm -f tmp.der
