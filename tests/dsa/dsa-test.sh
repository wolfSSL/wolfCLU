#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

run() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"./wolfssl $1\""
        exit 99
    fi
}

run "dsaparam 1024"
echo $RESULT | grep -e "-----BEGIN DSA PARAMETERS-----"
if [ $? != 0 ]; then
    echo "unexpected text output found"
    echo "$RESULT"
    exit 99
fi

run_fail "dsaparam 0"
run "dsaparam -out dsa.params 1024"

rm -f dsa.params

echo "Done"
exit 0

