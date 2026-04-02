#!/bin/bash

run_success() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_success "-bench aes-cbc -time 1"
run_success "-bench sha -time 1"
run_success "-bench md5 -time 1"

# Test missing argument value for -time (must fail gracefully, not segfault)
(./wolfssl -bench -time) 2>/dev/null
RET=$?
if [ $RET -eq 0 ]; then
    echo "Expected failure for missing -time value"
    exit 99
fi
if [ $RET -ge 129 ] && [ $RET -le 192 ]; then
    echo "Missing -time value caused signal $(($RET - 128)), expected graceful error"
    exit 99
fi

echo "Done"
exit 0
