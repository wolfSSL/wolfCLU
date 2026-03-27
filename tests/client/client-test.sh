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


echo | ./wolfssl s_client -connect www.google.com:443 | ./wolfssl x509 -outform pem -out tmp.crt

RESULT=`./wolfssl x509 -in tmp.crt`

echo $RESULT | grep -e "-----BEGIN CERTIFICATE-----"
if [ $? != 0 ]; then
    echo "Expected x509 input not found"
    exit 99
fi

rm tmp.crt

# Regression tests: shell injection via hostname must not execute injected command.
# Applies to the WOLFSSL_USE_POPEN_HOST path where peer is concatenated into a
# popen() shell command.  On other builds, getaddrinfo/gethostbyname reject
# these hostnames before any shell is involved, so the tests pass either way.
INJFILE="clu_injection_probe.txt"
rm -f "$INJFILE"

# Semicolon: "evil.com;touch clu_injection_probe.txt" passed as peer
./wolfssl s_client -connect 'evil.com;touch clu_injection_probe.txt:443' \
    2>/dev/null
if [ -f "$INJFILE" ]; then
    echo "SECURITY FAILURE: command injection via hostname (semicolon)"
    rm -f "$INJFILE"
    exit 99
fi

# Command substitution: "$(touch clu_injection_probe.txt)" passed as peer
./wolfssl s_client -connect '$(touch clu_injection_probe.txt):443' \
    2>/dev/null
if [ -f "$INJFILE" ]; then
    echo "SECURITY FAILURE: command injection via hostname (command substitution)"
    rm -f "$INJFILE"
    exit 99
fi

# Pipe: "evil.com|touch clu_injection_probe.txt" passed as peer
./wolfssl s_client -connect 'evil.com|touch clu_injection_probe.txt:443' \
    2>/dev/null
if [ -f "$INJFILE" ]; then
    echo "SECURITY FAILURE: command injection via hostname (pipe)"
    rm -f "$INJFILE"
    exit 99
fi

echo "Done"
exit 0
