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

READYFILE="readyfile"
rm -f $READYFILE

# Build s_server in background
./wolfssl s_server -port 11111 -key ./certs/server-key.pem\
    -cert ./certs/server-cert.pem -noVerify -readyFile $READYFILE &
pid_server=$!

counter=0
# If readyfile exists, the server is considered ready.
while [ ! -e $READYFILE ] && [ "$counter" -lt 100 ]; do
    ((counter++))
    sleep 0.01
done
rm -f $READYFILE

# Timeout
if [ "$counter" -eq 100 ]; then
    echo "s_server was not built successfully."
    kill $pid_server
    exit 99
fi

echo `ps | grep wolfssl`
./wolfssl s_client -connect 127.0.0.1:11111 -CAfile ./certs/ca-cert.pem
if [ $? != 0 ] ; then
    echo "test communication failed."
    exit 99
fi

echo "Done"
exit 0