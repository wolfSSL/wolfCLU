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

./wolfssl s_server -port 11111 -key ./certs/server-key.pem\
    -cert ./certs/server-cert.pem -noVerify &
pid_server=$!
sleep 0.001
./wolfssl s_client -connect 127.0.0.1:11111

sleep 0.1
# Check if the server process has already completed
if ps $pid_server; then
    echo "s_server did not terminate successfully."
    kill $pid_server
    exit 99
fi
echo "Done"
exit 0