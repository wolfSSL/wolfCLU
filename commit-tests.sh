#!/bin/sh

#commit-tests.sh


# make sure basic config is ok
echo -e "\n\nTesting basic config too...\n\n"
./configure
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nBasic config ./configure failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nBasic config make test failed" && exit 1

exit 0
