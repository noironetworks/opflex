#!/bin/bash

set -o errtrace
set -x

trap 'catch $? $LINENO' ERR

catch() {
  echo "Error $1 occurred on $2"
}

export BOOST_TEST_COLOR_OUTPUT=yes
export BOOST_TEST_LOG_LEVEL=test_suite

pushd agent-ovs
# ./autogen.sh &> /dev/null
# ./configure --enable-coverage --enable-gprof --enable-grpc &> /dev/null
# make -j2
# sudo make install
# set +e
make check
result=$?
find . -name test-suite.log|xargs cat | grep -A 20 -B 20 -i failed

popd

printf '\n\n'
echo "Sorted time taken per unit test:"
find . -name *_test.log | xargs grep "Leaving test case" | \
    awk '{gsub(/\"|\;/,"")}1' | sed 's/..$//; s/\// /g; s/\:/ /g' | \
    awk '{print $NF , $6 , $10}' | sort -nrk1 | \
    awk '{print "time:"$1"us", "test:"$2":"$3}'

exit $result