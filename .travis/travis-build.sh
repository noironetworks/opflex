#!/bin/bash

set -o errtrace
set -x

export BOOST_TEST_COLOR_OUTPUT=yes
export BOOST_TEST_LOG_LEVEL=test_suite

pushd libopflex
./autogen.sh
./configure --enable-coverage &> /dev/null
make -j2
make check
sudo make install
find . -name test-suite.log|xargs cat
popd

pushd genie
mvn compile exec:java &> /dev/null
pushd target/libmodelgbp
bash autogen.sh &> /dev/null
./configure &> /dev/null
make &> /dev/null
sudo make install &> /dev/null
popd
popd

pushd agent-ovs
./autogen.sh &> /dev/null
./configure --enable-coverage &> /dev/null
make -j2
sudo make install
make check
find . -name test-suite.log|xargs cat
popd

find . -name *_test.log | xargs grep "Leaving test case" | \
    awk '{gsub(/\"|\;/,"")}1' | sed 's/..$//; s/\// /g; s/\:/ /g' | \
    awk '{print $NF , $6 , $10}' | sort -nrk1 | \
    awk '{print "time:"$1"us", "test:"$2":"$3}'
