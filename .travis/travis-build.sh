#!/bin/bash

set -o errtrace
set -x

export BOOST_TEST_COLOR_OUTPUT=yes
export BOOST_TEST_LOG_LEVEL=test_suite

pushd libopflex
./autogen.sh
./configure --enable-coverage --enable-gprof &> /dev/null
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
./configure --enable-coverage --enable-gprof &> /dev/null
make -j2
sudo make install
make check
find . -name test-suite.log|xargs cat

# Dump gprof output:
# Note:
# - https://linux.die.net/man/1/gprof
# - https://ftp.gnu.org/old-gnu/Manuals/gprof-2.9.1/html_mono/gprof.html
printf '\n\n'
echo "Gprof - top methods consuming cpu cycles:"
gprof -b -p .libs/agent_test gmon.out | head -n 20

printf '\n\n'
echo "Gprof - call graphs of first few top methods:"
gprof -b -P .libs/agent_test gmon.out | head -n 100
popd

printf '\n\n'
echo "Sorted time taken per unit test:"
find . -name *_test.log | xargs grep "Leaving test case" | \
    awk '{gsub(/\"|\;/,"")}1' | sed 's/..$//; s/\// /g; s/\:/ /g' | \
    awk '{print $NF , $6 , $10}' | sort -nrk1 | \
    awk '{print "time:"$1"us", "test:"$2":"$3}'
