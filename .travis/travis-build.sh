#!/bin/bash

set -o errtrace
set -x

trap 'catch $? $LINENO' ERR

catch() {
  echo "Error $1 occurred on $2"
}

export BOOST_TEST_COLOR_OUTPUT=yes
export BOOST_TEST_LOG_LEVEL=test_suite

pushd libopflex
set -e
./autogen.sh
./configure --enable-coverage --enable-gprof &> /dev/null
make -j2
sudo make install
set +e
make check
find . -name test-suite.log|xargs cat
popd

set -e
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
export LD_LIBRARY_PATH=/usr/local/lib
./autogen.sh &> /dev/null
./configure --enable-coverage --enable-gprof --enable-grpc &> /dev/null
make -j2
sudo make install
set +e
popd