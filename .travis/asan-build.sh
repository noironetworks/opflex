#!/bin/bash

set -o errtrace
set -x

trap 'catch $? $LINENO' ERR

catch() {
  echo "Error $1 occurred on $2"
}

pushd libopflex
set -e
./autogen.sh
./configure --enable-asan &> /dev/null
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

git apply .travis/agent_test_log.patch
pushd agent-ovs
./autogen.sh &> /dev/null
./configure --enable-asan &> /dev/null
make -j2
sudo make install
set +e
make check
result=$?
find . -name test-suite.log|xargs cat
popd

exit $result
