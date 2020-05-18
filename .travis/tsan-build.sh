#!/bin/bash

set -o errtrace
set -x

pushd libopflex
./autogen.sh
./configure --enable-tsan &> /dev/null
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
./configure --enable-tsan &> /dev/null
make -j2
sudo make install
make check
find . -name test-suite.log|xargs cat
popd
