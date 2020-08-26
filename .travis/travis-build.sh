#!/bin/bash

set -o errtrace
set -x

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

wget https://travisci-static-artifacts-dd485362-9714-11ea-bb37-0242ac130002.s3.us-east-2.amazonaws.com/artifacts.tgz
tar -xvzf artifacts.tgz
sudo dpkg -i libnoiro-openvswitch_2.12.0-1_amd64.deb
sudo dpkg -i libnoiro-openvswitch-dev_2.12.0-1_amd64.deb
sudo dpkg -i prometheus-cpp_0.9.0_amd64.deb

pushd agent-ovs
./autogen.sh &> /dev/null
./configure --enable-coverage &> /dev/null
make -j2
sudo make install
make check
find . -name test-suite.log|xargs cat
popd
