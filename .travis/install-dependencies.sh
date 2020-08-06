#!/bin/bash

set -o errtrace
set -x

wget https://travisci-static-artifacts-dd485362-9714-11ea-bb37-0242ac130002.s3.us-east-2.amazonaws.com/artifacts.tgz
tar -xvzf artifacts.tgz
sudo dpkg -i libnoiro-openvswitch_2.12.0-1_amd64.deb
sudo dpkg -i libnoiro-openvswitch-dev_2.12.0-1_amd64.deb
sudo dpkg -i prometheus-cpp_0.9.0_amd64.deb

mkdir -p ../grpc
pushd ../grpc
if ! [ "$(ls -A .)" ]; then
    git clone https://github.com/grpc/grpc
    pushd grpc
    git checkout 5052efd666ab6fdda2a4b3045569f70ce0c5fa57
    git submodule update --init
    make -j2
    pushd third_party/protobuf
    ./autogen.sh
    ./configure
    make -j2
    popd
    popd
else
    echo "using cached grpc"
fi
pushd grpc
sudo make install
pushd third_party/protobuf
sudo make install
popd
popd
popd
