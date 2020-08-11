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
    wget -q -O cmake-linux.sh https://github.com/Kitware/CMake/releases/download/v3.17.0/cmake-3.17.0-Linux-x86_64.sh
    mkdir -p ../cmake-tmp
    sh cmake-linux.sh -- --skip-license --prefix=../cmake-tmp
    rm cmake-linux.sh
    cmake --version
    git clone --recurse-submodules -b v1.31.0 https://github.com/grpc/grpc
    pushd grpc
    mkdir -p cmake/build
    pushd cmake/build
    cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ../..
    make -j4
    popd
    popd
else
    echo "using cached grpc"
fi
pushd grpc
sudo make install
popd
popd
