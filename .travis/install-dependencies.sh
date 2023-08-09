#!/bin/bash

set -o errtrace
set -x

# Force openssl 1.1 on 22.04 systems, default is 3.0
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_1.1.1f-1ubuntu2.19_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1f-1ubuntu2.19_amd64.deb
wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb

sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb
sudo dpkg -i libssl-dev_1.1.1f-1ubuntu2.19_amd64.deb
sudo dpkg -i openssl_1.1.1f-1ubuntu2.19_amd64.deb

wget https://travisci-static-artifacts-dd485362-9714-11ea-bb37-0242ac130002.s3.us-east-2.amazonaws.com/artifacts.tgz
tar -xvzf artifacts.tgz

sudo dpkg -i libnoiro-openvswitch_2.12.0-1_amd64.deb
sudo dpkg -i libnoiro-openvswitch-dev_2.12.0-1_amd64.deb
sudo dpkg -i prometheus-cpp_1.0.1_amd64.deb

mkdir -p ../grpc
pushd ../grpc
if ! [ "$(ls -A .)" ]; then
    git clone -b v1.52.2 https://github.com/grpc/grpc
    pushd grpc
    git submodule update --init
    mkdir -p cmake/build
    pushd cmake/build
    cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local \
                            -DgRPC_BUILD_GRPC_PYTHON_PLUGIN=OFF -DgRPC_BUILD_CSHARP_EXT=OFF -DgRPC_BUILD_GRPC_CSHARP_PLUGIN=OFF \
                            -DgRPC_BUILD_GRPC_NODE_PLUGIN=OFF -DgRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN=OFF -DgRPC_BUILD_GRPC_PHP_PLUGIN=OFF \
                            -DgRPC_BUILD_GRPC_PYTHON_PLUGIN=OFF -DgRPC_BUILD_GRPC_RUBY_PLUGIN=OFF ../..
    make -j4
    popd
    popd
else
    echo "using cached grpc"
fi
pushd grpc/cmake/build
sudo make install
sudo cp ../../third_party/re2/re2.pc /usr/local/share/pkgconfig/
sudo cp third_party/protobuf/*.pc /usr/local/share/pkgconfig/
sudo cp libs/opt/pkgconfig/*.pc /usr/local/share/pkgconfig/
popd
popd
