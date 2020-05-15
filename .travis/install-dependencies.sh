#!/bin/bash

set -o errtrace
set -x

mkdir -p ../ovs
pushd ../ovs
if ! [ "$(ls -A .)" ]; then
    git clone https://github.com/openvswitch/ovs.git --branch v2.12.0 --depth 1
    pushd ovs
    ./boot.sh &> /dev/null
    ./configure  --enable-shared &> /dev/null
    make -j2 &> /dev/null
    popd
else
    echo "using cached ovs"
fi
pushd ovs
sudo make install &> /dev/null
sudo mkdir -p /usr/local/include/openvswitch/openvswitch
sudo mv /usr/local/include/openvswitch/*.h /usr/local/include/openvswitch/openvswitch
sudo mv /usr/local/include/openflow /usr/local/include/openvswitch
sudo cp -t "/usr/local/include/openvswitch/" include/*.h
sudo find lib -name "*.h" -exec cp --parents -t "/usr/local/include/openvswitch/" {} \;
popd
popd

mkdir -p ../prometheus-cpp
pushd ../prometheus-cpp
if ! [ "$(ls -A .)" ]; then
    git clone https://github.com/noironetworks/3rdparty-debian.git
    cp 3rdparty-debian/prometheus/prometheus-cpp.patch ~
    git clone https://github.com/jupp0r/prometheus-cpp.git
    pushd prometheus-cpp
    git checkout 9effb90b0c266316358680cbf862a8564eb2c2d4
    git submodule init
    git submodule update
    git apply ~/prometheus-cpp.patch
    mkdir _build && cd _build
    cmake .. -DBUILD_SHARED_LIBS=ON &> /dev/null
    make $make_args
    popd
else
    echo "using cached prometheus-cpp"
fi
pushd prometheus-cpp/_build
sudo make install &> /dev/null
popd
popd
