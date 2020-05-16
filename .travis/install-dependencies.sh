#!/bin/bash

set -o errtrace
set -x

wget https://travisci-static-artifacts-dd485362-9714-11ea-bb37-0242ac130002.s3.us-east-2.amazonaws.com/artifacts.tgz
tar -xvzf artifacts.tgz
sudo dpkg -i libnoiro-openvswitch_2.12.0-1_amd64.deb
sudo dpkg -i libnoiro-openvswitch-dev_2.12.0-1_amd64.deb
sudo dpkg -i prometheus-cpp_0.9.0_amd64.deb
