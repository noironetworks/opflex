#!/bin/bash
set -o errtrace
set -x

python3 -m pip install --upgrade --user pip setuptools wheel packaging
python3 -m pip install --upgrade --user cpp-coveralls PyYAML
export PATH="$HOME/.local/bin:$PATH"

# Patch cpp-coveralls for PyYAML Loader API
COVERALLS_INIT=$(python3 -c "import site, os; print(os.path.join(site.getusersitepackages(), 'cpp_coveralls', '__init__.py'))")
sed -i 's/yaml.load(fp)/yaml.safe_load(fp)/' "$COVERALLS_INIT"

# Install .deb artifacts
wget https://travisci-static-artifacts-dd485362-9714-11ea-bb37-0242ac130002.s3.us-east-2.amazonaws.com/artifacts.tgz
tar -xvzf artifacts.tgz
sudo dpkg -i jammy/libnoiro-openvswitch_2.12.0-1_amd64.deb
sudo dpkg -i jammy/libnoiro-openvswitch-dev_2.12.0-1_amd64.deb
sudo dpkg -i prometheus-cpp_1.0.1_amd64.deb

# Ensure pkgconfig dir exists
sudo mkdir -p /usr/local/share/pkgconfig

# Build grpc
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
    sudo make install
    popd
    popd
else
    echo "using cached grpc"
    pushd grpc
    # Ensure cmake/build exists + is configured
    mkdir -p cmake/build
    pushd cmake/build
    if [ ! -f Makefile ]; then
        cmake -DgRPC_INSTALL=ON -DgRPC_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ../..
        make -j4
    fi
    sudo make install
    popd
    popd
fi

# Copy .pc files
sudo cp ../grpc/third_party/re2/re2.pc /usr/local/share/pkgconfig/
sudo cp ../grpc/third_party/protobuf/*.pc /usr/local/share/pkgconfig/
sudo cp ../grpc/libs/opt/pkgconfig/*.pc /usr/local/share/pkgconfig/

popd