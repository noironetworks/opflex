#!/bin/bash
# usage: ./build_opflex.sh <docker-reg> <docker-tag> <docker-build-args>
set -x

OPFLEX_BRANCH=kmr2-5.2.7
DOCKER_HUB_ID=$1
DOCKER_TAG=$2
BUILDARG=$3
[ -z "$DOCKER_HUB_ID" ] && DOCKER_HUB_ID=
[ -z "$DOCKER_TAG" ] && DOCKER_TAG=
[ -z "$BUILDARG" ] && BUILDARG=
export DOCKER_HUB_ID
export DOCKER_TAG
export BUILDARG

SECOPT=
export SECOPT

DOCKER_DIR=docker/travis

OPFLEX_DIR=.
export OPFLEX_DIR

# Check if the tag contains "opflex-build-base"
if [[ "${TRAVIS_TAG}" == *"opflex-build-base"* ]]; then
  BUILD_BASE=true
else
  BUILD_BASE=false
fi

set -Eeuxo pipefail
if [[ "${BUILD_BASE}" == true ]]; then
    echo "starting opflex-base build"
    docker build $BUILDARG $SECOPT -t $DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build-base . &> /tmp/opflex-build-base.log &
    while [ ! -f  /tmp/opflex-build-base.log ]; do sleep 10; done
    tail -f /tmp/opflex-build-base.log | awk 'NR%100-1==0' &
    #while [[ "$(docker images -q $DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG 2> /dev/null)" == ""]] && [[ "$(pgrep -x 'docker' 2> /dev/null)" != '' ]]; do sleep 60; done
    while [[ "$(pgrep -x 'docker' 2> /dev/null)" != '' ]]; do sleep 60; done
else
    echo "starting opflex build"
    #docker push $DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG
    #docker pull quay.io/noirolabs/opflex-build-base:sumit-kmr2-test
    docker pull $DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG

    pushd $OPFLEX_DIR/genie
    mvn compile exec:java
    popd

    pushd $OPFLEX_DIR
    cd ..
    tar cvfz opflex.tgz opflex
    cp opflex.tgz opflex/
    popd

    docker build $BUILDARG --build-arg DOCKER_HUB_ID=$DOCKER_HUB_ID --build-arg DOCKER_TAG=$DOCKER_TAG $SECOPT -t $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build $OPFLEX_DIR &> /tmp/opflex-build.log &
    #docker build $SECOPT -t $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG -f $DOCKER_DIR/Dockerfile-opflex-build $OPFLEX_DIR
    ##docker push $DOCKER_HUB_ID/opflex-build$DOCKER_TAG
    while [ ! -f  /tmp/opflex-build.log ]; do sleep 10; done
    tail -f /tmp/opflex-build.log | awk 'NR%100-1==0' &

    #while [[ "$(docker images -q $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG 2> /dev/null)" == ""]] && [[ "$(pgrep -x 'docker' 2> /dev/null)" != "" ]]; do sleep 60; done
    while [[ "$(pgrep -x 'docker' 2> /dev/null)" != '' ]]; do sleep 60; tail -n 2 /tmp/opflex-build.log; done

    ################## Copy everything from build into host ###############
    rm -Rf build/opflex/dist
    mkdir -p build/opflex/dist
    mkdir -p build/opflex/dist/agent
    mkdir -p build/opflex/dist/server
    mkdir -p build/opflex/dist/usr/local/lib64
    id=$(docker create $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG)
    docker cp -L $id:/usr/local/lib64 build/opflex/dist/usr/local
    docker rm -v $id

    docker run $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG tar -c -C /usr/local \
        bin/opflex_agent bin/gbp_inspect bin/mcast_daemon bin/opflex_server \
        | tar -x -C build/opflex/dist
    docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c 'find lib \(\
             -name '\''libopflex*.so*'\'' -o \
             -name '\''libmodelgbp*so*'\'' -o \
             -name '\''libopenvswitch*so*'\'' -o \
             -name '\''libsflow*so*'\'' -o \
             -name '\''libprometheus-cpp-*so*'\'' -o \
             -name '\''libgrpc*so*'\'' -o \
             -name '\''libproto*so*'\'' -o \
             -name '\''libre2*so*'\'' -o \
             -name '\''libupb*so*'\'' -o \
             -name '\''libabsl*so*'\'' -o \
             -name '\''libssl*so*'\'' -o \
             -name '\''libcrypto*so*'\'' -o \
             -name '\''libaddress_sorting*so*'\'' -o \
             -name '\''libgpr*so*'\'' -o \
             -name '\''libofproto*so*'\'' \
             \) ! -name '\''*debug'\'' \
            | xargs tar -c ' \
        | tar -x -C build/opflex/dist
    docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c 'find lib \(\
             -name '\''libopflex*.so*'\'' -o \
             -name '\''libmodelgbp*so*'\'' -o \
             -name '\''libopenvswitch*so*'\'' -o \
             -name '\''libsflow*so*'\'' -o \
             -name '\''libprometheus-cpp-*so*'\'' -o \
             -name '\''libofproto*so*'\'' \
             \) ! -name '\''*debug'\'' \
            | xargs tar -c ' \
        | tar -x -C build/opflex/dist/agent
    docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c 'find lib \(\
             -name '\''libopflex*.so*'\'' -o \
             -name '\''libmodelgbp*so*'\'' -o \
             -name '\''libprometheus-cpp-*so*'\'' -o \
             -name '\''libgrpc*so*'\'' -o \
             -name '\''libproto*so*'\'' -o \
             -name '\''libre2*so*'\'' -o \
             -name '\''libupb*so*'\'' -o \
             -name '\''libabsl*so*'\'' -o \
             -name '\''libssl*so*'\'' -o \
             -name '\''libcrypto*so*'\'' -o \
             -name '\''libaddress_sorting*so*'\'' -o \
             -name '\''libgpr*so*'\'' \
             \) ! -name '\''*debug'\'' \
            | xargs tar -c ' \
        | tar -x -C build/opflex/dist/server
    docker run -w /usr/local $DOCKER_HUB_ID/opflex-build:$DOCKER_TAG /bin/sh -c \
      'find lib bin -name '\''*.debug'\'' | xargs tar -cz' \
       > opflex-debuginfo.tar.gz
    cp $DOCKER_DIR/launch-opflexagent.sh build/opflex/dist/bin/
    cp $DOCKER_DIR/launch-mcastdaemon.sh build/opflex/dist/bin/
    cp $DOCKER_DIR/launch-opflexserver.sh build/opflex/dist/bin/
    cp $DOCKER_DIR/Dockerfile-opflex build/opflex/dist/
    cp $DOCKER_DIR/Dockerfile-opflexserver build/opflex/dist/
    mkdir build/opflex/dist/licenses
    cp $DOCKER_DIR/../licenses/* build/opflex/dist/licenses

    #######################################################################################
    docker build $BUILDARG -t $DOCKER_HUB_ID/opflex:$DOCKER_TAG -f ./build/opflex/dist/Dockerfile-opflex build/opflex/dist
fi