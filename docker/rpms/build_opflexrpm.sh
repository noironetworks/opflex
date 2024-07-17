#!/bin/bash
# Usage ./build_opflexrpm.sh <docker_user> <docker_tag> <baseimage> <branch> <buildversion>
# branch default master
# buildversion default private
set -x

if test "$#" -lt 3; then
  echo "Usage: ./build_opflexrpm.sh <docker_user> <docker_tag> <baseimage> <branch> <buildversion>"
  echo "branch default master"
  echo "buildversion default private"
  exit -1
fi

DOCKER_USER=$1
DOCKER_TAG=$2
BASEIMAGE=$3
BRANCH=$4
BUILDVER=$5

if [ -z "$4" ]; then
  BRANCH="master"
fi

if [ -z "$5" ]; then
  BUILDVER="private"
fi

docker build --no-cache --build-arg baseimage="$BASEIMAGE" --build-arg branch="$BRANCH" \
   --build-arg buildversion="$BUILDVER"  -t "$DOCKER_USER"/opflexrpm-build:"$DOCKER_TAG" \
   -f ./docker/rpms/Dockerfile-opflexrpm-build .
cid=$(docker create "$DOCKER_USER"/opflexrpm-build:"$DOCKER_TAG")
docker cp "$cid:/root/opflexrpms-$BUILDVER.tar.gz" ./opflexrpms-"$BUILDVER".tar.gz
docker rm "$cid"
