#!/bin/bash
# Usage ./build_opflex_baserpm.sh <docker_user> <docker_tag> <optional proxy>

set -x

if test "$#" -lt 2; then
  echo "Usage ./build_opflex_baserpm.sh <docker_user> <docker_tag> <optional proxy>"
  exit -1
fi

DOCKER_USER=$1
DOCKER_TAG=$2
PROXY=$3

podman build --no-cache --build-arg proxy="$PROXY" -t "$DOCKER_USER"/opflexrpm-build-base:"$DOCKER_TAG" -f ./Dockerfile-opflexrpm-build-base .
