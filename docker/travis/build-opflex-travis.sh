#!/bin/bash
# usage: ./build_opflex.sh <docker-reg> <docker-tag> <docker-build-args>

if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  set -Eeuo pipefail
else
  set -x
fi

OPFLEX_BRANCH=kmr2-5.2.7
DOCKER_HUB_ID=${1:-}
DOCKER_TAG=${2:-}
BUILDARG=${3:-}
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

# Travis selects the phase by tag. GitHub Actions uses an explicit phase so a
# single safe Jenkins tag can orchestrate both jobs without creating a second
# tag or moving a release tag.
if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  : "${GHA_OPFLEX_BUILD_PHASE:?GHA_OPFLEX_BUILD_PHASE is required}"
  : "${GHA_PLATFORM:?GHA_PLATFORM is required}"
  [[ "${GHA_PLATFORM}" == "linux/amd64" ]] || {
    echo "Unsupported GitHub Actions platform ${GHA_PLATFORM}" >&2
    exit 1
  }
  case "${GHA_OPFLEX_BUILD_PHASE}" in
    base)
      BUILD_BASE=true
      ;;
    runtime)
      BUILD_BASE=false
      ;;
    *)
      echo "GHA_OPFLEX_BUILD_PHASE must be base or runtime" >&2
      exit 1
      ;;
  esac
  PLATFORM_ARGS=(--platform "${GHA_PLATFORM}")
else
  if [[ "${TRAVIS_TAG}" == *"opflex-build-base"* ]]; then
    BUILD_BASE=true
  else
    BUILD_BASE=false
  fi
  PLATFORM_ARGS=()
  set -Eeuxo pipefail
fi

ACTIVE_BUILD_PID=""
cleanup_active_build() {
  if [[ -n "${ACTIVE_BUILD_PID}" ]] && kill -0 "${ACTIVE_BUILD_PID}" 2>/dev/null; then
    kill "${ACTIVE_BUILD_PID}" 2>/dev/null || true
    wait "${ACTIVE_BUILD_PID}" 2>/dev/null || true
  fi
}
trap cleanup_active_build EXIT
trap 'cleanup_active_build; exit 130' INT
trap 'cleanup_active_build; exit 143' TERM

run_logged_docker_build() {
  local description=$1
  local log_file=$2
  shift 2

  rm -f "${log_file}"
  "$@" >"${log_file}" 2>&1 &
  ACTIVE_BUILD_PID=$!

  while kill -0 "${ACTIVE_BUILD_PID}" 2>/dev/null; do
    echo "${description} is still running ($(date -u +%FT%TZ)); full output is in ${log_file}"
    sleep 60
  done

  set +e
  wait "${ACTIVE_BUILD_PID}"
  local build_status=$?
  set -e
  ACTIVE_BUILD_PID=""

  if [[ "${build_status}" -ne 0 ]]; then
    echo "${description} failed; final 200 log lines follow" >&2
    tail -200 "${log_file}" >&2 || true
    return "${build_status}"
  fi
  tail -50 "${log_file}"
}

if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  BUILD_LOG_DIR="${CI_ARTIFACT_DIR:?CI_ARTIFACT_DIR is required}"
  mkdir -p "${BUILD_LOG_DIR}"
else
  BUILD_LOG_DIR=/tmp
fi

if [[ "${BUILD_BASE}" == true ]]; then
    echo "starting opflex-base build"
    run_logged_docker_build "opflex-build-base image build" "${BUILD_LOG_DIR}/opflex-build-base.log" \
      docker build "${PLATFORM_ARGS[@]}" $BUILDARG $SECOPT \
      -t "$DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG" \
      -f "$DOCKER_DIR/Dockerfile-opflex-build-base" .
else
    echo "starting opflex build"
    #docker push $DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG
    #docker pull quay.io/noirolabs/opflex-build-base:sumit-kmr2-test
    BASE_IMAGE_REF="$DOCKER_HUB_ID/opflex-build-base:$DOCKER_TAG"
    docker pull "${BASE_IMAGE_REF}"
    if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
      : "${EXPECTED_OPFLEX_BASE_DIGEST:?EXPECTED_OPFLEX_BASE_DIGEST is required}"
      [[ "${EXPECTED_OPFLEX_BASE_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
        echo "Invalid expected opflex-build-base digest ${EXPECTED_OPFLEX_BASE_DIGEST}" >&2
        exit 1
      }
      ACTUAL_BASE_REPODIGEST=$(docker image inspect \
        --format='{{index .RepoDigests 0}}' "${BASE_IMAGE_REF}")
      ACTUAL_BASE_DIGEST="${ACTUAL_BASE_REPODIGEST##*@}"
      [[ "${ACTUAL_BASE_DIGEST}" == "${EXPECTED_OPFLEX_BASE_DIGEST}" ]] || {
        echo "Pulled base digest ${ACTUAL_BASE_DIGEST}, expected ${EXPECTED_OPFLEX_BASE_DIGEST}" >&2
        exit 1
      }
      printf 'opflex_build_base_ref=%s\nopflex_build_base_digest=%s\n' \
        "${BASE_IMAGE_REF}" "${ACTUAL_BASE_DIGEST}" \
        > "${CI_ARTIFACT_DIR}/opflex-build-base-input.txt"
    fi

    pushd $OPFLEX_DIR/genie
    mvn compile exec:java
    popd

    pushd $OPFLEX_DIR
    cd ..
    if [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
      tar czf opflex.tgz opflex
    else
      tar cvfz opflex.tgz opflex
    fi
    cp opflex.tgz opflex/
    popd

    run_logged_docker_build "opflex-build image build" "${BUILD_LOG_DIR}/opflex-build.log" \
      docker build "${PLATFORM_ARGS[@]}" $BUILDARG \
      --build-arg "DOCKER_HUB_ID=$DOCKER_HUB_ID" \
      --build-arg "DOCKER_TAG=$DOCKER_TAG" $SECOPT \
      -t "$DOCKER_HUB_ID/opflex-build:$DOCKER_TAG" \
      -f "$DOCKER_DIR/Dockerfile-opflex-build" "$OPFLEX_DIR"

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
    run_logged_docker_build "opflex runtime image build" "${BUILD_LOG_DIR}/opflex.log" \
      docker build "${PLATFORM_ARGS[@]}" $BUILDARG \
      -t "$DOCKER_HUB_ID/opflex:$DOCKER_TAG" \
      -f ./build/opflex/dist/Dockerfile-opflex build/opflex/dist
fi

trap - EXIT INT TERM
