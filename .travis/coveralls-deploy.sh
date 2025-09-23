#!/bin/bash

if [ "$TEST_SUITE" == "travis-build.sh" ]; then
  # Capture with early filtering - prevents processing unwanted files
  lcov --capture \
       --directory . \
       --base-directory "$(pwd)" \
       --no-external \
       --ignore-errors gcov,source \
       --exclude '/usr/include/*' \
       --exclude '/usr/local/include/*' \
       --exclude '*/test/*' \
       --exclude '*/cmd/gbp_inspect.cpp' \
       --exclude '*/cmd/mcast_daemon.cpp' \
       --exclude '*/cmd/opflex_agent.cpp' \
       --exclude '*/cmd/integration-test/*' \
       --exclude '*/debian/*' \
       --exclude '*/rpm/*' \
       --exclude '*/m4/*' \
       --exclude '*/doc/*' \
       --exclude '*/sample/*' \
       --exclude '*/ovs/*' \
       --exclude '*/autogen.sh' \
       --exclude '*configure.ac' \
       --exclude '*Makefile.am' \
       --exclude '*.in' \
       --exclude '*/Doxyfile*' \
       --output-file coverage-all.info \
       >/dev/null 2>&1


  coveralls --lcov-file coverage-all.info \
    --gcov-options '\-lp' \
    >/dev/null 2>&1
fi