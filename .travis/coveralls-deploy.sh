#!/bin/bash

if [ "$TEST_SUITE" == "travis-build.sh" ]; then
  lcov --capture --directory . --output-file coverage-all.info > /dev/null
  lcov --remove coverage-all.info -o coverage-all.info '/usr/include/*' '/usr/local/include/*' '*/test/*' > /dev/null
  export COVERALLS_SERVICE_NAME=travis-pro
  coveralls --lcov-file coverage-all.info --exclude '/usr/include' --exclude '/usr/local/include' --exclude-pattern '.*/test/.*' --gcov-options '\-lp' > /dev/null
fi
