#!/bin/bash

if [ "$TEST_SUITE" == "travis-build.sh" ]; then
  echo "Generating coverage report..."
  lcov --capture --directory . --output-file coverage-all.info > /dev/null 2>&1
  lcov --remove coverage-all.info -o coverage-all.info \
    '/usr/include/*' '/usr/local/include/*' '*/test/*' > /dev/null 2>&1

  echo "Uploading to coveralls.io..."
  cpp-coveralls \
    --lcov-file coverage-all.info \
    --exclude '/usr/include' \
    --exclude '/usr/local/include' \
    --exclude-pattern '.*/test/.*' \
    --gcov-options '\-lp' > /dev/null 2>&1

  echo "Coverage upload complete."
fi