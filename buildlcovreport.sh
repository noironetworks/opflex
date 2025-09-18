#!/bin/bash
lcov --capture --directory . --output-file coverage-all.info --remove "/usr/include*" --remove "/usr/local/include/*" --remove "*/test/*"
genhtml coverage-all.info --output-directory out

