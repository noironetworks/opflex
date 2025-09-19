if [ "$TEST_SUITE" == "travis-build.sh" ]; then
  lcov --capture \
       --directory . \
       --base-directory "$(pwd)" \
       --no-external \
       --ignore-errors gcov,source \
       --output-file coverage-all.info \
       >/dev/null 2>/dev/null

  #lcov --capture --directory . --output-file coverage-all.info >/dev/null 2>/dev/null
  
  lcov --remove coverage-all.info -o coverage-all.info \
  '/usr/include/*' '/usr/local/include/*' '*/test/*' \
  '*/cmd/gbp_inspect.cpp' '*/cmd/mcast_daemon.cpp' '*/cmd/opflex_agent.cpp' \
  '*/cmd/integration-test/*' '*/debian/*' '*/rpm/*' '*/m4/*' '*/doc/*' \
  '*/sample/*' '*/ovs/*' '*/autogen.sh' '*configure.ac' '*Makefile.am' '*.in' \
  '*/Doxyfile*' >/dev/null 2>/dev/null 


  coveralls --lcov-file coverage-all.info \
    --exclude '/usr/include' \
    --exclude '/usr/local/include' \
    --exclude-pattern '.*/(test|integration-test|debian|rpm|m4|doc|sample|ovs)/.*' \
    --exclude-pattern '.*/cmd/(gbp_inspect|mcast_daemon|opflex_agent)\.cpp' \
    --exclude-pattern '.*(configure\.ac|Makefile\.am|\.in|Doxyfile.*)' \
    --gcov-options '\-lp'
fi
