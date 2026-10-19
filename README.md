# opflex

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/c933707764264654a804c6b522f0a57e)](https://app.codacy.com/gh/noironetworks/opflex?utm_source=github.com&utm_medium=referral&utm_content=noironetworks/opflex&utm_campaign=Badge_Grade_Dashboard)
[![Build Status](https://travis-ci.com/noironetworks/opflex.svg?branch=master)](https://travis-ci.com/noironetworks/opflex)
[![Coverage Status](https://coveralls.io/repos/github/noironetworks/opflex/badge.svg?branch=master)](https://coveralls.io/github/noironetworks/opflex?branch=master)

[Building and Running](docs/building_and_running.md)

[Prometheus integration](docs/prometheus.md)

[Configuring and using drop logs](docs/drop_logs.md)

## Running unit tests

The PR workflow in `.github/workflows/opflex-images.yml` runs the existing
`.travis/travis-build.sh` script on Ubuntu 22.04 with the required development
dependencies installed. It builds and tests `libopflex`, generates and builds
`libmodelgbp` with Genie, then builds and tests `agent-ovs`.

The default test configuration enables coverage and profiling, but not gRPC.
This native build does not build or publish container images. The workflow
uploads build logs, test reports, and coverage as Actions artifacts.
