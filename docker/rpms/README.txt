The rpm build is completely containerized and has no host dependencies
except the following repos that need to be enabled on the rhel8 host so
the container can import them. Additionally the subscription manager
on the host needs to be setup to run in container mode since the
container itself will run as a non root user.

Host repos to be enabled
========================

repo id                                    repo name
codeready-builder-for-rhel-8-x86_64-rpms   Red Hat CodeReady Linux Builder for RHEL 8 x86_64 (RPMs)
epel                                       Extra Packages for Enterprise Linux 8 - x86_64
rhel-8-for-x86_64-appstream-rpms           Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms              Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)

When setup correectly the following will be seen on a yum repolist
inside a container.

[noiro@slave-06-rhel8 ~]$ podman run -it ubi8 sh
sh-4.4# yum repolist
Updating Subscription Management repositories.
Unable to read consumer identity
subscription-manager is operating in container mode.
repo id                                repo name
rhel-8-for-x86_64-appstream-rpms       Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms          Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
ubi-8-appstream-rpms                   Red Hat Universal Base Image 8 (RPMs) - AppStream
ubi-8-baseos-rpms                      Red Hat Universal Base Image 8 (RPMs) - BaseOS
ubi-8-codeready-builder-rpms           Red Hat Universal Base Image 8 (RPMs) - CodeReady Builder

Usage
=====

There are 2 docker files and 2 build scripts corresponding to them.

A. Dockerfile-opflexrpm-build-base / build_opflex_baserpm.sh
invoked as ./build_opflex_baserpm.sh noiro latest proxy.esl.cisco.com

The last argument is optional unless running on a lab vm that needs proxy in
which case it would be the name of the proxy.
This script will build noiro/opflexrpm-build-base:latest
This image need not be build unless the opflex dependencies it installs within
change. These rarely change.

These dependencies are
1. 3rdparty-rpm
2. ovs
3. libuv (built but not used because the system provided one compiles just fine)
4. prometheus-cpp
5. rapidjson

B. Dockerfile-opflexrpm-build / build_opflexrpm.sh
invoked as ./build_opflexrpm.sh noiro latest noiro/opflexrpm-build-base:latest master 1.1
3rd argument is the base image that was build in step A
4th argument is optional to build a particular branch, default master
5th argument is optional to build rpms with a particular build number, default private

This script will build noiro/opflexrpm-build:latest and additionally copy all the opflexrpm
artifacts to /root/opflexrpms.tar.gz inside the container and also copy them out of the
container into the current directly.

The result will be opflexrpms-1.1.tar.gz that can be posted to the customer for
installing inside the openstack container
