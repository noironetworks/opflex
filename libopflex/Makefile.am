#
# libopflex: a framework for developing opflex-based policy agents
# Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v1.0 which accompanies this distribution,
# and is available at http://www.eclipse.org/legal/epl-v10.html
#
###########
#
# Process this file with automake to produce a Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -Wall -Wno-sign-compare --Werror -std=c++11

if ENABLE_TSAN
  AM_CPPFLAGS += -fsanitize=thread
endif

if ENABLE_ASAN
  AM_CPPFLAGS += -fsanitize=address
endif

if ENABLE_UBSAN
  AM_CPPFLAGS += -fsanitize=undefined
endif

if ENABLE_COVERAGE
  AM_CPPFLAGS += --coverage
endif

if ENABLE_GPROF
  AM_CPPFLAGS += -pg
endif

SUBDIRS  =
SUBDIRS += util
SUBDIRS += logging
SUBDIRS += modb
SUBDIRS += comms
SUBDIRS += engine
SUBDIRS += ofcore
SUBDIRS += cwrapper
SUBDIRS += .

EXTRA_DIST =
EXTRA_DIST += debian

modb_includedir = $(includedir)/opflex/modb
modb_include_HEADERS = \
	include/opflex/modb/ClassInfo.h \
	include/opflex/modb/ConstInfo.h \
	include/opflex/modb/EnumInfo.h \
	include/opflex/modb/ModelMetadata.h \
	include/opflex/modb/Mutator.h \
	include/opflex/modb/ObjectListener.h \
	include/opflex/modb/PropertyInfo.h \
	include/opflex/modb/URIBuilder.h \
	include/opflex/modb/URI.h \
	include/opflex/modb/MAC.h
modb_mo_includedir = $(includedir)/opflex/modb/mo-internal
modb_mo_include_HEADERS = \
	include/opflex/modb/mo-internal/MO.h \
	include/opflex/modb/mo-internal/ObjectInstance.h \
	include/opflex/modb/mo-internal/StoreClient.h 
core_includedir = $(includedir)/opflex/ofcore
core_include_HEADERS = \
	include/opflex/ofcore/OFFramework.h \
	include/opflex/ofcore/PeerStatusListener.h \
	include/opflex/ofcore/MainLoopAdaptor.h \
	include/opflex/ofcore/InspectorClient.h \
	include/opflex/ofcore/OFConstants.h \
	include/opflex/ofcore/OFAgentStats.h \
	include/opflex/ofcore/OFServerStats.h
test_includedir = $(includedir)/opflex/test
test_include_HEADERS = \
	include/opflex/test/GbpOpflexServer.h 
logging_includedir = $(includedir)/opflex/logging
logging_include_HEADERS = \
	include/opflex/logging/OFLogHandler.h \
	include/opflex/logging/StdOutLogHandler.h
c_includedir = $(includedir)/opflex/c
c_include_HEADERS = \
	include/opflex/c/ofcore_c.h \
	include/opflex/c/ofuri_c.h \
	include/opflex/c/ofloghandler_c.h \
	include/opflex/c/ofobjectlistener_c.h \
	include/opflex/c/ofpeerstatuslistener_c.h \
	include/opflex/c/ofmutator_c.h \
	include/opflex/c/offramework_c.h
rpc_includedir = $(includedir)/opflex/rpc
rpc_include_HEADERS = \
	include/opflex/rpc/JsonRpcConnection.h \
	include/opflex/rpc/JsonRpcHandler.h \
	include/opflex/rpc/JsonRpcMessage.h
gbp_includedir = $(includedir)/opflex/gbp
gbp_include_HEADERS = \
	include/opflex/gbp/Policy.h
util_includedir = $(includedir)/opflex/util
util_include_HEADERS = \
	include/opflex/util/ThreadManager.h
yajr_includedir = $(includedir)/opflex/yajr
yajr_include_HEADERS = \
    include/opflex/yajr/yajr.hpp \
    include/opflex/yajr/async_doc_parser.hpp
yajr_internal_includedir = $(includedir)/opflex/yajr/internal
yajr_internal_include_HEADERS = \
    include/opflex/yajr/internal/comms.hpp
yajr_rpc_includedir = $(includedir)/opflex/yajr/rpc
yajr_rpc_include_HEADERS = \
    include/opflex/yajr/rpc/message_factory.hpp \
    include/opflex/yajr/rpc/rpc.hpp \
    include/opflex/yajr/rpc/send_handler.hpp
yajr_transport_includedir = $(includedir)/opflex/yajr/transport
yajr_transport_include_HEADERS = \
    include/opflex/yajr/transport/engine.hpp \
    include/opflex/yajr/transport/PlainText.hpp

lib_LTLIBRARIES = libopflex.la
libopflex_la_SOURCES = 
# Dummy C++ source to cause C++ linking.
nodist_EXTRA_libopflex_la_SOURCES = dummy.cxx
libopflex_la_LIBADD  =
libopflex_la_LIBADD += modb/libmodb.la
libopflex_la_LIBADD += comms/libcomms.la
libopflex_la_LIBADD += engine/libengine.la
libopflex_la_LIBADD += ofcore/libcore.la
libopflex_la_LIBADD += cwrapper/libcwrapper.la
libopflex_la_LIBADD += util/libutil.la
libopflex_la_LIBADD += logging/liblogging.la
libopflex_la_LDFLAGS = -version-info ${VERSION_INFO}

if ENABLE_TSAN
  libopflex_la_LDFLAGS += -fsanitize=thread
endif

if ENABLE_ASAN
  libopflex_la_LDFLAGS += -fsanitize=address
endif

if ENABLE_UBSAN
  libopflex_la_LDFLAGS += -fsanitize=undefined
endif

if ENABLE_COVERAGE
  libopflex_la_LDFLAGS += --coverage
endif

if ENABLE_GPROF
  libopflex_la_LDFLAGS += -pg
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libopflex.pc

if HAVE_DOXYGEN
  noinst_DATA = \
	doc/html
endif

doc/html: $(modb_include_HEADERS) $(modb_mo_include_HEADERS) $(core_include_HEADERS)  $(logging_include_HEADERS) $(c_include_HEADERS) $(rpc_include_HEADERS) $(gbp_include_HEADERS) $(util_include_HEADERS) $(yajr_include_HEADERS) $(yajr_internal_include_HEADERS) $(yajr_rpc_include_HEADERS) $(yajr_transport_include_HEADERS) doc/Doxyfile
if HAVE_DOXYGEN
	cd doc && ${DOXYGEN} Doxyfile
endif
doc: doc/html
doc/html-internal: clean-doc-internal $(modb_include_HEADERS) $(modb_mo_include_HEADERS) $(core_include_HEADERS)  $(logging_include_HEADERS) $(c_include_HEADERS) $(rpc_include_HEADERS) $(gbp_include_HEADERS) $(util_include_HEADERS) $(yajr_include_HEADERS) $(yajr_internal_include_HEADERS) $(yajr_rpc_include_HEADERS) $(yajr_transport_include_HEADERS) doc/Doxyfile-internal
if HAVE_DOXYGEN
	cd doc && ${DOXYGEN} Doxyfile-internal
endif
doc-internal: doc/html-internal
install-data-local: doc
	@$(NORMAL_INSTALL)
if HAVE_DOXYGEN
	test -z "${DESTDIR}/${docdir}/html" || $(mkdir_p) "${DESTDIR}/${docdir}/html"
	for i in `ls $(top_builddir)/doc/html`; do \
	  $(INSTALL) -m 0644 $(top_builddir)/doc/html/$$i "${DESTDIR}/${docdir}/html"; \
	done
endif
uninstall-local: 
	@$(NORMAL_UNINSTALL)
	rm -rf "${DESTDIR}/${docdir}/html"
	rm -rf "${DESTDIR}/${includedir}/opflex"

clean-doc:
	rm -rf doc/html doc/latex
clean-doc-internal:
	rm -rf doc/html-internal
clean-local: clean-doc clean-doc-internal
	rm -f *.rpm *.deb

CWD=`pwd`
RPMFLAGS=--define "_topdir ${CWD}/rpm"
ARCH=x86_64
SOURCE_FILE=${PACKAGE}-${VERSION}.tar.gz
RPMDIRS=rpm/BUILD rpm/SOURCES rpm/RPMS rpm/SRPMS
rpm: dist rpm/${PACKAGE}.spec
	mkdir -p ${RPMDIRS}
	cp ${SOURCE_FILE} rpm/SOURCES/
	rpmbuild ${RPMFLAGS} -ba rpm/${PACKAGE}.spec
	cp rpm/RPMS/${ARCH}/*.rpm .
	cp rpm/SRPMS/*.rpm .
	rm -rf ${RPMDIRS}
srpm: dist rpm/${PACKAGE}.spec
	mkdir -p ${RPMDIRS}
	cp ${SOURCE_FILE} rpm/SOURCES/
	rpmbuild ${RPMFLAGS} -bs rpm/${PACKAGE}.spec
	cp rpm/SRPMS/*.rpm .
	rm -rf ${RPMDIRS}

EXTRA_DIST += debian/libopflex.install debian/libopflex-dev.install \
	debian/changelog debian/compat debian/control \
	debian/copyright debian/rules debian/source/format

# Set env var DEB_BUILD_OPTIONS="parallel=<#cores>" to speed up package builds
DEB_PKG_DIR=deb-pkg-build
deb: dist deb-pkg-build
	- rm -rf  $(DEB_PKG_DIR)
	mkdir -p $(DEB_PKG_DIR)
	cp $(SOURCE_FILE) $(DEB_PKG_DIR)/
	tar -C $(DEB_PKG_DIR)/ -xf $(DEB_PKG_DIR)/$(SOURCE_FILE)
	mv $(DEB_PKG_DIR)/$(SOURCE_FILE) $(DEB_PKG_DIR)/$(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(DEB_PKG_DIR)/$(PACKAGE)-$(VERSION)/; \
		VERSION_WITH_BUILD=$(VERSION)-$(SDK_BVERSION) \
		dpkg-buildpackage -us -uc -rfakeroot -b
	cp $(DEB_PKG_DIR)/*.deb .
	rm -rf $(DEB_PKG_DIR)

dsc: dist
	- rm -rf  $(DEB_PKG_DIR)
	mkdir -p $(DEB_PKG_DIR)
	cp $(SOURCE_FILE) $(DEB_PKG_DIR)/
	tar -C $(DEB_PKG_DIR)/ -xf $(DEB_PKG_DIR)/$(SOURCE_FILE)
	mv $(DEB_PKG_DIR)/$(SOURCE_FILE) $(DEB_PKG_DIR)/$(PACKAGE)_$(VERSION).orig.tar.gz
	cd $(DEB_PKG_DIR)/$(PACKAGE)-$(VERSION)/; \
		dpkg-buildpackage -d -us -uc -rfakeroot -S
