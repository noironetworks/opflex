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

AM_CPPFLAGS = $(BOOST_CPPFLAGS) -DBOOST_TEST_DYN_LINK \
	-Wall \
	-Werror \
	-std=c++11 \
	-I$(srcdir)/../include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/util/include

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

AM_LDFLAGS = $(BOOST_LDFLAGS)

if ENABLE_TSAN
  AM_LDFLAGS += -fsanitize=thread
endif

if ENABLE_ASAN
  AM_LDFLAGS += -fsanitize=address
endif

if ENABLE_UBSAN
  AM_LDFLAGS += -fsanitize=undefined
endif

if ENABLE_COVERAGE
  AM_LDFLAGS += --coverage
endif

if ENABLE_GPROF
  AM_LDFLAGS += -pg
endif

TESTS = modb_test
modb_test_CXXFLAGS = $(UV_CFLAGS)

modb_test_SOURCES = \
	MDFixture.h \
	BaseFixture.h \
	TestListener.h \
	main.cpp \
	URIBuilder_test.cpp \
	MAC_test.cpp \
	ObjectInstance_test.cpp \
	ObjectStore_test.cpp
modb_test_LDADD = ../libmodb.la \
	../../util/libutil.la \
	../../logging/liblogging.la \
	$(UV_LIBS) \
	$(BOOST_UNIT_TEST_FRAMEWORK_LIB)

if MAKE_ALL_TESTS
    noinst_PROGRAMS = $(TESTS)
else
    check_PROGRAMS = $(TESTS)
endif
