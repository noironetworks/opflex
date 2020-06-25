/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for Snat manager
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>
#include <boost/filesystem/fstream.hpp>
#include <opflexagent/FSSnatSource.h>
#include <opflexagent/test/BaseFixture.h>
#include <opflexagent/Snat.h>
#include <opflexagent/SnatManager.h>
#include <opflexagent/Agent.h>
#include <opflexagent/FSWatcher.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

namespace opflexagent {

using std::string;
using boost::optional;
namespace fs = boost::filesystem;

class FSSnatFixture : public BaseFixture {
public:
    FSSnatFixture()
        : BaseFixture(),
          temp(fs::temp_directory_path() / fs::unique_path()) {
        fs::create_directory(temp);
    }
    ~FSSnatFixture() {
        fs::remove_all(temp);
    }

    fs::path temp;
};

bool hasSnat(SnatManager& snatMgr, const string& uuid) {
    auto snat = snatMgr.getSnat(uuid);
    return snat && snat->isLocal() && snat->getUUID() == uuid;
}

BOOST_FIXTURE_TEST_CASE( fssource, FSSnatFixture ) {
   // check already existing snat file
   const std::string uuid1 = "00000000-0000-0000-0000-ffff01650164";
   fs::path path1(temp / (uuid1 + ".snat"));
   fs::ofstream os(path1);
   os  << "{"
	<< "\"uuid\":\"" << uuid1 << "\","
	<< "\"interface-name\":\"veth0\","
	<< "\"snat-ip\":\"10.0.0.1\","
	<< "\"interface-mac\":\"10:ff:00:a4:02:01\","
	<< "\"local\": true,"
	<< "\"dest\":[\"0.0.0.0/0\"],"
	<< "\"port-range\":["
	<< "{\"start\":8000,"
	<< "\"end\":10999}"
	<< "],"
	<< "\"interface-vlan\": 102,"
	<< "\"zone\":8191,"
	<< "\"remote\":["
        << "{\"mac\":\"10:ff:00:a3:01:00\","
        << "\"port-range\":["
        << "{\"start\":8000,"
        << "\"end\":10999}"
        << "]"
        << "}"
        << "]"
	<< "}" << std::endl;
    os.close();

    SnatManager& snatMgr = agent.getSnatManager();
    FSWatcher watcher;
    FSSnatSource source(&snatMgr, watcher, temp.string());
    watcher.start();
    WAIT_FOR(hasSnat(snatMgr, uuid1), 500);
  
    fs::path path2(temp / (uuid1 + ".snat"));
    fs::ofstream os2(path2);
    os2 << "{"
	<< "\"uuid\":\"" << uuid1 << "\","
        << "\"interface-name\":\"veth1\","
        << "\"snat-ip\":\"10.0.0.1\","
        << "\"interface-mac\":\"10:ff:00:a4:02:01\","
        << "\"local\": true,"
        << "\"dest\":[\"0.0.0.0/0\"],"
        << "\"port-range\":["
        << "{\"start\":8000,"
        << "\"end\":10999}"
        << "],"
        << "\"interface-vlan\": 102,"
        << "\"zone\":8191,"
        << "\"remote\":["
        << "{\"mac\":\"10:ff:00:a3:01:00\","
        << "\"port-range\":["
        << "{\"start\":8000,"
        << "\"end\":10999}"
        << "]"
        << "}"
        << "]"
        << "}" << std::endl;
    os2.close();
	

    WAIT_FOR(hasSnat(snatMgr, uuid1) && snatMgr.getSnat(uuid1)->getInterfaceName() == "veth1", 500);
    auto snat1 = snatMgr.getSnat(uuid1);
    BOOST_CHECK(snat1->getInterfaceName() == "veth1");
    watcher.stop();

}

BOOST_FIXTURE_TEST_CASE( fsextsvisource, FSSnatFixture ) {

    // check for a new Snat added to watch directory
    fs::path path1(temp / "00000000-0000-0000-0000-ffff01650165.snat");
    fs::ofstream os(path1);
    os<< "{"
	<< "\"uuid\":\"00000000-0000-0000-0000-ffff01650165\","
        << "\"interface-name\":\"veth0\","
        << "\"snat-ip\":\"10.0.0.1\","
        << "\"interface-mac\":\"10:ff:00:a4:02:01\","
        << "\"local\": true,"
        << "\"dest\":[\"0.0.0.0/0\"],"
        << "\"port-range\":["
        << "{\"start\":8000,"
        << "\"end\":10999}"
        << "],"
        << "\"interface-vlan\": 102,"
        << "\"zone\":8191,"
        << "\"remote\":["
        << "{\"mac\":\"10:ff:00:a3:01:00\","
        << "\"port-range\":["
        << "{\"start\":8000,"
        << "\"end\":10999}"
        << "]"
        << "}"
        << "]"
	<< "}" << std::endl;
    os.close();
    FSWatcher watcher;
    FSSnatSource source(&agent.getSnatManager(), watcher,
                             temp.string());
    watcher.start();
    WAIT_FOR((agent.getSnatManager().getSnat("00000000-0000-0000-0000-ffff01650165") != nullptr), 500);
    auto extSnat = agent.getSnatManager().getSnat("00000000-0000-0000-0000-ffff01650165");
  
    BOOST_CHECK(extSnat->getSnatIP() == "10.0.0.1");

    // check for removing a Snat
    fs::remove(path1);
    WAIT_FOR((agent.getSnatManager().getSnat("00000000-0000-0000-0000-ffff01650165") == nullptr), 500);

    watcher.stop();
}
} /* namespace opflexagent */
