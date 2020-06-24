/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for Snat manager
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflex/modb/ObjectListener.h>
#include <boost/test/unit_test.hpp>
#include <boost/test/tools/assertion_result.hpp>
#include <boost/filesystem/fstream.hpp>
#include <opflexagent/FSSnatSource.h>
#include <opflexagent/logging.h>
#include <opflexagent/test/BaseFixture.h>
#include <opflexagent/Snat.h>
#include <opflexagent/SnatManager.h>
#include <opflexagent/Agent.h>
#include <opflexagent/FSWatcher.h>
#include <string.h>
#include <iostream>

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



BOOST_FIXTURE_TEST_CASE( fssource, FSSnatFixture ) {

    // check already existing snat file
    const std::string& uuid1 = "00000000-0000-0000-0000-ffff01650164";
    fs::path path1(temp / "00000000-0000-0000-0000-ffff01650164.snat");
    fs::ofstream os(path1);
    os  << "{"
	<< "\"uuid\":\"" << uuid1 << "\","
	<< "\"interface-name\":\"bond0\","
		//<< "\"mac\":\"10:ff:00:a3:02:01\","
	<< "\"snat-ip\":\"1.101.1.100\","
	<< "\"interface-mac\":\"88:1d:fc:a9:c2:ef\","
	<< "\"local\": true,"
	<< "\"dest\":[\"0.0.0.0/0\"],"
	<< "\"port-range\":["
	<< "{\"start\":8000,"
	<< "\"end\":10999}"
	<< "],"
	<< "\"interface-vlan\": 102,"
	<< "\"zone\":8191"
	<< "}" << std::endl;
    os.close();

    SnatManager& snatMgr = agent.getSnatManager();
   // WAIT_FOR(snatMgr.getSnat(uuid1), 500);
	//std::cout << "snatMgr is :" << snatMgr << endl;
    FSWatcher watcher;
    FSSnatSource source(&agent.getSnatManager(), watcher,
                                    temp.string());

    watcher.start();
    usleep(0.1*1000*1000);
    WAIT_FOR(snatMgr.getSnat("00000000-0000-0000-0000-ffff01650164"), 500);

    fs::path path2(temp / "00000000-0000-0000-0000-ffff01650164.snat");
    fs::ofstream os2(path2);
    os2 << "{"
	<< "\"uuid\":\"00000000-0000-0000-0000-ffff01650164\","
	<< "\"interface-name\":\"bond1\","
		//<< "\"mac\":\"10:ff:00:a3:02:01\","
	<< "\"snat-ip\":\"1.101.1.100\","
	<< "\"interface-mac\":\"88:1d:fc:a9:c2:ef\","
	<< "\"local\": true,"
	<< "\"dest\":[\"0.0.0.0/0\"],"
	<< "\"port-range\":["
	<< "{\"start\":8000,"
	<< "\"end\":10999}"
	<< "],"
	<< "\"interface-vlan\": 102,"
	<< "\"zone\":8191"
	<< "}" << std::endl;
    os2.close();
	
	usleep(0.1*1000*1000);
	WAIT_FOR(agent.getSnatManager().getSnat(
            "00000000-0000-0000-0000-ffff01650164"), 500);
    
   
   auto snat1 = agent.getSnatManager().getSnat(
            "00000000-0000-0000-0000-ffff01650164");
   //WAIT_FOR(snatMgr.getSnat("00000000-0000-0000-0000-ffff01650164"), 50000);
   BOOST_CHECK(snat1->getInterfaceName() == "bond1");
   watcher.stop();


}

BOOST_FIXTURE_TEST_CASE( fsextsvisource, FSSnatFixture ) {

    // check for a new Snat added to watch directory
    fs::path path1(temp / "00000000-0000-0000-0000-ffff01650165.snat");
    fs::ofstream os(path1);
    os<< "{"
	<< "\"uuid\":\"00000000-0000-0000-0000-ffff01650165\","
	<< "\"interface-name\":\"bond0\","
	//<< "\"mac\":\"10:ff:00:a3:02:01\","
	<< "\"snat-ip\":\"1.101.1.100\","
	<< "\"interface-mac\":\"88:1d:fc:a9:c2:ef\","
	<< "\"local\": true,"
	<< "\"dest\":[\"0.0.0.0/0\"],"
	<< "\"port-range\":["
	<< "{\"start\":8000,"
	<< "\"end\":10999}"
	<< "],"
	<< "\"interface-vlan\": 102,"
	<< "\"zone\":8191"
	<< "}" << std::endl;
    os.close();
    FSWatcher watcher;
    FSSnatSource source(&agent.getSnatManager(), watcher,
                             temp.string());
    watcher.start();
   // usleep(1000*1000);
    WAIT_FOR((agent.getSnatManager().getSnat(
            "00000000-0000-0000-0000-ffff01650165") != nullptr), 500);
    auto extSnat = agent.getSnatManager().getSnat(
            "00000000-0000-0000-0000-ffff01650165");
    //BOOST_CHECK(extSnat->isExternal());
    BOOST_CHECK(extSnat->getSnatIP() == "1.101.1.100");

    // check for removing an endpoint
    fs::remove(path1);

   // usleep(1000*1000);

    WAIT_FOR((agent.getSnatManager().getSnat(
            "00000000-0000-0000-0000-ffff01650165") == nullptr), 500);

    watcher.stop();
}
}
