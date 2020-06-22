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
    const std::string &uuid1 = "83f18f0b-80f7-46e2-b06c-4d9487b0c754";
    fs::path path1(temp / "83f18f0b-80f7-46e2-b06c-4d9487b0c754.st");
    fs::ofstream os(path1);
    os << "{"
       << "\"uuid\":\"" << uuid1 << "\","
       << "\"mac\":\"10:ff:00:a3:02:01\","
       << "\"snat-ip\":\"10.0.0.10\","
       //<< "\"local\":[\"10.0.0.1\",\"10.0.0.2\",\"10.0.0.3\"],"
       << "\"interface-name\":\"veth0\","
       //<< "\"interface-mac\":\"veth0-acc\","
       //<< "\"interface-vlan\":\"/PolicyUniverse/PolicySpace/test/GbpEpGroup/epg/\","
       //<< "\"dest\":["
       //<< "{\"zone\":\"sg1-space1\",\"name\":\"sg1\"},"
       //<< "{\"port-range\":\"sg2-space2\",\"name\":\"sg2\"}"
       //<< "],"
       //<< "\"start\":{"
       //<< "\"end\":\"value1\",\"attr2\":\"value2\""
       //<< "\"remote\":\"value1\",\"attr2\":\"value2\""
       //<< "}"
       << "}" << std::endl;
    os.close();

    SnatManager& snatMgr = agent.getSnatManager();

    FSWatcher watcher;
    FSSnatSource source(&agent.getSnatManager(), watcher,
                                    temp.string());

    watcher.start();

    WAIT_FOR(snatMgr.getSnat(uuid1), 500);

    fs::path path2(temp / "83f18f0b-80f7-46e2-b06c-4d9487b0c754.st");
    fs::ofstream os2(path2);
    os2 << "{"
    << "\"uuid\":\"83f18f0b-80f7-46e2-b06c-4d9487b0c754\","
    << "\"mac\":\"10:ff:00:a3:02:01\","
    << "\"snat-ip\":[\"10.0.0.10\"],"
    << "\"interface-name\":\"veth1\","
    //<< "\"policy-space-name\":\"test\","
    //<< "\"path-attachment\":\"ext_int2\","
    //<< "\"node-attachment\":\"ext_node2\""
    << "}" << std::endl;
    os2.close();
    
    auto snat1 = snatMgr.getSnat(uuid1);
    // WAIT_FOR(snatMgr.getSnat(uuid1), 500);
    BOOST_CHECK(snat1->getInterfaceName() == "veth1");
    watcher.stop();


}
}
