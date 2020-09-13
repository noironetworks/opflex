/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for extra config manager
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>
#include <boost/filesystem/fstream.hpp>

#include <opflexagent/FSRDConfigSource.h>
#include <opflexagent/FSPacketDropLogConfigSource.h>

#include <opflexagent/test/BaseFixture.h>

namespace opflexagent {

namespace fs = boost::filesystem;

class FSConfigFixture : public BaseFixture {
public:
    FSConfigFixture() : BaseFixture(),
        temp(fs::temp_directory_path() / fs::unique_path()) {
        fs::create_directory(temp);
    }

    ~FSConfigFixture() {
        fs::remove_all(temp);
    }

    fs::path temp;
};

BOOST_AUTO_TEST_SUITE(ExtraConfigManager_test)

BOOST_FIXTURE_TEST_CASE( rdconfigsource, FSConfigFixture ) {

    // check for a new RDConfig added to watch directory
    fs::path path1(temp / "abc.rdconfig");

    fs::ofstream os(path1);
    os << "{"
       << "\"uuid\":\"83f18f0b-80f7-46e2-b06c-4d9487b0c793\","
       << "\"domain-name\":\"rd1\","
       << "\"domain-policy-space\":\"space1\","
       << "\"internal-subnets\" : [\"1.2.3.4\", \"5.6.7.8\"]"
       << "}" << std::endl;
    os.close();
    FSWatcher watcher;
    FSRDConfigSource source(&agent.getExtraConfigManager(), watcher,
                             temp.string());
    watcher.start();
    URI rdUri("/PolicyUniverse/PolicySpace/space1/GbpRoutingDomain/rd1/");
    WAIT_FOR((agent.getExtraConfigManager().getRDConfig(rdUri) != nullptr), 500);

    // check for removing an RDConfig
    fs::remove(path1);

    WAIT_FOR((agent.getExtraConfigManager().getRDConfig(rdUri) == nullptr), 500);
    watcher.stop();
}

BOOST_FIXTURE_TEST_CASE( droplogconfigsource, FSConfigFixture ) {
    using modelgbp::observer::DropLogConfig;
    using modelgbp::observer::DropLogModeEnumT;
    fs::path path(temp / "a.droplogcfg");
    fs::ofstream os(path);
    os << "{"
       << "\"drop-log-enable\": true"
       << "}" << std::endl;
    os.close();
    FSWatcher watcher;
    opflex::modb::URI uri =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropLogConfig").build();
    FSPacketDropLogConfigSource source(&agent.getExtraConfigManager(), watcher,
                                       temp.string(), uri);
    watcher.start();

    WAIT_FOR(DropLogConfig::resolve(agent.getFramework(), uri), 500);
    boost::optional<shared_ptr<DropLogConfig>> dropLogCfg = DropLogConfig::resolve(agent.getFramework(), uri);
    BOOST_CHECK(dropLogCfg.get()->getDropLogMode().get()== DropLogModeEnumT::CONST_UNFILTERED_DROP_LOG);
    BOOST_CHECK(dropLogCfg.get()->getDropLogEnable().get());
    fs::ofstream os2(path);
    os2 << "{"
       << "\"drop-log-enable\": false"
       << "}" << std::endl;
    os2.close();
    WAIT_FOR((DropLogConfig::resolve(agent.getFramework(), uri).get()->getDropLogEnable().get()==0), 500);
    fs::remove(path);
    WAIT_FOR(!(DropLogConfig::resolve(agent.getFramework(), uri)), 500);
    watcher.stop();
}

BOOST_FIXTURE_TEST_CASE( dropflowconfigsource, FSConfigFixture ) {
    using modelgbp::observer::DropFlowConfig;
    fs::path path(temp / "a.dropflowcfg");
    fs::ofstream os(path);
    os << "{"
       << "\"uuid\":\"83f18f0b-80f7-46e2-b06c-4d9487b0c793\""
       << "}" << std::endl;
    os.close();
    FSWatcher watcher;
    opflex::modb::URI uri =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropLogConfig").build();
    FSPacketDropLogConfigSource source(&agent.getExtraConfigManager(), watcher,
                                       temp.string(), uri);
    watcher.start();

    opflex::modb::URI flowUri = opflex::modb::URIBuilder()
        .addElement("ObserverDropFlowConfigUniverse")
        .addElement("ObserverDropFlowConfig")
        .addElement("83f18f0b-80f7-46e2-b06c-4d9487b0c793").build();

    WAIT_FOR(DropFlowConfig::resolve(agent.getFramework(), flowUri), 500);

    fs::remove(path);
    WAIT_FOR(!(DropFlowConfig::resolve(agent.getFramework(), flowUri)), 500);
    watcher.stop();
}

BOOST_AUTO_TEST_SUITE_END()
}
