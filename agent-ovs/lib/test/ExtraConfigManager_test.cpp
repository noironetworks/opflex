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

BOOST_FIXTURE_TEST_CASE( droplogpruneconfigsource, FSConfigFixture ) {
    using modelgbp::observer::DropLogConfig;
    using modelgbp::observer::DropLogModeEnumT;
    using modelgbp::observer::DropPruneConfig;
    fs::path path(temp / "b.droplogcfg");
    fs::ofstream os(path);
    os << "{"
       << "\"drop-log-enable\": true,\n"
       << "\"drop-log-pruning\": {\n"
       << "\"flt1\":{"
       << "\"name\":\"flt1\",\"sip\":\"1.2.3.4\",\"dip\":\"5.6.7.0/24\",\"smac\":\"00:01:02:03:04:05/FF:FF:00:00:00:00\",\"dmac\":\"06:07:08:09:0A:0B/FF:FF:FF:FF:FF:FF\",\"ip_proto\":6, \"sport\":12000,\"dport\":13000"
       << "}\n"
       <<"}\n"
       << "}" << std::endl;
    os.close();
    FSWatcher watcher;
    opflex::modb::URI uri =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropLogConfig").build();
    opflex::modb::URI dropPruneUri =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropPruneConfig").addElement("flt1").build();
    FSPacketDropLogConfigSource source(&agent.getExtraConfigManager(), watcher,
                                       temp.string(), uri);
    watcher.start();
    WAIT_FOR(DropLogConfig::resolve(agent.getFramework(), uri), 500);
    boost::optional<shared_ptr<DropLogConfig>> dropLogCfg = DropLogConfig::resolve(agent.getFramework(), uri);
    BOOST_CHECK(dropLogCfg.get()->getDropLogMode().get()== DropLogModeEnumT::CONST_UNFILTERED_DROP_LOG);
    BOOST_CHECK(dropLogCfg.get()->getDropLogEnable().get());
    /*Test create prune filter*/
    WAIT_FOR(DropPruneConfig::resolve(agent.getFramework(), dropPruneUri), 500);
    boost::optional<shared_ptr<DropPruneConfig>> dropPruneCfg = DropPruneConfig::resolve(agent.getFramework(), dropPruneUri);
    BOOST_CHECK(dropPruneCfg.get()->getFilterName().get() == "flt1");
    BOOST_CHECK(dropPruneCfg.get()->getSrcAddress().get() == "1.2.3.4");
    BOOST_CHECK(dropPruneCfg.get()->getSrcPrefixLen().get() == 32);
    BOOST_CHECK(dropPruneCfg.get()->getDstAddress().get() == "5.6.7.0");
    BOOST_CHECK(dropPruneCfg.get()->getDstPrefixLen().get() == 24);
    BOOST_CHECK(dropPruneCfg.get()->getSrcMac().get().toString() == "00:01:02:03:04:05");
    BOOST_CHECK(dropPruneCfg.get()->getDstMac().get().toString() == "06:07:08:09:0a:0b");
    BOOST_CHECK(dropPruneCfg.get()->getSrcMacMask().get().toString() == "ff:ff:00:00:00:00");
    BOOST_CHECK(dropPruneCfg.get()->getDstMacMask().get().toString() == "ff:ff:ff:ff:ff:ff");
    BOOST_CHECK(dropPruneCfg.get()->getIpProto().get() == 6);
    BOOST_CHECK(dropPruneCfg.get()->getSrcPort().get() == 12000);
    BOOST_CHECK(dropPruneCfg.get()->getDstPort().get() == 13000);
    /*Test update prune filter*/
    fs::ofstream os2(path);
    os2 << "{"
       << "\"drop-log-enable\": true,\n"
       << "\"drop-log-pruning\": {\n"
       << "\"flt2\":{"
       << "\"name\":\"flt2\",\"sip\":\"10.0.0.1/24\",\"dip\":\"192.168.0.1/16\",\"smac\":\"00:01:02:03:04:05\",\"dmac\":\"06:07:08:09:0A:0B\",\"ip_proto\":17, \"dport\":13000"
       << "},\n"
       << "\"flt3\":{"
       << "\"name\":\"flt3\",\"sip\":\"10.0.0.10/\",\"dip\":\"192.168.0.1/16\",\"smac\":\"00:01:02:03:04:05\",\"dmac\":\"06:07:08:09:0A:0B\",\"ip_proto\":17, \"dport\":13000"
       << "},\n"
       << "\"flt4\":{"
       << "\"name\":\"flt4\",\"sip\":\"10.0.0.10/24\",\"dip\":\"192.168.0.1/16\",\"smac\":\"00:01:02:03:04:05/\",\"dmac\":\"06:07:08:09:0A:0B\",\"ip_proto\":17, \"dport\":13000"
       << "},\n"
       << "\"flt5\":{"
       << "\"name\":\"flt5\",\"sip\":\"10.0.0.10/24\",\"dip\":\"192.168.0.1/a\",\"smac\":\"00:01:02:03:04:05/\",\"dmac\":\"06:07:08:09:0A:0B\",\"ip_proto\":17, \"dport\":13000"
       << "},\n"
       << "\"flt6\":{"
       << "\"name\":\"flt6\",\"sip\":\"10.0.0.10/24\",\"dip\":\"192.168.0.1/16\",\"smac\":\"00:01:02:03:04:05\",\"dmac\":\"06:07:08:09:0A:0B/a\",\"ip_proto\":17, \"dport\":13000"
       << "},\n"
       << "\"flt7\":{"
       << "\"name\":\"flt7\",\"sip\":\"10.0.0.10/24\",\"dip\":\"224.0.0.251\",\"ip_proto\":17, \"dport\":13000"
       << "}\n"
       << "}\n"
       << "}" << std::endl;
    os2.close();
    WAIT_FOR(!(DropPruneConfig::resolve(agent.getFramework(), dropPruneUri)),500);
    opflex::modb::URI dropPruneUri2 =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropPruneConfig").addElement("flt2").build();
    opflex::modb::URI dropPruneUri3 =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropPruneConfig").addElement("flt3").build();
    opflex::modb::URI dropPruneUri4 =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropPruneConfig").addElement("flt4").build();
    opflex::modb::URI dropPruneUri5 =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropPruneConfig").addElement("flt5").build();
    opflex::modb::URI dropPruneUri6 =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropPruneConfig").addElement("flt6").build();
    opflex::modb::URI dropPruneUri7 =
        opflex::modb::URIBuilder().addElement("PolicyUniverse")
            .addElement("ObserverDropPruneConfig").addElement("flt7").build();
    WAIT_FOR(DropPruneConfig::resolve(agent.getFramework(), dropPruneUri2), 500);
    boost::optional<shared_ptr<DropPruneConfig>> dropPruneCfg2 = DropPruneConfig::resolve(agent.getFramework(), dropPruneUri2);
    BOOST_CHECK(dropPruneCfg2.get()->getFilterName().get() == "flt2");
    BOOST_CHECK(dropPruneCfg2.get()->getSrcAddress().get() == "10.0.0.1");
    BOOST_CHECK(dropPruneCfg2.get()->getSrcPrefixLen().get() == 24);
    BOOST_CHECK(dropPruneCfg2.get()->getDstAddress().get() == "192.168.0.1");
    BOOST_CHECK(dropPruneCfg2.get()->getDstPrefixLen().get() == 16);
    BOOST_CHECK(dropPruneCfg2.get()->getSrcMac().get().toString() == "00:01:02:03:04:05");
    BOOST_CHECK(dropPruneCfg2.get()->getDstMac().get().toString() == "06:07:08:09:0a:0b");
    BOOST_CHECK(!dropPruneCfg2.get()->getSrcMacMask());
    BOOST_CHECK(!dropPruneCfg2.get()->getDstMacMask());
    BOOST_CHECK(dropPruneCfg2.get()->getIpProto().get() == 17);
    BOOST_CHECK(!dropPruneCfg2.get()->getSrcPort());
    BOOST_CHECK(dropPruneCfg2.get()->getDstPort().get() == 13000);
    /*Missing prefixlength*/
    WAIT_FOR(!DropPruneConfig::resolve(agent.getFramework(), dropPruneUri3), 500);
    /*Missing macmask*/
    WAIT_FOR(!DropPruneConfig::resolve(agent.getFramework(), dropPruneUri4), 500);
    /*Incorrect prefixlength*/
    WAIT_FOR(!DropPruneConfig::resolve(agent.getFramework(), dropPruneUri5), 500);
    /*Incorrect macmask*/
    WAIT_FOR(!DropPruneConfig::resolve(agent.getFramework(), dropPruneUri6), 500);
    /*Valid input*/
    WAIT_FOR(DropPruneConfig::resolve(agent.getFramework(), dropPruneUri7), 500);
    fs::remove(path);
    WAIT_FOR(!(DropLogConfig::resolve(agent.getFramework(), uri)), 500);
    WAIT_FOR(!(DropPruneConfig::resolve(agent.getFramework(), dropPruneUri2)), 500);
    WAIT_FOR(!(DropPruneConfig::resolve(agent.getFramework(), dropPruneUri7)), 500);
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
