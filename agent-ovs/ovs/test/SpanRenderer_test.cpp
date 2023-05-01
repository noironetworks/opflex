/*
 * Test suite for class SpanRenderer
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>

#include <opflexagent/logging.h>
#include <opflexagent/test/BaseFixture.h>
#include "SpanRenderer.h"
#include "MockRpcConnection.h"
#include <opflexagent/SpanSessionState.h>
#include <modelgbp/dmtree/Root.hpp>

namespace opflexagent {

using namespace std;
using namespace modelgbp;
using modelgbp::gbp::DirectionEnumT;

const string ERSPAN_PORT_PREFIX = "erspan-";

BOOST_AUTO_TEST_SUITE(SpanRenderer_test)

class SpanRendererFixture : public BaseFixture {
public:
    SpanRendererFixture() : BaseFixture() {
        spr = make_shared<SpanRenderer>(agent);
        initLogging("debug", false, "");
        conn.reset(new MockRpcConnection());
        vector<std::string&> swNames{"br-int"};
        spr->start(swNames, conn.get());
        spr->connect();

        // simulate results of monitor
        OvsdbRowDetails rowDetails;
        string uuid = "9b7295f4-07a8-41ac-a681-e0ee82560262";
        rowDetails["uuid"] = OvsdbValue(uuid);
        OvsdbTableDetails tableDetails;
        tableDetails["br-int"] = rowDetails;
        conn->getOvsdbState().fullUpdate(OvsdbTable::BRIDGE, tableDetails);

        OvsdbRowDetails portDetail;
        uuid = "ffaee0cd-bb7d-4698-9af1-99f57f9b7081";
        portDetail["uuid"] = OvsdbValue(uuid);
        const string brInt("br-int");
        portDetail["name"] = OvsdbValue(brInt);
        OvsdbTableDetails portDetails;
        portDetails[uuid] = portDetail;

        const string erspanPortUuid = "fff42dce-44cb-4b6a-8920-dfc32d88ec07";
        portDetail["uuid"] = OvsdbValue(erspanPortUuid);
        const string portName(ERSPAN_PORT_PREFIX);
        portDetail["name"] = OvsdbValue(portName);
        portDetails[erspanPortUuid] = portDetail;

        const string p1PortUuid = "0a7a4d65-e785-4674-a219-167391d10c3f";
        portDetail["uuid"] = OvsdbValue(p1PortUuid);
        const string p1("p1-tap");
        portDetail["name"] = OvsdbValue(p1);
        portDetails[p1PortUuid] = portDetail;

        const string p2PortUuid = "373108c7-ce2d-4d46-a419-1654a5bf47ef";
        portDetail["uuid"] = OvsdbValue(p2PortUuid);
        const string p2("p2-tap");
        portDetail["name"] = OvsdbValue(p2);
        portDetails[p2PortUuid] = portDetail;

        const string erspanPortUuid2 = "f9f42dce-44cb-1234-8920-dfc32d88ec07";
        portDetail["uuid"] = OvsdbValue(erspanPortUuid2);
        const string portName2(ERSPAN_PORT_PREFIX + "test");
        portDetail["name"] = OvsdbValue(portName2);
        portDetails[erspanPortUuid2] = portDetail;

        const string erspanPortUuid3 = "f9f42dce-44cb-1234-8920-dfc32d88dd07";
        portDetail["uuid"] = OvsdbValue(erspanPortUuid3);
        const string portName3(ERSPAN_PORT_PREFIX + "abc");
        portDetail["name"] = OvsdbValue(portName3);
        portDetails[erspanPortUuid3] = portDetail;

        conn->getOvsdbState().fullUpdate(OvsdbTable::PORT, portDetails);

        OvsdbTableDetails mirrorDetails;
        OvsdbRowDetails mirrorDetail;
        uuid = "999108c7-ce2d-4d46-a419-1654a5bf47ef";
        mirrorDetail["uuid"] = OvsdbValue(uuid);
        const string mirrorName("abc");
        mirrorDetail["name"] = OvsdbValue(mirrorName);
        mirrorDetail["out_port"] = OvsdbValue(erspanPortUuid);
        map<string, string> srcPorts;
        srcPorts[p1PortUuid];
        srcPorts[p2PortUuid];
        mirrorDetail["select_src_port"] = OvsdbValue(Dtype::SET, "set", srcPorts);
        map<string, string> dstPorts;
        dstPorts[p1PortUuid];
        dstPorts[p2PortUuid];
        mirrorDetail["select_dst_port"] = OvsdbValue(Dtype::SET, "set", dstPorts);
        mirrorDetails[uuid] = mirrorDetail;

        OvsdbRowDetails mirrorDetail2;
        uuid = "922108c7-ce2d-4d46-a419-1654a5bf47ef";
        mirrorDetail2["uuid"] = OvsdbValue(uuid);
        const string mirrorName2("ugh-vspan");
        mirrorDetail2["name"] = OvsdbValue(mirrorName2);
        mirrorDetail2["out_port"] = OvsdbValue(erspanPortUuid2);
        mirrorDetail2["select_src_port"] = OvsdbValue(Dtype::SET, "set", srcPorts);
        mirrorDetail2["select_dst_port"] = OvsdbValue(Dtype::SET, "set", dstPorts);
        mirrorDetails[uuid] = mirrorDetail2;

        conn->getOvsdbState().fullUpdate(OvsdbTable::MIRROR, mirrorDetails);

        OvsdbTableDetails interfaceDetails;
        {
            OvsdbRowDetails interfaceDetail;
            string interfaceUuid = "9b7295f4-07a8-41ac-a681-e0ee82123456";
            interfaceDetail["uuid"] = OvsdbValue(interfaceUuid);
            interfaceDetail["name"] = OvsdbValue(ERSPAN_PORT_PREFIX);
            map<string, string> options;
            const string version = "2";
            options["erspan_ver"] = version;
            const string remoteIp = "99.99.99.99";
            options["remote_ip"] = remoteIp;
            const string key = "1";
            options["key"] = key;
            interfaceDetail["options"] = OvsdbValue(Dtype::MAP, "map", options);
            interfaceDetails[interfaceUuid] = interfaceDetail;
        }

        {
            OvsdbRowDetails interfaceDetail;
            string interfaceUuid = "aaaaaaaa-07a8-41ac-a681-e0ee82123456";
            interfaceDetail["uuid"] = OvsdbValue(interfaceUuid);
            interfaceDetail["name"] = OvsdbValue(ERSPAN_PORT_PREFIX + "test");
            map<string, string> options;
            const string version = "2";
            options["erspan_ver"] = version;
            const string remoteIp = "99.99.99.12";
            options["remote_ip"] = remoteIp;
            const string key = "5";
            options["key"] = key;
            interfaceDetail["options"] = OvsdbValue(Dtype::MAP, "map", options);
            interfaceDetails[interfaceUuid] = interfaceDetail;
        }
        conn->getOvsdbState().fullUpdate(OvsdbTable::INTERFACE, interfaceDetails);
    }

    virtual ~SpanRendererFixture() {
        spr->stop();
    };

    shared_ptr<SpanRenderer> spr;
    unique_ptr<OvsdbConnection> conn;
};

static bool verifyCreateDestroy(const shared_ptr<SpanRenderer>& spr, unique_ptr<OvsdbConnection>& conn) {
    opflexagent::mirror mir;
    if (!conn->getOvsdbState().getMirrorState("abc", mir)) {
        return false;
    }
    string erspanUuid;
    conn->getOvsdbState().getUuidForName(OvsdbTable::PORT, ERSPAN_PORT_PREFIX, erspanUuid);
    if (erspanUuid.empty()) {
        LOG(WARNING) << "Unable to find UUID for port erspan";
        return false;
    }

    string sessionName("abc");
    spr->deleteMirror(sessionName);

    set<string> src_ports = {"p1-tap", "p2-tap"};
    set<string> dst_ports = {"p1-tap", "p2-tap"};
    set<string> out_ports = {ERSPAN_PORT_PREFIX};
    URI sessUri("/SpanUniverse/SpanSession/" + sessionName);
    auto sess = std::make_shared<SessionState>(sessUri, sessionName);
    sess->setDestination(boost::asio::ip::address::from_string("10.20.120.240"));
    sess->setVersion(2);
    sess->setSessionId(8);
    sess->setDestPort(ERSPAN_PORT_PREFIX);
    spr->createMirrorAndOutputPort(sess, src_ports, dst_ports);

    // hits case where mirror isn't already present
    string sessionName2("not-present");
    URI sessUri2("/SpanUniverse/SpanSession/" + sessionName2);
    sess = std::make_shared<SessionState>(sessUri2, sessionName2);
    sess->setDestination(boost::asio::ip::address::from_string("10.20.120.240"));
    sess->setVersion(2);
    sess->setSessionId(8);
    sess->setDestPort(ERSPAN_PORT_PREFIX);
    spr->createMirrorAndOutputPort(sess, src_ports, dst_ports);
    return true;
}

BOOST_FIXTURE_TEST_CASE( verify_getport, SpanRendererFixture ) {
    BOOST_CHECK_EQUAL(true,verifyCreateDestroy(spr, conn));

    // test handling of delete for non-existant mirror
    spr->deleteMirror("notpresent");
}

BOOST_FIXTURE_TEST_CASE( delete_session, SpanRendererFixture ) {
    URI sessionUri("/SpanUniverse/SpanSession/abc/");
    string sessionName("abc");
    shared_ptr<SessionState> sessionState = make_shared<SessionState>(sessionUri, sessionName);
    spr->spanDeleted(sessionState);
}

BOOST_FIXTURE_TEST_CASE( verify_get_erspan_params, SpanRendererFixture ) {
    auto pu = policy::Universe::resolve(framework).get();
    auto su = span::Universe::resolve(framework).get();
    Mutator mutator(framework, "policyreg");
    auto space = pu->addPolicySpace("test");
    auto bd = space->addGbpBridgeDomain("bd");
    auto session = su->addSpanSession("ugh-vspan");
    session->setState(platform::AdminStateEnumT::CONST_ON);
    auto srcGrp1 = session->addSpanSrcGrp("SrcGrp1");
    auto srcMem1 = srcGrp1->addSpanSrcMember("SrcMem1");

    shared_ptr<span::DstGrp> dstGrp1 = session->addSpanDstGrp("DstGrp1");
    shared_ptr<span::DstMember> dstMem1 = dstGrp1->addSpanDstMember("DstMem1");
    auto dstSumm1 = dstMem1->addSpanDstSummary();
    auto lEp1 = session->addSpanLocalEp("localEp1");
    lEp1->setName("p1-tap");
    srcMem1->addSpanMemberToRefRSrc()->setTargetLocalEp(lEp1->getURI());
    srcMem1->setDir('0');
    srcGrp1->addSpanSrcMember(srcMem1->getName().get());

    dstGrp1->addSpanDstMember(dstMem1->getName().get());
    dstSumm1->setDest("192.168.20.100");
    dstSumm1->setVersion(1);

    mutator.commit();

    auto epr = epr::L2Universe::resolve(framework).get();
    Mutator mutator2(framework, "policyelement");
    MAC l2Mac("aa:bb:cc:dd:01:01");
    auto l2Ep = epr->addEprL2Ep(bd->getURI().toString(), l2Mac);
    l2Ep->setInterfaceName("p1-tap");
    MAC l2Mac2("aa:bb:cc:dd:01:02");
    auto l2Ep2 = epr->addEprL2Ep(bd->getURI().toString(), l2Mac2);
    l2Ep2->setInterfaceName("p2-tap");
    mutator2.commit();

    ErspanParams params;
    BOOST_CHECK_EQUAL(true, conn->getOvsdbState().getErspanParams(ERSPAN_PORT_PREFIX, params));
    Mutator mutator3(framework, "policyreg");
    auto localEp = session->addSpanLocalEp("p1-tap");
    localEp->setName("p1-tap");
    auto epRel = localEp->addSpanLocalEpToEpRSrc();
    epRel->setTargetL2Ep(l2Ep->getURI());
    auto localEp2 = session->addSpanLocalEp("p2-tap");
    localEp2->setName("p2-tap");
    auto ep2Rel = localEp2->addSpanLocalEpToEpRSrc();
    ep2Rel->setTargetL2Ep(l2Ep2->getURI());
    mutator3.commit();
    WAIT_FOR(modelgbp::span::LocalEpToEpRSrc::resolve(framework, ep2Rel->getURI()), 500);

    {
        // TOOD - populate SrcGrps in modb instead
        lock_guard <recursive_mutex> guard(SpanManager::updates);
        agent.getSpanManager().addEndpoint(localEp, l2Ep, DirectionEnumT::CONST_IN);
        agent.getSpanManager().addEndpoint(localEp2, l2Ep2, DirectionEnumT::CONST_BIDIRECTIONAL);
    }
    spr->spanUpdated(session->getURI());

    // test buildPortSets
    auto sessionState =
        make_shared<SessionState>(session->getURI(), session->getName().get());
    SourceEndpoint srcEp("some-name", "veth1", DirectionEnumT::CONST_BIDIRECTIONAL);
    sessionState->addSrcEndpoint(srcEp);

    SourceEndpoint srcEp2("another-name", "veth2", DirectionEnumT::CONST_IN);
    sessionState->addSrcEndpoint(srcEp2);

    SourceEndpoint srcEp3("last-name", "veth3", DirectionEnumT::CONST_OUT);
    sessionState->addSrcEndpoint(srcEp3);

    sessionState->setDestPort(ERSPAN_PORT_PREFIX + "abc");
    sessionState->setDestination(boost::asio::ip::address::from_string("1.2.3.4"));
    sessionState->setVersion(2);
    sessionState->setAdminState(platform::AdminStateEnumT::CONST_ON);

    spr->updateMirrorConfig(sessionState);
}

BOOST_AUTO_TEST_SUITE_END()

}
