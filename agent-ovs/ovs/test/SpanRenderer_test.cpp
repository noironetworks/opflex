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
#include <SpanRenderer.h>
#include "MockRpcConnection.h"
#include <opflexagent/SpanSessionState.h>
#include <modelgbp/dmtree/Root.hpp>

namespace opflexagent {

using namespace std;
using namespace rapidjson;
using namespace modelgbp;

BOOST_AUTO_TEST_SUITE(SpanRenderer_test)

class SpanRendererFixture : public BaseFixture {
public:
    SpanRendererFixture() : BaseFixture() {
        spr = make_shared<SpanRenderer>(agent);
        initLogging("debug", false, "");
        conn.reset(new MockRpcConnection());
        spr->start("br-int", conn.get());
        spr->connect();
    }

    virtual ~SpanRendererFixture() {
        spr->stop();
    };

    shared_ptr<SpanRenderer> spr;
    unique_ptr<OvsdbConnection> conn;
};

static bool verifyCreateDestroy(const shared_ptr<SpanRenderer>& spr) {
    spr->setNextId(1000);
    JsonRpc::mirror mir;
    if (!spr->jRpc->getOvsdbMirrorConfig("abc",mir)) {
        return false;
    }
    string erspanUuid;
    spr->jRpc->getUuid(OvsdbTable::PORT, "erspan", erspanUuid);
    if (erspanUuid.empty()) {
        return false;
    }
    if (!spr->jRpc->updateBridgePorts("br-int", erspanUuid, false)) {
        return false;
    }

    string sessionName("abc");
    if (!spr->deleteMirror(sessionName)) {
        return false;
    }
    ErspanParams params;
    params.setPortName("erspan");
    params.setRemoteIp("10.20.120.240");
    params.setVersion(1);
    if (!spr->jRpc->addErspanPort("br-int", params)) {
        return false;
    }
    set<string> src_ports = {"p1-tap", "p2-tap"};
    set<string> dst_ports = {"p1-tap", "p2-tap"};
    set<string> out_ports = {"erspan"};
    return spr->createMirror("sess1", src_ports, dst_ports);
}

BOOST_FIXTURE_TEST_CASE( verify_getport, SpanRendererFixture ) {
    BOOST_CHECK_EQUAL(true,verifyCreateDestroy(spr));
}

BOOST_FIXTURE_TEST_CASE( verify_add_remote_port, SpanRendererFixture ) {
    spr->setNextId(1012);

    BOOST_CHECK_EQUAL(true, spr->addErspanPort(ERSPAN_PORT_PREFIX, "3.3.3.3", 2));
    BOOST_CHECK_EQUAL(true, spr->deleteErspanPort(ERSPAN_PORT_PREFIX));
}

BOOST_FIXTURE_TEST_CASE( delete_session, SpanRendererFixture ) {
    spr->setNextId(1015);

    URI sessionUri("/SpanUniverse/SpanSession/abc/");
    string sessionName("abc");
    shared_ptr<SessionState> sessionState = std::make_shared<SessionState>(sessionUri, sessionName);
    spr->spanDeleted(sessionState);
}

BOOST_FIXTURE_TEST_CASE( verify_get_erspan_params, SpanRendererFixture ) {
    spr->setNextId(1019);

    auto pu = policy::Universe::resolve(framework).get();
    auto su = span::Universe::resolve(framework).get();
    Mutator mutator(framework, "policyreg");
    auto space = pu->addPolicySpace("test");
    auto bd = space->addGbpBridgeDomain("bd");
    auto session = su->addSpanSession("ugh-vspan");
    session->setState(0);
    mutator.commit();

    auto epr = epr::L2Universe::resolve(framework).get();
    Mutator mutator2(framework, "policyelement");
    MAC l2Mac("aa:bb:cc:dd:01:01");
    auto l2Ep = epr->addEprL2Ep(bd->getURI().toString(), l2Mac);
    MAC l2Mac2("aa:bb:cc:dd:01:02");
    auto l2Ep2 = epr->addEprL2Ep(bd->getURI().toString(), l2Mac2);
    mutator2.commit();

    ErspanParams params;
    BOOST_CHECK_EQUAL(true, spr->jRpc->getCurrentErspanParams(ERSPAN_PORT_PREFIX, params));
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

    spr->spanUpdated(session->getURI());
}

BOOST_AUTO_TEST_SUITE_END()

}
