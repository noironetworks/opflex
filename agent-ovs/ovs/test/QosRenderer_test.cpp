/*
 * Test suite for class QosRenderer
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>

#include <opflexagent/logging.h>
#include <opflexagent/test/BaseFixture.h>
#include <QosRenderer.h>
#include "MockRpcConnection.h"

namespace opflexagent {

using namespace std;
using namespace rapidjson;

BOOST_AUTO_TEST_SUITE(QosRenderer_test)

class QosRendererFixture : public BaseFixture {
public:
    QosRendererFixture() : BaseFixture() {
        qosRenderer = make_shared<QosRenderer>(agent);
        initLogging("debug", false, "");
        conn.reset(new MockRpcConnection());
        qosRenderer->start("br-int", conn.get());
        qosRenderer->connect();

        // simulate results of monitor
        OvsdbRowDetails rowDetails;
        std::string uuid = " 9b7295f4-07a8-41ac-a681-e0ee82560262";
        rowDetails["uuid"] = OvsdbValue(uuid);
        OvsdbTableDetails tableDetails;
        tableDetails["intf1"] = rowDetails;
        conn->getOvsdbState().fullUpdate(OvsdbTable::INTERFACE, tableDetails);

        uuid = "34a18e6b-8748-430c-bf7b-b4c7220b36c0";
        rowDetails["uuid"] = OvsdbValue(uuid);
        tableDetails["intf1"] = rowDetails;
        conn->getOvsdbState().fullUpdate(OvsdbTable::PORT, tableDetails);
    }

    virtual ~QosRendererFixture() {
        qosRenderer->stop();
    };

    shared_ptr<QosRenderer> qosRenderer;
    unique_ptr<OvsdbConnection> conn;
};

bool verifyCreateDestroy(Agent& agent, const shared_ptr<QosRenderer>& qosRenderer) {
    qosRenderer->updateEgressQosParams("intf1", 3000, 300);
    qosRenderer->deleteEgressQos("intf1");

    qosRenderer->updateIngressQosParams("intf1", 4000, 400, 4);
    qosRenderer->deleteIngressQos("intf1");

    return true;
}

BOOST_FIXTURE_TEST_CASE( verify_createdestroy, QosRendererFixture ) {
    BOOST_CHECK_EQUAL(true, verifyCreateDestroy(agent, qosRenderer));
}
BOOST_AUTO_TEST_SUITE_END()

}
