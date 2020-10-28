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

        OvsdbTableDetails qosTableDetails;
        OvsdbRowDetails qosRowDetails;
        uuid = "f53499ff-0f9f-4f05-9e21-e15738bc7149";
        qosRowDetails["uuid"] = OvsdbValue(uuid);
        std::map<std::string, std::string> queueMap;
        queueMap.insert(make_pair("0", "7e35b63f-227b-4c96-b01b-9bd0c0562852"));
        qosRowDetails["queues"] = OvsdbValue(Dtype::MAP, "map", queueMap);
        qosTableDetails[uuid] = qosRowDetails;
        conn->getOvsdbState().fullUpdate(OvsdbTable::QOS, qosTableDetails);

        OvsdbTableDetails portTableDetails;
        OvsdbRowDetails portRowDetails;
        uuid = "34a18e6b-8748-430c-bf7b-b4c7220b36c0";
        portRowDetails["uuid"] = OvsdbValue(uuid);
        std::map<std::string, std::string> qosMap;
        qosMap["f53499ff-0f9f-4f05-9e21-e15738bc7149"] = "";
        portRowDetails["qos"] = OvsdbValue(Dtype::MAP, "map", qosMap);
        const string portName ("intf1");
        portRowDetails["name"] = OvsdbValue(portName);
        portTableDetails[uuid] = portRowDetails;

        conn->getOvsdbState().fullUpdate(OvsdbTable::PORT, portTableDetails);
    }

    virtual ~QosRendererFixture() {
        qosRenderer->stop();
    };

    shared_ptr<QosRenderer> qosRenderer;
    unique_ptr<OvsdbConnection> conn;
};

bool verifyCreateDestroy(const shared_ptr<QosRenderer>& qosRenderer, unique_ptr<OvsdbConnection>& conn) {
    string interface("intf1");
    qosRenderer->updateEgressQosParams(interface, 3000, 300);
    qosRenderer->deleteEgressQos(interface);

    qosRenderer->updateIngressQosParams(interface, 4000, 400);
    string qosUuid;
    conn->getOvsdbState().getQosUuidForPort(interface, qosUuid);
    if (qosUuid.empty()) {
        LOG(WARNING) << "Could not find qos for interface.";
        return false;
    }

    string queueUuid;
    conn->getOvsdbState().getQueueUuidForQos(qosUuid, queueUuid);
    if (queueUuid.empty()) {
        LOG(WARNING) << "Could not find queue for qos.";
        return false;
    }

    qosRenderer->deleteIngressQos("intf1");
    return true;
}

BOOST_FIXTURE_TEST_CASE( verify_createdestroy, QosRendererFixture ) {
    BOOST_CHECK_EQUAL(true, verifyCreateDestroy(qosRenderer, conn));
}
BOOST_AUTO_TEST_SUITE_END()

}
