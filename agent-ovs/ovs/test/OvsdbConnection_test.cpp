/*
 * Test suite for class OvsdbConnection
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
#include "MockRpcConnection.h"

namespace opflexagent {

using namespace std;
using namespace rapidjson;

BOOST_AUTO_TEST_SUITE(OvsdbConnection_test)

class OvsdbConnectionFixture : public BaseFixture {
public:
    OvsdbConnectionFixture() : BaseFixture() {
        initLogging("debug", false, "");
        conn.reset(new MockRpcConnection());
    }

    virtual ~OvsdbConnectionFixture() {
        conn->disconnect();
    };

    const string bridgeMonitorResponse {"{\"Bridge\":{\"0a581b90-92f8-4b35-8d28-dc4b8894d056\":{\"new\":{\"netflow\":[\"set\",[]],\"name\":\"br-access\",\"ports\":[\"uuid\",\"43ac6ab8-9ca0-4e8a-a224-23370a9951de\"],\"ipfix\":[\"set\",[]],\"mirrors\":[\"set\",[]]}},\"18368680-b320-458f-927c-3e8e87a75a7a\":{\"new\":{\"netflow\":[\"set\",[]],\"name\":\"br-int\",\"ports\":[\"set\",[[\"uuid\",\"6c7ed412-778c-43e6-a28a-90ec3d5c23d2\"],[\"uuid\",\"78e8ffe1-b227-4020-84ea-bd9c32ae3c81\"],[\"uuid\",\"79af9603-c805-4772-9b5d-56cc4c0aa02b\"],[\"uuid\",\"8a7ce194-ffe4-4f50-8f1b-ec2e29abef6c\"],[\"uuid\",\"d781b46b-3220-4872-9dc1-fb988bdd698e\"],[\"uuid\",\"e8a58da4-a1bb-4d3f-86f9-ab2a8a008c89\"]]],\"ipfix\":[\"uuid\",\"72c9bcd4-c66f-41d1-8f14-85241d098eba\"],\"mirrors\":[\"set\",[[\"uuid\",\"76f28e5d-2a96-4c1c-b226-0e10cef76bf3\"],[\"uuid\",\"cc7387e0-a63f-4945-9c8d-446ea36f7b53\"]]]}}}}"};
    const string bridgeMonitorUpdate = "[\"Bridge\"," + bridgeMonitorResponse + "]";
    const string portMonitorResponse {"{\"Port\":{\"8a7ce194-ffe4-4f50-8f1b-ec2e29abef6c\":{\"new\":{\"name\":\"veth25\",\"interfaces\":[\"uuid\",\"be01b633-ff0c-4b3a-b1af-09506068fe27\"]}},\"2cd48b4d-4b6d-468c-8cff-e88f4a9bb2b3\":{\"new\":{\"name\":\"erspan-ughadf-vspan\",\"interfaces\":[\"uuid\",\"072d002d-f8fb-47d8-8ba9-7d59022b7e9c\"]}},\"e8a58da4-a1bb-4d3f-86f9-ab2a8a008c89\":{\"new\":{\"name\":\"veth19-1\",\"interfaces\":[\"uuid\",\"177160de-af8b-4666-99de-e1221040bd55\"]}},\"79af9603-c805-4772-9b5d-56cc4c0aa02b\":{\"new\":{\"name\":\"br-int\",\"interfaces\":[\"uuid\",\"d7b6d459-b8fb-4c6d-adaf-763a11af59a3\"]}},\"e0af933c-089e-4fde-a45e-ccd8251232e7\":{\"new\":{\"name\":\"erspan-ugh-vspan\",\"interfaces\":[\"uuid\",\"3eb3b8ee-dcdc-445e-b527-a69f107bd5b3\"]}},\"78e8ffe1-b227-4020-84ea-bd9c32ae3c81\":{\"new\":{\"name\":\"veth19-2\",\"interfaces\":[\"uuid\",\"cf369886-4d38-490d-9c21-ed0b3bf1d60b\"]}},\"43ac6ab8-9ca0-4e8a-a224-23370a9951de\":{\"new\":{\"name\":\"br-access\",\"interfaces\":[\"uuid\",\"5f710771-f935-4ee6-aac5-7224e350a10a\"]}}}}"};
    const string portMonitorUpdate = "[\"Port\"," + portMonitorResponse + "]";
    const string interfaceMonitorResponse {"{\"Interface\":{\"cf369886-4d38-490d-9c21-ed0b3bf1d60b\":{\"new\":{\"name\":\"veth19-2\",\"options\":[\"map\",[]],\"type\":\"\"}},\"d7b6d459-b8fb-4c6d-adaf-763a11af59a3\":{\"new\":{\"name\":\"br-int\",\"options\":[\"map\",[]],\"type\":\"internal\"}},\"5f710771-f935-4ee6-aac5-7224e350a10a\":{\"new\":{\"name\":\"br-access\",\"options\":[\"map\",[]],\"type\":\"internal\"}},\"be01b633-ff0c-4b3a-b1af-09506068fe27\":{\"new\":{\"name\":\"veth25\",\"options\":[\"map\",[]],\"type\":\"\"}},\"177160de-af8b-4666-99de-e1221040bd55\":{\"new\":{\"name\":\"veth19-1\",\"options\":[\"map\",[]],\"type\":\"\"}},\"3eb3b8ee-dcdc-445e-b527-a69f107bd5b3\":{\"new\":{\"name\":\"erspan-ugh-vspan\",\"options\":[\"map\",[[\"erspan_ver\",\"2\"],[\"remote_ip\",\"11.2.3.4\"]]],\"type\":\"erspan\"}},\"072d002d-f8fb-47d8-8ba9-7d59022b7e9c\":{\"new\":{\"name\":\"erspan-ughadf-vspan\",\"options\":[\"map\",[[\"erspan_ver\",\"2\"],[\"remote_ip\",\"172.28.184.26\"]]],\"type\":\"erspan\"}}}}"};
    const string interfaceMonitorUpdate = "[\"Interface\"," + interfaceMonitorResponse + "]";
    const string mirrorMonitorResponse {"{\"Mirror\":{\"5c1f62a9-6a27-4408-a24b-5990018beb05\":{\"new\":{\"name\":\"ugh-vspan\",\"output_port\":[\"uuid\",\"e0af933c-089e-4fde-a45e-ccd8251232e7\"],\"select_dst_port\":[\"uuid\",\"8a7ce194-ffe4-4f50-8f1b-ec2e29abef6c\"],\"select_src_port\":[\"uuid\",\"8a7ce194-ffe4-4f50-8f1b-ec2e29abef6c\"]}},\"95d2860e-e1ea-41f3-9743-af32fe4debad\":{\"new\":{\"name\":\"ughadf-vspan\",\"output_port\":[\"uuid\",\"2cd48b4d-4b6d-468c-8cff-e88f4a9bb2b3\"],\"select_dst_port\":[\"uuid\",\"78e8ffe1-b227-4020-84ea-bd9c32ae3c81\"],\"select_src_port\":[\"uuid\",\"78e8ffe1-b227-4020-84ea-bd9c32ae3c81\"]}}}}"};
    const string mirrorMonitorUpdate = "[\"Mirror\"," + mirrorMonitorResponse + "]";
    const string netflowMonitorResponse {"{\"NetFlow\":{\"cf88e525-ed28-4599-9fbe-8a4eabd9c62b\":{\"new\":{\"active_timeout\":180,\"add_id_to_interface\":false,\"targets\":\"172.28.184.76:2055\"}}}}"};
    const string netflowMonitorUpdate = "[\"NetFlow\"," + netflowMonitorResponse + "]";
    const string ipfixMonitorResponse {"{\"IPFIX\":{\"b85011b0-4aa6-43ce-831b-4d2e4f97af30\":{\"new\":{\"other_config\":[\"map\",[[\"enable-tunnel-sampling\",\"true\"]]],\"targets\":\"172.28.184.9:2055\",\"sampling\":[\"set\",[]]}}}}"};
    const string ipfixMonitorUpdate = "[\"IPFIX\"," + ipfixMonitorResponse + "]";
    const string qosMonitorResponse = {"{\"QoS\":{\"8d8d8e4d-617c-40c9-9aa6-43b9a73d6c28\":{\"new\":{\"queues\":[\"map\",[]]}}}}"};
    const string qosMonitorUpdate = "[\"QoS\"," + qosMonitorResponse + "]";
    unique_ptr<OvsdbConnection> conn;
};

BOOST_FIXTURE_TEST_CASE( verify_connect, OvsdbConnectionFixture ) {
    conn->start();
    conn->connect();

    // sample monitor call
    LOG(WARNING) << "sending monitor req";
    conn->sendMonitorRequests();

    // mock monitor response
    Document payload;
    payload.GetAllocator().Clear();
    payload.Parse(bridgeMonitorResponse.c_str());
    conn->handleMonitor(1, payload);
    payload.GetAllocator().Clear();
    payload.Parse(bridgeMonitorUpdate.c_str());
    conn->handleUpdate(payload);

    payload.GetAllocator().Clear();
    payload.Parse(portMonitorResponse.c_str());
    conn->handleMonitor(2, payload);
    payload.GetAllocator().Clear();
    payload.Parse(portMonitorUpdate.c_str());
    conn->handleUpdate(payload);

    payload.GetAllocator().Clear();
    payload.Parse(interfaceMonitorResponse.c_str());
    conn->handleMonitor(3, payload);
    payload.GetAllocator().Clear();
    payload.Parse(interfaceMonitorUpdate.c_str());
    conn->handleUpdate(payload);

    payload.GetAllocator().Clear();
    payload.Parse(mirrorMonitorResponse.c_str());
    conn->handleMonitor(4, payload);
    payload.GetAllocator().Clear();
    payload.Parse(mirrorMonitorUpdate.c_str());
    conn->handleUpdate(payload);

    payload.GetAllocator().Clear();
    payload.Parse(netflowMonitorResponse.c_str());
    conn->handleMonitor(5, payload);
    payload.GetAllocator().Clear();
    payload.Parse(netflowMonitorUpdate.c_str());
    conn->handleUpdate(payload);

    payload.GetAllocator().Clear();
    payload.Parse(ipfixMonitorResponse.c_str());
    conn->handleMonitor(6, payload);
    payload.GetAllocator().Clear();
    payload.Parse(ipfixMonitorUpdate.c_str());
    conn->handleUpdate(payload);

    payload.GetAllocator().Clear();
    payload.Parse(qosMonitorResponse.c_str());
    conn->handleMonitor(7, payload);
    payload.GetAllocator().Clear();
    payload.Parse(qosMonitorUpdate.c_str());
    conn->handleUpdate(payload);

    conn->stop();
}
BOOST_AUTO_TEST_SUITE_END()

}