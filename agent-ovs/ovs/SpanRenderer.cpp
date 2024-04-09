
/*
 * Copyright (c) 2014-2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "SpanRenderer.h"
#include "OvsdbState.h"
#include <opflexagent/logging.h>
#include <boost/optional.hpp>


namespace opflexagent {
    using boost::optional;
    using namespace std;
    using modelgbp::gbp::DirectionEnumT;

    SpanRenderer::SpanRenderer(Agent& agent_) : JsonRpcRenderer(agent_) {}

    void SpanRenderer::start(const std::string& swName, OvsdbConnection* conn) {
        LOG(DEBUG) << "starting span renderer";
        JsonRpcRenderer::start(swName, conn);
        agent.getSpanManager().registerListener(this);
    }

    void SpanRenderer::stop() {
        LOG(DEBUG) << "stopping span renderer";
        JsonRpcRenderer::stop();
        agent.getSpanManager().unregisterListener(this);
    }

    void SpanRenderer::spanUpdated(const opflex::modb::URI& spanURI) {
        LOG(INFO) << "span updated " << spanURI;
        handleSpanUpdate(spanURI);
    }

    void SpanRenderer::spanDeleted(const shared_ptr<SessionState>& seSt) {
        if (!connect()) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(DEBUG) << "OVSDB connection not ready, retry in " << CONNECTION_RETRY << " seconds";
            // connection failed, start a timer to try again
            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                                                      boost::posix_time::seconds(CONNECTION_RETRY)));
            connection_timer->async_wait(boost::bind(&SpanRenderer::delConnectPtrCb, this,
                                                     boost::asio::placeholders::error, seSt));
            timerStarted = true;
            return;
        }
        sessionDeleted(seSt->getName());
    }

    void SpanRenderer::updateConnectCb(const boost::system::error_code& ec,
            const opflex::modb::URI& spanURI) {
        LOG(DEBUG) << "timer update cb";
        if (ec) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(WARNING) << "reset timer";
            connection_timer.reset();
            return;
        }
        spanUpdated(spanURI);
    }

    void SpanRenderer::delConnectPtrCb(const boost::system::error_code& ec, const shared_ptr<SessionState>& pSt) {
        if (ec) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(WARNING) << "reset timer";
            connection_timer.reset();
            return;
        }
        LOG(DEBUG) << "timer span del with ptr cb";
        spanDeleted(pSt);
    }

    void SpanRenderer::sessionDeleted(const string& sessionName) {
        LOG(INFO) << "deleting session " << sessionName;
        deleteMirror(sessionName);
    }

    void SpanRenderer::updateOutputPort(const shared_ptr<SessionState>& session) {
        // get ERSPAN interface params if configured
        ErspanParams params;
        list<OvsdbTransactMessage> requests;
        OvsdbTransactMessage msg(OvsdbOperation::UPDATE, OvsdbTable::INTERFACE);

        vector<OvsdbValue> vec;
        const string typeString("erspan");
        OvsdbValue typeData(typeString);
        vec.push_back(typeData);
        OvsdbValues values2(vec);
        msg.rowData.emplace("type", values2);

        vec.clear();
        vec.emplace_back("erspan_ver", std::to_string(session->getVersion()));
        static const string erspanDir("1");
        vec.emplace_back("erspan_dir", erspanDir);
        static const string erspanHwId("4");
        vec.emplace_back("erspan_hwid", erspanHwId);
        vec.emplace_back("remote_ip", session->getDestination().to_string());
        vec.emplace_back("key", std::to_string(session->getSessionId()));
        OvsdbValues values3("map", vec);
        msg.rowData.emplace("options", values3);

        set<tuple<string, OvsdbFunction, string>> condSet;
        condSet.emplace("name", OvsdbFunction::EQ, session->getDestPort());
        msg.conditions = std::move(condSet);

        requests.push_back(msg);
        sendAsyncTransactRequests(requests);
    }

    void SpanRenderer::handleSpanUpdate(const opflex::modb::URI& spanURI) {
        if (!connect()) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(DEBUG) << "OVSDB connection not ready, retry in " << CONNECTION_RETRY << " seconds";
            // connection failed, start a timer to try again
            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                                                      milliseconds(CONNECTION_RETRY * 1000)));
            connection_timer->async_wait(boost::bind(&SpanRenderer::updateConnectCb, this,
                                                     boost::asio::placeholders::error, spanURI));
            timerStarted = true;
            LOG(DEBUG) << "conn timer " << connection_timer << ", timerStarted: " << timerStarted;
            return;
        }

        SpanManager& spMgr = agent.getSpanManager();
        lock_guard<recursive_mutex> guard(opflexagent::SpanManager::updates);
        optional<shared_ptr<SessionState>> seSt = spMgr.getSessionState(spanURI);
        // Is the session state pointer set
        if (!seSt) {
            return;
        }

        // get mirror artifacts from OVSDB if provisioned
        opflexagent::mirror mir;
        bool isMirProv = conn->getOvsdbState().getMirrorState(seSt.get()->getName(), mir);

        // There should be at least one source and the destination should be set
        // Admin state should be ON.
        if (!seSt.get()->hasSrcEndpoints() ||
            seSt.get()->getDestination().is_unspecified() ||
            seSt.get()->getAdminState() == 0) {
            LOG(INFO) << "Incomplete mirror config. Either admin down or missing src/dest EPs";
            if (isMirProv) {
                sessionDeleted(seSt.get()->getName());
            }
            return;
        }

        set<string> srcPorts;
        set<string> dstPorts;
        buildPortSets(seSt.get(), srcPorts, dstPorts);

        LOG(DEBUG) << "src port count = " << srcPorts.size();
        LOG(DEBUG) << "dest port count = " << dstPorts.size();

        // check if the number of source and dest ports are the
        // same as provisioned.
        if (srcPorts.size() != mir.src_ports.size() ||
            dstPorts.size() != mir.dst_ports.size()) {
            updateMirrorConfig(seSt.get());
            return;
        }

        // compare port names. If at least one is different, the config
        // has changed.
        for (const auto& src_port : mir.src_ports) {
            auto itr = srcPorts.find(src_port);
            if (itr == srcPorts.end()) {
                updateMirrorConfig(seSt.get());
                return;
            }
        }

        for (const auto& dst_port : mir.dst_ports) {
            auto itr = dstPorts.find(dst_port);
            if (itr == dstPorts.end()) {
                updateMirrorConfig(seSt.get());
                return;
            }
        }

        // get ERSPAN interface params if configured
        ErspanParams params;
        if (!conn->getOvsdbState().getErspanParams(seSt.get()->getDestPort(), params)) {
            LOG(DEBUG) << "Unable to get ERSPAN parameters";
            return;
        }

        if (isOutputPortUpdateRequired(seSt.get())) {
            LOG(INFO) << "Output port config has changed for " << seSt.get()->getName();
            updateOutputPort(seSt.get());
        }
    }

    bool SpanRenderer::isOutputPortUpdateRequired(const shared_ptr<SessionState>& session) {
        // get ERSPAN interface params if configured
        ErspanParams params;
        if (!conn->getOvsdbState().getErspanParams(session->getDestPort(), params)) {
            LOG(DEBUG) << "Unable to get ERSPAN parameters";
            return false;
        }
        return
            params.getRemoteIp() != session->getDestination().to_string() ||
            params.getVersion() != session->getVersion() ||
            params.getSessionId() != session->getSessionId();
    }

    void SpanRenderer::buildPortSets(const shared_ptr<SessionState>& session, set<string>& srcPorts, set<string>& dstPorts) {
        SessionState::srcEpSet srcEps;
        session->getSrcEndpointSet(srcEps);
        for (auto& src : srcEps) {
            if (src.getDirection() == DirectionEnumT::CONST_BIDIRECTIONAL ||
                src.getDirection() == DirectionEnumT::CONST_OUT) {
                srcPorts.emplace(src.getPort());
            }
            if (src.getDirection() == DirectionEnumT::CONST_BIDIRECTIONAL ||
                src.getDirection() == DirectionEnumT::CONST_IN) {
                dstPorts.emplace(src.getPort());
            }
        }
    }

    void SpanRenderer::updateMirrorConfig(const shared_ptr<SessionState>& seSt) {
        // get the source ports.
        set<string> srcPorts;
        set<string> dstPorts;
        buildPortSets(seSt, srcPorts, dstPorts);

        LOG(DEBUG) << "create/update mirror config with srcport count = " << srcPorts.size() << " and dstport count = " << dstPorts.size();
        createMirrorAndOutputPort(seSt, srcPorts, dstPorts);
    }

    void SpanRenderer::deleteMirror(const string& sessionName) {
        LOG(DEBUG) << "deleting mirror " << sessionName;
        string sessionUuid;
        conn->getOvsdbState().getUuidForName(OvsdbTable::MIRROR, sessionName, sessionUuid);
        if (sessionUuid.empty()) {
            // nothing to do
            LOG(DEBUG) << "Unable to find session for name " << sessionName;
            return;
        }

        OvsdbTransactMessage msg(OvsdbOperation::MUTATE, OvsdbTable::BRIDGE);
        set<tuple<string, OvsdbFunction, string>> condSet;
        condSet.emplace("name", OvsdbFunction::EQ, switchName);
        msg.conditions = std::move(condSet);

        vector<OvsdbValue> values;
        values.emplace_back("uuid", sessionUuid);
        OvsdbValues tdSet = OvsdbValues(std::move(values));
        msg.mutateRowData.emplace("mirrors", std::make_pair(OvsdbOperation::DELETE, tdSet));

        const list<OvsdbTransactMessage> requests = {msg};
        sendAsyncTransactRequests(requests);
    }

    void SpanRenderer::createMirrorAndOutputPort(
        const shared_ptr<SessionState>& sess, const set<string>& srcPorts, const set<string>& dstPorts) {
        string brUuid;
        conn->getOvsdbState().getBridgeUuid(switchName, brUuid);
        LOG(DEBUG) << "bridge uuid " << brUuid;

        list<OvsdbTransactMessage> requests;

        // first make sure the output port is present, create it if it's not
        string outputPortUuid;
        conn->getOvsdbState().getUuidForName(OvsdbTable::PORT, sess->getDestPort(), outputPortUuid);
        const string portNamedUuid = "port1";
        if (outputPortUuid.empty()) {
            // need to create port/interface
            OvsdbTransactMessage msg(OvsdbOperation::INSERT, OvsdbTable::PORT);
            vector<OvsdbValue> values;
            values.emplace_back(sess->getDestPort());
            OvsdbValues tdSet(values);
            msg.rowData.emplace("name", tdSet);

            // uuid-name
            msg.externalKey = make_pair("uuid-name", portNamedUuid);

            // interfaces
            values.clear();
            const string named_uuid = "interface1";
            values.emplace_back("named-uuid", named_uuid);
            OvsdbValues tdSet2(values);
            msg.rowData.emplace("interfaces", tdSet2);

            // uuid-name
            OvsdbTransactMessage msg2(OvsdbOperation::INSERT, OvsdbTable::INTERFACE);
            msg2.externalKey = make_pair("uuid-name", named_uuid);

            // row entries
            // name
            values.clear();
            values.emplace_back(sess->getDestPort());
            OvsdbValues tdSet3(values);
            msg2.rowData.emplace("name", tdSet3);

            values.clear();
            const string typeString("erspan");
            OvsdbValue typeData(typeString);
            values.push_back(typeData);
            OvsdbValues tdSet4(values);
            msg2.rowData.emplace("type", tdSet4);

            values.clear();
            values.emplace_back("erspan_ver", std::to_string(sess->getVersion()));
            static const string erspanDir("1");
            values.emplace_back("erspan_dir", erspanDir);
            static const string erspanHwId("4");
            values.emplace_back("erspan_hwid", erspanHwId);
            values.emplace_back("remote_ip", sess->getDestination().to_string());
            values.emplace_back("key", std::to_string(sess->getSessionId()));
            OvsdbValues tdSet5("map", values);
            msg2.rowData.emplace("options", tdSet5);

            requests.push_back(msg);
            requests.push_back(msg2);
        } else {
            // check if update required
            if (isOutputPortUpdateRequired(sess)) {
                LOG(INFO) << "Output port config has changed for " << sess->getName();
                updateOutputPort(sess);
            } else {
                LOG(INFO) << "Using existing output port uuid " << outputPortUuid;
            }
        }

        string sessionUuid;
        conn->getOvsdbState().getUuidForName(OvsdbTable::MIRROR, sess->getName(), sessionUuid);
        bool sessionExists = !sessionUuid.empty();

        OvsdbOperation operation = sessionExists ? OvsdbOperation::UPDATE : OvsdbOperation::INSERT;
        OvsdbTransactMessage msg1(operation, OvsdbTable::MIRROR);
        vector<OvsdbValue> srcPortUuids;
        for (auto &srcPort : srcPorts) {
            string srcPortUuid;
            LOG(DEBUG) << "Looking up port " << srcPort;
            conn->getOvsdbState().getUuidForName(OvsdbTable::PORT, srcPort, srcPortUuid);
            if (!srcPortUuid.empty()) {
                LOG(DEBUG) << "uuid for port " << srcPort << " is " << srcPortUuid;
                srcPortUuids.emplace_back("uuid", srcPortUuid);
            } else {
                LOG(DEBUG) << "Unable to find uuid for port " << srcPort;
            }
        }

        LOG(INFO) << "mirror src_port size " << srcPortUuids.size();
        OvsdbValues tdSet("set", srcPortUuids);
        msg1.rowData.emplace("select_src_port", tdSet);

        // dst ports
        vector<OvsdbValue> dstPortUuids;
        for (auto &dstPort : dstPorts) {
            string dstPortUuid;
            conn->getOvsdbState().getUuidForName(OvsdbTable::PORT, dstPort, dstPortUuid);
            if (!dstPortUuid.empty()) {
                dstPortUuids.emplace_back("uuid", dstPortUuid);
            } else {
                LOG(WARNING) << "Unable to find uuid for port " << dstPort;
            }
        }
        LOG(INFO) << "mirror dst_port size " << dstPortUuids.size();
        OvsdbValues tdSet2("set", dstPortUuids);
        msg1.rowData.emplace("select_dst_port", tdSet2);

        // output ports
        vector<OvsdbValue> outputPort;
        if (outputPortUuid.empty()) {
            // port is being newly created in this set of requests
            OvsdbValue outPort("named-uuid", portNamedUuid);
            outputPort.emplace_back(outPort);
        } else {
            OvsdbValue outPort("uuid", outputPortUuid);
            outputPort.emplace_back(outPort);
        }
        OvsdbValues tdSet3(outputPort);
        msg1.rowData.emplace("output_port", tdSet3);

        // name
        vector<OvsdbValue> values;
        values.emplace_back(sess->getName());
        OvsdbValues tdSet4(values);
        msg1.rowData.emplace("name", tdSet4);

        if (!sessionExists) {
            const string mirrorUuidName = "mirror1";
            msg1.externalKey = make_pair("uuid-name", mirrorUuidName);

            OvsdbTransactMessage msg2(OvsdbOperation::MUTATE, OvsdbTable::BRIDGE);
            set<tuple<string, OvsdbFunction, string>> condSet;
            condSet.emplace("_uuid", OvsdbFunction::EQ, brUuid);
            msg2.conditions = condSet;
            values.clear();
            values.emplace_back("named-uuid", mirrorUuidName);
            OvsdbValues tdSet5(values);
            msg2.mutateRowData.emplace("mirrors", std::make_pair(OvsdbOperation::INSERT, tdSet5));
            // only if we're adding the port now as well
            if (outputPortUuid.empty()) {
                values.clear();
                values.emplace_back("named-uuid", portNamedUuid);
                OvsdbValues tdSet6(values);
                msg2.mutateRowData.emplace("ports", std::make_pair(OvsdbOperation::INSERT, tdSet6));
            }

            requests.push_back(msg1);
            requests.push_back(msg2);
        } else {
            set<tuple<string, OvsdbFunction, string>> condSet;
            condSet.emplace("_uuid", OvsdbFunction::EQ, sessionUuid);
            msg1.conditions = condSet;
            requests.push_back(msg1);
        }
        sendAsyncTransactRequests(requests);
    }
}
