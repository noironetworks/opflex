/*
 * Copyright (c) 2014-2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <vector>

#include "NetFlowRenderer.h"
#include <opflexagent/logging.h>
#include <modelgbp/netflow/CollectorVersionEnumT.hpp>


namespace opflexagent {
    using boost::optional;

    NetFlowRenderer::NetFlowRenderer(Agent& agent_) : JsonRpcRenderer(agent_) {
    }

    void NetFlowRenderer::start(const vector<std::string&> swNames, OvsdbConnection* conn) {
        LOG(DEBUG) << "starting NetFlow renderer";
        JsonRpcRenderer::start(swNames conn);
        agent.getNetFlowManager().registerListener(this);
    }

    void NetFlowRenderer::stop() {
        LOG(DEBUG) << "stopping NetFlow renderer";
        JsonRpcRenderer::stop();
        agent.getNetFlowManager().unregisterListener(this);
    }

    void NetFlowRenderer::exporterUpdated(const opflex::modb::URI& netFlowURI) {
        LOG(DEBUG) << "NetFlow exporter updated";
        handleNetFlowUpdate(netFlowURI);
    }

    void NetFlowRenderer::exporterDeleted(const shared_ptr<ExporterConfigState>& expSt) {
        if (!connect()) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(DEBUG) << "failed to connect, retry in " << CONNECTION_RETRY << " seconds";
            // connection failed, start a timer to try again
            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                                                        boost::posix_time::seconds(CONNECTION_RETRY)));
            connection_timer->async_wait(boost::bind(&NetFlowRenderer::delConnectCb, this,
                                                    boost::asio::placeholders::error, expSt));
            timerStarted = true;
            return;
        }
        LOG(DEBUG) << "deleting exporter";
        if (!expSt) {
            return;
        }
        if (expSt->getVersion() ==  CollectorVersionEnumT::CONST_V5) {
            deleteNetFlow();
        } else if(expSt->getVersion() == CollectorVersionEnumT::CONST_V9) {
            deleteIpfix();
        }
    }

    void NetFlowRenderer::handleNetFlowUpdate(const opflex::modb::URI& netFlowURI) {
        if (!connect()) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(DEBUG) << "OVSDB connection not ready, retry in " << CONNECTION_RETRY << " seconds";
            // connection failed, start a timer to try again

            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                                                      milliseconds(CONNECTION_RETRY * 1000)));
            connection_timer->async_wait(boost::bind(&NetFlowRenderer::updateConnectCb, this,
                                                     boost::asio::placeholders::error, netFlowURI));
            timerStarted = true;
            LOG(DEBUG) << "conn timer " << connection_timer << ", timerStarted: " << timerStarted;
            return;
        }
        NetFlowManager &spMgr = agent.getNetFlowManager();
        optional<shared_ptr<ExporterConfigState>> expSt =
            spMgr.getExporterConfigState(netFlowURI);
        // Is the exporter config state pointer set
        if (!expSt) {
            return;
        }
        std::string target = expSt.get()->getDstAddress() + ":";
        std::string port = std::to_string(expSt.get()->getDestinationPort());
        target += port;
        LOG(DEBUG) << "netflow/ipfix target " << target.c_str() << " version is " << std::to_string(expSt.get()->getVersion());

        if (expSt.get()->getVersion() == CollectorVersionEnumT::CONST_V5) {
            uint32_t timeout = expSt.get()->getActiveFlowTimeOut();
            createNetFlow(target, timeout);
        } else if (expSt.get()->getVersion() == CollectorVersionEnumT::CONST_V9) {
            uint32_t sampling = expSt.get()->getSamplingRate();
            uint32_t activeTimeout = expSt.get()->getActiveFlowTimeOut();
            createIpfix(target, sampling, activeTimeout);
        }
    }

    void NetFlowRenderer::deleteNetFlow() {
        LOG(DEBUG) << "deleting netflow";

        vector<OvsdbValue> values;
        OvsdbValues tdSet("set", values);

        list<OvsdbTransactMessage> msgs;

        for (std::string& switchName : switchNames) {
            OvsdbTransactMessage msg(OvsdbOperation::UPDATE, OvsdbTable::BRIDGE);
            set<tuple<string, OvsdbFunction, string>> condSet;
            condSet.emplace("name", OvsdbFunction::EQ, switchName);
            msg.conditions = condSet;
            msg.rowData.emplace("netflow", tdSet);
            msgs.push_back(msg);
        }
        sendAsyncTransactRequests(msgs);
    }

    void NetFlowRenderer::deleteIpfix() {
        LOG(DEBUG) << "deleting IPFIX";

        vector<OvsdbValue> values;
        OvsdbValues tdSet("set", values);

        const list<OvsdbTransactMessage> requests;

        for (std::string& switchName : switchNames) {
            OvsdbTransactMessage msg(OvsdbOperation::UPDATE, OvsdbTable::BRIDGE);
            set<tuple<string, OvsdbFunction, string>> condSet;
            condSet.emplace("name", OvsdbFunction::EQ, switchName);
            msg.conditions = condSet;
            msg.rowData.emplace("ipfix", tdSet);

            requests.push_back(msg);
        }
        sendAsyncTransactRequests(requests);
    }

    void NetFlowRenderer::createNetFlow(const string& targets, int timeout) {
        vector<OvsdbValue> values;
        values.emplace_back(targets);
        OvsdbValues tdSet(values);
        OvsdbTransactMessage msg1(OvsdbOperation::INSERT, OvsdbTable::NETFLOW);
        msg1.rowData["targets"] = tdSet;

        values.clear();
        values.emplace_back(timeout);
        OvsdbValues tdSet2(values);
        msg1.rowData["active_timeout"] = tdSet2;

        values.clear();
        values.emplace_back(false);
        OvsdbValues tdSet3(values);
        msg1.rowData["add_id_to_interface"] = tdSet3;

        const string uuid_name = "netflow1";
        msg1.externalKey = make_pair("uuid-name", uuid_name);

        const list<OvsdbTransactMessage> requests = {msg1};

        values.clear();
        values.emplace_back("named-uuid", uuid_name);
        OvsdbValues tdSet4(values);

        for (std::string& switchName : switchNames) {
            string brUuid;
            conn->getOvsdbState().getBridgeUuid(switchName, brUuid);
            LOG(DEBUG) << "bridge uuid " << brUuid;

            OvsdbTransactMessage msg2(OvsdbOperation::UPDATE, OvsdbTable::BRIDGE);
            set<tuple<string, OvsdbFunction, string>> condSet;
            condSet.emplace("_uuid", OvsdbFunction::EQ, brUuid);
            msg2.conditions = condSet;

            msg2.rowData.emplace("netflow", tdSet4);
            // make sure there is no ipfix config
            values.clear();
            OvsdbValues emptySet("set", values);
            msg2.rowData.emplace("ipfix", emptySet);

           requests.push_back(msg2);
        }
        sendAsyncTransactRequests(requests);
    }

    void NetFlowRenderer::createIpfix(const string& targets, int sampling, int activeTimeout) {
        vector<OvsdbValue> values;
        values.emplace_back(targets);
        OvsdbValues tdSet(values);
        OvsdbTransactMessage msg1(OvsdbOperation::INSERT, OvsdbTable::IPFIX);
        msg1.rowData.emplace("targets", tdSet);
        if (sampling != 0) {
            values.clear();
            values.emplace_back(sampling);
            OvsdbValues tdSet2(values);
            msg1.rowData.emplace("sampling", tdSet2);
        }

        // hash the agent UUID to build a domain ID
        uint64_t domainId = std::hash<string>{}(agent.getUuid());
        domainId &= 0x0ffffffful;
        values.clear();
        values.emplace_back(domainId);
        OvsdbValues domainSet(values);
        msg1.rowData.emplace("obs_domain_id", domainSet);

        values.clear();
        const uint64_t pointId = 1ull;
        values.emplace_back(pointId);
        OvsdbValues pointSet(values);
        msg1.rowData.emplace("obs_point_id", pointSet);

        if (activeTimeout) {
            values.clear();
            values.emplace_back(activeTimeout);
            OvsdbValues timeoutSet(values);
            msg1.rowData.emplace("cache_active_timeout", timeoutSet);
        }

        values.clear();
        static const string disabled("false");
        values.emplace_back("enable-tunnel-sampling", disabled);
        //values.emplace_back("enable-output-sampling", disabled);
        //static const string enabled("true");
        //values.emplace_back("enable-input-sampling", enabled);
        OvsdbValues tdSet3("map", values);
        msg1.rowData.emplace("other_config", tdSet3);
        const string uuid_name = "ipfix1";
        msg1.externalKey = make_pair("uuid-name", uuid_name);

        values.clear();
        values.emplace_back("named-uuid", uuid_name);
        OvsdbValues tdSet4(values);

        const list<OvsdbTransactMessage> requests = {msg1};

        for (std::string& switchName : switchNames) {
            string brUuid;
            conn->getOvsdbState().getBridgeUuid(switchName, brUuid);
            LOG(DEBUG) << "bridge uuid " << brUuid << " sampling rate is " << sampling
                << "active flow timeout " << activeTimeout;

            OvsdbTransactMessage msg2(OvsdbOperation::UPDATE, OvsdbTable::BRIDGE);
            set<tuple<string, OvsdbFunction, string>> condSet;
            condSet.emplace("_uuid", OvsdbFunction::EQ, brUuid);
            msg2.conditions = condSet;

            msg2.rowData.emplace("ipfix", tdSet4);
            // make sure there is no netflow config
            values.clear();
            OvsdbValues emptySet("set", values);
            msg2.rowData.emplace("netflow", emptySet);
            requests.push_back(msg2);
        }
        sendAsyncTransactRequests(requests);
    }

    void NetFlowRenderer::updateConnectCb(const boost::system::error_code& ec, const opflex::modb::URI& spanURI) {
        LOG(DEBUG) << "timer update cb";
        if (ec) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(WARNING) << "reset timer";
            connection_timer.reset();
            return;
        }
        exporterUpdated(spanURI);
    }

    void NetFlowRenderer::delConnectCb(const boost::system::error_code& ec,
                                       shared_ptr<ExporterConfigState>& expSt) {
        if (ec) {
            const std::lock_guard<std::mutex> guard(timer_mutex);
            LOG(WARNING) << "reset timer";
            connection_timer.reset();
            return;
        }
        LOG(DEBUG) << "timer span del cb";
        exporterDeleted(expSt);
    }
}
