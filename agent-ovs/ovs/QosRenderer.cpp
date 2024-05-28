
/*
 * Copyright (c) 2014-2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <vector>
#include "QosRenderer.h"

namespace opflexagent {
    using boost::optional;

    QosRenderer::QosRenderer(Agent& agent_) : JsonRpcRenderer(agent_) {
    }

    void QosRenderer::start(const string& swName, OvsdbConnection* conn) {
        LOG(DEBUG) << "starting QosRenderer";
        JsonRpcRenderer::start(swName, conn);
        agent.getQosManager().registerListener(this);
    }

    void QosRenderer::stop() {
        LOG(DEBUG) << "stopping QosRenderer";
        JsonRpcRenderer::stop();
        agent.getQosManager().unregisterListener(this);
    }

    void QosRenderer::ingressQosUpdated(const string& interface,
            const optional<shared_ptr<QosConfigState>>& qosConfig) {
        LOG(DEBUG) << "interface: " << interface;
        handleIngressQosUpdate(interface, qosConfig);
    }

    void QosRenderer::egressQosUpdated(const string& interface,
            const optional<shared_ptr<QosConfigState>>& qosConfig) {
        LOG(DEBUG) << "interface: " << interface;
        handleEgressQosUpdate(interface, qosConfig);
    }

    void QosRenderer::qosDeleted(const string& interface) {
        LOG(DEBUG) << "Process QosDeleted for interface " << interface;
        if (!connect()) {
            const lock_guard<mutex> guard(timer_mutex);
            LOG(DEBUG) << "failed to connect, retry in " << CONNECTION_RETRY << " seconds";
            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                        boost::posix_time::seconds(CONNECTION_RETRY)));
            connection_timer->async_wait(boost::bind(&QosRenderer::delConnectCb, this,
                        boost::asio::placeholders::error, interface));
            timerStarted = true;
            return;
        }

        LOG(DEBUG) << "clearing egress and ingress qos for interface: " << interface;
        deleteEgressQos(interface);
        deleteIngressQos(interface);
    }

    void QosRenderer::handleEgressQosUpdate(const string& interface,
            const optional<shared_ptr<QosConfigState>>& qosConfigState) {
        LOG(DEBUG) << "interface: " << interface;

        if (!connect()) {
            const lock_guard<mutex> guard(timer_mutex);
            LOG(DEBUG) << "failed to connect, retry in " << CONNECTION_RETRY << " seconds";

            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                        milliseconds(CONNECTION_RETRY * 1000)));
            connection_timer->async_wait(boost::bind(&QosRenderer::updateConnectCb, this,
                        boost::asio::placeholders::error, interface, qosConfigState));
            timerStarted = true;
            LOG(DEBUG) << "conn timer " << connection_timer << ", timerStarted: " << timerStarted;
            return;
        }

        deleteEgressQos(interface);
        if (!qosConfigState) {
            return;
        }

        uint64_t rate = qosConfigState.get()->getRate();
        uint64_t burst = qosConfigState.get()->getBurst();

        updateEgressQosParams(interface, rate, burst);
    }

    void QosRenderer::handleIngressQosUpdate(const string& interface,
            const optional<shared_ptr<QosConfigState>>& qosConfigState) {
        LOG(DEBUG) << "interface: "<< interface;

        if (!connect()) {
            const lock_guard<mutex> guard(timer_mutex);
            LOG(DEBUG) << "failed to connect, retry in " << CONNECTION_RETRY << " seconds";

            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                        milliseconds(CONNECTION_RETRY * 1000)));
            connection_timer->async_wait(boost::bind(&QosRenderer::updateConnectCb, this,
                        boost::asio::placeholders::error, interface, qosConfigState));
            timerStarted = true;
            LOG(DEBUG) << "conn timer " << connection_timer << ", timerStarted: " << timerStarted;
            return;
        }

        deleteIngressQos(interface);
        if (!qosConfigState) {
            return;
        }

        uint64_t rate = qosConfigState.get()->getRate();
        uint64_t burst = qosConfigState.get()->getBurst();

        rate = rate * 1024;
        burst = burst * 1024;
        updateIngressQosParams(interface, rate, burst);
    }

    void QosRenderer::updateConnectCb(const boost::system::error_code& ec,
            const string& interface, const optional<shared_ptr<QosConfigState>>& qosConfigState) {
        LOG(DEBUG) << "timer update cb";
        if (ec) {
            const lock_guard<mutex> guard(timer_mutex);
            LOG(WARNING) << "reset timer";
            connection_timer.reset();
            return;
        }

        egressQosUpdated(interface, qosConfigState);
        ingressQosUpdated(interface, qosConfigState);
    }

    void QosRenderer::delConnectCb(const boost::system::error_code& ec,
            const string& interface) {
        if (ec) {
            const lock_guard<mutex> guard(timer_mutex);
            connection_timer.reset();
            return;
        }
        LOG(DEBUG) << "timer qos del cb";
        qosDeleted(interface);
    }

    void QosRenderer::updateEgressQosParams(const string& interface, const uint64_t& rate, const uint64_t& burst){
        OvsdbTransactMessage msg1(OvsdbOperation::UPDATE, OvsdbTable::INTERFACE);
        set<tuple<string, OvsdbFunction, string>> conditionSet;
        conditionSet.emplace("name", OvsdbFunction::EQ, interface);
        msg1.conditions = std::move(conditionSet);

        vector<OvsdbValue> values;
        values.emplace_back(rate);
        OvsdbValues tdSet1(values);
        msg1.rowData["ingress_policing_rate"] = tdSet1;

        values.clear();
        values.emplace_back(burst);
        OvsdbValues tdSet2(std::move(values));
        msg1.rowData["ingress_policing_burst"] = tdSet2;

        const list<OvsdbTransactMessage> requests = {msg1};
        sendAsyncTransactRequests(requests) ;
    }

    void QosRenderer::deleteEgressQos(const string& interface){
        updateEgressQosParams(interface, 0, 0);
    }

    void QosRenderer::updateIngressQosParams(const string& interface, const uint64_t& rate, const uint64_t& burst){
        vector<OvsdbValue> values;
        OvsdbTransactMessage msg1(OvsdbOperation::INSERT, OvsdbTable::QUEUE);

        ostringstream burstString;
        burstString << burst;
        const string burstS  = burstString.str();
        values.emplace_back("burst", burstS);

        ostringstream rateString;
        rateString << rate;
        const string rateS = rateString.str();
        values.emplace_back("max-rate", rateS);

        OvsdbValues tdSet1("map", values);
        msg1.rowData.emplace("other_config", tdSet1);

        const string queue_uuid = "queue1";
        msg1.externalKey = make_pair("uuid-name", queue_uuid);

        OvsdbTransactMessage msg2(OvsdbOperation::INSERT, OvsdbTable::QOS);

        values.clear();

        map<string, string> queueUuid;
        queueUuid.insert(make_pair("named-uuid",queue_uuid));

        values.emplace_back(Dtype::MAP, "0", queueUuid);
        OvsdbValues tdSet2 ("map", values);
        msg2.rowData["queues"] =  tdSet2;

        const string queue_type = "linux-htb";
        values.clear();
        values.emplace_back(queue_type);
        OvsdbValues tdSet3(values);
        msg2.rowData["type"] =  tdSet3;

        const string uuid_name = "qos1";
        msg2.externalKey = make_pair("uuid-name", uuid_name);

        OvsdbTransactMessage msg3(OvsdbOperation::UPDATE, OvsdbTable::PORT);

        set<tuple<string, OvsdbFunction, string>> conditionSet;
        conditionSet.emplace("name", OvsdbFunction::EQ, interface);
        msg3.conditions = std::move(conditionSet);

        values.clear();
        values.emplace_back("named-uuid", uuid_name);
        OvsdbValues tdSet4(std::move(values));
        msg3.rowData["qos"] = tdSet4;

        const list<OvsdbTransactMessage> requests = {msg1,msg2,msg3};
        sendAsyncTransactRequests(requests);
    }

    void QosRenderer::deleteIngressQos(const string& interface) {
        string qosUuid;
        conn->getOvsdbState().getQosUuidForPort(interface, qosUuid);

        if (!qosUuid.empty()) {
            LOG(INFO) << "found qos-uuid: "<< qosUuid;
            OvsdbTransactMessage msg0(OvsdbOperation::DELETE, OvsdbTable::QOS);
            set<tuple<string, OvsdbFunction, string>> conditionSet0;
            conditionSet0.emplace("_uuid", OvsdbFunction::EQ, qosUuid);
            msg0.conditions = std::move(conditionSet0);
            const list<OvsdbTransactMessage> qosDelRequest = {msg0};
            sendAsyncTransactRequests(qosDelRequest);
        }

        string queueUuid;
        conn->getOvsdbState().getQueueUuidForQos(qosUuid, queueUuid);

        if (!queueUuid.empty()) {
            LOG(INFO) << "found queue-uuid: " << queueUuid;
            OvsdbTransactMessage msg2(OvsdbOperation::DELETE, OvsdbTable::QUEUE);
            set<tuple<string, OvsdbFunction, string>> conditionSet2;
            conditionSet2.emplace("_uuid", OvsdbFunction::EQ, queueUuid);
            msg2.conditions = std::move(conditionSet2);
            const list<OvsdbTransactMessage> queueDelRequest = {msg2};
            sendAsyncTransactRequests(queueDelRequest);
        }

        OvsdbTransactMessage msg1(OvsdbOperation::UPDATE, OvsdbTable::PORT);
        vector<OvsdbValue> values;
        OvsdbValues emptySet("set", std::move(values));
        msg1.rowData.emplace("qos", emptySet);

        set<tuple<string, OvsdbFunction, string>> conditionSet;
        conditionSet.emplace("name", OvsdbFunction::EQ, interface);
        msg1.conditions = std::move(conditionSet);

        const list<OvsdbTransactMessage> requests = {msg1};
        sendAsyncTransactRequests(requests);
    }
}
