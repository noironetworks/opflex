
/*
 * Copyright (c) 2014-2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <vector>
#include "QosRenderer.h"
#include <opflexagent/logging.h>
#include <opflexagent/QosManager.h>
#include <boost/optional.hpp>
#include <boost/format.hpp>

namespace opflexagent {
    using boost::optional;

    QosRenderer::QosRenderer(Agent& agent_) : JsonRpcRenderer(agent_) {
    }

    void QosRenderer::start(const std::string& swName, OvsdbConnection* conn) {
        LOG(DEBUG) << "starting QosRenderer";
        JsonRpcRenderer::start(swName, conn);
        agent.getQosManager().registerListener(this);
    }

    void QosRenderer::stop() {
        LOG(DEBUG) << "stopping QosRenderer";
        agent.getQosManager().unregisterListener(this);
    }

    void QosRenderer::ingressQosUpdated(const string& interface) {
        LOG(DEBUG) << "ingressUpdate" << interface;
        handleIngressQosUpdate(interface);
    }

    void QosRenderer::egressQosUpdated(const string& interface) {
        LOG(DEBUG) << "egressUpdate" << interface;
        handleEgressQosUpdate(interface);
    }


    void QosRenderer::qosDeleted(const string& interface) {
        LOG(DEBUG) << "Process QosDeleted for interface " << interface;
        if (!connect()) {
            LOG(DEBUG) << "failed to connect, retry in " << CONNECTION_RETRY << " seconds";
            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                        boost::posix_time::seconds(CONNECTION_RETRY)));
            connection_timer->async_wait(boost::bind(&QosRenderer::delConnectCb, this,
                        boost::asio::placeholders::error, interface));
            timerStarted = true;
            return;
        }

        QosManager &qosMgr = agent.getQosManager();
        optional<shared_ptr<QosConfigState>> egressConfigState =
            qosMgr.getEgressQosConfigState(interface);
        if (!egressConfigState){
            LOG(DEBUG) << "clearing egress qos for interface: " << interface ;
            deleteEgressQos(interface);
        }

        optional<shared_ptr<QosConfigState>> ingressConfigState =
            qosMgr.getIngressQosConfigState(interface);
        if (!ingressConfigState){
            LOG(DEBUG) << "clearing ingress qos for interface: " << interface ;
            deleteIngressQos(interface);
        }

    }

    void QosRenderer::handleEgressQosUpdate(const string& interface) {
        LOG(DEBUG) << "thread " << std::this_thread::get_id();
        LOG(DEBUG) << "interface: "<< interface;
        QosManager &qosMgr = agent.getQosManager();

        optional<shared_ptr<QosConfigState>> qosConfigState =
            qosMgr.getEgressQosConfigState(interface);
        if (!qosConfigState) {
            return;
        }
        if (!connect()) {
            LOG(DEBUG) << "failed to connect, retry in " << CONNECTION_RETRY << " seconds";

            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                        milliseconds(CONNECTION_RETRY * 1000)));
            connection_timer->async_wait(boost::bind(&QosRenderer::updateConnectCb, this,
                        boost::asio::placeholders::error, interface));
            timerStarted = true;
            LOG(DEBUG) << "conn timer " << connection_timer << ", timerStarted: " << timerStarted;
            return;
        }
        uint64_t rate = qosConfigState.get()->getRate();
        uint64_t burst = qosConfigState.get()->getBurst();

        updateEgressQosParams(interface, rate, burst);
    }


    void QosRenderer::handleIngressQosUpdate(const string& interface) {
        LOG(DEBUG) << "thread " << std::this_thread::get_id();
        LOG(DEBUG) << "interface: "<< interface;
        QosManager &qosMgr = agent.getQosManager();

        optional<shared_ptr<QosConfigState>> qosConfigState =
            qosMgr.getIngressQosConfigState(interface);
        if (!qosConfigState) {
            return;
        }
        if (!connect()) {
            LOG(DEBUG) << "failed to connect, retry in " << CONNECTION_RETRY << " seconds";

            connection_timer.reset(new deadline_timer(agent.getAgentIOService(),
                        milliseconds(CONNECTION_RETRY * 1000)));
            connection_timer->async_wait(boost::bind(&QosRenderer::updateConnectCb, this,
                        boost::asio::placeholders::error, interface));
            timerStarted = true;
            LOG(DEBUG) << "conn timer " << connection_timer << ", timerStarted: " << timerStarted;
            return;
        }
        uint64_t rate = qosConfigState.get()->getRate();
        uint64_t burst = qosConfigState.get()->getBurst();

        updateIngressQosParams(interface, rate, burst);
    }

    void QosRenderer::updateConnectCb(const boost::system::error_code& ec,
            const string& interface) {
        LOG(DEBUG) << "timer update cb";
        if (ec) {
            string cat = string(ec.category().name());
            LOG(DEBUG) << "timer error " << cat << ":" << ec.value();
            if (!(cat == "system" &&
                        ec.value() == 125)) {
                connection_timer->cancel();
                timerStarted = false;
            }
            return;
        }

        egressQosUpdated(interface);
        ingressQosUpdated(interface);
    }

    void QosRenderer::delConnectCb(const boost::system::error_code& ec,
            const string& interface) {
        if (ec) {
            connection_timer.reset();
            return;
        }
        LOG(DEBUG) << "timer span del cb";
        qosDeleted(interface);
    }

    void QosRenderer::updateEgressQosParams(const string& interface, const uint64_t& rate, const uint64_t& burst){
        OvsdbTransactMessage msg1(OvsdbOperation::UPDATE, OvsdbTable::INTERFACE);
        set<tuple<string, OvsdbFunction, string>> conditionSet;
        conditionSet.emplace("name", OvsdbFunction::EQ, interface);
        msg1.conditions = conditionSet;

        vector<OvsdbValue> values;
        values.emplace_back(rate);
        OvsdbValues tdSet1(values);
        msg1.rowData["ingress_policing_rate"] = tdSet1;

        values.clear();
        values.emplace_back(burst);
        OvsdbValues tdSet2(values);
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

        std::ostringstream burstString;
        burstString << burst;
        const string burstS  = burstString.str();
        values.emplace_back("burst", burstS);

        std::ostringstream rateString;
        rateString << rate;
        const string rateS = rateString.str();
        values.emplace_back("max-rate", rateS);

        OvsdbValues tdSet1("map", values);
        msg1.rowData.emplace("other_config", tdSet1);

        const string queue_uuid = "queue1";
        msg1.externalKey = make_pair("uuid-name", queue_uuid);

        OvsdbTransactMessage msg2(OvsdbOperation::INSERT, OvsdbTable::QOS);

        values.clear();

        std::map<std::string, std::string> queueUuid;
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
        msg3.conditions = conditionSet;

        values.clear();
        values.emplace_back("named-uuid", uuid_name);
        OvsdbValues tdSet4(values);
        msg3.rowData["qos"] = tdSet4;

        const list<OvsdbTransactMessage> requests = {msg1,msg2,msg3};
        sendAsyncTransactRequests(requests);
    }

    void QosRenderer::deleteIngressQos(const string& interface){
    }

}
