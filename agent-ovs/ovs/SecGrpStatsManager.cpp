/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for SecGrpStatsManager class.
 *
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/logging.h>
#include "AccessFlowManager.h"
#include <opflexagent/IdGenerator.h>
#include <opflexagent/Agent.h>
#include "TableState.h"
#include "SecGrpStatsManager.h"

#include "ovs-ofputil.h"

extern "C" {
#include <openvswitch/ofp-msgs.h>
}

#include <opflex/modb/URI.h>
#include <opflex/modb/Mutator.h>
#include <modelgbp/gbpe/L24Classifier.hpp>
#include <modelgbp/gbpe/SecGrpClassifierCounter.hpp>
#include <modelgbp/gbpe/LocalSecGrpClassifierCounter.hpp>
#include <modelgbp/observer/PolicyStatUniverse.hpp>

namespace opflexagent {

using std::string;
using std::shared_ptr;
using boost::optional;
using opflex::modb::URI;
using opflex::modb::Mutator;
using namespace modelgbp::gbp;
using namespace modelgbp::observer;
using namespace modelgbp::gbpe;
using boost::asio::placeholders::error;
using boost::posix_time::milliseconds;
using std::bind;
using boost::system::error_code;

SecGrpStatsManager::SecGrpStatsManager(Agent* agent_, IdGenerator& idGen_,
                                       SwitchManager& switchManager_,
                                       long timer_interval_)
    : PolicyStatsManager(agent_,idGen_,switchManager_,timer_interval_) {
}


SecGrpStatsManager::~SecGrpStatsManager() {

}

void SecGrpStatsManager::start() {
    LOG(DEBUG) << "Starting security group stats manager ("
               << timer_interval << " ms)";
    PolicyStatsManager::start();

    {
        std::lock_guard<std::mutex> lock(timer_mutex);
        timer->async_wait(bind(&SecGrpStatsManager::on_timer, this, error));
    }
}

void SecGrpStatsManager::stop() {
    LOG(DEBUG) << "Stopping security group stats manager";
    PolicyStatsManager::stop();
}

void SecGrpStatsManager::on_timer(const error_code& ec) {
    if (ec) {
        std::lock_guard<std::mutex> lock(timer_mutex);
        // shut down the timer when we get a cancellation
        timer.reset();
        return;
    }

    TableState::cookie_callback_t cb_func;
    cb_func = [this](uint64_t cookie, uint16_t priority,
                     const struct match& match) {
        const std::lock_guard<std::mutex> lock(pstatMtx);
        updateFlowEntryMap(secGrpInState, cookie, priority, match);
    };

    // Request Switch Manager to provide flow entries
    {
        switchManager.
            forEachCookieMatch(AccessFlowManager::SEC_GROUP_IN_TABLE_ID,
                               cb_func);

        cb_func = [this](uint64_t cookie, uint16_t priority,
                         const struct match& match) {
            const std::lock_guard<std::mutex> lock(pstatMtx);
            updateFlowEntryMap(secGrpOutState, cookie, priority, match);
        };
        switchManager.
            forEachCookieMatch(AccessFlowManager::SEC_GROUP_OUT_TABLE_ID,
                               cb_func);

        const std::lock_guard<std::mutex> lock(pstatMtx);
        PolicyCounterMap_t newClassCountersMap1;
        PolicyCounterMap_t newClassCountersMap2;
        on_timer_base(ec, secGrpInState, newClassCountersMap1);
        on_timer_base(ec, secGrpOutState, newClassCountersMap2);
        generatePolicyStatsObjects(&newClassCountersMap1,
                                   &newClassCountersMap2);
    }

    sendRequest(AccessFlowManager::SEC_GROUP_IN_TABLE_ID);
    sendRequest(AccessFlowManager::SEC_GROUP_OUT_TABLE_ID);
    if (!stopping) {
        std::lock_guard<std::mutex> lock(timer_mutex);
        if (timer) {
            timer->expires_from_now(milliseconds(timer_interval));
            timer->async_wait(bind(&SecGrpStatsManager::on_timer, this, error));
        }
    }
}

void SecGrpStatsManager::clearCounterObject(const string& key,
                                            uint8_t index) {
    if (agent->getPolicyManager().useLocalNetpol()) {
        LocalSecGrpClassifierCounter::remove(agent->getFramework(),
                                             getAgentUUID(),
                                             genIdList_[key]->uidList[index],key);
    } else {
        SecGrpClassifierCounter::remove(agent->getFramework(),
                                        getAgentUUID(),
                                        genIdList_[key]->uidList[index],key);
    }
}

void SecGrpStatsManager::
updatePolicyStatsCounters(const string& l24Classifier,
                          FlowStats_t& newVals1,
                          FlowStats_t& newVals2) {
    Mutator mutator(agent->getFramework(), "policyelement");
    optional<shared_ptr<PolicyStatUniverse> > su =
        PolicyStatUniverse::resolve(agent->getFramework());
    if (su) {
        uint64_t nextId = getNextClsfrGenId();
        clearOldCounters(l24Classifier,nextId);
        if (newVals1.byte_count && newVals2.byte_count) {
            if (agent->getPolicyManager().useLocalNetpol()) {
                su.get()->addGbpeLocalSecGrpClassifierCounter(getAgentUUID(),
                                                              nextId,
                                                              l24Classifier)
                    ->setTxpackets(newVals2.packet_count.get())
                    .setTxbytes(newVals2.byte_count.get())
                    .setRxpackets(newVals1.packet_count.get())
                    .setRxbytes(newVals1.byte_count.get());
            } else {
                su.get()->addGbpeSecGrpClassifierCounter(getAgentUUID(),
                                                         nextId,
                                                         l24Classifier)
                    ->setTxpackets(newVals2.packet_count.get())
                    .setTxbytes(newVals2.byte_count.get())
                    .setRxpackets(newVals1.packet_count.get())
                    .setRxbytes(newVals1.byte_count.get());
            }
            prometheusManager.addNUpdateSGClassifierCounter(l24Classifier,
                                                            newVals1.byte_count.get(),
                                                            newVals1.packet_count.get(),
                                                            newVals2.byte_count.get(),
                                                            newVals2.packet_count.get());
        } else if (newVals1.byte_count) {
            if (agent->getPolicyManager().useLocalNetpol()) {
                su.get()->addGbpeLocalSecGrpClassifierCounter(getAgentUUID(),
                                                              nextId,
                                                              l24Classifier)
                    ->setRxpackets(newVals1.packet_count.get())
                    .setRxbytes(newVals1.byte_count.get());
            } else {
                su.get()->addGbpeSecGrpClassifierCounter(getAgentUUID(),
                                                         nextId,
                                                         l24Classifier)
                    ->setRxpackets(newVals1.packet_count.get())
                    .setRxbytes(newVals1.byte_count.get());
            }
            prometheusManager.addNUpdateSGClassifierCounter(l24Classifier,
                                                            newVals1.byte_count.get(),
                                                            newVals1.packet_count.get(),
                                                            0, 0);
        } else if (newVals2.byte_count) {
            if (agent->getPolicyManager().useLocalNetpol()) {
                su.get()->addGbpeLocalSecGrpClassifierCounter(getAgentUUID(),
                                                              nextId,
                                                              l24Classifier)
                    ->setTxpackets(newVals2.packet_count.get())
                    .setTxbytes(newVals2.byte_count.get());
            } else {
                su.get()->addGbpeSecGrpClassifierCounter(getAgentUUID(),
                                                         nextId,
                                                         l24Classifier)
                    ->setTxpackets(newVals2.packet_count.get())
                    .setTxbytes(newVals2.byte_count.get());
            }
            prometheusManager.addNUpdateSGClassifierCounter(l24Classifier,
                                                            0, 0,
                                                            newVals2.byte_count.get(),
                                                            newVals2.packet_count.get());
        }
    }
    mutator.commit();
}

void SecGrpStatsManager::objectUpdated(opflex::modb::class_id_t class_id,
                                       const URI& uri) {
    if (class_id == L24Classifier::CLASS_ID) {
        if (!L24Classifier::resolve(agent->getFramework(),uri)) {
            removeAllCounterObjects(uri.toString());
            prometheusManager.removeSGClassifierCounter(uri.toString());
        }
    } else if (class_id == LocalL24Classifier::CLASS_ID) {
        if (!LocalL24Classifier::resolve(agent->getFramework(),uri)) {
            removeAllCounterObjects(uri.toString());
            prometheusManager.removeSGClassifierCounter(uri.toString());
       }
    }
}

void SecGrpStatsManager::Handle(SwitchConnection* connection,
                                int msgType,
                                ofpbuf *msg,
                                struct ofputil_flow_removed* fentry) {
    handleMessage(msgType, msg,
                  [this](uint32_t table_id) -> flowCounterState_t* {
                      switch (table_id) {
                      case AccessFlowManager::SEC_GROUP_IN_TABLE_ID:
                          return &secGrpInState;
                      case AccessFlowManager::SEC_GROUP_OUT_TABLE_ID:
                          return &secGrpOutState;
                      default:
                          return NULL;
                      }
                  }, fentry);
}

} /* namespace opflexagent */
