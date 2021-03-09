/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for SysStatsManager class.
 *
 * Copyright (c) 2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/logging.h>
#include <opflexagent/Agent.h>
#include <opflexagent/SysStatsManager.h>

namespace opflexagent {

using boost::asio::placeholders::error;
using boost::posix_time::milliseconds;
using std::bind;
using boost::system::error_code;
using namespace modelgbp::observer;

SysStatsManager::SysStatsManager (Agent* agent_) :
                                  agent(agent_),
    prometheusManager(agent->getPrometheusManager()),
                                  stopping(true) {
}

SysStatsManager::~SysStatsManager() {
}

void SysStatsManager::start (long timer_interval_) {
    stopping = false;
    timer_interval = timer_interval_;
    LOG(DEBUG) << "Starting sys stats manager ("
               << timer_interval << " ms)";
    std::lock_guard<std::mutex> lock(timer_mutex);
    timer.reset(new deadline_timer(agent->getAgentIOService(),
                                   milliseconds(timer_interval)));
    timer->async_wait(bind(&SysStatsManager::on_timer, this, error));
}

void SysStatsManager::stop () {
    if (stopping)
        return;

    LOG(DEBUG) << "Stopping sys stats manager";
    stopping = true;

    try {
        std::lock_guard<std::mutex> lock(timer_mutex);
        if (timer) {
            LOG(DEBUG) << "timer cancelled";
            timer->cancel();
        }
    } catch (const boost::system::system_error &e ) {
        LOG(DEBUG) << "Failed to cancel timer: " << e.what();
    }
}

void SysStatsManager::on_timer(const error_code& ec) {
    if (ec) {
        std::lock_guard<std::mutex> lock(timer_mutex);
        // shut down the timer when we get a cancellation
        LOG(DEBUG) << "Resetting timer, error: " << ec.message();
        timer.reset();
        return;
    }

    updateOpflexPeerStats();
    updateMoDBCounts();

    if (!stopping) {
        std::lock_guard<std::mutex> lock(timer_mutex);
        if (timer) {
            timer->expires_from_now(milliseconds(timer_interval));
            timer->async_wait(bind(&SysStatsManager::on_timer, this, error));
        }
    }
}

// Update peer specific opflex stats
void SysStatsManager::updateOpflexPeerStats()
{
    std::unordered_map<string, std::shared_ptr<OFAgentStats>> stats;
    agent->getFramework().getOpflexPeerStats(stats);
    Mutator mutator(agent->getFramework(), "policyelement");
    optional<shared_ptr<SysStatUniverse> > ssu =
        SysStatUniverse::resolve(agent->getFramework());
    if (ssu) {
        for (const auto& peerStat : stats) {
            ssu.get()->addObserverOpflexAgentCounter(peerStat.first)
                    ->setIdentReqs(peerStat.second->getIdentReqs())
                    .setIdentResps(peerStat.second->getIdentResps())
                    .setIdentErrs(peerStat.second->getIdentErrs())
                    .setPolResolves(peerStat.second->getPolResolves())
                    .setPolResolveResps(peerStat.second->getPolResolveResps())
                    .setPolResolveErrs(peerStat.second->getPolResolveErrs())
                    .setPolUnresolves(peerStat.second->getPolUnresolves())
                    .setPolUnresolveResps(peerStat.second->getPolUnresolveResps())
                    .setPolUnresolveErrs(peerStat.second->getPolUnresolveErrs())
                    .setPolUpdates(peerStat.second->getPolUpdates())
                    .setEpDeclares(peerStat.second->getEpDeclares())
                    .setEpDeclareResps(peerStat.second->getEpDeclareResps())
                    .setEpDeclareErrs(peerStat.second->getEpDeclareErrs())
                    .setEpUndeclares(peerStat.second->getEpUndeclares())
                    .setEpUndeclareResps(peerStat.second->getEpUndeclareResps())
                    .setEpUndeclareErrs(peerStat.second->getEpUndeclareErrs())
                    .setStateReports(peerStat.second->getStateReports())
                    .setStateReportResps(peerStat.second->getStateReportResps())
                    .setStateReportErrs(peerStat.second->getStateReportErrs())
                    .setPolUnresolvedCount(peerStat.second->getPolUnresolvedCount());
            prometheusManager.addNUpdateOFPeerStats(peerStat.first, peerStat.second);
        }
        // Remove mos for deleted connections
        std::vector<std::shared_ptr<modelgbp::observer::OpflexAgentCounter> > out;
        ssu.get()->resolveObserverOpflexAgentCounter(out);
        for (auto &peerCounter: out) {
            boost::optional<const std::string&> peer =
                                                peerCounter->getPeer();
            if (peer) {
                if (stats.find(peer.get()) == stats.end()) {
                    peerCounter->remove();
                    prometheusManager.removeOFPeerStats(peer.get());
                }
            }
        }
    }
    mutator.commit();
}

// Update total count per object type in MoDB
void SysStatsManager::updateMoDBCounts()
{
    Mutator mutator(agent->getFramework(), "policyelement");
    optional<shared_ptr<SysStatUniverse> > ssu =
        SysStatUniverse::resolve(agent->getFramework());
    if (ssu) {
        auto pMoDBCounts = ssu.get()->addObserverModbCounts();
        pMoDBCounts->setLocalEP(agent->getEndpointManager().getEpCount())
                 .setRemoteEP(agent->getEndpointManager().getEpRemoteCount())
                 .setExtEP(agent->getEndpointManager().getEpExternalCount())
                 .setEpg(agent->getPolicyManager().getEPGCount())
                 .setRd(agent->getPolicyManager().getRDCount())
                 .setExtIntfs(agent->getPolicyManager().getExtIntfCount())
                 .setService(agent->getServiceManager().getServiceCount())
                 .setContract(agent->getPolicyManager().getContractCount())
                 .setSg(agent->getPolicyManager().getSecGrpCount());
        prometheusManager.addNUpdateMoDBCounts(pMoDBCounts);
    }
    mutator.commit();
}

} /* namespace opflexagent */