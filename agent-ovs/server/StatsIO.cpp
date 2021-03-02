/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of interface for stats IO thread in opflex-server.
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/logging.h>
#include "StatsIO.h"
#include <opflex/ofcore/OFFramework.h>
#include <opflex/ofcore/OFServerStats.h>
#include <modelgbp/dmtree/Root.hpp>
#include <modelgbp/observer/SysStatUniverse.hpp>

using boost::asio::deadline_timer;
using boost::posix_time::seconds;
using namespace opflex::modb;
using namespace modelgbp::observer;
using namespace modelgbp::dmtree;

namespace opflexagent {

StatsIO::StatsIO (ServerPrometheusManager& prometheusManager_,
                  opflex::test::GbpOpflexServer& server_,
                  opflex::ofcore::OFFramework& framework_,
                  int stats_interval_secs_) :
                  prometheusManager(prometheusManager_),
                  server(server_),
                  framework(framework_),
                  stats_interval_secs(stats_interval_secs_),
                  stopping(false) {
}

StatsIO::~StatsIO() {
}

void StatsIO::start() {
    if (stopping)
        return;
    LOG(INFO) << "starting stats IO thread; interval:" << stats_interval_secs;
    const std::lock_guard<std::mutex> guard(stats_timer_mutex);
    stats_timer.reset(new deadline_timer(io, seconds(stats_interval_secs)));
    stats_timer->async_wait([this](const boost::system::error_code& ec) {
            on_timer_stats(ec);
        });

    io_service_thread.reset(new std::thread([this]() { io.run(); }));
}

void StatsIO::stop() {
    stopping = true;
    LOG(INFO) << "stopping stats IO thread";
    {
        const std::lock_guard<std::mutex> guard(stats_timer_mutex);
        if (stats_timer) {
            stats_timer->cancel();
        }
    }

    if (io_service_thread) {
        io_service_thread->join();
        io_service_thread.reset();
    }
}

void StatsIO::on_timer_stats (const boost::system::error_code& ec) {
    if (ec) {
        const std::lock_guard<std::mutex> guard(stats_timer_mutex);
        stats_timer.reset();
        return;
    }

    std::unordered_map<string, std::shared_ptr<OFServerStats>> stats;
    server.getOpflexPeerStats(stats);
    optional<shared_ptr<SysStatUniverse> > ssu =
        SysStatUniverse::resolve(framework);
    if (!ssu) {
        Mutator mutator(framework, "init");
        optional<shared_ptr<Root> > root = Root::resolve(framework, URI::ROOT);
        if (root)
            ssu = root.get()->addObserverSysStatUniverse();
        mutator.commit();
    }
    Mutator mutator(framework, "policyelement");
    if (ssu) {
        for (const auto& peerStat : stats) {
            ssu.get()->addObserverOpflexServerCounter(peerStat.first)
                    ->setIdentReqs(peerStat.second->getIdentReqs())
                    .setPolUpdates(peerStat.second->getPolUpdates())
                    .setPolResolves(peerStat.second->getPolResolves())
                    .setPolResolveErrs(peerStat.second->getPolResolveErrs())
                    .setPolUnavailableResolves(peerStat.second->getPolUnavailableResolves())
                    .setPolUnresolves(peerStat.second->getPolUnresolves())
                    .setPolUnresolveErrs(peerStat.second->getPolUnresolveErrs())
                    .setEpDeclares(peerStat.second->getEpDeclares())
                    .setEpDeclareErrs(peerStat.second->getEpDeclareErrs())
                    .setEpUndeclares(peerStat.second->getEpUndeclares())
                    .setEpUndeclareErrs(peerStat.second->getEpUndeclareErrs())
                    .setEpResolves(peerStat.second->getEpResolves())
                    .setEpResolveErrs(peerStat.second->getEpResolveErrs())
                    .setEpUnresolves(peerStat.second->getEpUnresolves())
                    .setEpUnresolveErrs(peerStat.second->getEpUnresolveErrs())
                    .setStateReports(peerStat.second->getStateReports())
                    .setStateReportErrs(peerStat.second->getStateReportErrs());
            prometheusManager.addNUpdateOFAgentStats(peerStat.first, peerStat.second);
        }
        // Remove mos for deleted connections
        std::vector<std::shared_ptr<modelgbp::observer::OpflexServerCounter> > out;
        ssu.get()->resolveObserverOpflexServerCounter(out);
        for (auto &serverCounter: out) {
            boost::optional<const std::string&> agent =
                                                serverCounter->getPeer();
            if (agent) {
                if (stats.find(agent.get()) == stats.end()) {
                    serverCounter->remove();
                    prometheusManager.removeOFAgentStats(agent.get());
                }
            }
        }
    }
    mutator.commit();

    if (!stopping) {
        const std::lock_guard<std::mutex> guard(stats_timer_mutex);
        stats_timer->expires_at(stats_timer->expires_at() +
                              seconds(stats_interval_secs));
        stats_timer->async_wait([this](const boost::system::error_code& ec) {
                on_timer_stats(ec);
            });
    }
}

} /* namespace opflexagent */
