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
#include <modelgbp/observer/SysStatUniverse.hpp>

using boost::asio::deadline_timer;
using boost::posix_time::seconds;
using namespace opflex::modb;
using namespace modelgbp::observer;

namespace opflexagent {

#ifdef HAVE_PROMETHEUS_SUPPORT
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
#else
StatsIO::StatsIO (opflex::test::GbpOpflexServer& server_,
                  const opflex::ofcore::OFFramework& framework_,
                  int stats_interval_secs_) :
                  server(server_),
                  framework(framework_),
                  stats_interval_secs(stats_interval_secs_),
                  stopping(false) {
}
#endif

StatsIO::~StatsIO() {
}

void StatsIO::start() {
    if (stopping)
        return;
    LOG(DEBUG) << "starting stats IO thread";
    const std::lock_guard<std::mutex> guard(stats_timer_mutex);
    stats_timer.reset(new deadline_timer(io, seconds(stats_interval_secs)));
    stats_timer->async_wait([this](const boost::system::error_code& ec) {
            on_timer_stats(ec);
        });

    io_service_thread.reset(new std::thread([this]() { io.run(); }));
}

void StatsIO::stop() {
    stopping = true;
    LOG(DEBUG) << "stopping stats IO thread";
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
    Mutator mutator(framework, "policyelement");
    optional<shared_ptr<SysStatUniverse> > ssu =
        SysStatUniverse::resolve(framework);
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
#ifdef HAVE_PROMETHEUS_SUPPORT
            prometheusManager.addNUpdateOFAgentStats(peerStat.first, peerStat.second);
#endif
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
