/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file StatsIO.h
 * @brief Interface definition file for Stats IO thread
 */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef STATS_IO_H
#define STATS_IO_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <thread>
#include <mutex>
#include <boost/asio/io_service.hpp>
#include <boost/asio/deadline_timer.hpp>

#ifdef HAVE_PROMETHEUS_SUPPORT
#include <opflexagent/PrometheusManager.h>
#endif
#include <opflex/ofcore/OFFramework.h>
#include <opflex/test/GbpOpflexServer.h>

namespace opflexagent {

class StatsIO {
public:
#ifdef HAVE_PROMETHEUS_SUPPORT
    StatsIO(ServerPrometheusManager& prometheusManager_,
            opflex::test::GbpOpflexServer& server_,
            opflex::ofcore::OFFramework& framework_,
            int stats_interval_secs_);
#else
    StatsIO(opflex::ofcore::OFFramework& framework_,
            opflex::test::GbpOpflexServer& server_,
            int stats_interval_secs_);
#endif
    ~StatsIO();
    void start();
    void stop();
private:
    void on_timer_stats(const boost::system::error_code& ec);
#ifdef HAVE_PROMETHEUS_SUPPORT
    ServerPrometheusManager& prometheusManager;
#endif
    opflex::test::GbpOpflexServer& server;
    opflex::ofcore::OFFramework& framework;
    int stats_interval_secs;
    std::atomic<bool> stopping;
    std::unique_ptr<std::thread> io_service_thread;
    boost::asio::io_service io;
    std::unique_ptr<boost::asio::deadline_timer> stats_timer;
    std::mutex stats_timer_mutex;
};

} /* namespace opflexagent */

#endif /* STATS_IO_H */
