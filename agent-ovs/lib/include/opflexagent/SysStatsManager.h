/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for SysStatsManager
 *
 * Copyright (c) 2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_SysStatsManager_H
#define OPFLEXAGENT_SysStatsManager_H

#include <boost/asio.hpp>
#include <mutex>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <opflexagent/PrometheusManager.h>

namespace opflexagent {

class Agent;

/**
 * Periodically update system level statistics
 */
class SysStatsManager {
public:
    /**
     * Instantiate a new system stats manager that will use the
     * provided io service for scheduling asynchronous tasks
     * @param agent the agent associated with the SysStatsManager
     */
    SysStatsManager(Agent* agent);

    /**
     * Destroy the sys stats manager and clean up all state
     */
    virtual ~SysStatsManager();

    /**
     * Start the sys stats manager
     * @param timer_interval the interval for the stats timer in
     * milliseconds
     */
    void start(long timer_interval = 10000);

    /**
     * Stop the sys stats manager
     */
    void stop();

    /**
     * Timer interval handler
     */
    void on_timer(const boost::system::error_code& ec);

private:
    void updateOpflexPeerStats();
    void updateMoDBCounts();

    /**
     * The agent object
     */
    Agent* agent;

    /**
     * The prometheus manager that exports stats to prometheus server
     */
    AgentPrometheusManager& prometheusManager;

    /**
     * mutex for timer
     */
    std::mutex timer_mutex;

    /**
     * timer for periodically querying for stats
     */
    std::unique_ptr<boost::asio::deadline_timer> timer;

    /**
     * The timer interval to use for querying stats
     */
    long timer_interval;

    /**
     * True if shutting down
     */
    std::atomic<bool> stopping;
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_SysStatsManager_H */
