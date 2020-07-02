/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for ServerPrometheusManager class.
 *
 * Copyright (c) 2020-2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/PrometheusManager.h>

namespace opflexagent {

using std::make_shared;
using namespace prometheus::detail;

// construct ServerPrometheusManager for opflex server
ServerPrometheusManager::ServerPrometheusManager ()
                                 : PrometheusManager() {}

// Start of ServerPrometheusManager instance
void ServerPrometheusManager::start (bool exposeLocalHostOnly)
{
    disabled = false;
    LOG(DEBUG) << "starting prometheus manager,"
               << " exposeLHOnly: " << exposeLocalHostOnly;
    /**
     * create an http server running on port 9632
     * Note: The third argument is the total worker thread count. Prometheus
     * follows boss-worker thread model. 1 boss thread will get created to
     * intercept HTTP requests. The requests will then be serviced by free
     * worker threads. We are using 1 worker thread to service the requests.
     * Note: Port #9632 has been reserved for opflex server here:
     * https://github.com/prometheus/prometheus/wiki/Default-port-allocations
     */
    registry_ptr = make_shared<Registry>();
    if (exposeLocalHostOnly)
        exposer_ptr = unique_ptr<Exposer>(new Exposer{"127.0.0.1:9632", "/metrics", 1});
    else
        exposer_ptr = unique_ptr<Exposer>(new Exposer{"9632", "/metrics", 1});

    // ask the exposer to scrape the registry on incoming scrapes
    exposer_ptr->RegisterCollectable(registry_ptr);
}

// Stop of AgentPrometheusManager instance
void ServerPrometheusManager::stop ()
{
    RETURN_IF_DISABLED
    disabled = true;
    LOG(DEBUG) << "stopping prometheus manager";

    gauge_check.clear();
    counter_check.clear();

    exposer_ptr.reset();
    exposer_ptr = nullptr;

    registry_ptr.reset();
    registry_ptr = nullptr;
}

} /* namespace opflexagent */
