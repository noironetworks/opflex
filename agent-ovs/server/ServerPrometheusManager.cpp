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
#include <opflex/ofcore/OFServerStats.h>

namespace opflexagent {

using std::make_shared;
using namespace prometheus::detail;

static string ofagent_family_names[] =
{
  "opflex_agent_identity_req_count",
  "opflex_agent_policy_update_count",
  "opflex_agent_policy_unavailable_resolve_count",
  "opflex_agent_policy_resolve_count",
  "opflex_agent_policy_resolve_err_count",
  "opflex_agent_policy_unresolve_count",
  "opflex_agent_policy_unresolve_err_count",
  "opflex_agent_ep_declare_count",
  "opflex_agent_ep_declare_err_count",
  "opflex_agent_ep_undeclare_count",
  "opflex_agent_ep_undeclare_err_count",
  "opflex_agent_ep_resolve_count",
  "opflex_agent_ep_resolve_err_count",
  "opflex_agent_ep_unresolve_count",
  "opflex_agent_ep_unresolve_err_count",
  "opflex_agent_state_report_count",
  "opflex_agent_state_report_err_count"
};

static string ofagent_family_help[] =
{
  "number of identity requests received from an opflex agent",
  "number of policy updates received from grpc server that are sent to an opflex agent",
  "number of unavailable policies on resolves received from an opflex agent",
  "number of policy resolves received from an opflex agent",
  "number of errors on policy resolves received from an opflex agent",
  "number of policy unresolves received from an opflex agent",
  "number of errors on policy unresolves received from an opflex agent",
  "number of endpoint declares received from an opflex agent",
  "number of errors on endpoint declares received from an opflex agent",
  "number of endpoint undeclares received from an opflex agent",
  "number of errors on endpoint undeclares received from an opflex agent",
  "number of endpoint resolves received from an opflex agent",
  "number of errors on endpoint resolves received from an opflex agent",
  "number of endpoint unresolves received from an opflex agent",
  "number of errors on endpoint unresolves received from an opflex agent",
  "number of state reports received from an opflex agent",
  "number of errors on state reports received from an opflex agent"
};

// construct ServerPrometheusManager for opflex server
ServerPrometheusManager::ServerPrometheusManager ()
                                 : PrometheusManager()
{
    init();
}

// initialize state of ServerPrometheusManager instance
void ServerPrometheusManager::init ()
{
    {
        const lock_guard<mutex> lock(ofagent_stats_mutex);
        for (OFAGENT_METRICS metric=OFAGENT_METRICS_MIN;
                metric <= OFAGENT_METRICS_MAX;
                    metric = OFAGENT_METRICS(metric+1)) {
            gauge_ofagent_family_ptr[metric] = nullptr;
        }
    }
}

// create all gauge families during start
void ServerPrometheusManager::createStaticGaugeFamilies (void)
{
    {
        const lock_guard<mutex> lock(ofagent_stats_mutex);
        createStaticGaugeFamiliesOFAgent();
    }
}

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

    /* Initialize Metric families which can be created during
     * init time */
    createStaticCounterFamilies();
    createStaticGaugeFamilies();
}

// Stop of ServerPrometheusManager instance
void ServerPrometheusManager::stop ()
{
    RETURN_IF_DISABLED
    disabled = true;
    LOG(DEBUG) << "stopping prometheus manager";

    // Gracefully delete state
    // Remove metrics
    removeDynamicGauges();

    // Remove metric families
    removeStaticGaugeFamilies();

    gauge_check.clear();
    counter_check.clear();

    exposer_ptr.reset();
    exposer_ptr = nullptr;

    registry_ptr.reset();
    registry_ptr = nullptr;
}

// Remove all statically allocated gauge families
void ServerPrometheusManager::removeStaticGaugeFamilies()
{
    // OFAgent stats specific
    {
        const lock_guard<mutex> lock(ofagent_stats_mutex);
        removeStaticGaugeFamiliesOFAgent();
    }
}

// remove all dynamic counters during stop
void ServerPrometheusManager::removeDynamicGauges ()
{
    // Remove OFAgentStat related gauges
    {
        const lock_guard<mutex> lock(ofagent_stats_mutex);
        removeDynamicGaugeOFAgent();
    }
}

// create all OFAgent specific gauge families during start
void ServerPrometheusManager::createStaticGaugeFamiliesOFAgent (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (OFAGENT_METRICS metric=OFAGENT_METRICS_MIN;
            metric <= OFAGENT_METRICS_MAX;
                metric = OFAGENT_METRICS(metric+1)) {
        auto& gauge_ofagent_family = BuildGauge()
                             .Name(ofagent_family_names[metric])
                             .Help(ofagent_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_ofagent_family_ptr[metric] = &gauge_ofagent_family;
    }
}

// Create OFAgentStats gauge given metric type, agent (IP,port) tuple
void ServerPrometheusManager::createDynamicGaugeOFAgent (OFAGENT_METRICS metric,
                                                       const string& agent)
{
    // Retrieve the Gauge if its already created
    if (getDynamicGaugeOFAgent(metric, agent))
        return;

    auto& gauge = gauge_ofagent_family_ptr[metric]->Add({{"agent", agent}});
    if (gauge_check.is_dup(&gauge)) {
        LOG(ERROR) << "duplicate ofagent dyn gauge family"
                   << " metric: " << metric
                   << " agent: " << agent;
        return;
    }
    LOG(DEBUG) << "created ofagent dyn gauge family"
               << " metric: " << metric
               << " agent: " << agent;
    gauge_check.add(&gauge);
    ofagent_gauge_map[metric][agent] = &gauge;
}

// Get OFAgent stats gauge given the metric, agent (IP,port) tuple
Gauge * ServerPrometheusManager::getDynamicGaugeOFAgent (OFAGENT_METRICS metric,
                                                       const string& agent)
{
    Gauge *pgauge = nullptr;
    auto itr = ofagent_gauge_map[metric].find(agent);
    if (itr == ofagent_gauge_map[metric].end()) {
        LOG(TRACE) << "Dyn Gauge OFAgent stats not found"
                   << " metric: " << metric
                   << " agent: " << agent;
    } else {
        pgauge = itr->second;
    }

    return pgauge;
}

// Remove dynamic OFAgentStats gauge given a metic type and agent (IP,port) tuple
bool ServerPrometheusManager::removeDynamicGaugeOFAgent (OFAGENT_METRICS metric,
                                                       const string& agent)
{
    Gauge *pgauge = getDynamicGaugeOFAgent(metric, agent);
    if (pgauge) {
        ofagent_gauge_map[metric].erase(agent);
        gauge_check.remove(pgauge);
        gauge_ofagent_family_ptr[metric]->Remove(pgauge);
    } else {
        LOG(DEBUG) << "remove dynamic gauge ofagent stats not found agent:" << agent;
        return false;
    }
    return true;
}

// Remove dynamic OFAgentStats gauge given a metric type
void ServerPrometheusManager::removeDynamicGaugeOFAgent (OFAGENT_METRICS metric)
{
    auto itr = ofagent_gauge_map[metric].begin();
    while (itr != ofagent_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete OFAgent stats agent: " << itr->first
                   << " Gauge: " << itr->second;
        gauge_check.remove(itr->second);
        gauge_ofagent_family_ptr[metric]->Remove(itr->second);
        itr++;
    }

    ofagent_gauge_map[metric].clear();
}

// Remove dynamic OFAgentStats gauges for all metrics
void ServerPrometheusManager::removeDynamicGaugeOFAgent ()
{
    for (OFAGENT_METRICS metric=OFAGENT_METRICS_MIN;
            metric <= OFAGENT_METRICS_MAX;
                metric = OFAGENT_METRICS(metric+1)) {
        removeDynamicGaugeOFAgent(metric);
    }
}

// Remove all statically allocated OFAgent gauge families
void ServerPrometheusManager::removeStaticGaugeFamiliesOFAgent ()
{
    for (OFAGENT_METRICS metric=OFAGENT_METRICS_MIN;
            metric <= OFAGENT_METRICS_MAX;
                metric = OFAGENT_METRICS(metric+1)) {
        gauge_ofagent_family_ptr[metric] = nullptr;
    }
}

/* Function called from PolicyStatsManager to update OFAgentStats */
void ServerPrometheusManager::addNUpdateOFAgentStats (const std::string& agent,
                                                    const std::shared_ptr<OFServerStats> stats)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(ofagent_stats_mutex);

    if (!stats)
        return;

    // Create gauge metrics if they arent present already
    for (OFAGENT_METRICS metric=OFAGENT_METRICS_MIN;
            metric <= OFAGENT_METRICS_MAX;
                metric = OFAGENT_METRICS(metric+1))
        createDynamicGaugeOFAgent(metric, agent);

    // Update the metrics
    for (OFAGENT_METRICS metric=OFAGENT_METRICS_MIN;
            metric <= OFAGENT_METRICS_MAX;
                metric = OFAGENT_METRICS(metric+1)) {
        Gauge *pgauge = getDynamicGaugeOFAgent(metric, agent);
        optional<uint64_t>   metric_opt;
        switch (metric) {
        case OFAGENT_IDENT_REQS:
            metric_opt = stats->getIdentReqs();
            break;
        case OFAGENT_POL_UPDATES:
            metric_opt = stats->getPolUpdates();
            break;
        case OFAGENT_POL_UNAVAILABLE_RESOLVES:
            metric_opt = stats->getPolUnavailableResolves();
            break;
        case OFAGENT_POL_RESOLVES:
            metric_opt = stats->getPolResolves();
            break;
        case OFAGENT_POL_RESOLVE_ERRS:
            metric_opt = stats->getPolResolveErrs();
            break;
        case OFAGENT_POL_UNRESOLVES:
            metric_opt = stats->getPolUnresolves();
            break;
        case OFAGENT_POL_UNRESOLVE_ERRS:
            metric_opt = stats->getPolUnresolveErrs();
            break;
        case OFAGENT_EP_DECLARES:
            metric_opt = stats->getEpDeclares();
            break;
        case OFAGENT_EP_DECLARE_ERRS:
            metric_opt = stats->getEpDeclareErrs();
            break;
        case OFAGENT_EP_UNDECLARES:
            metric_opt = stats->getEpUndeclares();
            break;
        case OFAGENT_EP_UNDECLARE_ERRS:
            metric_opt = stats->getEpUndeclareErrs();
            break;
        case OFAGENT_EP_RESOLVES:
            metric_opt = stats->getEpResolves();
            break;
        case OFAGENT_EP_RESOLVE_ERRS:
            metric_opt = stats->getEpResolveErrs();
            break;
        case OFAGENT_EP_UNRESOLVES:
            metric_opt = stats->getEpUnresolves();
            break;
        case OFAGENT_EP_UNRESOLVE_ERRS:
            metric_opt = stats->getEpUnresolveErrs();
            break;
        case OFAGENT_STATE_REPORTS:
            metric_opt = stats->getStateReports();
            break;
        case OFAGENT_STATE_REPORT_ERRS:
            metric_opt = stats->getStateReportErrs();
            break;
        default:
            LOG(ERROR) << "Unhandled ofagent metric: " << metric;
        }
        if (metric_opt && pgauge)
            pgauge->Set(static_cast<double>(metric_opt.get()));
        if (!pgauge) {
            LOG(ERROR) << "Invalid ofagent update agent: " << agent;
            break;
        }
    }
}

// Function called from StatsIO to remove OFAgentStats
void ServerPrometheusManager::removeOFAgentStats (const string& agent)
{
    RETURN_IF_DISABLED
    LOG(DEBUG) << "Deleting OFAgentStats for agent: " << agent;
    const lock_guard<mutex> lock(ofagent_stats_mutex);
    for (OFAGENT_METRICS metric=OFAGENT_METRICS_MIN;
            metric <= OFAGENT_METRICS_MAX;
                metric = OFAGENT_METRICS(metric+1)) {
        if (!removeDynamicGaugeOFAgent(metric, agent))
            break;
    }
}

} /* namespace opflexagent */
