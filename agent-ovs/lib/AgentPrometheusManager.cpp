/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for AgentPrometheusManager class.
 *
 * Copyright (c) 2019-2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/Agent.h>
#include <opflexagent/Endpoint.h>
#include <opflex/ofcore/OFAgentStats.h>
#include <opflexagent/PrometheusManager.h>
#include <modelgbp/gbpe/L24Classifier.hpp>
#include <map>
#include <boost/optional.hpp>
#include <boost/algorithm/string.hpp>
#include <prometheus/detail/utils.h>

namespace opflexagent {

using std::vector;
using std::size_t;
using std::to_string;
using namespace prometheus::detail;
using boost::split;
using namespace modelgbp::observer;

static string ep_family_names[] =
{
  "opflex_endpoint_rx_bytes",
  "opflex_endpoint_rx_packets",
  "opflex_endpoint_rx_drop_packets",
  "opflex_endpoint_rx_ucast_packets",
  "opflex_endpoint_rx_mcast_packets",
  "opflex_endpoint_rx_bcast_packets",
  "opflex_endpoint_tx_bytes",
  "opflex_endpoint_tx_packets",
  "opflex_endpoint_tx_drop_packets",
  "opflex_endpoint_tx_ucast_packets",
  "opflex_endpoint_tx_mcast_packets",
  "opflex_endpoint_tx_bcast_packets"
};

static string ep_family_help[] =
{
  "Local endpoint rx bytes",
  "Local endpoint rx packets",
  "Local endpoint rx drop packets",
  "Local endpoint rx unicast packets",
  "Local endpoint rx multicast packets",
  "Local endpoint rx broadcast packets",
  "Local endpoint tx bytes",
  "Local endpoint tx packets",
  "Local endpoint tx drop packets",
  "Local endpoint tx unicast packets",
  "Local endpoint tx multicast packets",
  "Local endpoint tx broadcast packets"
};

static string podsvc_family_names[] =
{
  "opflex_endpoint_to_svc_bytes",
  "opflex_endpoint_to_svc_packets",
  "opflex_svc_to_endpoint_bytes",
  "opflex_svc_to_endpoint_packets"
};

static string podsvc_family_help[] =
{
  "endpoint to service bytes",
  "endpoint to service packets",
  "service to endpoint bytes",
  "service to endpoint packets"
};

static string svc_family_names[] =
{
  "opflex_svc_rx_bytes",
  "opflex_svc_rx_packets",
  "opflex_svc_tx_bytes",
  "opflex_svc_tx_packets"
};

static string svc_family_help[] =
{
  "service ingress/rx bytes",
  "service ingress/rx packets",
  "service egress/tx bytes",
  "service egress/tx packets"
};

static string svc_target_family_names[] =
{
  "opflex_svc_target_rx_bytes",
  "opflex_svc_target_rx_packets",
  "opflex_svc_target_tx_bytes",
  "opflex_svc_target_tx_packets"
};

static string svc_target_family_help[] =
{
  "cluster service target ingress/rx bytes",
  "cluster service target ingress/rx packets",
  "cluster service target egress/tx bytes",
  "cluster service target egress/tx packets"
};

static string ofpeer_family_names[] =
{
  "opflex_peer_identity_req_count",
  "opflex_peer_identity_resp_count",
  "opflex_peer_identity_err_count",
  "opflex_peer_policy_resolve_req_count",
  "opflex_peer_policy_resolve_resp_count",
  "opflex_peer_policy_resolve_err_count",
  "opflex_peer_policy_unresolve_req_count",
  "opflex_peer_policy_unresolve_resp_count",
  "opflex_peer_policy_unresolve_err_count",
  "opflex_peer_policy_update_receive_count",
  "opflex_peer_ep_declare_req_count",
  "opflex_peer_ep_declare_resp_count",
  "opflex_peer_ep_declare_err_count",
  "opflex_peer_ep_undeclare_req_count",
  "opflex_peer_ep_undeclare_resp_count",
  "opflex_peer_ep_undeclare_err_count",
  "opflex_peer_state_report_req_count",
  "opflex_peer_state_report_resp_count",
  "opflex_peer_state_report_err_count",
  "opflex_peer_unresolved_policy_count"
};

static string ofpeer_family_help[] =
{
  "number of identity requests sent to opflex peer",
  "number of identity responses received from opflex peer",
  "number of identity error responses from opflex peer",
  "number of policy resolves sent to opflex peer",
  "number of policy resolve responses received from opflex peer",
  "number of policy resolve error responses from opflex peer",
  "number of policy unresolves sent to opflex peer",
  "number of policy unresolve responses received from opflex peer",
  "number of policy unresolve error responses from opflex peer",
  "number of policy updates received from opflex peer",
  "number of endpoint declares sent to opflex peer",
  "number of endpoint declare responses received from opflex peer",
  "number of endpoint declare error responses from opflex peer",
  "number of endpoint undeclares sent to opflex peer",
  "number of endpoint undeclare responses received from opflex peer",
  "number of endpoint undeclare error responses from opflex peer",
  "number of state reports sent to opflex peer",
  "number of state reports responses received from opflex peer",
  "number of state reports error repsonses from opflex peer",
  "number of policies requested by the agent which aren't yet resolved by opflex peer"
};

static string modb_count_family_names[] =
{
  "opflex_total_ep_local",
  "opflex_total_ep_remote",
  "opflex_total_ep_ext",
  "opflex_total_epg",
  "opflex_total_ext_intf",
  "opflex_total_rd",
  "opflex_total_service",
  "opflex_total_contract",
  "opflex_total_sg"
};

static string modb_count_family_help[] =
{
  "number of local endpoints",
  "number of remote endpoints",
  "number of external endpoints",
  "number of endpoint groups",
  "number of external interfaces",
  "number of routing domains",
  "number of services",
  "number of contracts",
  "number of security groups"
};

static string rddrop_family_names[] =
{
  "opflex_policy_drop_bytes",
  "opflex_policy_drop_packets"
};

static string rddrop_family_help[] =
{
  "number of policy/contract dropped bytes per routing domain",
  "number of policy/contract dropped packets per routing domain"
};

static string sgclassifier_family_names[] =
{
  "opflex_sg_tx_bytes",
  "opflex_sg_tx_packets",
  "opflex_sg_rx_bytes",
  "opflex_sg_rx_packets"
};

static string sgclassifier_family_help[] =
{
  "security-group classifier tx bytes",
  "security-group classifier tx packets",
  "security-group classifier rx bytes",
  "security-group classifier rx packets"
};

static string contract_family_names[] =
{
  "opflex_contract_bytes",
  "opflex_contract_packets"
};

static string contract_family_help[] =
{
  "contract classifier bytes",
  "contract classifier packets",
};

static string table_drop_family_names[] =
{
  "opflex_table_drop_bytes",
  "opflex_table_drop_packets"
};

static string table_drop_family_help[] =
{
  "opflex table drop bytes",
  "opflex table drop packets"
};

static string nat_family_names[] =
{
  "opflex_endpoint_to_extnetwork_bytes",
  "opflex_endpoint_to_extnetwork_packets",
  "opflex_extnetwork_to_endpoint_bytes",
  "opflex_extnetwork_to_endpoint_packets"
};

static string nat_family_help[] =
{
  "endpoint to extnetwork bytes",
  "endpoint to extnetwork packets",
  "extnetwork to endpoint bytes",
  "extnetwork to endpoint packets"
};

#define RETURN_IF_DISABLED  if (disabled) {return;}

// construct AgentPrometheusManager for opflex agent
AgentPrometheusManager::AgentPrometheusManager(Agent &agent_,
                                             opflex::ofcore::OFFramework &fwk_) :
                                             PrometheusManager(),
                                             agent(agent_),
                                             framework(fwk_),
                                             exposeEpSvcNan{false}
{
    //Init state to avoid coverty warnings
    init();
}

// create all ep counter families during start
void AgentPrometheusManager::createStaticCounterFamiliesEp (void)
{
    // add a new counter family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    /* Counter family to track the total calls made to EpCounter update/remove
     * from other clients */
    auto& counter_ep_create_family = BuildCounter()
                         .Name("opflex_endpoint_created_total")
                         .Help("Total number of local endpoint creates")
                         .Labels({})
                         .Register(*registry_ptr);
    counter_ep_create_family_ptr = &counter_ep_create_family;

    auto& counter_ep_remove_family = BuildCounter()
                         .Name("opflex_endpoint_removed_total")
                         .Help("Total number of local endpoint deletes")
                         .Labels({})
                         .Register(*registry_ptr);
    counter_ep_remove_family_ptr = &counter_ep_remove_family;
}

// create all svc counter families during start
void AgentPrometheusManager::createStaticCounterFamiliesSvc (void)
{
    // add a new counter family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    /* Counter family to track the total calls made to SvcCounter create/remove
     * from other clients */
    auto& counter_svc_create_family = BuildCounter()
                         .Name("opflex_svc_created_total")
                         .Help("Total number of SVC creates")
                         .Labels({})
                         .Register(*registry_ptr);
    counter_svc_create_family_ptr = &counter_svc_create_family;

    auto& counter_svc_remove_family = BuildCounter()
                         .Name("opflex_svc_removed_total")
                         .Help("Total number of SVC deletes")
                         .Labels({})
                         .Register(*registry_ptr);
    counter_svc_remove_family_ptr = &counter_svc_remove_family;
}

// create all counter families during start
void AgentPrometheusManager::createStaticCounterFamilies (void)
{
    // EpCounter families
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        createStaticCounterFamiliesEp();
    }

    // SvcCounter families
    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        createStaticCounterFamiliesSvc();
    }
}

// create all static ep counters during start
void AgentPrometheusManager::createStaticCountersEp ()
{
    auto& counter_ep_create = counter_ep_create_family_ptr->Add({});
    counter_ep_create_ptr = &counter_ep_create;

    auto& counter_ep_remove = counter_ep_remove_family_ptr->Add({});
    counter_ep_remove_ptr = &counter_ep_remove;
}

// create all static svc counters during start
void AgentPrometheusManager::createStaticCountersSvc ()
{
    auto& counter_svc_create = counter_svc_create_family_ptr->Add({});
    counter_svc_create_ptr = &counter_svc_create;

    auto& counter_svc_remove = counter_svc_remove_family_ptr->Add({});
    counter_svc_remove_ptr = &counter_svc_remove;
}

// create all static counters during start
void AgentPrometheusManager::createStaticCounters ()
{
    // EpCounter related metrics
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        createStaticCountersEp();
    }

    // SvcCounter related metrics
    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        createStaticCountersSvc();
    }
}

// remove all dynamic counters during stop
void AgentPrometheusManager::removeDynamicCounters ()
{
    // No dynamic counters as of now
}

// remove all dynamic counters during stop
void AgentPrometheusManager::removeDynamicGauges ()
{
    // Remove EpCounter related gauges
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        removeDynamicGaugeEp();
    }

    // Remove SvcTargetCounter related gauges
    {
        const lock_guard<mutex> lock(svc_target_counter_mutex);
        removeDynamicGaugeSvcTarget();
    }

    // Remove SvcCounter related gauges
    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        removeDynamicGaugeSvc();
    }

    // Remove PodSvcCounter related gauges
    {
        const lock_guard<mutex> lock(podsvc_counter_mutex);
        removeDynamicGaugePodSvc();
    }

    // Remove OFPeerStat related gauges
    {
        const lock_guard<mutex> lock(ofpeer_stats_mutex);
        removeDynamicGaugeOFPeer();
    }

    // Remove MoDBCounts related gauges
    {
        const lock_guard<mutex> lock(modb_count_mutex);
        removeDynamicGaugeMoDBCount();
    }

    // Remove RDDropCounter related gauges
    {
        const lock_guard<mutex> lock(rddrop_stats_mutex);
        removeDynamicGaugeRDDrop();
    }

    // Remove SGClassifierCounter related gauges
    {
        const lock_guard<mutex> lock(sgclassifier_stats_mutex);
        removeDynamicGaugeSGClassifier();
    }

    // Remove ContractClassifierCounter related gauges
    {
        const lock_guard<mutex> lock(contract_stats_mutex);
        removeDynamicGaugeContractClassifier();
    }
    
    // Remove Nat Stats related gauges
    {
       const lock_guard<mutex> lock(nat_counter_mutex); 
       removeDynamicGaugeNatStats();
    }
}

// remove all static ep counters during stop
void AgentPrometheusManager::removeStaticCountersEp ()
{
    counter_ep_create_family_ptr->Remove(counter_ep_create_ptr);
    counter_ep_create_ptr = nullptr;

    counter_ep_remove_family_ptr->Remove(counter_ep_remove_ptr);
    counter_ep_remove_ptr = nullptr;
}

// remove all static svc counters during stop
void AgentPrometheusManager::removeStaticCountersSvc ()
{
    counter_svc_create_family_ptr->Remove(counter_svc_create_ptr);
    counter_svc_create_ptr = nullptr;

    counter_svc_remove_family_ptr->Remove(counter_svc_remove_ptr);
    counter_svc_remove_ptr = nullptr;
}

// remove all static counters during stop
void AgentPrometheusManager::removeStaticCounters ()
{

    // Remove EpCounter related counter metrics
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        removeStaticCountersEp();
    }

    // Remove SvcCounter related counter metrics
    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        removeStaticCountersSvc();
    }
}

// create all OFPeer specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesOFPeer (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (OFPEER_METRICS metric=OFPEER_METRICS_MIN;
            metric <= OFPEER_METRICS_MAX;
                metric = OFPEER_METRICS(metric+1)) {
        auto& gauge_ofpeer_family = BuildGauge()
                             .Name(ofpeer_family_names[metric])
                             .Help(ofpeer_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_ofpeer_family_ptr[metric] = &gauge_ofpeer_family;
    }
}

// create all ContractClassifier specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesContractClassifier (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (CONTRACT_METRICS metric=CONTRACT_METRICS_MIN;
            metric <= CONTRACT_METRICS_MAX;
                metric = CONTRACT_METRICS(metric+1)) {
        auto& gauge_contract_family = BuildGauge()
                             .Name(contract_family_names[metric])
                             .Help(contract_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_contract_family_ptr[metric] = &gauge_contract_family;
    }
}

// create all SGClassifier specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesSGClassifier (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (SGCLASSIFIER_METRICS metric=SGCLASSIFIER_METRICS_MIN;
            metric <= SGCLASSIFIER_METRICS_MAX;
                metric = SGCLASSIFIER_METRICS(metric+1)) {
        auto& gauge_sgclassifier_family = BuildGauge()
                             .Name(sgclassifier_family_names[metric])
                             .Help(sgclassifier_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_sgclassifier_family_ptr[metric] = &gauge_sgclassifier_family;
    }
}

// create all MoDBCount specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesMoDBCount (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (MODB_COUNT_METRICS metric=MODB_COUNT_METRICS_MIN;
            metric <= MODB_COUNT_METRICS_MAX;
                metric = MODB_COUNT_METRICS(metric+1)) {
        auto& gauge_modb_count_family = BuildGauge()
                             .Name(modb_count_family_names[metric])
                             .Help(modb_count_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_modb_count_family_ptr[metric] = &gauge_modb_count_family;

        // metrics per family will be created later
        modb_count_gauge_map[metric] = nullptr;
    }
}

// create all RDDrop specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesRDDrop (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (RDDROP_METRICS metric=RDDROP_METRICS_MIN;
            metric <= RDDROP_METRICS_MAX;
                metric = RDDROP_METRICS(metric+1)) {
        auto& gauge_rddrop_family = BuildGauge()
                             .Name(rddrop_family_names[metric])
                             .Help(rddrop_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_rddrop_family_ptr[metric] = &gauge_rddrop_family;
    }
}

// create all EP specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesEp (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().
    for (EP_METRICS metric=EP_METRICS_MIN;
            metric < EP_METRICS_MAX;
                metric = EP_METRICS(metric+1)) {
        auto& gauge_ep_family = BuildGauge()
                             .Name(ep_family_names[metric])
                             .Help(ep_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_ep_family_ptr[metric] = &gauge_ep_family;
    }
}

// create all SvcTarget specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesSvcTarget (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (SVC_TARGET_METRICS metric=SVC_TARGET_METRICS_MIN;
            metric <= SVC_TARGET_METRICS_MAX;
                metric = SVC_TARGET_METRICS(metric+1)) {
        auto& gauge_svc_target_family = BuildGauge()
                             .Name(svc_target_family_names[metric])
                             .Help(svc_target_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_svc_target_family_ptr[metric] = &gauge_svc_target_family;
    }
}

// create all SVC specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesSvc (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().
    for (SVC_METRICS metric=SVC_METRICS_MIN;
            metric <= SVC_METRICS_MAX;
                metric = SVC_METRICS(metric+1)) {
        auto& gauge_svc_family = BuildGauge()
                             .Name(svc_family_names[metric])
                             .Help(svc_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_svc_family_ptr[metric] = &gauge_svc_family;
    }
}

// create all PODSVC specific gauge families during start
void AgentPrometheusManager::createStaticGaugeFamiliesPodSvc (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (PODSVC_METRICS metric=PODSVC_METRICS_MIN;
            metric <= PODSVC_METRICS_MAX;
                metric = PODSVC_METRICS(metric+1)) {
        auto& gauge_podsvc_family = BuildGauge()
                             .Name(podsvc_family_names[metric])
                             .Help(podsvc_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_podsvc_family_ptr[metric] = &gauge_podsvc_family;
    }
}

void AgentPrometheusManager::createStaticGaugeFamiliesTableDrop(void) {
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().
    const lock_guard<mutex> lock(table_drop_counter_mutex);

    for (TABLE_DROP_METRICS metric=TABLE_DROP_METRICS_MIN;
            metric <= TABLE_DROP_METRICS_MAX;
                metric = TABLE_DROP_METRICS(metric+1)) {
        auto& gauge_table_drop_family = BuildGauge()
                             .Name(table_drop_family_names[metric])
                             .Help(table_drop_family_help[metric])
                             .Labels({})
                             .Register(*registry_ptr);
        gauge_table_drop_family_ptr[metric] = &gauge_table_drop_family;
    }
}

// remove all static counters during stop
void AgentPrometheusManager::removeStaticGaugesTableDrop ()
{
    // Remove Table Drop related counter metrics
    const lock_guard<mutex> lock(table_drop_counter_mutex);

    for (TABLE_DROP_METRICS metric=TABLE_DROP_METRICS_MIN;
                         metric <= TABLE_DROP_METRICS_MAX;
                     metric = TABLE_DROP_METRICS(metric+1)) {
        for (auto itr = table_drop_gauge_map[metric].begin();
            itr != table_drop_gauge_map[metric].end(); itr++) {
            LOG(DEBUG) << "Delete TableDrop " << itr->first
                   << " Gauge: " << itr->second.get().second;
            gauge_table_drop_family_ptr[metric]->Remove(
                    itr->second.get().second);
        }
        table_drop_gauge_map[metric].clear();
    }
}

// create all gauge families during start
void AgentPrometheusManager::createStaticGaugeFamilies (void)
{
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        createStaticGaugeFamiliesEp();
    }

    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        createStaticGaugeFamiliesSvc();
    }

    {
        const lock_guard<mutex> lock(svc_target_counter_mutex);
        createStaticGaugeFamiliesSvcTarget();
    }

    {
        const lock_guard<mutex> lock(podsvc_counter_mutex);
        createStaticGaugeFamiliesPodSvc();
    }

    {
        const lock_guard<mutex> lock(ofpeer_stats_mutex);
        createStaticGaugeFamiliesOFPeer();
    }

    {
        const lock_guard<mutex> lock(modb_count_mutex);
        createStaticGaugeFamiliesMoDBCount();
    }

    {
        const lock_guard<mutex> lock(rddrop_stats_mutex);
        createStaticGaugeFamiliesRDDrop();
    }

    {
        const lock_guard<mutex> lock(sgclassifier_stats_mutex);
        createStaticGaugeFamiliesSGClassifier();
    }

    createStaticGaugeFamiliesTableDrop();

    {
        const lock_guard<mutex> lock(contract_stats_mutex);
        createStaticGaugeFamiliesContractClassifier();
    }
   
    {   
	const lock_guard<mutex> lock(nat_counter_mutex);
        createStaticGaugeFamiliesNatCounter();
    }
}

// remove gauges during stop
void AgentPrometheusManager::removeStaticGauges ()
{
    // Remove TableDropCounter related gauges
    removeStaticGaugesTableDrop();

}

// Start of AgentPrometheusManager instance
void AgentPrometheusManager::start (bool exposeLocalHostOnly, bool exposeEpSvcNan_)
{
    disabled = false;
    exposeEpSvcNan = exposeEpSvcNan_;
    LOG(DEBUG) << "starting prometheus manager,"
               << " exposeLHOnly: " << exposeLocalHostOnly
               << " exposeEpSvcNan: " << exposeEpSvcNan;
    /**
     * create an http server running on port 9612
     * Note: The third argument is the total worker thread count. Prometheus
     * follows boss-worker thread model. 1 boss thread will get created to
     * intercept HTTP requests. The requests will then be serviced by free
     * worker threads. We are using 1 worker thread to service the requests.
     * Note: Port #9612 has been reserved for opflex here:
     * https://github.com/prometheus/prometheus/wiki/Default-port-allocations
     */
    registry_ptr = make_shared<Registry>();
    if (exposeLocalHostOnly)
        exposer_ptr = unique_ptr<Exposer>(new Exposer{"127.0.0.1:9612", 1});
    else
        exposer_ptr = unique_ptr<Exposer>(new Exposer{"9612", 1});

    /* Initialize Metric families which can be created during
     * init time */
    createStaticCounterFamilies();
    createStaticGaugeFamilies();

    // Add static metrics
    createStaticCounters();

    // ask the exposer to scrape the registry on incoming scrapes
    exposer_ptr->RegisterCollectable(registry_ptr);

    string allowed;
    for (const auto& allow : agent.getPrometheusEpAttributes())
        allowed += allow+",";
    LOG(DEBUG) << "Agent config's allowed ep attributes: " << allowed;
}

// initialize state of AgentPrometheusManager instance
void AgentPrometheusManager::init ()
{
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        counter_ep_create_ptr = nullptr;
        counter_ep_remove_ptr = nullptr;
        counter_ep_create_family_ptr = nullptr;
        counter_ep_remove_family_ptr = nullptr;
        for (EP_METRICS metric=EP_METRICS_MIN;
                metric < EP_METRICS_MAX;
                    metric = EP_METRICS(metric+1)) {
            gauge_ep_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(svc_target_counter_mutex);
        for (SVC_TARGET_METRICS metric=SVC_TARGET_METRICS_MIN;
                metric <= SVC_TARGET_METRICS_MAX;
                    metric = SVC_TARGET_METRICS(metric+1)) {
            gauge_svc_target_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        counter_svc_create_ptr = nullptr;
        counter_svc_remove_ptr = nullptr;
        counter_svc_create_family_ptr = nullptr;
        counter_svc_remove_family_ptr = nullptr;
        for (SVC_METRICS metric=SVC_METRICS_MIN;
                metric <= SVC_METRICS_MAX;
                    metric = SVC_METRICS(metric+1)) {
            gauge_svc_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(podsvc_counter_mutex);
        for (PODSVC_METRICS metric=PODSVC_METRICS_MIN;
                metric <= PODSVC_METRICS_MAX;
                    metric = PODSVC_METRICS(metric+1)) {
            gauge_podsvc_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(ofpeer_stats_mutex);
        for (OFPEER_METRICS metric=OFPEER_METRICS_MIN;
                metric <= OFPEER_METRICS_MAX;
                    metric = OFPEER_METRICS(metric+1)) {
            gauge_ofpeer_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(modb_count_mutex);
        for (MODB_COUNT_METRICS metric=MODB_COUNT_METRICS_MIN;
                metric <= MODB_COUNT_METRICS_MAX;
                    metric = MODB_COUNT_METRICS(metric+1)) {
            gauge_modb_count_family_ptr[metric] = nullptr;
            modb_count_gauge_map[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(rddrop_stats_mutex);
        for (RDDROP_METRICS metric=RDDROP_METRICS_MIN;
                metric <= RDDROP_METRICS_MAX;
                    metric = RDDROP_METRICS(metric+1)) {
            gauge_rddrop_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(table_drop_counter_mutex);
        for (TABLE_DROP_METRICS metric = TABLE_DROP_BYTES;
                metric <= TABLE_DROP_METRICS_MAX;
                    metric = TABLE_DROP_METRICS(metric+1)) {
            gauge_table_drop_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(sgclassifier_stats_mutex);
        for (SGCLASSIFIER_METRICS metric=SGCLASSIFIER_METRICS_MIN;
                metric <= SGCLASSIFIER_METRICS_MAX;
                    metric = SGCLASSIFIER_METRICS(metric+1)) {
            gauge_sgclassifier_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(contract_stats_mutex);
        for (CONTRACT_METRICS metric=CONTRACT_METRICS_MIN;
                metric <= CONTRACT_METRICS_MAX;
                    metric = CONTRACT_METRICS(metric+1)) {
            gauge_contract_family_ptr[metric] = nullptr;
        }
    }

    {
        const lock_guard<mutex> lock(nat_counter_mutex);
        for (NAT_METRICS metric=NAT_METRICS_MIN;
             metric <= NAT_METRICS_MAX;
             metric = NAT_METRICS(metric+1)) {
             gauge_nat_counter_family_ptr[metric] = nullptr;
        }
    }
}

// Stop of AgentPrometheusManager instance
void AgentPrometheusManager::stop ()
{
    RETURN_IF_DISABLED
    disabled = true;
    LOG(DEBUG) << "stopping prometheus manager";

    // Gracefully delete state

    // Remove metrics
    removeDynamicGauges();
    removeDynamicCounters();
    removeStaticCounters();
    removeStaticGauges();

    // Remove metric families
    removeStaticCounterFamilies();
    removeStaticGaugeFamilies();
    removeDynamicCounterFamilies();
    removeDynamicGaugeFamilies();

    gauge_check.clear();
    counter_check.clear();

    exposer_ptr.reset();
    exposer_ptr = nullptr;

    registry_ptr.reset();
    registry_ptr = nullptr;
}

// Increment Ep count
void AgentPrometheusManager::incStaticCounterEpCreate ()
{
    counter_ep_create_ptr->Increment();
}

// decrement ep count
void AgentPrometheusManager::incStaticCounterEpRemove ()
{
    counter_ep_remove_ptr->Increment();
}

// Increment Svc count
void AgentPrometheusManager::incStaticCounterSvcCreate ()
{
    counter_svc_create_ptr->Increment();
}

// decrement svc count
void AgentPrometheusManager::incStaticCounterSvcRemove ()
{
    counter_svc_remove_ptr->Increment();
}

// Create OFPeerStats gauge given metric type, peer (IP,port) tuple
void AgentPrometheusManager::createDynamicGaugeOFPeer (OFPEER_METRICS metric,
                                                       const string& peer)
{
    // Retrieve the Gauge if its already created
    if (getDynamicGaugeOFPeer(metric, peer))
        return;

    auto& gauge = gauge_ofpeer_family_ptr[metric]->Add({{"peer", peer}});
    if (gauge_check.is_dup(&gauge)) {
        LOG(WARNING) << "duplicate ofpeer dyn gauge family"
                   << " metric: " << metric
                   << " peer: " << peer;
        return;
    }
    LOG(DEBUG) << "created ofpeer dyn gauge family"
               << " metric: " << metric
               << " peer: " << peer;
    gauge_check.add(&gauge);
    ofpeer_gauge_map[metric][peer] = &gauge;
}

// Create ContractClassifierCounter gauge given metric type,
// name of srcEpg, dstEpg & classifier
bool AgentPrometheusManager::createDynamicGaugeContractClassifier (CONTRACT_METRICS metric,
                                                                  const string& srcEpg,
                                                                  const string& dstEpg,
                                                                  const string& classifier)
{
    // Retrieve the Gauge if its already created
    if (getDynamicGaugeContractClassifier(metric,
                                          srcEpg,
                                          dstEpg,
                                          classifier))
        return false;


    auto& gauge = gauge_contract_family_ptr[metric]->Add(
                    {
                        {"src_epg", constructEpgLabel(srcEpg)},
                        {"dst_epg", constructEpgLabel(dstEpg)},
                        {"classifier", constructClassifierLabel(classifier,
                                                                false)}
                    });
    if (gauge_check.is_dup(&gauge)) {
        LOG(WARNING) << "duplicate contract dyn gauge family"
                   << " metric: " << metric
                   << " srcEpg: " << srcEpg
                   << " dstEpg: " << dstEpg
                   << " classifier: " << classifier;
        return false;
    }
    LOG(DEBUG) << "created contract dyn gauge family"
               << " metric: " << metric
               << " srcEpg: " << srcEpg
               << " dstEpg: " << dstEpg
               << " classifier: " << classifier;
    gauge_check.add(&gauge);
    const string& key = srcEpg+dstEpg+classifier;
    contract_gauge_map[metric][key] = &gauge;
    return true;
}

// Create SGClassifierCounter gauge given metric type, classifier
bool AgentPrometheusManager::createDynamicGaugeSGClassifier (SGCLASSIFIER_METRICS metric,
                                                             const string& classifier)
{
    // Retrieve the Gauge if its already created
    if (getDynamicGaugeSGClassifier(metric, classifier))
        return false;

    auto& gauge = gauge_sgclassifier_family_ptr[metric]->Add(
                    {
                        {"classifier", constructClassifierLabel(classifier,
                                                                true)}
                    });
    if (gauge_check.is_dup(&gauge)) {
        LOG(DEBUG) << "duplicate sgclassifier dyn gauge family"
                   << " metric: " << metric
                   << " classifier: " << classifier;
        return false;
    }
    LOG(DEBUG) << "created sgclassifier dyn gauge family"
               << " metric: " << metric
               << " classifier: " << classifier;
    gauge_check.add(&gauge);
    sgclassifier_gauge_map[metric][classifier] = &gauge;
    return true;
}

// Construct label, given EPG URI
string AgentPrometheusManager::constructEpgLabel (const string& epg)
{
    /* Example EPG URI:
     * /PolicyUniverse/PolicySpace/kube/GbpEpGroup/kubernetes%7ckube-system/
     * We want to produce these annotations for every metric:
     * label_map: {{src_epg: "tenant:kube,policy:kube-system"},
     */
    size_t tLow = epg.find("PolicySpace") + 12;
    size_t gEpGStart = epg.rfind("GbpEpGroup");
    string tenant = epg.substr(tLow,gEpGStart-tLow-1);
    size_t nHigh = epg.size()-2;
    size_t nLow = gEpGStart+11;
    string ename = epg.substr(nLow,nHigh-nLow+1);
    string name = "tenant:" + tenant;
    name += ",policy:" + ename;
    return name;
}

// Construct label, given classifier URI
string AgentPrometheusManager::constructClassifierLabel (const string& classifier,
                                                         bool isSecGrp)
{
    /* Example classifier URI:
     * /PolicyUniverse/PolicySpace/kube/GbpeL24Classifier/SGkube_np_static-discovery%7cdiscovery%7carp-ingress/
     * We want to produce these annotations for every metric:
     * label_map: {{classifier: "tenant:kube,policy:kube_np_static-discovery,subj:discovery,rule:arp-ingress,
     *                           [string version of classifier]}}
     */
    size_t tLow = classifier.find("PolicySpace") + 12;
    size_t gL24Start = classifier.rfind("GbpeL24Classifier");
    string tenant = classifier.substr(tLow,gL24Start-tLow-1);
    size_t nHigh = classifier.size()-2;
    size_t nLow = gL24Start+18;
    string cname = classifier.substr(nLow,nHigh-nLow+1);
    string name = "tenant:" + tenant;
    // When the agent works along with aci fabric, the name of SG will be:
    // SGkube_np_static-discovery%7cdiscovery%7carp-ingress
    // In case of GBP server, the SG name will be like below:
    // kube_np_static-discovery
    // Remove the SG if its a prefix and if we have '|' separators.
    vector<string> results;
    // Note: splitting with '%' since "%7c" is treated as 3 chars. The assumption
    // is that GBP server policies dont have classifier name with '%'.
    split(results, cname, [](char c){return c == '%';});
    // 2 '|' will lead to 3 strings: policy, subj, and rule
    if (results.size() == 3) {
        if (isSecGrp)
            name += ",policy:" + results[0].substr(2); // Post "SG"
        else
            name += ",policy:" + results[0];
        name += ",subj:" + results[1].substr(2); // Post 7c
        name += ",rule:" + results[2].substr(2); // Post 7c

        // Note: MO resolves dont work with encoded ascii "%7c"
        // hence modifying the lookup string with actual ascii character '|'
        cname = results[0] + "|"
                    + results[1].substr(2) + "|"
                    + results[2].substr(2);
    } else {
        name += ",policy:" + cname;
    }

    return name+",["+stringizeClassifier(tenant, cname)+"]";
}

// Get a compressed human readable form of classifier
string AgentPrometheusManager::stringizeClassifier (const string& tenant,
                                                    const string& classifier)
{
    using namespace modelgbp::gbpe;
    string compressed;
    const auto& counter = L24Classifier::resolve(agent.getFramework(),
                                                 tenant,
                                                 classifier);
    if (counter) {
        auto arp_opc = counter.get()->getArpOpc();
        if (arp_opc)
            compressed += "arp_opc:" + to_string(arp_opc.get()) + ",";

        auto etype = counter.get()->getEtherT();
        if (etype)
            compressed += "etype:" + to_string(etype.get()) + ",";

        auto proto = counter.get()->getProt();
        if (proto)
            compressed += "proto:" + to_string(proto.get()) + ",";

        auto s_from_port = counter.get()->getSFromPort();
        if (s_from_port)
            compressed += "sport:" + to_string(s_from_port.get());

        auto s_to_port = counter.get()->getSToPort();
        if (s_to_port)
            compressed += "-" + to_string(s_to_port.get()) + ",";

        auto d_from_port = counter.get()->getDFromPort();
        if (d_from_port)
            compressed += "dport:" + to_string(d_from_port.get());

        auto d_to_port = counter.get()->getDToPort();
        if (d_to_port)
            compressed += "-" + to_string(d_to_port.get()) + ",";

        auto frag_flags = counter.get()->getFragmentFlags();
        if (frag_flags)
            compressed += "frag_flags:" + to_string(frag_flags.get()) + ",";

        auto icmp_code = counter.get()->getIcmpCode();
        if (icmp_code)
            compressed += "icmp_code" + to_string(icmp_code.get()) + ",";

        auto icmp_type = counter.get()->getIcmpType();
        if (icmp_type)
            compressed += "icmp_type:" + to_string(icmp_type.get()) + ",";

        auto tcp_flags = counter.get()->getTcpFlags();
        if (tcp_flags)
            compressed += "tcp_flags:" + to_string(tcp_flags.get()) + ",";

        auto ct = counter.get()->getConnectionTracking();
        if (ct)
            compressed += "ct:" + to_string(ct.get());
    } else {
        LOG(DEBUG) << "No classifier found for tenant: " << tenant
                   << " classifier: " << classifier;
    }

    return compressed;
}

// Create MoDBCount gauge given metric type
void AgentPrometheusManager::createDynamicGaugeMoDBCount (MODB_COUNT_METRICS metric)
{
    // Retrieve the Gauge if its already created
    if (getDynamicGaugeMoDBCount(metric))
        return;

    LOG(DEBUG) << "creating MoDB Count dyn gauge family"
               << " metric: " << metric;

    auto& gauge = gauge_modb_count_family_ptr[metric]->Add({});
    modb_count_gauge_map[metric] = &gauge;
}

// Create RDDropCounter gauge given metric type, rdURI
void AgentPrometheusManager::createDynamicGaugeRDDrop (RDDROP_METRICS metric,
                                                       const string& rdURI)
{
    // Retrieve the Gauge if its already created
    if (getDynamicGaugeRDDrop(metric, rdURI))
        return;

    /* Example rdURI: /PolicyUniverse/PolicySpace/test/GbpRoutingDomain/rd/
     * We want to just get the tenant name and the vrf. */
    size_t tLow = rdURI.find("PolicySpace") + 12;
    size_t gRDStart = rdURI.rfind("GbpRoutingDomain");
    string tenant = rdURI.substr(tLow,gRDStart-tLow-1);
    size_t rHigh = rdURI.size()-2;
    size_t rLow = gRDStart+17;
    string rd = rdURI.substr(rLow,rHigh-rLow+1);

    auto& gauge = gauge_rddrop_family_ptr[metric]->Add({{"routing_domain",
                                                         tenant+":"+rd}});
    if (gauge_check.is_dup(&gauge)) {
        LOG(DEBUG) << "duplicate rddrop dyn gauge family"
                   << " metric: " << metric
                   << " rdURI: " << rdURI;
        return;
    }
    LOG(DEBUG) << "created rddrop dyn gauge family"
               << " metric: " << metric
               << " rdURI: " << rdURI;
    gauge_check.add(&gauge);
    rddrop_gauge_map[metric][rdURI] = &gauge;
}

// Create SvcTargetCounter gauge given metric type, svc-tgt uuid & ep attr_map
void AgentPrometheusManager::createDynamicGaugeSvcTarget (SVC_TARGET_METRICS metric,
                                                         const string& key,
                                                         const string& uuid,
                                                         const string& nhip,
                        const unordered_map<string, string>&    svc_attr_map,
                        const unordered_map<string, string>&    ep_attr_map,
                                                         bool createIfNotPresent,
                                                         bool updateLabels,
                                                         bool isNodePort)
{
    // Retrieve the Gauge if its already created
    auto const &mgauge = getDynamicGaugeSvcTarget(metric, key);

    // Creation and deletion of this metric is controlled by ServiceManager based on
    // config events. Allow IntFlowManager to update pod specific attributes only
    // if the metric is already present.
    if (!mgauge && !createIfNotPresent)
        return;

    // During counter update from stats manager, dont create new gauge metric
    if (!updateLabels)
        return;

    auto const &label_map = createLabelMapFromSvcTargetAttr(uuid, nhip, svc_attr_map,
                                                            ep_attr_map, isNodePort);
    LabelHasher hasher;
    auto hash_new = hasher(label_map);

    if (mgauge) {
        /**
         * Detect attribute change by comparing hashes of cached label map
         * with new label map
         */
        if (hash_new == hasher(mgauge.get().first))
            return;
        else {
            LOG(DEBUG) << "addNupdate svctargetcounter key " << key
                       << "existing svc target metric, but deleting: hash modified;"
                       << " metric: " << svc_target_family_names[metric]
                       << " gaugeptr: " << mgauge.get().second;
            removeDynamicGaugeSvcTarget(metric, key);
        }
    }

    // We shouldnt add a gauge for SvcTarget which doesnt have svc-target name.
    // i.e. no vm-name for EPs
    if (!hash_new) {
        LOG(WARNING) << "label map is empty for svc-target dyn gauge family"
               << " metric: " << metric
               << " key: " << key;
        return;
    }

    auto& gauge = gauge_svc_target_family_ptr[metric]->Add(label_map);
    if (gauge_check.is_dup(&gauge)) {
        // Suppressing below log for all the other metrics of this family
        if (metric == SVC_TARGET_METRICS_MIN) {
            LOG(WARNING) << "duplicate svc-target dyn gauge family"
                       << " key: " << key
                       << " label hash: " << hash_new;
        }
        return;
    }
    LOG(DEBUG) << "created svc-target dyn gauge family"
               << " metric: " << metric
               << " key: " << key
               << " label hash: " << hash_new;
    gauge_check.add(&gauge);
    svc_target_gauge_map[metric][key] = make_pair(std::move(label_map), &gauge);
}

// Create SvcCounter gauge given metric type, svc uuid & attr_map
void AgentPrometheusManager::createDynamicGaugeSvc (SVC_METRICS metric,
                                                   const string& uuid,
                        const unordered_map<string, string>&    svc_attr_map,
                                                   bool isNodePort)
{
    // During counter update from stats manager, dont create new gauge metric
    if (svc_attr_map.size() == 0)
        return;

    auto const &label_map = createLabelMapFromSvcAttr(uuid, svc_attr_map, isNodePort);
    LabelHasher hasher;
    auto hash_new = hasher(label_map);

    // Retrieve the Gauge if its already created
    auto const &mgauge = getDynamicGaugeSvc(metric, uuid);
    if (mgauge) {
        /**
         * Detect attribute change by comparing hashes of cached label map
         * with new label map
         */
        if (hash_new == hasher(mgauge.get().first))
            return;
        else {
            LOG(DEBUG) << "addNupdate svccounter uuid " << uuid
                       << "existing svc metric, but deleting: hash modified;"
                       << " metric: " << svc_family_names[metric]
                       << " gaugeptr: " << mgauge.get().second;
            removeDynamicGaugeSvc(metric, uuid);
        }
    }

    // We shouldnt add a gauge for Svc which doesnt have svc name.
    if (!hash_new) {
        LOG(WARNING) << "label map is empty for svc dyn gauge family"
               << " metric: " << metric
               << " uuid: " << uuid;
        return;
    }

    auto& gauge = gauge_svc_family_ptr[metric]->Add(label_map);
    if (gauge_check.is_dup(&gauge)) {
        if (metric == SVC_METRICS_MIN) {
            LOG(WARNING) << "duplicate svc dyn gauge family"
                       << " uuid: " << uuid
                       << " label hash: " << hash_new;
        }
        return;
    }
    LOG(DEBUG) << "created svc dyn gauge family"
               << " metric: " << metric
               << " uuid: " << uuid
               << " label hash: " << hash_new;
    gauge_check.add(&gauge);
    svc_gauge_map[metric][uuid] = make_pair(std::move(label_map), &gauge);
}

// Create PodSvcCounter gauge given metric type, ep+svc uuid & attr_maps
void AgentPrometheusManager::createDynamicGaugePodSvc (PODSVC_METRICS metric,
                                                      const string& uuid,
                        const unordered_map<string, string>&    ep_attr_map,
                        const unordered_map<string, string>&    svc_attr_map)
{
    // During counter update from stats manager, dont create new gauge metric
    if ((ep_attr_map.size() == 0) && (svc_attr_map.size() == 0))
        return;

    auto const &label_map = createLabelMapFromPodSvcAttr(ep_attr_map, svc_attr_map);
    LabelHasher hasher;
    auto hash_new = hasher(label_map);

    // Retrieve the Gauge if its already created
    auto const &mgauge = getDynamicGaugePodSvc(metric, uuid);
    if (mgauge) {
        /**
         * Detect attribute change by comparing hashes of cached label map
         * with new label map
         */
        if (hash_new == hasher(mgauge.get().first))
            return;
        else {
            LOG(DEBUG) << "addNupdate podsvccounter uuid " << uuid
                       << "existing podsvc metric, but deleting: hash modified;"
                       << " metric: " << podsvc_family_names[metric]
                       << " gaugeptr: " << mgauge.get().second;
            removeDynamicGaugePodSvc(metric, uuid);
        }
    }

    // We shouldnt add a gauge for PodSvc which doesnt have
    // ep name and svc name.
    if (!hash_new) {
        LOG(WARNING) << "label map is empty for podsvc dyn gauge family"
               << " metric: " << metric
               << " uuid: " << uuid;
        return;
    }

    auto& gauge = gauge_podsvc_family_ptr[metric]->Add(label_map);
    if (gauge_check.is_dup(&gauge)) {
        LOG(WARNING) << "duplicate podsvc dyn gauge family"
                   << " metric: " << metric
                   << " uuid: " << uuid
                   << " label hash: " << hash_new;
        return;
    }
    LOG(DEBUG) << "created podsvc dyn gauge family"
               << " metric: " << metric
               << " uuid: " << uuid
               << " label hash: " << hash_new;
    gauge_check.add(&gauge);
    podsvc_gauge_map[metric][uuid] = make_pair(std::move(label_map), &gauge);
}

// Create EpCounter gauge given metric type and an uuid
bool AgentPrometheusManager::createDynamicGaugeEp (EP_METRICS metric,
                                                  const string& uuid,
                                                  const string& ep_name,
                                                  bool annotate_ep_name,
                                                  const size_t& attr_hash,
                        const unordered_map<string, string>&    attr_map)
{
    /**
     * We create a hash of all the key, value pairs in label attr_map
     * and then maintain a map of uuid to another pair of all attr hash
     * and gauge ptr
     * {uuid: pair(old_all_attr_hash, gauge_ptr)}
     */
    auto hgauge = getDynamicGaugeEp(metric, uuid);
    if (hgauge) {
        /**
         * Detect attribute change by comparing hashes:
         * Check incoming hash with the cached hash to detect attribute change
         * Note:
         * - we dont do a delete and create of metric for every attribute change.
         * Rather the dttribute's delete and create will get processed in EP Mgr.
         * Then during periodic update of epCounter, we will detect attr change in
         * AgentPrometheusManager and do a delete/create of metric for latest label
         * annotations.
         * - by not doing del/add of metric for every attribute change, we reduce
         * # of metric+label creation in prometheus.
         */
        if (attr_hash == hgauge.get().first)
            return false;
        else {
            LOG(DEBUG) << "addNupdate epcounter: " << ep_name
                       << " incoming attr_hash: " << attr_hash << "\n"
                       << "existing ep metric, but deleting: hash modified;"
                       << " metric: " << ep_family_names[metric]
                       << " hash: " << hgauge.get().first
                       << " gaugeptr: " << hgauge.get().second;
            removeDynamicGaugeEp(metric, uuid);
        }
    }

    auto label_map = createLabelMapFromEpAttr(ep_name,
                                              annotate_ep_name,
                                              attr_map,
                                              agent.getPrometheusEpAttributes());
    LabelHasher hasher;
    auto hash = hasher(label_map);
    auto& gauge = gauge_ep_family_ptr[metric]->Add(label_map);
    if (gauge_check.is_dup(&gauge)) {
        // Suppressing below log for all the other metrics of this EP
        if (metric == EP_METRICS_MIN) {
            LOG(WARNING) << "duplicate ep dyn gauge family: " << ep_name
                       << " uuid: " << uuid
                       << " label hash: " << hash
                       << " gaugeptr: " << &gauge;
        }

        // Note: return true so that: if metrics are created before and later
        // result in duplication due to change in attributes, the pre-duplicated
        // metrics can get freed.
        return true;
    }
    LOG(DEBUG) << "created ep dyn gauge family: " << ep_name
               << " metric: " << metric
               << " uuid: " << uuid
               << " label hash: " << hash
               << " gaugeptr: " << &gauge;
    gauge_check.add(&gauge);

    ep_gauge_map[metric][uuid] = make_pair(hash, &gauge);

    // If the gauge is already present and if we created last new metric due to
    // attribute change, then return false so that the active ep count and total
    // created ep count dont change
    if (hgauge && (metric == (EP_METRICS_MAX-1)))
        return false;

    return true;
}

// Create a label map that can be used for annotation, given the ep attr map
const map<string,string> AgentPrometheusManager::createLabelMapFromSvcTargetAttr (
                                                               const string& svc_uuid,
                                                               const string& nhip,
                                const unordered_map<string, string>&  svc_attr_map,
                                const unordered_map<string, string>&  ep_attr_map,
                                bool isNodePort)
{
    map<string,string>   label_map;
    label_map["svc_uuid"] = svc_uuid;

    // If there are multiple IPs per EP and if these 2 IPs are nexthops of service,
    // then gauge dup checker will crib for updates from these 2 IP flows.
    // Since this is the unique key for SvcTargetCounter, keeping it as part of
    // annotation. In grafana, we can filter out if the IP is not needed.
    label_map["ip"] = nhip;

    auto svc_name_itr = svc_attr_map.find("name");
    if (svc_name_itr != svc_attr_map.end()) {
        label_map["svc_name"] = svc_name_itr->second;
    }

    auto svc_ns_itr = svc_attr_map.find("namespace");
    if (svc_ns_itr != svc_attr_map.end()) {
        label_map["svc_namespace"] = svc_ns_itr->second;
    }

    auto svc_scope_itr = svc_attr_map.find("scope");
    if (svc_scope_itr != svc_attr_map.end()) {
        if (isNodePort)
            label_map["svc_scope"] = "nodePort";
        else
            label_map["svc_scope"] = svc_scope_itr->second;
    }

    auto ep_name_itr = ep_attr_map.find("vm-name");
    if (ep_name_itr != ep_attr_map.end()) {
        label_map["ep_name"] = ep_name_itr->second;
    }

    auto ep_ns_itr = ep_attr_map.find("namespace");
    if (ep_ns_itr != ep_attr_map.end()) {
        label_map["ep_namespace"] = ep_ns_itr->second;
    }

    return label_map;
}

// Create a label map that can be used for annotation, given the svc attr_map
const map<string,string> AgentPrometheusManager::createLabelMapFromSvcAttr (
                              const string& uuid,
                              const unordered_map<string, string>&  svc_attr_map,
                              bool isNodePort)
{
    map<string,string>   label_map;
    label_map["uuid"] = uuid;

    auto svc_name_itr = svc_attr_map.find("name");
    // Ensuring svc's name is present in attributes
    // If not, there is no point in creating this metric
    if (svc_name_itr != svc_attr_map.end()) {
        label_map["name"] = svc_name_itr->second;
    } else {
        return label_map;
    }

    auto svc_ns_itr = svc_attr_map.find("namespace");
    if (svc_ns_itr != svc_attr_map.end()) {
        label_map["namespace"] = svc_ns_itr->second;
    }

    auto svc_scope_itr = svc_attr_map.find("scope");
    if (svc_scope_itr != svc_attr_map.end()) {
        if (isNodePort)
            label_map["scope"] = "nodePort";
        else
            label_map["scope"] = svc_scope_itr->second;
    }

    return label_map;
}

// Create a label map that can be used for annotation, given the ep attr map
// and svc attr_map
const map<string,string> AgentPrometheusManager::createLabelMapFromPodSvcAttr (
                              const unordered_map<string, string>&  ep_attr_map,
                              const unordered_map<string, string>&  svc_attr_map)
{
    map<string,string>   label_map;

    auto ep_name_itr = ep_attr_map.find("vm-name");
    auto svc_name_itr = svc_attr_map.find("name");
    // Ensuring both ep and svc's names are present in attributes
    // If not, there is no point in creating this metric
    if ((ep_name_itr != ep_attr_map.end())
            && (svc_name_itr != svc_attr_map.end())) {
        label_map["ep_name"] = ep_name_itr->second;
        label_map["svc_name"] = svc_name_itr->second;
    } else {
        return label_map;
    }

    auto ep_ns_itr = ep_attr_map.find("namespace");
    if (ep_ns_itr != ep_attr_map.end()) {
        label_map["ep_namespace"] = ep_ns_itr->second;
    }

    auto svc_ns_itr = svc_attr_map.find("namespace");
    if (svc_ns_itr != svc_attr_map.end()) {
        label_map["svc_namespace"] = svc_ns_itr->second;
    }

    auto svc_scope_itr = svc_attr_map.find("scope");
    if (svc_scope_itr != svc_attr_map.end()) {
        label_map["svc_scope"] = svc_scope_itr->second;
    }

    return label_map;
}

// Create a label map that can be used for annotation, given the ep attr map
map<string,string> AgentPrometheusManager::createLabelMapFromEpAttr (
                                                           const string& ep_name,
                                                           bool annotate_ep_name,
                                 const unordered_map<string, string>&   attr_map,
                                 const unordered_set<string>&        allowed_set)
{
    map<string,string>   label_map;
    if (annotate_ep_name)
        label_map["if"] = ep_name;

    auto pod_itr = attr_map.find("vm-name");
    if (pod_itr != attr_map.end())
        label_map["name"] = pod_itr->second;
    else {
        // Note: if vm-name is not part of ep attributes, then just
        // set the ep_name as "name". This is to avoid label clash between
        // ep metrics that dont have vm-name.
        label_map["name"] = ep_name;
    }

    auto ns_itr = attr_map.find("namespace");
    if (ns_itr != attr_map.end())
        label_map["namespace"] = ns_itr->second;

    for (const auto& allowed : allowed_set) {

        if (!allowed.compare("vm-name")
                || !allowed.compare("namespace"))
            continue;

        auto allowed_itr = attr_map.find(allowed);
        if (allowed_itr != attr_map.end()) {
            // empty values can be discarded
            if (allowed_itr->second.empty())
                continue;

            // Label values can be anything in prometheus, but
            // the key has to cater to specific regex
            if (checkMetricName(allowed_itr->first)) {
                label_map[allowed_itr->first] = allowed_itr->second;
            } else {
                const auto& label = sanitizeMetricName(allowed_itr->first);
                LOG(DEBUG) << "ep attr not compatible with prometheus"
                           << " K:" << allowed_itr->first
                           << " V:" << allowed_itr->second
                           << " sanitized name:" << label;
                label_map[label] = allowed_itr->second;
            }
        }
    }

    return label_map;
}

// Get OFPeer stats gauge given the metric, peer (IP,port) tuple
Gauge * AgentPrometheusManager::getDynamicGaugeOFPeer (OFPEER_METRICS metric,
                                                       const string& peer)
{
    Gauge *pgauge = nullptr;
    auto itr = ofpeer_gauge_map[metric].find(peer);
    if (itr == ofpeer_gauge_map[metric].end()) {
        LOG(TRACE) << "Dyn Gauge OFPeer stats not found"
                   << " metric: " << metric
                   << " peer: " << peer;
    } else {
        pgauge = itr->second;
    }

    return pgauge;
}

// Get ContractClassifierCounter gauge given the metric,
// name of srcEpg, dstEpg & classifier
Gauge * AgentPrometheusManager::getDynamicGaugeContractClassifier (CONTRACT_METRICS metric,
                                                                  const string& srcEpg,
                                                                  const string& dstEpg,
                                                                  const string& classifier)
{
    Gauge *pgauge = nullptr;
    const string& key = srcEpg+dstEpg+classifier;
    auto itr = contract_gauge_map[metric].find(key);
    if (itr == contract_gauge_map[metric].end()) {
        LOG(DEBUG) << "Dyn Gauge ContractClassifier stats not found"
                   << " metric: " << metric
                   << " srcEpg: " << srcEpg
                   << " dstEpg: " << dstEpg
                   << " classifier: " << classifier;
    } else {
        pgauge = itr->second;
    }

    return pgauge;
}

// Get SGClassifierCounter gauge given the metric, classifier
Gauge * AgentPrometheusManager::getDynamicGaugeSGClassifier (SGCLASSIFIER_METRICS metric,
                                                             const string& classifier)
{
    Gauge *pgauge = nullptr;
    auto itr = sgclassifier_gauge_map[metric].find(classifier);
    if (itr == sgclassifier_gauge_map[metric].end()) {
        LOG(DEBUG) << "Dyn Gauge SGClassifier stats not found"
                   << " metric: " << metric
                   << " classifier: " << classifier;
    } else {
        pgauge = itr->second;
    }

    return pgauge;
}

// Get MoDBCount gauge given the metric
Gauge * AgentPrometheusManager::getDynamicGaugeMoDBCount (MODB_COUNT_METRICS metric)
{
    return modb_count_gauge_map[metric];
}

// Get RDDropCounter gauge given the metric, rdURI
Gauge * AgentPrometheusManager::getDynamicGaugeRDDrop (RDDROP_METRICS metric,
                                                       const string& rdURI)
{
    Gauge *pgauge = nullptr;
    auto itr = rddrop_gauge_map[metric].find(rdURI);
    if (itr == rddrop_gauge_map[metric].end()) {
        LOG(DEBUG) << "Dyn Gauge RDDrop stats not found"
                   << " metric: " << metric
                   << " rdURI: " << rdURI;
    } else {
        pgauge = itr->second;
    }

    return pgauge;
}

// Get SvcTargetCounter gauge given the metric, uuid of SvcTarget
mgauge_pair_t AgentPrometheusManager::getDynamicGaugeSvcTarget (SVC_TARGET_METRICS metric,
                                                                const string& uuid)
{
    mgauge_pair_t mgauge = boost::none;
    auto itr = svc_target_gauge_map[metric].find(uuid);
    if (itr == svc_target_gauge_map[metric].end()) {
        LOG(TRACE) << "Dyn Gauge SvcTargetCounter not found"
                   << " metric: " << metric
                   << " uuid: " << uuid;
    } else {
        mgauge = itr->second;
    }

    return mgauge;
}

// Get SvcCounter gauge given the metric, uuid of Svc
mgauge_pair_t AgentPrometheusManager::getDynamicGaugeSvc (SVC_METRICS metric,
                                                          const string& uuid)
{
    mgauge_pair_t mgauge = boost::none;
    auto itr = svc_gauge_map[metric].find(uuid);
    if (itr == svc_gauge_map[metric].end()) {
        LOG(TRACE) << "Dyn Gauge SvcCounter not found"
                   << " metric: " << metric
                   << " uuid: " << uuid;
    } else {
        mgauge = itr->second;
    }

    return mgauge;
}

// Get PodSvcCounter gauge given the metric, uuid of Pod+Svc
mgauge_pair_t AgentPrometheusManager::getDynamicGaugePodSvc (PODSVC_METRICS metric,
                                                            const string& uuid)
{
    mgauge_pair_t mgauge = boost::none;
    auto itr = podsvc_gauge_map[metric].find(uuid);
    if (itr == podsvc_gauge_map[metric].end()) {
        LOG(TRACE) << "Dyn Gauge PodSvcCounter not found"
                   << " metric: " << metric
                   << " uuid: " << uuid;
    } else {
        mgauge = itr->second;
    }

    return mgauge;
}

// Get EpCounter gauge given the metric, uuid of EP
hgauge_pair_t AgentPrometheusManager::getDynamicGaugeEp (EP_METRICS metric,
                                                        const string& uuid)
{
    hgauge_pair_t hgauge = boost::none;
    auto itr = ep_gauge_map[metric].find(uuid);
    if (itr == ep_gauge_map[metric].end()) {
        LOG(TRACE) << "Dyn Gauge EpCounter not found " << uuid;
    } else {
        hgauge = itr->second;
    }

    return hgauge;
}

// Remove dynamic ContractClassifierCounter gauge given a metic type and
// name of srcEpg, dstEpg & classifier
bool AgentPrometheusManager::removeDynamicGaugeContractClassifier (CONTRACT_METRICS metric,
                                                                  const string& srcEpg,
                                                                  const string& dstEpg,
                                                                  const string& classifier)
{
    Gauge *pgauge = getDynamicGaugeContractClassifier(metric,
                                                      srcEpg,
                                                      dstEpg,
                                                      classifier);
    if (pgauge) {
        LOG(DEBUG) << "remove ContractClassifierCounter"
                   << " srcEpg: " << srcEpg
                   << " dstEpg: " << dstEpg
                   << " classifier: " << classifier
                   << " metric: " << metric;
        const string& key = srcEpg+dstEpg+classifier;
        contract_gauge_map[metric].erase(key);
        gauge_check.remove(pgauge);
        gauge_contract_family_ptr[metric]->Remove(pgauge);
    } else {
        LOG(DEBUG) << "remove dynamic gauge contract stats not found"
                   << " srcEpg:" << srcEpg
                   << " dstEpg:" << dstEpg
                   << " classifier:" << classifier;
        return false;
    }
    return true;
}

// Remove dynamic ContractClassifierCounter gauge given a metric type
void AgentPrometheusManager::removeDynamicGaugeContractClassifier (CONTRACT_METRICS metric)
{
    auto itr = contract_gauge_map[metric].begin();
    while (itr != contract_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete ContractClassifierCounter"
                   << " key: " << itr->first
                   << " Gauge: " << itr->second;
        gauge_check.remove(itr->second);
        gauge_contract_family_ptr[metric]->Remove(itr->second);
        itr++;
    }

    contract_gauge_map[metric].clear();
}

// Remove dynamic ContractClassifierCounter gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeContractClassifier ()
{
    for (CONTRACT_METRICS metric=CONTRACT_METRICS_MIN;
            metric <= CONTRACT_METRICS_MAX;
                metric = CONTRACT_METRICS(metric+1)) {
        removeDynamicGaugeContractClassifier(metric);
    }
}

// Remove dynamic SGClassifierCounter gauge given a metic type and classifier
bool AgentPrometheusManager::removeDynamicGaugeSGClassifier (SGCLASSIFIER_METRICS metric,
                                                             const string& classifier)
{
    Gauge *pgauge = getDynamicGaugeSGClassifier(metric, classifier);
    if (pgauge) {
        sgclassifier_gauge_map[metric].erase(classifier);
        gauge_check.remove(pgauge);
        gauge_sgclassifier_family_ptr[metric]->Remove(pgauge);
    } else {
        LOG(DEBUG) << "remove dynamic gauge sgclassifier stats not found"
                   << " classifier:" << classifier;
        return false;
    }
    return true;
}

// Remove dynamic SGClassifierCounter gauge given a metric type
void AgentPrometheusManager::removeDynamicGaugeSGClassifier (SGCLASSIFIER_METRICS metric)
{
    auto itr = sgclassifier_gauge_map[metric].begin();
    while (itr != sgclassifier_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete SGClassifierCounter"
                   << " classifier: " << itr->first
                   << " Gauge: " << itr->second;
        gauge_check.remove(itr->second);
        gauge_sgclassifier_family_ptr[metric]->Remove(itr->second);
        itr++;
    }

    sgclassifier_gauge_map[metric].clear();
}

// Remove dynamic SGClassifierCounter gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeSGClassifier ()
{
    for (SGCLASSIFIER_METRICS metric=SGCLASSIFIER_METRICS_MIN;
            metric <= SGCLASSIFIER_METRICS_MAX;
                metric = SGCLASSIFIER_METRICS(metric+1)) {
        removeDynamicGaugeSGClassifier(metric);
    }
}

// Remove dynamic MoDBCount gauge given a metic type
bool AgentPrometheusManager::removeDynamicGaugeMoDBCount (MODB_COUNT_METRICS metric)
{
    Gauge *pgauge = getDynamicGaugeMoDBCount(metric);
    if (pgauge) {
        gauge_modb_count_family_ptr[metric]->Remove(pgauge);
    } else {
        LOG(TRACE) << "remove dynamic gauge MoDBCount not found; metric:" << metric;
        return false;
    }
    return true;
}

// Remove dynamic MoDBCount gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeMoDBCount ()
{
    for (MODB_COUNT_METRICS metric=MODB_COUNT_METRICS_MIN;
            metric <= MODB_COUNT_METRICS_MAX;
                metric = MODB_COUNT_METRICS(metric+1)) {
        removeDynamicGaugeMoDBCount(metric);
    }
}

// Remove dynamic RDDropCounter gauge given a metic type and rdURI
bool AgentPrometheusManager::removeDynamicGaugeRDDrop (RDDROP_METRICS metric,
                                                       const string& rdURI)
{
    Gauge *pgauge = getDynamicGaugeRDDrop(metric, rdURI);
    if (pgauge) {
        rddrop_gauge_map[metric].erase(rdURI);
        gauge_check.remove(pgauge);
        gauge_rddrop_family_ptr[metric]->Remove(pgauge);
    } else {
        LOG(DEBUG) << "remove dynamic gauge rddrop stats not found rdURI:" << rdURI;
        return false;
    }
    return true;
}

// Remove dynamic RDDropCounter gauge given a metric type
void AgentPrometheusManager::removeDynamicGaugeRDDrop (RDDROP_METRICS metric)
{
    auto itr = rddrop_gauge_map[metric].begin();
    while (itr != rddrop_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete RDDropCounter rdURI: " << itr->first
                   << " Gauge: " << itr->second;
        gauge_check.remove(itr->second);
        gauge_rddrop_family_ptr[metric]->Remove(itr->second);
        itr++;
    }

    rddrop_gauge_map[metric].clear();
}

// Remove dynamic RDDropCounter gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeRDDrop ()
{
    for (RDDROP_METRICS metric=RDDROP_METRICS_MIN;
            metric <= RDDROP_METRICS_MAX;
                metric = RDDROP_METRICS(metric+1)) {
        removeDynamicGaugeRDDrop(metric);
    }
}

// Remove dynamic OFPeerStats gauge given a metic type and peer (IP,port) tuple
bool AgentPrometheusManager::removeDynamicGaugeOFPeer (OFPEER_METRICS metric,
                                                       const string& peer)
{
    Gauge *pgauge = getDynamicGaugeOFPeer(metric, peer);
    if (pgauge) {
        ofpeer_gauge_map[metric].erase(peer);
        gauge_check.remove(pgauge);
        gauge_ofpeer_family_ptr[metric]->Remove(pgauge);
    } else {
        LOG(DEBUG) << "remove dynamic gauge ofpeer stats not found peer:" << peer;
        return false;
    }
    return true;
}

// Remove dynamic OFPeerStats gauge given a metric type
void AgentPrometheusManager::removeDynamicGaugeOFPeer (OFPEER_METRICS metric)
{
    auto itr = ofpeer_gauge_map[metric].begin();
    while (itr != ofpeer_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete OFPeer stats peer: " << itr->first
                   << " Gauge: " << itr->second;
        gauge_check.remove(itr->second);
        gauge_ofpeer_family_ptr[metric]->Remove(itr->second);
        itr++;
    }

    ofpeer_gauge_map[metric].clear();
}

// Remove dynamic OFPeerStats gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeOFPeer ()
{
    for (OFPEER_METRICS metric=OFPEER_METRICS_MIN;
            metric <= OFPEER_METRICS_MAX;
                metric = OFPEER_METRICS(metric+1)) {
        removeDynamicGaugeOFPeer(metric);
    }
}

// Remove dynamic SvcTargetCounter gauge given a metic type and svc-target uuid
bool AgentPrometheusManager::removeDynamicGaugeSvcTarget (SVC_TARGET_METRICS metric,
                                                          const string& uuid)
{
    auto mgauge = getDynamicGaugeSvcTarget(metric, uuid);
    if (mgauge) {
        auto &mpair = svc_target_gauge_map[metric][uuid];
        mpair.get().first.clear(); // free the label map
        svc_target_gauge_map[metric].erase(uuid);
        gauge_check.remove(mgauge.get().second);
        gauge_svc_target_family_ptr[metric]->Remove(mgauge.get().second);
    } else {
        LOG(DEBUG) << "remove dynamic gauge svc-target not found uuid:" << uuid;
        return false;
    }
    return true;
}

// Remove dynamic SvcTargetCounter gauge given a metric type
void AgentPrometheusManager::removeDynamicGaugeSvcTarget (SVC_TARGET_METRICS metric)
{
    auto itr = svc_target_gauge_map[metric].begin();
    while (itr != svc_target_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete SvcTarget uuid: " << itr->first
                   << " Gauge: " << itr->second.get().second;
        gauge_check.remove(itr->second.get().second);
        gauge_svc_target_family_ptr[metric]->Remove(itr->second.get().second);
        itr->second.get().first.clear(); // free the label map
        itr++;
    }

    svc_target_gauge_map[metric].clear();
}

// Remove dynamic SvcTargetCounter gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeSvcTarget ()
{
    for (SVC_TARGET_METRICS metric=SVC_TARGET_METRICS_MIN;
            metric <= SVC_TARGET_METRICS_MAX;
                metric = SVC_TARGET_METRICS(metric+1)) {
        removeDynamicGaugeSvcTarget(metric);
    }
}

// Remove dynamic SvcCounter gauge given a metic type and svc uuid
bool AgentPrometheusManager::removeDynamicGaugeSvc (SVC_METRICS metric,
                                                    const string& uuid)
{
    auto mgauge = getDynamicGaugeSvc(metric, uuid);
    if (mgauge) {
        auto &mpair = svc_gauge_map[metric][uuid];
        mpair.get().first.clear(); // free the label map
        svc_gauge_map[metric].erase(uuid);
        gauge_check.remove(mgauge.get().second);
        gauge_svc_family_ptr[metric]->Remove(mgauge.get().second);
    } else {
        LOG(DEBUG) << "remove dynamic gauge svc not found uuid:" << uuid;
        return false;
    }
    return true;
}

// Remove dynamic SvcCounter gauge given a metric type
void AgentPrometheusManager::removeDynamicGaugeSvc (SVC_METRICS metric)
{
    auto itr = svc_gauge_map[metric].begin();
    while (itr != svc_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete Svc uuid: " << itr->first
                   << " Gauge: " << itr->second.get().second;
        gauge_check.remove(itr->second.get().second);
        gauge_svc_family_ptr[metric]->Remove(itr->second.get().second);
        itr->second.get().first.clear(); // free the label map
        itr++;
    }

    svc_gauge_map[metric].clear();
}

// Remove dynamic SvcCounter gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeSvc ()
{
    for (SVC_METRICS metric=SVC_METRICS_MIN;
            metric <= SVC_METRICS_MAX;
                metric = SVC_METRICS(metric+1)) {
        removeDynamicGaugeSvc(metric);
    }
}

// Remove dynamic PodSvcCounter gauge given a metic type and podsvc uuid
bool AgentPrometheusManager::removeDynamicGaugePodSvc (PODSVC_METRICS metric,
                                                       const string& uuid)
{
    auto mgauge = getDynamicGaugePodSvc(metric, uuid);
    if (mgauge) {
        auto &mpair = podsvc_gauge_map[metric][uuid];
        mpair.get().first.clear(); // free the label map
        podsvc_gauge_map[metric].erase(uuid);
        gauge_check.remove(mgauge.get().second);
        gauge_podsvc_family_ptr[metric]->Remove(mgauge.get().second);
    } else {
        LOG(TRACE) << "remove dynamic gauge podsvc not found uuid:" << uuid;
        return false;
    }
    return true;
}

// Remove dynamic PodSvcCounter gauge given a metric type
void AgentPrometheusManager::removeDynamicGaugePodSvc (PODSVC_METRICS metric)
{
    auto itr = podsvc_gauge_map[metric].begin();
    while (itr != podsvc_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete PodSvc uuid: " << itr->first
                   << " Gauge: " << itr->second.get().second;
        gauge_check.remove(itr->second.get().second);
        gauge_podsvc_family_ptr[metric]->Remove(itr->second.get().second);
        itr->second.get().first.clear(); // free the label map
        itr++;
    }

    podsvc_gauge_map[metric].clear();
}

// Remove dynamic PodSvcCounter gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugePodSvc ()
{
    for (PODSVC_METRICS metric=PODSVC_METRICS_MIN;
            metric <= PODSVC_METRICS_MAX;
                metric = PODSVC_METRICS(metric+1)) {
        removeDynamicGaugePodSvc(metric);
    }
}

// Remove dynamic EpCounter gauge given a metic type and ep uuid
bool AgentPrometheusManager::removeDynamicGaugeEp (EP_METRICS metric,
                                                   const string& uuid)
{
    auto hgauge = getDynamicGaugeEp(metric, uuid);
    if (hgauge) {
        ep_gauge_map[metric].erase(uuid);
        gauge_check.remove(hgauge.get().second);
        gauge_ep_family_ptr[metric]->Remove(hgauge.get().second);
    } else {
        LOG(DEBUG) << "remove dynamic gauge ep not found uuid:" << uuid;
        return false;
    }
    return true;
}

// Remove dynamic EpCounter gauge given a metic type
void AgentPrometheusManager::removeDynamicGaugeEp (EP_METRICS metric)
{
    auto itr = ep_gauge_map[metric].begin();
    while (itr != ep_gauge_map[metric].end()) {
        LOG(DEBUG) << "Delete Ep uuid: " << itr->first
                   << " hash: " << itr->second.get().first
                   << " Gauge: " << itr->second.get().second;
        gauge_check.remove(itr->second.get().second);
        gauge_ep_family_ptr[metric]->Remove(itr->second.get().second);
        itr++;

        if (metric == (EP_METRICS_MAX-1)) {
            incStaticCounterEpRemove();
        }
    }

    ep_gauge_map[metric].clear();
}

// Remove dynamic EpCounter gauges for all metrics
void AgentPrometheusManager::removeDynamicGaugeEp ()
{
    for (EP_METRICS metric=EP_METRICS_MIN;
            metric < EP_METRICS_MAX;
                metric = EP_METRICS(metric+1)) {
        removeDynamicGaugeEp(metric);
    }
}

// Remove all dynamically allocated counter families
void AgentPrometheusManager::removeDynamicCounterFamilies ()
{
    // No dynamic counter families as of now
}

// Remove all dynamically allocated gauge families
void AgentPrometheusManager::removeDynamicGaugeFamilies ()
{
    // No dynamic gauge families as of now
}

// Remove all statically  allocated ep counter families
void AgentPrometheusManager::removeStaticCounterFamiliesEp ()
{
    counter_ep_create_family_ptr = nullptr;
    counter_ep_remove_family_ptr = nullptr;

}

// Remove all statically  allocated svc counter families
void AgentPrometheusManager::removeStaticCounterFamiliesSvc ()
{
    counter_svc_create_family_ptr = nullptr;
    counter_svc_remove_family_ptr = nullptr;

}

// Remove all statically  allocated counter families
void AgentPrometheusManager::removeStaticCounterFamilies ()
{
    // EpCounter specific
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        removeStaticCounterFamiliesEp();
    }

    // SvcCounter specific
    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        removeStaticCounterFamiliesSvc();
    }
}

// Remove all statically allocated OFPeer gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesOFPeer ()
{
    for (OFPEER_METRICS metric=OFPEER_METRICS_MIN;
            metric <= OFPEER_METRICS_MAX;
                metric = OFPEER_METRICS(metric+1)) {
        gauge_ofpeer_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated ContractClassifier gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesContractClassifier ()
{
    for (CONTRACT_METRICS metric=CONTRACT_METRICS_MIN;
            metric <= CONTRACT_METRICS_MAX;
                metric = CONTRACT_METRICS(metric+1)) {
        gauge_contract_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated SGClassifier gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesSGClassifier ()
{
    for (SGCLASSIFIER_METRICS metric=SGCLASSIFIER_METRICS_MIN;
            metric <= SGCLASSIFIER_METRICS_MAX;
                metric = SGCLASSIFIER_METRICS(metric+1)) {
        gauge_sgclassifier_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated MoDBCount gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesMoDBCount ()
{
    for (MODB_COUNT_METRICS metric=MODB_COUNT_METRICS_MIN;
            metric <= MODB_COUNT_METRICS_MAX;
                metric = MODB_COUNT_METRICS(metric+1)) {
        gauge_modb_count_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated RDDrop gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesRDDrop ()
{
    for (RDDROP_METRICS metric=RDDROP_METRICS_MIN;
            metric <= RDDROP_METRICS_MAX;
                metric = RDDROP_METRICS(metric+1)) {
        gauge_rddrop_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated podsvc gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesPodSvc()
{
    for (PODSVC_METRICS metric=PODSVC_METRICS_MIN;
            metric <= PODSVC_METRICS_MAX;
                metric = PODSVC_METRICS(metric+1)) {
        gauge_podsvc_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated ep gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesEp()
{
    for (EP_METRICS metric=EP_METRICS_MIN;
            metric < EP_METRICS_MAX;
                metric = EP_METRICS(metric+1)) {
        gauge_ep_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated svc target gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesSvcTarget()
{
    for (SVC_TARGET_METRICS metric=SVC_TARGET_METRICS_MIN;
            metric <= SVC_TARGET_METRICS_MAX;
                metric = SVC_TARGET_METRICS(metric+1)) {
        gauge_svc_target_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated svc gauge families
void AgentPrometheusManager::removeStaticGaugeFamiliesSvc()
{
    for (SVC_METRICS metric=SVC_METRICS_MIN;
            metric <= SVC_METRICS_MAX;
                metric = SVC_METRICS(metric+1)) {
        gauge_svc_family_ptr[metric] = nullptr;
    }
}

void AgentPrometheusManager::removeStaticGaugeFamiliesTableDrop()
{
    const lock_guard<mutex> lock(table_drop_counter_mutex);
    for (TABLE_DROP_METRICS metric = TABLE_DROP_BYTES;
            metric <= TABLE_DROP_METRICS_MAX;
                metric = TABLE_DROP_METRICS(metric+1)) {
        gauge_table_drop_family_ptr[metric] = nullptr;
    }
}

void AgentPrometheusManager::removeStaticGaugeFamiliesNatCounter()
{
    for (NAT_METRICS metric=NAT_METRICS_MIN;
         metric <= NAT_METRICS_MAX;
         metric =  NAT_METRICS(metric+1)) {
         gauge_nat_counter_family_ptr[metric] = nullptr;
    }
}

// Remove all statically allocated gauge families
void AgentPrometheusManager::removeStaticGaugeFamilies()
{
    // EpCounter specific
    {
        const lock_guard<mutex> lock(ep_counter_mutex);
        removeStaticGaugeFamiliesEp();
    }

    // SvcTargetCounter specific
    {
        const lock_guard<mutex> lock(svc_target_counter_mutex);
        removeStaticGaugeFamiliesSvcTarget();
    }

    // SvcCounter specific
    {
        const lock_guard<mutex> lock(svc_counter_mutex);
        removeStaticGaugeFamiliesSvc();
    }

    // PodSvcCounter specific
    {
        const lock_guard<mutex> lock(podsvc_counter_mutex);
        removeStaticGaugeFamiliesPodSvc();
    }

    // OFPeer stats specific
    {
        const lock_guard<mutex> lock(ofpeer_stats_mutex);
        removeStaticGaugeFamiliesOFPeer();
    }

    // MoDBCount specific
    {
        const lock_guard<mutex> lock(modb_count_mutex);
        removeStaticGaugeFamiliesMoDBCount();
    }

    // RDDropCounter specific
    {
        const lock_guard<mutex> lock(rddrop_stats_mutex);
        removeStaticGaugeFamiliesRDDrop();
    }

    // SGClassifierCounter specific
    {
        const lock_guard<mutex> lock(sgclassifier_stats_mutex);
        removeStaticGaugeFamiliesSGClassifier();
    }

    // TableDrop specific
    removeStaticGaugeFamiliesTableDrop();

    // ContractClassifierCounter specific
    {
        const lock_guard<mutex> lock(contract_stats_mutex);
        removeStaticGaugeFamiliesContractClassifier();
    }
    // Nat Stat counter specific
    {
       const lock_guard<mutex> lock(nat_counter_mutex);
       removeStaticGaugeFamiliesNatCounter();
    }
}

// Return a rolling hash of attribute map for the ep
size_t AgentPrometheusManager::calcHashEpAttributes (const string& ep_name,
                                                     bool annotate_ep_name,
                          const unordered_map<string, string>& attr_map,
                          const unordered_set<string>&        allowed_set)
{
    auto label_map = createLabelMapFromEpAttr(ep_name,
                                              annotate_ep_name,
                                              attr_map,
                                              allowed_set);
    LabelHasher hasher;
    auto hash = hasher(label_map);
    LOG(DEBUG) << ep_name << ":calculated label hash = " << hash;
    return hash;
}

/* Function called from IntFlowManager to update PodSvcCounter */
void AgentPrometheusManager::addNUpdatePodSvcCounter (bool isEpToSvc,
                                                      const string& uuid,
                                                      uint64_t bytes,
                                                      uint64_t pkts,
                      const unordered_map<string, string>& ep_attr_map,
                      const unordered_map<string, string>& svc_attr_map)
{
    RETURN_IF_DISABLED

    const lock_guard<mutex> lock(podsvc_counter_mutex);

    if (!exposeEpSvcNan && !pkts)
        return;

    if (isEpToSvc) {
        // Create the gauge counters if they arent present already
        for (PODSVC_METRICS metric=PODSVC_EP2SVC_MIN;
                metric <= PODSVC_EP2SVC_MAX;
                    metric = PODSVC_METRICS(metric+1)) {
            createDynamicGaugePodSvc(metric,
                                     uuid,
                                     ep_attr_map,
                                     svc_attr_map);
        }

        // Update the metrics
        for (PODSVC_METRICS metric=PODSVC_EP2SVC_MIN;
                metric <= PODSVC_EP2SVC_MAX;
                    metric = PODSVC_METRICS(metric+1)) {
            const mgauge_pair_t &mgauge = getDynamicGaugePodSvc(metric, uuid);
            optional<uint64_t>   metric_opt;
            switch (metric) {
            case PODSVC_EP2SVC_BYTES:
                metric_opt = bytes;
                break;
            case PODSVC_EP2SVC_PKTS:
                metric_opt = pkts;
                break;
            default:
                LOG(WARNING) << "Unhandled eptosvc metric: " << metric;
            }
            if (metric_opt && mgauge)
                mgauge.get().second->Set(static_cast<double>(metric_opt.get()));
            if (!mgauge) {
                LOG(WARNING) << "ep2svc stats invalid update for uuid: " << uuid;
                break;
            }
        }
    } else {
        // Create the gauge counters if they arent present already
        for (PODSVC_METRICS metric=PODSVC_SVC2EP_MIN;
                metric <= PODSVC_SVC2EP_MAX;
                    metric = PODSVC_METRICS(metric+1)) {
            createDynamicGaugePodSvc(metric,
                                     uuid,
                                     ep_attr_map,
                                     svc_attr_map);
        }

        // Update the metrics
        for (PODSVC_METRICS metric=PODSVC_SVC2EP_MIN;
                metric <= PODSVC_SVC2EP_MAX;
                    metric = PODSVC_METRICS(metric+1)) {
            const mgauge_pair_t &mgauge = getDynamicGaugePodSvc(metric, uuid);
            optional<uint64_t>   metric_opt;
            switch (metric) {
            case PODSVC_SVC2EP_BYTES:
                metric_opt = bytes;
                break;
            case PODSVC_SVC2EP_PKTS:
                metric_opt = pkts;
                break;
            default:
                LOG(WARNING) << "Unhandled svctoep metric: " << metric;
            }
            if (metric_opt && mgauge)
                mgauge.get().second->Set(static_cast<double>(metric_opt.get()));
            if (!mgauge) {
                LOG(WARNING) << "svc2ep stats invalid update for uuid: " << uuid;
                break;
            }
        }
    }
}

/* Function called from IntFlowManager and ServiceManager to update SvcTargetCounter
 * Note: SvcTargetCounter's key is the next-hop-IP. There could be a chance
 * that multiple next-hop IPs of a service are part of same EP/Pod.
 * In that case, the label annotion for both the svc-targets will be same
 * if we dont annotate the IP address to prometheus. Metric duplication
 * checker will detect this and will neither create nor update gauge metric
 * for the conflicting IP.
 * To avoid confusion and keep things simple, we will annotate with the nhip
 * as well to avoid duplicate metrics. We can avoid showing the IP in grafana
 * if its not of much value. */
void AgentPrometheusManager::addNUpdateSvcTargetCounter (const string& uuid,
                                                         const string& nhip,
                                                         uint64_t rx_bytes,
                                                         uint64_t rx_pkts,
                                                         uint64_t tx_bytes,
                                                         uint64_t tx_pkts,
                             const unordered_map<string, string>& svc_attr_map,
                             const unordered_map<string, string>& ep_attr_map,
                                                         bool createIfNotPresent,
                                                         bool updateLabels,
                                                         bool isNodePort)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(svc_target_counter_mutex);

    const string& key = uuid+nhip;
    // Create the gauge counters if they arent present already
    for (SVC_TARGET_METRICS metric=SVC_TARGET_METRICS_MIN;
            metric <= SVC_TARGET_METRICS_MAX;
                metric = SVC_TARGET_METRICS(metric+1)) {
        createDynamicGaugeSvcTarget(metric,
                                    key,
                                    uuid,
                                    nhip,
                                    svc_attr_map,
                                    ep_attr_map,
                                    createIfNotPresent,
                                    updateLabels,
                                    isNodePort);
    }

    // Update the metrics
    for (SVC_TARGET_METRICS metric=SVC_TARGET_METRICS_MIN;
            metric <= SVC_TARGET_METRICS_MAX;
                metric = SVC_TARGET_METRICS(metric+1)) {
        const mgauge_pair_t &mgauge = getDynamicGaugeSvcTarget(metric, key);
        uint64_t   metric_val = 0;
        switch (metric) {
        case SVC_TARGET_RX_BYTES:
            metric_val = rx_bytes;
            break;
        case SVC_TARGET_RX_PKTS:
            metric_val = rx_pkts;
            break;
        case SVC_TARGET_TX_BYTES:
            metric_val = tx_bytes;
            break;
        case SVC_TARGET_TX_PKTS:
            metric_val = tx_pkts;
            break;
        default:
            LOG(WARNING) << "Unhandled svc-target metric: " << metric;
        }
        if (mgauge)
            mgauge.get().second->Set(static_cast<double>(metric_val));
        if (!mgauge && createIfNotPresent) {
            LOG(WARNING) << "svc-target stats invalid update for uuid: " << key;
            break;
        }
    }
}

/* Function called from IntFlowManager and ServiceManager to update SvcCounter */
void AgentPrometheusManager::addNUpdateSvcCounter (const string& uuid,
                                                   uint64_t rx_bytes,
                                                   uint64_t rx_pkts,
                                                   uint64_t tx_bytes,
                                                   uint64_t tx_pkts,
                      const unordered_map<string, string>& svc_attr_map,
                                                   bool isNodePort)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(svc_counter_mutex);

    // Create the gauge counters if they arent present already
    for (SVC_METRICS metric=SVC_METRICS_MIN;
            metric <= SVC_METRICS_MAX;
                metric = SVC_METRICS(metric+1)) {
        createDynamicGaugeSvc(metric,
                              uuid,
                              svc_attr_map,
                              isNodePort);
    }

    // Update the metrics
    for (SVC_METRICS metric=SVC_METRICS_MIN;
            metric <= SVC_METRICS_MAX;
                metric = SVC_METRICS(metric+1)) {
        const mgauge_pair_t &mgauge = getDynamicGaugeSvc(metric, uuid);
        uint64_t   metric_val = 0;
        switch (metric) {
        case SVC_RX_BYTES:
            metric_val = rx_bytes;
            break;
        case SVC_RX_PKTS:
            metric_val = rx_pkts;
            break;
        case SVC_TX_BYTES:
            metric_val = tx_bytes;
            break;
        case SVC_TX_PKTS:
            metric_val = tx_pkts;
            break;
        default:
            LOG(WARNING) << "Unhandled svc metric: " << metric;
        }
        if (mgauge)
            mgauge.get().second->Set(static_cast<double>(metric_val));
        if (!mgauge && !svc_attr_map.empty()) {
            LOG(WARNING) << "svc stats invalid update for uuid: " << uuid;
            break;
        }
    }
}

/* Function called from ContractStatsManager to add/update ContractClassifierCounter */
void AgentPrometheusManager::addNUpdateContractClassifierCounter (const string& srcEpg,
                                                                  const string& dstEpg,
                                                                  const string& classifier,
                                                                  uint64_t bytes,
                                                                  uint64_t pkts)
{
    RETURN_IF_DISABLED

    const lock_guard<mutex> lock(contract_stats_mutex);

    for (CONTRACT_METRICS metric=CONTRACT_METRICS_MIN;
            metric <= CONTRACT_METRICS_MAX;
                metric = CONTRACT_METRICS(metric+1))
        if (!createDynamicGaugeContractClassifier(metric,
                                                  srcEpg,
                                                  dstEpg,
                                                  classifier))
            break;

    // Update the metrics
    for (CONTRACT_METRICS metric=CONTRACT_METRICS_MIN;
            metric <= CONTRACT_METRICS_MAX;
                metric = CONTRACT_METRICS(metric+1)) {
        Gauge *pgauge = getDynamicGaugeContractClassifier(metric,
                                                          srcEpg,
                                                          dstEpg,
                                                          classifier);
        optional<uint64_t>   metric_opt;
        switch (metric) {
        case CONTRACT_BYTES:
            metric_opt = bytes;
            break;
        case CONTRACT_PACKETS:
            metric_opt = pkts;
            break;
        default:
            LOG(WARNING) << "Unhandled contract metric: " << metric;
        }
        if (metric_opt && pgauge)
            pgauge->Set(pgauge->Value() \
                        + static_cast<double>(metric_opt.get()));
        if (!pgauge) {
            LOG(WARNING) << "Invalid sgclassifier update"
                       << " srcEpg: " << srcEpg
                       << " dstEpg: " << dstEpg
                       << " classifier: " << classifier;
            break;
        }
    }
}

/* Function called from SecGrpStatsManager to add/update SGClassifierCounter */
void AgentPrometheusManager::addNUpdateSGClassifierCounter (const string& classifier,
                                                            uint64_t rx_bytes,
                                                            uint64_t rx_pkts,
                                                            uint64_t tx_bytes,
                                                            uint64_t tx_pkts)
{
    RETURN_IF_DISABLED

    const lock_guard<mutex> lock(sgclassifier_stats_mutex);

    for (SGCLASSIFIER_METRICS metric=SGCLASSIFIER_METRICS_MIN;
            metric <= SGCLASSIFIER_METRICS_MAX;
                metric = SGCLASSIFIER_METRICS(metric+1))
        if (!createDynamicGaugeSGClassifier(metric, classifier))
            break;

    // Update the metrics
    for (SGCLASSIFIER_METRICS metric=SGCLASSIFIER_METRICS_MIN;
            metric <= SGCLASSIFIER_METRICS_MAX;
                metric = SGCLASSIFIER_METRICS(metric+1)) {
        Gauge *pgauge = getDynamicGaugeSGClassifier(metric,
                                                    classifier);
        optional<uint64_t>   metric_opt;
        switch (metric) {
        case SGCLASSIFIER_RX_BYTES:
            metric_opt = rx_bytes;
            break;
        case SGCLASSIFIER_RX_PACKETS:
            metric_opt = rx_pkts;
            break;
        case SGCLASSIFIER_TX_BYTES:
            metric_opt = tx_bytes;
            break;
        case SGCLASSIFIER_TX_PACKETS:
            metric_opt = tx_pkts;
            break;
        default:
            LOG(WARNING) << "Unhandled sgclassifier metric: " << metric;
        }
        if (metric_opt && pgauge)
            pgauge->Set(pgauge->Value() \
                        + static_cast<double>(metric_opt.get()));
        if (!pgauge) {
            LOG(WARNING) << "Invalid sgclassifier update classifier: " << classifier;
            break;
        }
    }
}

/* Function called from ServiceManager to increment service count */
void AgentPrometheusManager::incSvcCounter (void)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(svc_counter_mutex);
    incStaticCounterSvcCreate();
}

/* Function called from ServiceManager to decrement service count */
void AgentPrometheusManager::decSvcCounter (void)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(svc_counter_mutex);
    incStaticCounterSvcRemove();
}

/* Function to create/update MoDB counts */
void AgentPrometheusManager::addNUpdateMoDBCounts (shared_ptr<ModbCounts> pCount)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(modb_count_mutex);

    // create the metric if its not present
    for (MODB_COUNT_METRICS metric=MODB_COUNT_METRICS_MIN;
            metric <= MODB_COUNT_METRICS_MAX;
                metric = MODB_COUNT_METRICS(metric+1))
        createDynamicGaugeMoDBCount(metric);

    for (MODB_COUNT_METRICS metric=MODB_COUNT_METRICS_MIN;
            metric <= MODB_COUNT_METRICS_MAX;
                metric = MODB_COUNT_METRICS(metric+1)) {
        Gauge *pgauge = getDynamicGaugeMoDBCount(metric);
        optional<uint64_t>   metric_opt;
        switch (metric) {
        case MODB_COUNT_EP_LOCAL:
            metric_opt = pCount->getLocalEP();
            break;
        case MODB_COUNT_EP_REMOTE:
            metric_opt = pCount->getRemoteEP();
            break;
        case MODB_COUNT_EP_EXT:
            metric_opt = pCount->getExtEP();
            break;
        case MODB_COUNT_EPG:
            metric_opt = pCount->getEpg();
            break;
        case MODB_COUNT_EXT_INTF:
            metric_opt = pCount->getExtIntfs();
            break;
        case MODB_COUNT_RD:
            metric_opt = pCount->getRd();
            break;
        case MODB_COUNT_SERVICE:
            metric_opt = pCount->getService();
            break;
        case MODB_COUNT_CONTRACT:
            metric_opt = pCount->getContract();
            break;
        case MODB_COUNT_SG:
            metric_opt = pCount->getSg();
            break;
        default:
            LOG(WARNING) << "Unhandled modb count metric: " << metric;
        }
        if (metric_opt && pgauge)
            pgauge->Set(static_cast<double>(metric_opt.get()));
        if (!pgauge) {
            LOG(WARNING) << "Invalid modb count update";
            break;
        }
    }
}

/* Function called from ContractStatsManager to update RDDropCounter
 * This will be called from IntFlowManager to create metrics. */
void AgentPrometheusManager::addNUpdateRDDropCounter (const string& rdURI,
                                                      bool isAdd,
                                                      uint64_t bytes,
                                                      uint64_t pkts)
{
    RETURN_IF_DISABLED

    const lock_guard<mutex> lock(rddrop_stats_mutex);

    if (isAdd) {
        LOG(DEBUG) << "create RDDropCounter rdURI: " << rdURI;
        for (RDDROP_METRICS metric=RDDROP_METRICS_MIN;
                metric <= RDDROP_METRICS_MAX;
                    metric = RDDROP_METRICS(metric+1))
            createDynamicGaugeRDDrop(metric, rdURI);
        return;
    }

    // Update the metrics
    for (RDDROP_METRICS metric=RDDROP_METRICS_MIN;
            metric <= RDDROP_METRICS_MAX;
                metric = RDDROP_METRICS(metric+1)) {
        Gauge *pgauge = getDynamicGaugeRDDrop(metric, rdURI);
        optional<uint64_t>   metric_opt;
        switch (metric) {
        case RDDROP_BYTES:
            metric_opt = bytes;
            break;
        case RDDROP_PACKETS:
            metric_opt = pkts;
            break;
        default:
            LOG(WARNING) << "Unhandled rddrop metric: " << metric;
        }
        if (metric_opt && pgauge)
            pgauge->Set(pgauge->Value() \
                        + static_cast<double>(metric_opt.get()));
        if (!pgauge && isAdd) {
            LOG(WARNING) << "Invalid rddrop update rdURI: " << rdURI;
            break;
        }
    }
}

/* Function called from PolicyStatsManager to update OFPeerStats */
void AgentPrometheusManager::addNUpdateOFPeerStats (const std::string& peer,
                                                    const std::shared_ptr<OFAgentStats> stats)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(ofpeer_stats_mutex);

    if (!stats)
        return;

    // Create gauge metrics if they arent present already
    for (OFPEER_METRICS metric=OFPEER_METRICS_MIN;
            metric <= OFPEER_METRICS_MAX;
                metric = OFPEER_METRICS(metric+1))
        createDynamicGaugeOFPeer(metric, peer);

    // Update the metrics
    for (OFPEER_METRICS metric=OFPEER_METRICS_MIN;
            metric <= OFPEER_METRICS_MAX;
                metric = OFPEER_METRICS(metric+1)) {
        Gauge *pgauge = getDynamicGaugeOFPeer(metric, peer);
        optional<uint64_t>   metric_opt;
        switch (metric) {
        case OFPEER_IDENT_REQS:
            metric_opt = stats->getIdentReqs();
            break;
        case OFPEER_IDENT_RESPS:
            metric_opt = stats->getIdentResps();
            break;
        case OFPEER_IDENT_ERRORS:
            metric_opt = stats->getIdentErrs();
            break;
        case OFPEER_POL_RESOLVES:
            metric_opt = stats->getPolResolves();
            break;
        case OFPEER_POL_RESOLVE_RESPS:
            metric_opt = stats->getPolResolveResps();
            break;
        case OFPEER_POL_RESOLVE_ERRS:
            metric_opt = stats->getPolResolveErrs();
            break;
        case OFPEER_POL_UNRESOLVES:
            metric_opt = stats->getPolUnresolves();
            break;
        case OFPEER_POL_UNRESOLVE_RESPS:
            metric_opt = stats->getPolUnresolveResps();
            break;
        case OFPEER_POL_UNRESOLVE_ERRS:
            metric_opt = stats->getPolUnresolveErrs();
            break;
        case OFPEER_POL_UPDATES:
            metric_opt = stats->getPolUpdates();
            break;
        case OFPEER_EP_DECLARES:
            metric_opt = stats->getEpDeclares();
            break;
        case OFPEER_EP_DECLARE_RESPS:
            metric_opt = stats->getEpDeclareResps();
            break;
        case OFPEER_EP_DECLARE_ERRS:
            metric_opt = stats->getEpDeclareErrs();
            break;
        case OFPEER_EP_UNDECLARES:
            metric_opt = stats->getEpUndeclares();
            break;
        case OFPEER_EP_UNDECLARE_RESPS:
            metric_opt = stats->getEpUndeclareResps();
            break;
        case OFPEER_EP_UNDECLARE_ERRS:
            metric_opt = stats->getEpUndeclareErrs();
            break;
        case OFPEER_STATE_REPORTS:
            metric_opt = stats->getStateReports();
            break;
        case OFPEER_STATE_REPORT_RESPS:
            metric_opt = stats->getStateReportResps();
            break;
        case OFPEER_STATE_REPORT_ERRS:
            metric_opt = stats->getStateReportErrs();
            break;
        case OFPEER_UNRESOLVED_POLS:
            metric_opt = stats->getPolUnresolvedCount();
            break;
        default:
            LOG(WARNING) << "Unhandled ofpeer metric: " << metric;
        }
        if (metric_opt && pgauge)
            pgauge->Set(static_cast<double>(metric_opt.get()));
        if (!pgauge) {
            LOG(WARNING) << "Invalid ofpeer update peer: " << peer;
            break;
        }
    }
}

/* Function called from EP Manager to update EpCounter */
void AgentPrometheusManager::addNUpdateEpCounter (const string& uuid,
                                                  const string& ep_name,
                                                  bool annotate_ep_name,
                                                  const size_t& attr_hash,
                                                  const unordered_map<string, string>& attr_map,
                                                  const EpCounters& counters)
{
    RETURN_IF_DISABLED

    const lock_guard<mutex> lock(ep_counter_mutex);

    // Create the gauge counters if they arent present already
    for (EP_METRICS metric=EP_METRICS_MIN;
            metric < EP_METRICS_MAX;
                metric = EP_METRICS(metric+1)) {
        if (!createDynamicGaugeEp(metric,
                                  uuid,
                                  ep_name,
                                  annotate_ep_name,
                                  attr_hash,
                                  attr_map)) {
            break;
        }

        if (metric == (EP_METRICS_MAX-1)) {
            incStaticCounterEpCreate();
        }
    }

    // Update the metrics
    for (EP_METRICS metric=EP_METRICS_MIN;
            metric < EP_METRICS_MAX;
                metric = EP_METRICS(metric+1)) {
        hgauge_pair_t hgauge = getDynamicGaugeEp(metric, uuid);
        optional<uint64_t>   metric_opt;
        switch (metric) {
        case EP_RX_BYTES:
            metric_opt = counters.rxBytes;
            break;
        case EP_RX_PKTS:
            metric_opt = counters.rxPackets;
            break;
        case EP_RX_DROPS:
            metric_opt = counters.rxDrop;
            break;
        case EP_RX_UCAST:
            metric_opt = counters.rxUnicast;
            break;
        case EP_RX_MCAST:
            metric_opt = counters.rxMulticast;
            break;
        case EP_RX_BCAST:
            metric_opt = counters.rxBroadcast;
            break;
        case EP_TX_BYTES:
            metric_opt = counters.txBytes;
            break;
        case EP_TX_PKTS:
            metric_opt = counters.txPackets;
            break;
        case EP_TX_DROPS:
            metric_opt = counters.txDrop;
            break;
        case EP_TX_UCAST:
            metric_opt = counters.txUnicast;
            break;
        case EP_TX_MCAST:
            metric_opt = counters.txMulticast;
            break;
        case EP_TX_BCAST:
            metric_opt = counters.txBroadcast;
            break;
        default:
            LOG(WARNING) << "Unhandled metric: " << metric;
        }
        if (metric_opt && hgauge)
            hgauge.get().second->Set(static_cast<double>(metric_opt.get()));
        if (!hgauge) {
            LOG(WARNING) << "ep stats invalid update for uuid: " << uuid;
            break;
        }
    }
}

// Function called from ServiceManager to remove SvcTargetCounter
void AgentPrometheusManager::removeSvcTargetCounter (const string& uuid,
                                                     const string& nhip)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(svc_target_counter_mutex);

    const string& key = uuid+nhip;
    LOG(DEBUG) << "remove svc-target counter uuid: " << key;

    for (SVC_TARGET_METRICS metric=SVC_TARGET_METRICS_MIN;
            metric <= SVC_TARGET_METRICS_MAX;
                metric = SVC_TARGET_METRICS(metric+1)) {
        if (!removeDynamicGaugeSvcTarget(metric, key))
            break;
    }
}

// Function called from ServiceManager to remove SvcCounter
void AgentPrometheusManager::removeSvcCounter (const string& uuid)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(svc_counter_mutex);

    LOG(DEBUG) << "remove svc counter uuid: " << uuid;

    for (SVC_METRICS metric=SVC_METRICS_MIN;
            metric <= SVC_METRICS_MAX;
                metric = SVC_METRICS(metric+1)) {
        if (!removeDynamicGaugeSvc(metric, uuid))
            break;
    }
}

// Function called from IntFlowManager to remove PodSvcCounter
void AgentPrometheusManager::removePodSvcCounter (bool isEpToSvc,
                                                  const string& uuid)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(podsvc_counter_mutex);


    if (isEpToSvc) {
        for (PODSVC_METRICS metric=PODSVC_EP2SVC_MIN;
                metric <= PODSVC_EP2SVC_MAX;
                    metric = PODSVC_METRICS(metric+1)) {
            if (!removeDynamicGaugePodSvc(metric, uuid)) {
                break;
            } else {
                LOG(DEBUG) << "remove podsvc counter"
                           << " eptosvc uuid: " << uuid
                           << " metric: " << metric;
            }
        }
    } else {
        for (PODSVC_METRICS metric=PODSVC_SVC2EP_MIN;
                metric <= PODSVC_SVC2EP_MAX;
                    metric = PODSVC_METRICS(metric+1)) {
            if (!removeDynamicGaugePodSvc(metric, uuid)) {
                break;
            } else {
                LOG(DEBUG) << "remove podsvc counter"
                           << " svctoep uuid: " << uuid
                           << " metric: " << metric;
            }
        }
    }
}

// Function called from EP Manager to remove EpCounter
void AgentPrometheusManager::removeEpCounter (const string& uuid,
                                              const string& ep_name)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(ep_counter_mutex);
    LOG(DEBUG) << "remove ep counter " << ep_name;

    for (EP_METRICS metric=EP_METRICS_MIN;
            metric < EP_METRICS_MAX;
                metric = EP_METRICS(metric+1)) {
        if (!removeDynamicGaugeEp(metric, uuid))
            break;

        if (metric == (EP_METRICS_MAX-1)) {
            incStaticCounterEpRemove();
        }
    }
}

// Function to remove MoDBCounts
void AgentPrometheusManager::removeMoDBCounts ()
{
    RETURN_IF_DISABLED
    LOG(DEBUG) << "Deleting MoDBCounts";
    const lock_guard<mutex> lock(modb_count_mutex);
    for (MODB_COUNT_METRICS metric=MODB_COUNT_METRICS_MIN;
            metric <= MODB_COUNT_METRICS_MAX;
                metric = MODB_COUNT_METRICS(metric+1)) {
        if (!removeDynamicGaugeMoDBCount(metric))
            break;
    }
}

// Function called from PolicyStatsManager to remove OFPeerStats
void AgentPrometheusManager::removeOFPeerStats (const string& peer)
{
    RETURN_IF_DISABLED
    LOG(DEBUG) << "Deleting OFPeerStats for peer: " << peer;
    const lock_guard<mutex> lock(ofpeer_stats_mutex);
    for (OFPEER_METRICS metric=OFPEER_METRICS_MIN;
            metric <= OFPEER_METRICS_MAX;
                metric = OFPEER_METRICS(metric+1)) {
        if (!removeDynamicGaugeOFPeer(metric, peer))
            break;
    }
}

// Function called from ContractStatsManager to remove ContractClassifierCounter
void AgentPrometheusManager::removeContractClassifierCounter (const string& srcEpg,
                                                              const string& dstEpg,
                                                              const string& classifier)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(contract_stats_mutex);
    for (CONTRACT_METRICS metric=CONTRACT_METRICS_MIN;
            metric <= CONTRACT_METRICS_MAX;
                metric = CONTRACT_METRICS(metric+1)) {
        if (!removeDynamicGaugeContractClassifier(metric,
                                                  srcEpg,
                                                  dstEpg,
                                                  classifier))
            break;
    }
}

// Function called from SecGrpStatsManager to remove SGClassifierCounter
void AgentPrometheusManager::removeSGClassifierCounter (const string& classifier)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(sgclassifier_stats_mutex);
    LOG(DEBUG) << "remove SGClassifierCounter"
               << " classifier: " << classifier;

    for (SGCLASSIFIER_METRICS metric=SGCLASSIFIER_METRICS_MIN;
            metric <= SGCLASSIFIER_METRICS_MAX;
                metric = SGCLASSIFIER_METRICS(metric+1)) {
        if (!removeDynamicGaugeSGClassifier(metric, classifier))
            break;
    }
}

// Function called from IntFlowManager to remove RDDropCounter
void AgentPrometheusManager::removeRDDropCounter (const string& rdURI)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(rddrop_stats_mutex);
    LOG(DEBUG) << "remove RDDropCounter rdURI: " << rdURI;

    for (RDDROP_METRICS metric=RDDROP_METRICS_MIN;
            metric <= RDDROP_METRICS_MAX;
                metric = RDDROP_METRICS(metric+1)) {
        if (!removeDynamicGaugeRDDrop(metric, rdURI))
            break;
    }
}

const map<string,string> AgentPrometheusManager::createLabelMapFromTableDropKey (
                                                    const string& bridge_name,
                                                    const string& table_name)
{
   map<string,string>   label_map;
   string table_str = bridge_name + string("_") + table_name;
   label_map["table"] = std::move(table_str);
   return label_map;
}

mgauge_pair_t AgentPrometheusManager::getStaticGaugeTableDrop (TABLE_DROP_METRICS metric,
                                                  const string& bridge_name,
                                                  const string& table_name)
{
    const string table_drop_key = bridge_name + table_name;
    const auto &gauge_itr = table_drop_gauge_map[metric].find(table_drop_key);
    if(gauge_itr == table_drop_gauge_map[metric].end()){
        return boost::none;
    }
    return gauge_itr->second;
}

void AgentPrometheusManager::createStaticGaugeTableDrop (const string& bridge_name,
                                                         const string& table_name)
{
    RETURN_IF_DISABLED
    if ((bridge_name.empty() || table_name.empty()))
        return;

    auto const &label_map = createLabelMapFromTableDropKey(bridge_name,
                                                           table_name);
    {
        const lock_guard<mutex> lock(table_drop_counter_mutex);
        // Retrieve the Gauge if its already created
        auto const &mgauge = getStaticGaugeTableDrop(TABLE_DROP_BYTES,
                                                     bridge_name,
                                                     table_name);
        if(!mgauge) {
            for (TABLE_DROP_METRICS metric=TABLE_DROP_BYTES;
                        metric <= TABLE_DROP_MAX;
                        metric = TABLE_DROP_METRICS(metric+1)) {
                auto& gauge = gauge_table_drop_family_ptr[metric]->Add(label_map);
                if (gauge_check.is_dup(&gauge)) {
                    LOG(WARNING) << "duplicate table drop static gauge"
                               << " bridge_name: " << bridge_name
                               << " table name: " << table_name;
                    return;
                }
                LOG(DEBUG) << "created table drop static gauge"
                           << " bridge_name: " << bridge_name
                           << " table name: " << table_name;
                gauge_check.add(&gauge);
                string table_drop_key = bridge_name + table_name;
                table_drop_gauge_map[metric][table_drop_key] =
                        make_pair(label_map, &gauge);
            }
        }
    }
}

void AgentPrometheusManager::removeTableDropGauge (const string& bridge_name,
                                                   const string& table_name)
{
    RETURN_IF_DISABLED
    string table_drop_key = bridge_name + table_name;

    const lock_guard<mutex> lock(table_drop_counter_mutex);

    for(TABLE_DROP_METRICS metric = TABLE_DROP_BYTES;
            metric <= TABLE_DROP_MAX; metric = TABLE_DROP_METRICS(metric+1)) {
        auto const &mgauge = getStaticGaugeTableDrop(metric,
                                                     bridge_name,
                                                     table_name);
        // Note: mgauge can be boost::none if the create resulted in a
        // duplicate metric.
        if (mgauge) {
            gauge_check.remove(mgauge.get().second);
            gauge_table_drop_family_ptr[metric]->Remove(mgauge.get().second);
            table_drop_gauge_map[metric].erase(table_drop_key);
        }
    }
}

void AgentPrometheusManager::updateTableDropGauge (const string& bridge_name,
                                                   const string& table_name,
                                                   const uint64_t &bytes,
                                                   const uint64_t &packets)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(table_drop_counter_mutex);
    // Update the metrics
    const mgauge_pair_t &mgauge_bytes = getStaticGaugeTableDrop(
                                                    TABLE_DROP_BYTES,
                                                    bridge_name,
                                                    table_name);
    if (mgauge_bytes) {
        mgauge_bytes.get().second->Set(static_cast<double>(bytes));
    } else {
        LOG(WARNING) << "Invalid bytes update for table drop"
                   << " bridge_name: " << bridge_name
                   << " table_name: " << table_name;
        return;
    }
    const mgauge_pair_t &mgauge_packets = getStaticGaugeTableDrop(
                                                        TABLE_DROP_PKTS,
                                                        bridge_name,
                                                        table_name);
    if (mgauge_packets) {
        mgauge_packets.get().second->Set(static_cast<double>(packets));
    } else {
        LOG(WARNING) << "Invalid pkts update for table drop"
                   << " bridge_name: " << bridge_name
                   << " table_name: " << table_name;
        return;
    }
}

/* Function called from IntFlowManager to update NAT Stats Counter */
void AgentPrometheusManager::addNUpdateNatStats (const string& uuid,
                                                 const string& dir,
                                                 uint64_t bytes,
                                                 uint64_t pkts,
                                                 const string& mappedIp,
                                                 const string& FIp,
                                                 const string& sepg,
                                                 const string& depg)
{
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(nat_counter_mutex);

     if (dir=="EpToExt") {
       // Update the metrics for Ep to External network Flow Stats
        for (NAT_METRICS metric=NAT_METRICS_MIN; 
             metric <=  NAT_VM2EXT_MAX; metric = NAT_METRICS(metric+1)) { 
        // Create the gauge counters if they arent present already
            if (!createDynamicGaugeNatStats(metric, uuid, mappedIp, FIp, dir, sepg, depg)) {
                break;
            }
            hgauge_pair_t hgauge = getDynamicGaugeNatCounter(metric, uuid);
            optional<uint64_t>   metric_opt;
            switch (metric) {
                case NAT_VM2EXT_BYTES:
                    metric_opt = bytes;
                    break;
                case NAT_VM2EXT_PKTS:
                    metric_opt = pkts;
                    break;
                default:
                    LOG(WARNING) << "Unhandled NAT Stats metric: " << metric;
            }
            if (metric_opt && hgauge) {
                hgauge.get().second->Set(static_cast<double>(metric_opt.get()));
            }
            if (!hgauge) {
                LOG(WARNING) << "NAT Stats invalid update for uuid: " << uuid;
                break;
            }
        }
    } else if (dir == "ExtToEp") {
        // Update the metrics for External network to Ep Flow Stats
        for (NAT_METRICS metric=NAT_EXT2VM_MIN; 
             metric <= NAT_METRICS_MAX; metric = NAT_METRICS(metric+1)) {
        // Create the gauge counters if they arent present already
            if (!createDynamicGaugeNatStats(metric, uuid, mappedIp, FIp, dir, sepg, depg)) {
                break;
            }
            hgauge_pair_t hgauge = getDynamicGaugeNatCounter(metric, uuid);
            optional<uint64_t>   metric_opt;
            switch (metric) {
                case NAT_EXT2VM_BYTES:
                    metric_opt = bytes;
                    break;
                case NAT_EXT2VM_PKTS:
                    metric_opt = pkts;
                    break;
                default:
                    LOG(WARNING) << "Unhandled NAT Stats metric: " << metric;
            }
           if (metric_opt && hgauge) {
                hgauge.get().second->Set(static_cast<double>(metric_opt.get()));
           }
           if (!hgauge) {
                LOG(WARNING) << "NAT Stats invalid update for uuid: " << uuid;
                break;
            }
       }
    }
    return;
}

// Function called from IntFlowManager to remove NatStats Counter
void AgentPrometheusManager::removeNatCounter(const string& dir, const string& uuid) {
    RETURN_IF_DISABLED
    const lock_guard<mutex> lock(nat_counter_mutex);

    LOG(DEBUG) << "Remove Nat Stat counter uuid: " << uuid;
    if (dir == "EpToExt") {
       for (NAT_METRICS metric=NAT_METRICS_MIN; metric <=  
            NAT_VM2EXT_MAX; metric = NAT_METRICS(metric+1)) {
            if (!removeDynamicGaugeNatStats(metric, uuid)) {
                break;
            }
        }
    } else if (dir == "ExtToEp") {
             for (NAT_METRICS metric=NAT_EXT2VM_MIN; metric <= 
                  NAT_METRICS_MAX; metric = NAT_METRICS(metric+1)) {
                  if (!removeDynamicGaugeNatStats(metric, uuid)) {
                      break;
                  }
             }  
    }
}

// Create Nat Counter gauge given metric type and an uuid
bool AgentPrometheusManager::createDynamicGaugeNatStats (NAT_METRICS metric,
                                                         const string& uuid,
                                                         const string& mappedIp,
                                                         const string& FIp,
                                                         const string& dir,
                                                         const string& sepg,
                                                         const string& depg)
{
    auto const &label_map = createLabelMapNatCounter(uuid, mappedIp, FIp, sepg, depg);
    LabelHasher hasher;
    auto hash_new = hasher(label_map);

    // Retrieve the Gauge if its already created
    auto hgauge = getDynamicGaugeNatCounter(metric, uuid);
    if (hgauge) {
        /**
         * Detect attribute change by comparing hashes of cached label map
         * with new label map
         */
        if (hash_new == hgauge.get().first) { 
            return true;
        } else {
            LOG(DEBUG) << "addNupdate Nat Stat counter uuid " << uuid
                       << "existing Nat Stat metric, but deleting: hash modified"
                       << " metric: " << nat_family_names[metric]
                       << " hash: " << hgauge.get().first
                       << "gaugeptr: "<< hgauge.get().second;
                       removeDynamicGaugeNatStats(metric, uuid);

        }
    }

   if (!hash_new) {
       return false;
   }
   if (gauge_nat_counter_family_ptr[metric]) {
       auto& gauge = gauge_nat_counter_family_ptr[metric]->Add(label_map);

       if (gauge_check.is_dup(&gauge)) {
           LOG(WARNING) << "duplicate Nat Stat counter dyn gauge family"
                        << " metric: " << metric
                        << " uuid: " << uuid
                        << " label hash: " << hash_new;
           return true;
       }
       gauge_check.add(&gauge);
       nat_gauge_map[metric][uuid] = make_pair(hash_new, &gauge);
       return true;
   }
  return false;
}

// Create a label map that can be used for annotation, given the ep attributes
const map<string,string>  AgentPrometheusManager::createLabelMapNatCounter( 
                                                        const string& uuid,
                                                        const string& mappedIp,
                                                        const string& FIp,
                                                        const string& sepg,
                                                        const string& depg)
{
    map<string,string>  label_map;
    label_map["ep_uuid"] = uuid;
    label_map["ep_mapped_ip"] = mappedIp;
    label_map["ep_floating_ip"] = FIp;
    label_map["sepg"] = sepg;
    label_map["depg"] = depg;
    return label_map;
}

// Get Nat Counter gauge given the metric, uuid of EP
hgauge_pair_t AgentPrometheusManager::getDynamicGaugeNatCounter (NAT_METRICS metric,
                                                                const string& uuid)
{
    hgauge_pair_t hgauge = boost::none;
    auto itr = nat_gauge_map[metric].find(uuid);
    if (itr == nat_gauge_map[metric].end()) {
        LOG(INFO) << "Dyn Gauge Nat Stat Counter not found for " << uuid;
    } else {
        hgauge = itr->second;
    }

    return hgauge;
}

void AgentPrometheusManager::createStaticGaugeFamiliesNatCounter (void)
{
    // add a new gauge family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    // Note: There is a unique ptr allocated and referencing the below reference
    // during Register().

    for (NAT_METRICS metric=NAT_METRICS_MIN;
         metric <= NAT_METRICS_MAX;
         metric =  NAT_METRICS(metric+1)) {
         auto& gauge_nat_family = BuildGauge()
                                 .Name(nat_family_names[metric])
                                 .Help(nat_family_help[metric])
                                 .Labels({})
                                 .Register(*registry_ptr);
        gauge_nat_counter_family_ptr[metric] = &gauge_nat_family;
    }
}


// func to remove gauge for NAT Counter given metric type, uuid
bool AgentPrometheusManager::removeDynamicGaugeNatStats (NAT_METRICS metric,
                                                       const string& uuid){

     auto hgauge = getDynamicGaugeNatCounter(metric, uuid);
     if (hgauge) {
         nat_gauge_map[metric].erase(uuid);
         gauge_check.remove(hgauge.get().second);
         gauge_nat_counter_family_ptr[metric]->Remove(hgauge.get().second); 
         return true;
     }
     return false;
}

// func to remove gauge for NAT Counter given metric type
void AgentPrometheusManager::removeDynamicGaugeNatStats (NAT_METRICS metric){

    auto itr = nat_gauge_map[metric].begin();
    while (itr != nat_gauge_map[metric].end()) {
       LOG(DEBUG) << "Deleting Nat Stat Ep uuid: "<< itr->first
                  << " hash: " << itr->second.get().first
                  << " Gauge: " << itr->second.get().second;
       gauge_check.remove(itr->second.get().second);
       gauge_nat_counter_family_ptr[metric]->Remove(itr->second.get().second);
       itr++;
    }
}

// func to remove all gauges of every NAT Counter
void AgentPrometheusManager::removeDynamicGaugeNatStats () {

    for (NAT_METRICS metric=NAT_METRICS_MIN;
         metric <= NAT_METRICS_MAX;
         metric =  NAT_METRICS(metric+1)) {
         removeDynamicGaugeNatStats(metric);
    }
}

} /* namespace opflexagent */
