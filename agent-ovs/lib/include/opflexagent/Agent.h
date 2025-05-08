/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for Agent
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_AGENT_H
#define OPFLEXAGENT_AGENT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <opflexagent/EndpointManager.h>
#include <opflexagent/ServiceManager.h>
#include <opflexagent/ExtraConfigManager.h>
#include <opflexagent/LearningBridgeManager.h>
#include <opflexagent/NotifServer.h>
#include <opflexagent/FSWatcher.h>
#include <opflexagent/SpanManager.h>
#include <opflexagent/SnatManager.h>
#include <opflexagent/FSNetpolSource.h>
#include <opflexagent/NetFlowManager.h>
#include <opflexagent/QosManager.h>
#include <opflexagent/SysStatsManager.h>

#include <opflexagent/PrometheusManager.h>

#include <boost/property_tree/ptree.hpp>
#include <boost/optional.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/noncopyable.hpp>
#include <opflex/ofcore/OFFramework.h>
#include <opflex/ofcore/OFConstants.h>
#include <modelgbp/metadata/metadata.hpp>

#include <atomic>
#include <set>
#include <utility>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <tuple>

#include <opflexagent/FaultManager.h>
#include <opflexagent/FaultSource.h>

namespace opflexagent {

class Renderer;
class RendererPlugin;
class EndpointSource;
class FaultSource;
class ServiceSource;
class FSRDConfigSource;
class LearningBridgeSource;
class SnatSource;
class FSPacketDropLogConfigSource;
class FSFaultSource;
typedef std::tuple<std::string, bool, std::string> LogParams;
enum StatMode { REAL, OFF };
/**
 * feature list enum. Always keep MAX at the end.
 */
enum FeatureList { ERSPAN=0, MAX };

/**
 * Master object for the OVS agent.  This class holds the state for
 * the agent and handles initialization, configuration and cleanup.
 */
class Agent : private boost::noncopyable {
typedef opflex::ofcore::OFConstants::OpflexElementMode opflex_elem_t;
public:
    /**
     * Instantiate a new agent using the specified framework
     * instance.
     *
     * @param framework the framework instance to use
     * @param _logParams logging parameters passed on commandline
     */
    Agent(opflex::ofcore::OFFramework& framework,
          const LogParams& _logParams);

    /**
     * Destroy the agent and clean up all state
     */
    ~Agent();

    /**
     * Configure the agent with the property tree specified
     *
     * @param properties the configuration properties to set for the
     * agent
     */
    void setProperties(const boost::property_tree::ptree& properties);

    /**
     * Apply the properties set with setProperties to the agent
     * configuration
     *
     * @throws std::runtime_error if the configuration is invalid
     */
    void applyProperties();

    /**
     * Start the agent
     */
    void start();

    /**
     * Stop the agent
     */
    void stop();

    /**
     * Get the opflex framework object for this agent
     */
    opflex::ofcore::OFFramework& getFramework() { return framework; }

    /**
     * Get the policy manager object for this agent
     */
    PolicyManager& getPolicyManager() { return policyManager; }

    /**
     * Get the span manager object for this agent
     */
    SpanManager& getSpanManager() { return spanManager; }

    /**
     * Get the prometheus manager object for this agent
     */
    AgentPrometheusManager& getPrometheusManager() { return prometheusManager; }

    /**
     *  Get the netflow manager object for this agent
     */
     NetFlowManager& getNetFlowManager() { return netflowManager; }

     /**
      * Get the qos manager object for this agent
      */
     QosManager& getQosManager() { return qosManager; }

    /**
     * Get the endpoint manager object for this agent
     */
    EndpointManager& getEndpointManager() { return endpointManager; }

    /**
     * Get the service manager object for this agent
     */
    ServiceManager& getServiceManager() { return serviceManager; }

    /**
     * Get the extra config manager object for this agent
     */
    ExtraConfigManager& getExtraConfigManager() { return extraConfigManager; }

    /**
     * Get the snat manager object for this agent
     */
    SnatManager& getSnatManager() { return snatManager; }

    /**
     * Get renderer forwarding mode for this agent
     */
    uint8_t getRendererForwardingMode() { return rendererFwdMode; }
    /**
     * Set renderer forwarding mode for this agent
     */
     bool setRendererForwardingMode(opflex_elem_t elemMode)
     {   if(started)
            return false;
         presetFwdMode = elemMode;
         if(elemMode != opflex_elem_t::INVALID_MODE) {
            rendererFwdMode = presetFwdMode;
         }
         return true;
     }
    /**
     * Get Proxy addresses for transport mode
     */
    void getV4Proxy(boost::asio::ip::address_v4 &v4ProxyAddress ) {
        framework.getV4Proxy(v4ProxyAddress);
    }

    /**
     * Get V6 Proxy addresses for transport mode
     */
    void getV6Proxy(boost::asio::ip::address_v4 &v6ProxyAddress ) {
        framework.getV6Proxy(v6ProxyAddress);
    }

    /**
     * Get MAC Proxy addresses for transport mode
     */
    void getMacProxy(boost::asio::ip::address_v4 &macProxyAddress ) {
        framework.getMacProxy(macProxyAddress);
    }

    /**
     * Get the learning bridge manager object for this agent
     */
    LearningBridgeManager& getLearningBridgeManager() {
        return learningBridgeManager;
    }

    /**
     * Get the notification server object for this agent
     */
    NotifServer& getNotifServer() { return notifServer; }

    /**
     * Get the ASIO service for the agent for scheduling asynchronous
     * tasks in the io service thread.  You must schedule your async
     * tasks in your start() method and close them (possibly
     * asynchronously) in your stop() method.
     *
     * @return the asio io service
     */
    boost::asio::io_service& getAgentIOService() { return agent_io; }

    /**
     * Get a unique identifer for the agent incarnation
     */
    const std::string& getUuid() { return uuid; }

    /**
     * Set valid uplink mac discovered from TunnelEpManager.
     * @param  mac - Mac address in canonical form xx:xx (17 chars)
     */
    void setUplinkMac(const std::string &mac);

    /**
     * Get the fault manager object for this agent
     */
    FaultManager& getFaultManager() { return faultManager; }

    /**
     * Get packet event notification socket file name
     */
    const std::string& getPacketEventNotifSock() { return packetEventNotifSockPath; }

    /**
     * get feature
     * @return true if feature is enabled, false otherwise.
     */
    bool isFeatureEnabled(FeatureList feature) { return featureFlag[feature];}

    /**
     * get behavior for adding l34flows without subnet
     * @return true if l34flows should be added without subnet,
     * false otherwise, defaults to true
     */
    bool addL34FlowsWithoutSubnet() { return behaviorL34FlowsWithoutSubnet; }

    /**
     * set behavior for adding l34flows without subnet
     * @param value the new value for behaviorL34FlowsWithoutSubnet
     */
    void setAddL34FlowsWithoutSubnet(bool value) {
        behaviorL34FlowsWithoutSubnet = value;
    }

    /**
     * clear feature flags. set them to true.
     */
    void clearFeatureFlags();

    /**
     * get allowed ep attributes specified in agent config file
     * @return true if feature is enabled, false otherwise.
     */
    std::unordered_set<std::string> getPrometheusEpAttributes (void)
    {
        return prometheusEpAttributes;
    }

    /**
     * Get packet event notification socket file name
     */
    const LogParams& getLogParams() { return logParams; }

    /**
     * Get Multicast cache timeout value
     */
    uint32_t getMulticastCacheTimeout() { return multicast_cache_timeout; }

    /**
     * Get Switch Sync delay value
     */
    uint32_t getSwitchSyncDelay() { return switch_sync_delay; }

    /**
     * Set Switch Sync delay value, used from test code
     * @param delay in seconds
     */
    void setSwitchSyncDelay(uint32_t delay) { switch_sync_delay = delay; }

    /**
     * Get if switch sync set to dynamic
     */
    uint32_t getSwitchSyncDynamic() { return switch_sync_dynamic; }

    /**
     * save the last PlatformConfig delete time
     */
    void updateResetTime() {
        std::unique_lock<std::mutex> guard(reset_time_mutex);

        reset_time = std::chrono::steady_clock::now();
    }

    /**
     * Check if enough time has passed since last PlatformConfig delete / reset
     */
    bool shouldReset() {
        std::unique_lock<std::mutex> guard(reset_time_mutex);

        auto diff = std::chrono::steady_clock::now() - reset_time;
        return diff > std::chrono::seconds(reset_wait_delay);
    }

    /**
     * Common function b/w Agent and Server to add all supported universes
     * @param root pointer to DmtreeRoot under which the universes will be created
     */
    static void createUniverse(std::shared_ptr<modelgbp::dmtree::Root> root);

private:
    boost::asio::io_service agent_io;
    std::unique_ptr<boost::asio::io_service::work> io_work;

    opflex::ofcore::OFFramework& framework;
    AgentPrometheusManager prometheusManager;
    PolicyManager policyManager;
    EndpointManager endpointManager;
    ServiceManager serviceManager;
    ExtraConfigManager extraConfigManager;
    LearningBridgeManager learningBridgeManager;
    SnatManager snatManager;
    NotifServer notifServer;
    FSWatcher fsWatcher;
    opflex_elem_t rendererFwdMode; 
    FaultManager faultManager;
    SysStatsManager sysStatsManager;

    boost::optional<std::string> opflexName;
    boost::optional<std::string> opflexDomain;

    boost::optional<bool> enableInspector;
    boost::optional<std::string> inspectorSock;
    boost::optional<bool> enableNotif;
    boost::optional<std::string> notifSock;
    boost::optional<std::string> notifOwner;
    boost::optional<std::string> notifGroup;
    boost::optional<std::string> notifPerms;
    // stats simulation
    StatMode statMode = StatMode::REAL;

    // timers
    // prr timer - policy resolve request timer
    boost::uint_t<64>::fast prr_timer = 7200;  /* seconds */
    // initial policy retry delay
    boost::uint_t<64>::fast policy_retry_delay_timer = 10;  /* seconds */
    /* handshake timeout */
    uint32_t peerHandshakeTimeout = 45000;
    /* keepalive timeout */
    uint32_t keepaliveTimeout = 120000;
    /* How long to wait before timing out old multicast cache */
    uint32_t multicast_cache_timeout = 300; /* seconds */
    /* How long to wait from platform config to switch Sync */
    uint32_t switch_sync_delay = 5; /* seconds */
    uint32_t switch_sync_dynamic = 0; /* dynamic retry default 0 no retry */
    uint32_t reset_wait_delay  = 5; /* seconds */
    /* Timestamp of last PlatformConfig delete event */
    std::chrono::steady_clock::time_point reset_time;
    /* mutex to update reset_time */
    std::mutex reset_time_mutex;
    // startup policy duration from new connection in seconds
    uint64_t startupPolicyDuration = 0; /* seconds */
    bool localResolveAftConn = false; /* local resolve after conn estb */

    std::set<std::string> endpointSourceFSPaths;
    std::set<std::string> disabledFeaturesSet;
    std::set<std::string> endpointSourceModelLocalNames;
    std::vector<std::unique_ptr<EndpointSource>> endpointSources;
    std::vector<std::unique_ptr<FSRDConfigSource>> rdConfigSources;
    std::vector<std::unique_ptr<LearningBridgeSource>> learningBridgeSources;
    std::string dropLogCfgSourcePath;
    std::set<std::string> hostAgentFaultPaths;
    std::string packetEventNotifSockPath;
    std::unique_ptr<FSPacketDropLogConfigSource> dropLogCfgSource;

    std::set<std::string> serviceSourcePaths;
    std::vector<std::unique_ptr<ServiceSource>> serviceSources;

    std::set<std::string> snatSourcePaths;
    std::vector<std::unique_ptr<SnatSource>> snatSources;

    std::set<std::string> netpolSourcePaths;
    std::vector<std::unique_ptr<FSNetpolSource>> netpolSources;

    std::vector<std::unique_ptr<FaultSource>> faultSources;

    std::unordered_set<std::string> rendPluginLibs;
    std::unordered_set<void*> rendPluginHandles;
    typedef std::unordered_map<std::string, const RendererPlugin*> rend_map_t;
    rend_map_t rendPlugins;
    std::unordered_map<std::string, std::unique_ptr<Renderer>> renderers;

    typedef std::pair<std::string, int> host_t;
    std::set<host_t> opflexPeers;
    boost::optional<std::string> sslMode;
    boost::optional<std::string> sslCaStore;
    boost::optional<std::string> sslClientCert;
    boost::optional<std::string> sslClientCertPass;

    /**
     * Thread for asynchronous tasks
     */
    std::unique_ptr<std::thread> io_service_thread;

    std::atomic<bool> started;
    opflex_elem_t presetFwdMode;

    void loadPlugin(const std::string& name);

    std::string uuid;

    static StatMode getStatModeFromString(const std::string& mode);

    SpanManager spanManager;
    NetFlowManager netflowManager;
    QosManager qosManager;

    // System Stats
    bool sysStatsEnabled;
    long sysStatsInterval;

    // feature flag array
    bool featureFlag[FeatureList::MAX];

    // Prometheus related parameters
    bool prometheusEnabled;
    bool prometheusExposeLocalHostOnly;
    bool prometheusExposeEpSvcNan;
    std::unordered_set<std::string> prometheusEpAttributes;
    bool behaviorL34FlowsWithoutSubnet;
    LogParams logParams;
    /* Persistent policy from disk */
    bool startupPolicyEnabled;
    /* Local Network Policy enable */
    bool localNetpolEnabled;
    /* Force an EP undeclare on update resulting in redeclare */
    bool force_ep_undeclares;
    boost::optional<std::string> opflexPolicyFile;
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_AGENT_H */
