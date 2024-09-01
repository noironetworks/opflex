/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Definition of EndpointTenantMapper class
 * Copyright (c) 2024 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_ENDPOINTTENANTMAPPER_H_
#define OPFLEXAGENT_ENDPOINTTENANTMAPPER_H_

#include <opflexagent/EndpointManager.h>
#include <opflex/ofcore/OFFramework.h>
#include <opflexagent/Agent.h>

#include <boost/optional.hpp>

#include <string>
#include <set>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <functional>

#include "SwitchManager.h"

using std::unordered_map;

namespace opflexagent {

/**
 * Class to keep track of EPG vnid -> Tenant ID
 * and Output Port -> Tenant ID mapping.
*/
class EndpointTenantMapper : public EndpointListener,
                             public ExtraConfigListener,
                             public LearningBridgeListener,
                             public PortStatusListener,
                             private boost::noncopyable {
public:
    EndpointTenantMapper(Agent* agent_, SwitchManager* accessSwitchManager_, boost::asio::io_service& ioService_);
    void start();
    void stop();
    /**
     * Update or create a mapping between the given vnid
     * and value.
    */
    void UpdateVNIDMapping(uint32_t key, std::string value);
    /**
     * Update or create a mapping between the given key
     * and tenant, which is extracted from the EPG URI.
    */
    void UpdateVNIDMappingFromURI(uint32_t key, std::string uri);
    /**
     * Update or creating a mapping between the given port
     * and tenant.
    */
    void UpdatePortMapping(uint32_t key, std::string value);
    /**
     * Update or create a mapping between the given key
     * and tenant, which is extracted from the EPG URI.
    */
    void UpdatePortMappingFromURI(uint32_t key, std::string uri);
    /**
    * Create a mapping between an access and uplink port.
    */
    void SetPortToPortMapping(uint32_t inPort, uint32_t outPort);
    /**
     * Get the mapping for the given key, if available.
     * If no mapping exists, returns an empty string.
    */
    std::string GetVNIDMapping(uint32_t key);
    /**
     * Get the mapping for the given key, if available.
     * If no mapping exists, returns an empty string.
    */
    std::string GetPortMapping(uint32_t key);
    /**
     * Get the port opposite of the one given.
    */
    uint32_t GetMatchingPort(uint32_t port);
    /**
     * If the drop log should include the source/destination
     * tenant.
    */
    bool shouldPrintTenant;

    /* Interface: EndpointListener */
    virtual void endpointUpdated(const std::string& uuid);
    virtual void secGroupSetUpdated(const EndpointListener::uri_set_t& secGrps){}

    /* Interface: LearningBridgeListener */
    virtual void lbIfaceUpdated(const std::string& uuid);

    /* Interface: ExtraConfigListener */
    virtual void rdConfigUpdated(const opflex::modb::URI& rdURI){}
    virtual void packetDropLogConfigUpdated(const opflex::modb::URI& dropLogCfgURI);
    virtual void packetDropFlowConfigUpdated(const opflex::modb::URI& dropFlowCfgURI){}
    virtual void packetDropPruneConfigUpdated(const std::string& pruneFilter){}
    virtual void outOfBandConfigUpdated(std::shared_ptr<OutOfBandConfigSpec> &oobSptr) {}

    /* Interface: PortStatusListener */
    virtual void portStatusUpdate(const std::string& portName,
                                  uint32_t portNo, bool fromDesc);
private:
    void handleEndpointUpdate(const string& uuid);
    void handlePortStatusUpdate(const std::string& portName, uint32_t portNo);

    Agent* agent;
    SwitchManager* accessSwitchManager;
    unordered_map<uint32_t, std::string> endpointTenantMap;
    unordered_map<uint32_t, std::string> portTenantMap;
    unordered_map<uint32_t, uint32_t> portToPortMap;
    TaskQueue taskQueue;
    std::atomic<bool> stopping;
};

} /* namespace opflexagent */

#endif // OPFLEXAGENT_ENDPOINTTENANTMAPPER_H_