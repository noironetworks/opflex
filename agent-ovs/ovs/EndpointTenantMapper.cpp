/*
 * Implemencletion of EndpointTenantMapper class
 * Copyright (c) 2024 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "EndpointTenantMapper.h"
#include "SwitchManager.h"


namespace opflexagent {

using std::string;
typedef EndpointListener::uri_set_t uri_set_t;

EndpointTenantMapper::EndpointTenantMapper(Agent* agent_, SwitchManager* accessSwitchManager_, boost::asio::io_service& ioService_)
    : agent(agent_), accessSwitchManager(accessSwitchManager_), taskQueue(ioService_) {
    endpointTenantMap = {};
    portTenantMap = {};
    portToPortMap = {};
}

void EndpointTenantMapper::start() {
    LOG(DEBUG) << "Starting EndpointTenantMapper";
    accessSwitchManager->getPortMapper().registerPortStatusListener(this);
    agent->getEndpointManager().registerListener(this);
    agent->getExtraConfigManager().registerListener(this);
    agent->getLearningBridgeManager().registerListener(this);
}

void EndpointTenantMapper::stop() {
    LOG(DEBUG) << "Stopping EndpointTenantMapper";
    stopping = true;
    accessSwitchManager->getPortMapper().unregisterPortStatusListener(this);
    agent->getEndpointManager().unregisterListener(this);
    agent->getExtraConfigManager().unregisterListener(this);
    agent->getLearningBridgeManager().unregisterListener(this);
}

void EndpointTenantMapper::UpdateVNIDMapping(uint32_t key, std::string value){
    endpointTenantMap[key] = value;
}

void EndpointTenantMapper::UpdateVNIDMappingFromURI(uint32_t key, std::string uri){
    size_t tLow = uri.find("PolicySpace") + 12;
    size_t gEpGStart = uri.rfind("GbpEpGroup");
    std::string tenant = uri.substr(tLow,gEpGStart-tLow-1);
    UpdateVNIDMapping(key, std::move(tenant));
}

void EndpointTenantMapper::UpdatePortMapping(uint32_t key, std::string value){
    portTenantMap[key] = value;
}

void EndpointTenantMapper::UpdatePortMappingFromURI(uint32_t key, std::string uri){
    size_t tLow = uri.find("PolicySpace") + 12;
    size_t gEpGStart = uri.rfind("GbpEpGroup");
    std::string tenant = uri.substr(tLow,gEpGStart-tLow-1);
    UpdatePortMapping(key, std::move(tenant));
}

void EndpointTenantMapper::SetPortToPortMapping(uint32_t inPort, uint32_t outPort){
    portToPortMap[inPort] = outPort;
    portToPortMap[outPort] = inPort;
}

std::string EndpointTenantMapper::GetVNIDMapping(uint32_t key){
    if(endpointTenantMap.find(key) == endpointTenantMap.end())
        return "";
    return endpointTenantMap[key];
}

std::string EndpointTenantMapper::GetPortMapping(uint32_t key){
    if(portTenantMap.find(key) == portTenantMap.end())
        return "";
    return portTenantMap[key];
}

uint32_t EndpointTenantMapper::GetMatchingPort(uint32_t port){
    if(portToPortMap.find(port) == portToPortMap.end())
        return OFPP_NONE;
    return portToPortMap[port];
}

void EndpointTenantMapper::handleEndpointUpdate(const string& uuid) {
    EndpointManager& epMgr = agent->getEndpointManager();
    shared_ptr<const Endpoint> epWrapper = epMgr.getEndpoint(uuid);

    if (!epWrapper) {   // EP removed
        return;
    }
    optional<URI> epgURI = epMgr.getComputedEPG(uuid);

    // IntFlowManager mapping
    if(epMgr.localExternalDomainExists(epgURI.get())) {
        optional<uint32_t> epgVnid = ((1<< 30) + epMgr.getExtEncapId(epgURI.get()));
        if (epgVnid) UpdateVNIDMappingFromURI(epgVnid.get(), epgURI.get().toString());
    }else{
        PolicyManager& polMgr = agent->getPolicyManager();
        optional<uint32_t> epgVnid = polMgr.getVnidForGroup(epgURI.get());
        if(epgVnid) UpdateVNIDMappingFromURI(epgVnid.get(), epgURI.get().toString());
    }

    // AccessFlowManager mapping
    uint32_t accessPort = OFPP_NONE;
    uint32_t uplinkPort = OFPP_NONE;
    const optional<string>& accessIface = epWrapper->getAccessInterface();
    const optional<string>& uplinkIface = epWrapper->getAccessUplinkInterface();
    if (accessIface){
        accessPort = accessSwitchManager->getPortMapper().FindPort(accessIface.get());
        if(epgURI) UpdatePortMappingFromURI(accessPort, epgURI.get().toString());
    }
    if (uplinkIface) {
        uplinkPort = accessSwitchManager->getPortMapper().FindPort(uplinkIface.get());
    }

    if(accessIface && uplinkIface){
        SetPortToPortMapping(accessPort, uplinkPort);
    }
}

void EndpointTenantMapper::endpointUpdated(const string& uuid) {
    if (stopping) return;
    taskQueue.dispatch(uuid, [=](){ handleEndpointUpdate(uuid); });
}

void EndpointTenantMapper::lbIfaceUpdated(const std::string& uuid) {
    if(stopping) return;
    LearningBridgeManager& lbMgr = agent->getLearningBridgeManager();
    shared_ptr<const LearningBridgeIface> iface = lbMgr.getLBIface(uuid);

    if (!iface)
        return;
    
    if (iface->getInterfaceName()) {
        EndpointManager& epMgr = agent->getEndpointManager();
        std::unordered_set<std::string> epUuids;
        epMgr.getEndpointsByIface(iface->getInterfaceName().get(), epUuids);

        for (auto& epUuid : epUuids) {
            endpointUpdated(epUuid);
        }
    }
}

void EndpointTenantMapper::packetDropLogConfigUpdated(const URI& dropLogCfgURI) {
    if(stopping) return;
    using modelgbp::observer::DropLogConfig;
    optional<shared_ptr<DropLogConfig>> dropLogCfg =
            DropLogConfig::resolve(agent->getFramework(), dropLogCfgURI);
    if(!dropLogCfg) {
        LOG(INFO) << "Defaulting to droplog tenant printing disabled";
        return;
    }
    shouldPrintTenant = dropLogCfg.get()->getDropLogPrintTenant(0) != 0;
    LOG(INFO) << "Droplog tenant printing set to " + std::to_string(dropLogCfg.get()->getDropLogPrintTenant(0));
}

void EndpointTenantMapper::portStatusUpdate(const string& portName,
                                         uint32_t portNo, bool) {
    if (stopping) return;
    agent->getAgentIOService().dispatch([=]() { handlePortStatusUpdate(portName, portNo); });
}

void EndpointTenantMapper::handlePortStatusUpdate(const string& portName,
                                               uint32_t) {
    unordered_set<std::string> eps;
    agent->getEndpointManager().getEndpointsByAccessIface(portName, eps);
    agent->getEndpointManager().getEndpointsByAccessUplink(portName, eps);
    for (const std::string& ep : eps)
        endpointUpdated(ep);
}
}