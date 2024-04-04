/*
 * Implementation of EndpointTenantMapper class
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/EndpointTenantMapper.h>


namespace opflexagent {

EndpointTenantMapper::EndpointTenantMapper() {
    endpointTenantMap = {};
}

void EndpointTenantMapper::UpdateMapping(uint32_t key, std::string value){
    endpointTenantMap[key] = value;
}

void EndpointTenantMapper::UpdateMappingFromURI(uint32_t key, std::string uri){
    size_t tLow = uri.find("PolicySpace") + 12;
    size_t gEpGStart = uri.rfind("GbpEpGroup");
    std::string tenant = uri.substr(tLow,gEpGStart-tLow-1);
    UpdateMapping(key, std::move(tenant));
}

std::string EndpointTenantMapper::GetMapping(uint32_t key){
    if(endpointTenantMap.find(key) == endpointTenantMap.end())
        return "";
    return endpointTenantMap[key];
}
}