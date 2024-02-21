/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Definition of EndpointTenantMapper class
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_ENDPOINTTENANTMAPPER_H_
#define OPFLEXAGENT_ENDPOINTTENANTMAPPER_H_

#include <opflex/ofcore/OFFramework.h>

#include <boost/optional.hpp>

#include <string>
#include <set>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <functional>

using std::unordered_map;

namespace opflexagent {

/**
 * Class to keep track of EPG vnid to tenant ID translation.
*/
class EndpointTenantMapper : private boost::noncopyable {
public:
    EndpointTenantMapper();
    /**
     * Update or create a mapping between the given key
     * and value
    */
    void UpdateMapping(uint32_t key, std::string value);
    /**
     * Update or create a mapping between the given key
     * and tenant, which is extracted from the EPG URI.
    */
    void UpdateMappingFromURI(uint32_t key, std::string uri);
    /**
     * Get the mapping for the given key, if available.
     * If no mapping exists, returns an empty string.
    */
    std::string GetMapping(uint32_t key);
    /**
     * If the drop log should print the source/destination
     * tenant.
    */
    bool shouldPrintTenant;
private:
    unordered_map<uint32_t, std::string> endpointTenantMap;
};

} /* namespace opflexagent */

#endif // OPFLEXAGENT_ENDPOINTTENANTMAPPER_H_