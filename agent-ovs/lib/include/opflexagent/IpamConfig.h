/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for ipam config
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_IPAMCONFIG_H
#define OPFLEXAGENT_IPAMCONFIG_H

#include <boost/optional.hpp>

#include <string>
#include <utility>
#include <vector>

namespace opflexagent {

/**
 * A class for a routing domain config
 */
class IpamConfig {
public:
    /**
     * Default constructor
     */
    IpamConfig() {}

    /**
     * Construct a new IpamConfig with the given uuid.
     *
     * @param uuid_ the uuid of the Ipam being configured
     */
    explicit IpamConfig(const std::string& uuid_)
        : uuid(uuid_) {}

    /**
     *
     * Get uuid of given ipam
     *
     * @return the uuid
     */
    const std::string& getUUID() const {
        return uuid;
    }

    /**
     * Set the UUID for the ipam
     *
     * @param uuid the unique ID for the ipam
     */
    void setUUID(const std::string& uuid) {
        this->uuid = uuid;
    }

    /**
     * Add an ipam entry (network, vtep) to map
     *
     * @param network the pod network/mask
     * @param vtep the vtep to reach the pod network
     */
    void addToMap(const std::string& network, const std::string& vtep) {
        map.push_back(std::make_pair(network, vtep));
    }

    /**
     * ipamMap maps a network to the corresponding vtep
     */
    typedef std::vector<std::pair<std::string, std::string>> ipamMap;

    /**
     * Get all ipam entries
     */
    const ipamMap& getMap() const {
        return map;
    }

private:
    std::string uuid;
    ipamMap map;
};

/**
 * Print an to an ostream
 */
std::ostream & operator<<(std::ostream &os, const IpamConfig& ipam);

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_IPAMCONFIG_H */
