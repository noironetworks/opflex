/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for filesystem ipam config source
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_IPAMCONFIGSOURCE_H
#define OPFLEXAGENT_IPAMCONFIGSOURCE_H

#include <opflexagent/FSWatcher.h>


#include <boost/filesystem.hpp>

#include <unordered_map>
#include <string>

namespace opflexagent {

class ExtraConfigManager;

/**
 * An ipam config source that gets extra configuration
 * information for routing domains from the filesystem.
 */
class FSIpamConfigSource : public FSWatcher::Watcher {
public:
    /**
     * Instantiate a new ipam config source.  It will set a
     * watch on the given path.
     */
    FSIpamConfigSource(ExtraConfigManager* manager,
                     FSWatcher& listener,
                     const std::string& IpamConfigDir);

    /**
     * Destroy the ipam config source and clean up all state
     */
    virtual ~FSIpamConfigSource() {}

    // See Watcher
    virtual void updated(const boost::filesystem::path& filePath);
    // See Watcher
    virtual void deleted(const boost::filesystem::path& filePath);

private:
    ExtraConfigManager* manager;
    typedef std::unordered_map<std::string, std::string> ipamconfig_map_t;

    /**
     * ipam configs that are known to the filesystem watcher
     */
    ipamconfig_map_t knownIpamConfigs;
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_IPAMCONFIGSOURCE_H */
