/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for filesystem netpol source
 *
 * Copyright (c) 2024 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_FSNETPOLSOURCE_H
#define OPFLEXAGENT_FSNETPOLSOURCE_H

#include <opflexagent/FSWatcher.h>
#include <opflex/ofcore/OFFramework.h>
#include <boost/filesystem.hpp>

#include <string>
#include <unordered_map>
#include <opflex/modb/mo-internal/StoreClient.h>

namespace opflexagent {

/**
 * An netpol source that gets information about netpols from JSON
 * files on the filesystem.  If supported, it will set an inotify
 * watch on the directory
 */
class FSNetpolSource
    : public FSWatcher::Watcher {
public:
    /**
     * Instantiate a new netpol source
     */
    FSNetpolSource(opflex::ofcore::OFFramework& framework,
                   FSWatcher& listener,
                   const std::string& netpolDir);

    /**
     * Destroy the netpol source and clean up all state
     */
    virtual ~FSNetpolSource() {}

    // See Watcher
    virtual void updated(const boost::filesystem::path& filePath);
    // See Watcher
    virtual void deleted(const boost::filesystem::path& filePath);

private:
    opflex::ofcore::OFFramework& framework;

    // Map filePath to <netpol-uuid>
    typedef std::unordered_map<std::string, opflex::modb::mointernal::StoreClient::notif_t> netpol_map_t;

    /**
     * Netpols that are known to the filesystem watcher
     */
    netpol_map_t knownNetpols;
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_FSNETPOLSOURCE_H */
