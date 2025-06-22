/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for filesystem out of band config source
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_OUTOFBANDCONFIGSOURCE_H
#define OPFLEXAGENT_OUTOFBANDCONFIGSOURCE_H

#include <opflexagent/FSWatcher.h>
#include <boost/filesystem.hpp>

#include <opflexagent/OutOfBandConfig.h>

#include <string>

namespace opflexagent {

class ExtraConfigManager;

/**
 * An out of band config source that gets information for 
 * out of band config from the filesystem.
 */
class FSOutOfBandConfigSource : public FSWatcher::Watcher {
public:
    /**
     * Instantiate a new out of band config source.  It will set a
     * watch on the given path.
     */
    FSOutOfBandConfigSource(ExtraConfigManager* manager,
                     FSWatcher& listener,
                     const std::string& OutOfBandConfigDir,
                     const opflex::modb::URI& uri);

    /**
     * Destroy the out of band config source and clean up all state
     */
    virtual ~FSOutOfBandConfigSource() {}

    // See Watcher
    virtual void updated(const boost::filesystem::path& filePath);
    // See Watcher
    virtual void deleted(const boost::filesystem::path& filePath);

private:
    ExtraConfigManager* manager;
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_OUTOFBANDCONFIGSOURCE_H */
