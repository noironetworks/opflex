/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for extra config listener
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_EXTRACONFIGLISTENER_H
#define OPFLEXAGENT_EXTRACONFIGLISTENER_H

#include <opflex/modb/URI.h>
#include <opflexagent/OutOfBandConfig.h>

namespace opflexagent {

/**
 * An abstract interface for classes interested in updates related to
 * the extraConfigs
 */
class ExtraConfigListener {
public:
    /**
     * Instantiate a new extraConfig listener
     */
    ExtraConfigListener() {};

    /**
     * Destroy the extraConfig listener and clean up all state
     */
    virtual ~ExtraConfigListener() {};

    /**
     * Called when a routing domain config object is updated
     *
     * @param domainURI the URI for the associated routing domain
     */
    virtual void rdConfigUpdated(const opflex::modb::URI& domainURI) = 0;

    /**
     * Called when a packet drop log config object is updated
     *
     * @param dropLogCfgURI the URI for the associated packet drop log
     */
    virtual void packetDropLogConfigUpdated(const opflex::modb::URI& dropLogCfgURI) = 0;

    /**
     * Called when a packet drop flow config object is updated
     *
     * @param dropFlowCfgURI Flow spec and path for the drop flow
     */
    virtual void packetDropFlowConfigUpdated(const opflex::modb::URI& dropFlowCfgURI) = 0;
    
    /**
     * Called when a packet drop log prune config filter is updated
     *
     * @param filterName Prune filter name 
     */
    virtual void packetDropPruneConfigUpdated(const std::string &filterName) = 0;

    /**
     * Called when an out of band config is updated
     *
     * @param oobSptr out of band config shared pointer
     */
    virtual void outOfBandConfigUpdated(std::shared_ptr<OutOfBandConfigSpec> &oobSptr) = 0;

};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_EXTRACONFIGLISTENER_H */
