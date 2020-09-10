/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for NetFlowRenderer
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef OPFLEX_NETFLOWRENDERER_H
#define OPFLEX_NETFLOWRENDERER_H

#include <boost/noncopyable.hpp>
#include <opflexagent/NetFlowListener.h>
#include "JsonRpcRenderer.h"


namespace opflexagent {

/**
 * class to render netflow export config on a virtual switch
 */
class NetFlowRenderer : public NetFlowListener,
                        public JsonRpcRenderer,
                        private boost::noncopyable {

public:
    /**
     * constructor for NetFlowRenderer
     * @param agent_ reference to an agent instance
     */
    explicit NetFlowRenderer(Agent& agent_);

    /**
     * Start the renderer
     * @param swName Switch to connect to
     * @param conn OVSDB connection
     */
    virtual void start(const std::string& swName, OvsdbConnection* conn);

    /**
     * Module stop
     */
    virtual void stop();

    /**
     * Called when netflow objects are updated.
     * @param netflowURI URI of update object
     */
    virtual void exporterUpdated(const opflex::modb::URI& netflowURI);

    /**
     * called when netflow exporterconfig has been deleted
     * @param expSt exporter state
     */
    virtual void exporterDeleted(const shared_ptr<ExporterConfigState>& expSt);

    /**
     * Compare and update netflow exporter config
     *
     * @param netflowURI URI of the changed netflow exporter object
    */
    void handleNetFlowUpdate(const opflex::modb::URI& netflowURI);

    /**
     * Delete the netflow exporter
    */
    void deleteNetFlow();

    /**
     * Create netflow
     * @param targets netflow target
     * @param timeout timeout
     */
    void createNetFlow(const string& targets, int timeout);

    /**
     * Delete the ipfix exporter
    */
    void deleteIpfix();

    /**
     * Create ipfix
     * @param targets ipfix target
     * @param sample sample
     * @param activeTimeout active flow timeout
     */
    void createIpfix(const string& targets, int sample, int activeTimeout);

private:
    void updateConnectCb(const boost::system::error_code& ec, const opflex::modb::URI& uri);
    void delConnectCb(const boost::system::error_code& ec, shared_ptr<ExporterConfigState>& expSt);
};
}
#endif //OPFLEX_NETFLOWRENDERER_H
