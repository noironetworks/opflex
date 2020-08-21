/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for SpanRenderer
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef OPFLEX_SPANRENDERER_H
#define OPFLEX_SPANRENDERER_H

#include <boost/noncopyable.hpp>
#include <opflexagent/SpanListener.h>
#include "JsonRpcRenderer.h"

namespace opflexagent {

/**
 * class to render span config on a virtual switch
 */
class SpanRenderer : public SpanListener,
                     public JsonRpcRenderer,
                     private boost::noncopyable {

public:
    /**
     * constructor for SpanRenderer
     * @param agent_ reference to an agent instance
     */
    explicit SpanRenderer(Agent& agent_);

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
     * handle updates to span artifacts
     * @param[in] spanURI URI pointing to a span session.
     */
    virtual void spanUpdated(const opflex::modb::URI& spanURI);

    /**
     * delete span pointed to by the pointer
     * @param[in] sesSt shared pointer to a Session object
     */
    virtual void spanDeleted(const shared_ptr<SessionState>& sesSt);

    /**
     * create mirror
     * @param[in] sess session details
     * @param[in] srcPorts source ports
     * @param[in] dstPorts dest ports
     */
    void createMirrorAndOutputPort(const shared_ptr<SessionState>& sess, const set<string>& srcPorts, const set<string>& dstPorts);

    /**
     * deletes mirror session
     * @param[in] sessionName name of session
     * @return true if success, false otherwise.
     */
    void deleteMirror(const string& sessionName);

    /**
     * Update mirror config using passed session state
     * @param session session
     */
    void updateMirrorConfig(const shared_ptr<SessionState>& session);

private:
    /**
     * Compare and update span config
     *
     * @param spanURI URI of the changed span object
     */
    void handleSpanUpdate(const opflex::modb::URI& spanURI);
    virtual void sessionDeleted(const string &sessionName);
    void updateOutputPort(const shared_ptr<SessionState>& session);
    bool isOutputPortUpdateRequired(const shared_ptr<SessionState>& session);
    void updateConnectCb(const boost::system::error_code& ec, const opflex::modb::URI& uri);
    void delConnectPtrCb(const boost::system::error_code& ec, const shared_ptr<SessionState>& pSt);

    static void buildPortSets(const shared_ptr<SessionState>& seSt, set<string>& srcPorts, set<string>& dstPorts);
};
}
#endif //OPFLEX_SPANRENDERER_H
