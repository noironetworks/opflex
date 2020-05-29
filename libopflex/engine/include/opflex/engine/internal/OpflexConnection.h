/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OpflexConnection.h
 * @brief Interface definition file for OpflexConnection
 */
/*
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <string>
#include <cstdint>
#include <sstream>
#include <list>
#include <utility>

#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <uv.h>

#include "opflex/yajr/yajr.hpp"
#include "opflex/yajr/rpc/message_factory.hpp"
#include "opflex/rpc/JsonRpcConnection.h"

#pragma once
#ifndef OPFLEX_ENGINE_OPFLEXCONNECTION_H
#define OPFLEX_ENGINE_OPFLEXCONNECTION_H

namespace opflex {
namespace engine {
namespace internal {

class OpflexPool;
class OpflexHandler;
class HandlerFactory;
class OpflexMessage;

/**
 * Maintain the connection state information for a connection to an
 * opflex peer
 */
class OpflexConnection : public opflex::jsonrpc::RpcConnection {
public:

    /**
     * Create a new opflex connection for the given hostname and port
     *
     * @param handlerFactory a factory that can allocate a handler for
     * the connection
     */
    OpflexConnection(HandlerFactory& handlerFactory);
    virtual ~OpflexConnection();

    /**
     * Initialize SSL global context
     */
    static void initSSL();

    /**
     * Connect to the remote host.  Must be called from the libuv
     * processing thread.
     */
    virtual void connect();

    /**
     * Disconnect this connection from the remote peer.  Must be
     * called from the libuv processing thread.  Will retry if the
     * connection type supports it.
     */
    virtual void disconnect();

    /**
     * Disconnect this connection from the remote peer and close the
     * connection.  Must be called from the libuv processing thread.
     * Will not retry.
     */
    virtual void close();

    /**
     * Get the unique name for this component in the policy domain
     *
     * @returns the string name
     */
    virtual const std::string& getName() = 0;

    /**
     * Get the globally unique name for this policy domain
     *
     * @returns the string domain name
     */
    virtual const std::string& getDomain() = 0;

    /**
     * Check whether the connection is ready to accept requests by
     * calling the opflex handler.  This means the handshake has
     * succeeded.
     *
     * @return true if the connection is ready
     */
    virtual bool isReady();

    /**
     * Get a human-readable view of the name of the remote peer
     *
     * @return the string name
     */
    virtual const std::string& getRemotePeer() = 0;

    /**
     * Get the handler associated with this connection
     *
     * @return the OpflexHandler for the connection.
     */
    virtual OpflexHandler* getHandler() { return handler; }

    /**
     * Get the peer handshake timeout (in ms)
     * @return timeout
     */
    uint32_t getHandshakeTimeout() const {
        return handshakeTimeout;
    }

    /**
     * Set the peer handshake timeout (in ms)
     * @param timeout timeout
     */
    void setHandshakeTimeout(uint32_t timeout) {
        handshakeTimeout = timeout;
    }

protected:
    /**
     * The handler for the connection
     */
    OpflexHandler* handler;

private:
    uint32_t handshakeTimeout;

    virtual void notifyReady();
    virtual void notifyFailed() {}

    friend class OpflexHandler;
};

/**
 * A factory that will manufacture new handlers for connections
 */
class HandlerFactory {
public:
    /**
     * Allocate a new OpflexHandler for the connection
     *
     * @param conn the connection associated with the handler
     * @return a newly-allocated handler that will be owned by the
     * connection
     */
    virtual OpflexHandler* newHandler(OpflexConnection* conn) = 0;
};

} /* namespace internal */
} /* namespace engine */
} /* namespace opflex */

#endif /* OPFLEX_ENGINE_OPFLEXCONNECTION_H */
