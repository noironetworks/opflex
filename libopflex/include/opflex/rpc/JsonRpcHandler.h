/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file JsonRpcHandler.h
 * @brief Handler for JSON-RPC communication
 */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_TEST_JSONRPCHANDLER_H
#define OPFLEX_TEST_JSONRPCHANDLER_H

#include <boost/noncopyable.hpp>
#include <boost/thread/mutex.hpp>

#include "JsonRpcConnection.h"

namespace opflex {
namespace jsonrpc {

/**
 * Abstract base class for implementing the JSON-RPC protocol
 */
class JsonRpcHandler : private boost::noncopyable {
public:
    /**
     * Construct a new handler associated with the given JSON-RPC
     * connection
     *
     * @param conn_ the opflex connection
     */
    JsonRpcHandler(RpcConnection* conn_) : conn(conn_), state(DISCONNECTED) {}

    /**
     * Destroy the handler
     */
    virtual ~JsonRpcHandler() {}

    /**
     * Get the JSON-RPC connection associated with this handler
     *
     * @return the RpcConnection pointer
     */
    virtual RpcConnection* getConnection() { return conn; }

    /**
     * The state of the connection
     */
    enum ConnectionState {
        DISCONNECTED,
        CONNECTED,
        READY,
        FAILED
    };

    /**
     * Check whether the connection is ready to accept requests.  This
     * means that the server handshake is complete and the connection
     * is active.
     *
     * @return true if the connection is ready
     */
    bool isReady();

    // *************************
    // Connection state handlers
    // *************************

    /**
     * Called when the connection is connected.  Note that the same
     * connection may disconnect and reconnect multiple times.
     */
    virtual void connected() {}

    /**
     * Called when the connection is disconnected.  Note that the same
     * connection may disconnect and reconnect multiple times.
     */
    virtual void disconnected() {}

    /**
     * Called when the connection handshake is complete and the
     * connection is ready to handle requests.
     */
    virtual void ready() {}

protected:
    /**
     * Set the connection state for the connection
     *
     * @param state the new connection state
     */
    void setState(ConnectionState state);

    /**
     * The JsonRpcConnection associated with the handler
     */
    RpcConnection* conn;

    /**
     * The current connection state
     */
    ConnectionState state;

    /**
     * Mutex to ensure access to connection state is controlled
     */
    boost::mutex stateMutex;
};
}
}

#endif //OPFLEX_TEST_JSONRPCHANDLER_H
