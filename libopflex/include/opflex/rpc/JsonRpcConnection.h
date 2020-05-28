/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file JsonRpcConnection.h
 * @brief Interface definition for various JSON/RPC messages used by the
 * engine
 */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef RPC_JSONRPCCONNECTION_H
#define RPC_JSONRPCCONNECTION_H

#include <boost/noncopyable.hpp>

#include <rapidjson/document.h>

#include "JsonRpcMessage.h"

namespace opflex {
namespace jsonrpc {

/**
 * Payload wrapper
 */
class PayloadWrapper {
public:
    /**
     * Construct a payload wrapper
     * @param message_ RPC message
     */
    PayloadWrapper(JsonRpcMessage* message_)
        : message(message_) { }

    /**
     * Operator to serialize a generic a payload
     * @param handler handler
     */
    virtual bool operator()(yajr::rpc::SendHandler& handler) const {
        message->serializePayload(handler);
        return true;
    }

private:
    JsonRpcMessage* message;
};

/**
 * class for managing RPC connection to a server.
 */
class RpcConnection : private boost::noncopyable {
    public:
    /**
     * Create a new JSON-RPC connection
     */
    RpcConnection() {}

    /**
     * call back for transaction response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleTransaction(uint64_t reqId, const rapidjson::Document& payload) {};

    /**
     * call back for transaction error response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleTransactionError(uint64_t reqId, const rapidjson::Document& payload) {};

    /**
     * call back for monitor response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleMonitor(uint64_t reqId, const rapidjson::Document& payload) {};

    /**
     * call back for monitor error response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleMonitorError(uint64_t reqId, const rapidjson::Document& payload) {};

    /**
     * destructor
     */
    virtual ~RpcConnection() {}

    /**
     * create a tcp connection to peer
     */
    virtual void connect() = 0;

    /**
     * Disconnect this connection from the remote peer.  Must be
     * called from the libuv processing thread.  Will retry if the
     * connection type supports it.
     */
    virtual void disconnect() = 0;

private:

    virtual void notifyReady() {};
    virtual void notifyFailed() {}

    friend class JsonRpcHandler;
};

}
}

#endif