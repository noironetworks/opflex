/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OvsdbConnection.h
 * @brief Interface definition for various JSON/RPC messages used by the
 * engine
 */
/*
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OVS_OVSDBCONNECTION_H
#define OVS_OVSDBCONNECTION_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <chrono>

#include <opflex/rpc/JsonRpcConnection.h>
#include <opflex/rpc/JsonRpcMessage.h>

#include "OvsdbState.h"
#include "OvsdbTransactMessage.h"

#include <rapidjson/document.h>
#include <opflex/util/ThreadManager.h>

namespace opflexagent {

using namespace std;
using namespace rapidjson;

/**
 * Used to establish a connection to OVSDB
 */
class OvsdbConnection : public opflex::jsonrpc::RpcConnection {
    public:
    /**
     * Construct an OVSDB connection
     */
    OvsdbConnection(bool useLocalTcpPort) : opflex::jsonrpc::RpcConnection(),
        peer(nullptr), client_loop(nullptr), connected(false),
        syncComplete(false), ovsdbUseLocalTcpPort(useLocalTcpPort) {
        connect_async = {};
        writeq_async = {};
    }

    /**
     * destructor
     */
    virtual ~OvsdbConnection() {}

    /**
     * get pointer to peer object
     * @return pointer to peer instance
     */
    yajr::Peer* getPeer() { return peer;};

    /**
     * initialize the module
     */
    virtual void start();

    /**
     * stop the module
     */
    virtual void stop();

    /**
     * get state of connection
     * @return true if connected, false otherwise
     */
    bool isConnected() {
        if (!connected) {
            return false;
        } else {
            unique_lock<mutex> lock(OvsdbConnection::ovsdbMtx);
            if (!ready.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT),
                                [=] { return isSyncComplete(); })) {
                LOG(DEBUG) << "lock timed out, no connection";
                return false;
            }
            return true;
        }
    };

    /**
     * set connection state
     * @param[in] state state of connection
     */
    void setConnected(bool state) {
        connected = state;
        // clear OVSDB state on disconnect
        // monitor calls will be made on reconnect
        if (!connected) {
            syncComplete = false;
            ovsdbState.clear();
        }
    }

    /** Has the initial sync with OVSDB completed */
    bool isSyncComplete() {
        return syncComplete;
    }

    /** set that the sync with OVSDB has completed */
    void setSyncComplete(bool isSyncComplete) {
        syncComplete = isSyncComplete;
    }

    /**
     * call back to handle connection state changes
     * @param[in] p pointer to Peer object
     * @param[in] data void pointer to passed in context
     * @param[in] stateChange call back to handle connection state changes
     * @param[in] error error reported by call back caller
     */
    static void on_state_change(yajr::Peer * p, void * data,
            yajr::StateChange::To stateChange,
            int error);

    /**
     * get loop selector attribute
     * @param[in] data void pointer to context
     * @return a pointer to uv_loop_t
     */
    static uv_loop_t* loop_selector(void* data);

    /**
     * create a connection to peer
     */
    virtual void connect();

    /**
     * Disconnect this connection from the remote peer.  Must be
     * called from the libuv processing thread.  Will retry if the
     * connection type supports it.
     */
    virtual void disconnect();

    /**
     * callback for invoking connect
     * @param[in] handle pointer to uv_async_t
     */
    static void connect_cb(uv_async_t* handle);

    /**
     * callback for sending queued requests
     * @param[in] handle pointer to uv_async_t
     */
    static void on_writeq_async(uv_async_t* handle);

    /**
     * call back for transaction response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleTransaction(uint64_t reqId, const Document& payload);

    /**
     * call back for transaction error response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleTransactionError(uint64_t reqId, const Document& payload);

    /**
     * call back for monitor response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleMonitor(uint64_t reqId, const Document& payload);

    /**
     * call back for monitor error response
     * @param[in] reqId request ID of the request for this response.
     * @param[in] payload rapidjson::Value reference of the response body.
     */
    virtual void handleMonitorError(uint64_t reqId, const Document& payload);

    /**
     * method for handling async updates
     */
    virtual void handleUpdate(const Document& payload);

    /**
     * condition variable used for synchronizing JSON/RPC
     * request and response
     */
    condition_variable ready;
    /**
     * mutex used for synchronizing JSON/RPC
     * request and response
     *
     * static for now as we only have a single OVSDB connection
     */
    static mutex ovsdbMtx;

    /**
     * Get a human-readable view of the name of the remote peer
     *
     * @return the string name
     */
    virtual const std::string& getRemotePeer() { return remote_peer; }

    /**
     * Get current OVSDB state
     * @return OVSDB state
     */
    OvsdbState& getOvsdbState() {
        return ovsdbState;
    }

    /**
     * Get the next req ID
     * @return req ID
     */
    uint64_t getNextId() { return ++id; }

    /**
     * Send OVSDB monitor requests
     */
    void sendMonitorRequests();

protected:

    /**
     * New messages are ready to be written to the socket.
     * processWriteQueue() must be called.
     */
    virtual void messagesReady();

private:

    void decrSyncMsgsRemaining() {
        syncMsgsRemaining--;
        if (syncMsgsRemaining == 0) {
            syncComplete = true;
        }
    }

    yajr::Peer* peer;
    uv_loop_t* client_loop;
    opflex::util::ThreadManager threadManager;
    uv_async_t connect_async;
    uv_async_t writeq_async;
    std::atomic<bool> connected;
    std::atomic<bool> syncComplete;
    std::atomic<int> syncMsgsRemaining;
    bool ovsdbUseLocalTcpPort;
    uint64_t id = 0;
    std::string remote_peer;
    OvsdbState ovsdbState;

    const int WAIT_TIMEOUT = 5000;
};


}
#endif
