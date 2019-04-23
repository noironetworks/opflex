/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for OpflexListener
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

/* This must be included before anything else */
#if HAVE_CONFIG_H
#  include <config.h>
#endif


#include <stdexcept>

#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>

#include "opflex/engine/internal/OpflexListener.h"
#include "opflex/engine/internal/OpflexPool.h"
#include "opflex/logging/internal/logging.hpp"
#include "RecursiveLockGuard.h"

#include <yajr/internal/comms.hpp>

namespace opflex {
namespace engine {
namespace internal {

using std::string;
using util::LockGuard;
using yajr::transport::ZeroCopyOpenSSL;

OpflexListener::OpflexListener(HandlerFactory& handlerFactory_,
                               int port_,
                               const std::string& name_,
                               const std::string& domain_)
    : handlerFactory(handlerFactory_), port(port_),
      name(name_), domain(domain_), active(true), conn_id(0) {
    uv_mutex_init(&conn_mutex);
    uv_key_create(&conn_mutex_key);
}

OpflexListener::OpflexListener(HandlerFactory& handlerFactory_,
                               const std::string& socketName_,
                               const std::string& name_,
                               const std::string& domain_)
    : handlerFactory(handlerFactory_), socketName(socketName_),
      port(-1), name(name_), domain(domain_), active(true), conn_id(0) {
    uv_mutex_init(&conn_mutex);
    uv_key_create(&conn_mutex_key);
}

OpflexListener::~OpflexListener() {
    uv_key_delete(&conn_mutex_key);
    uv_mutex_destroy(&conn_mutex);
}

void OpflexListener::enableSSL(const std::string& caStorePath,
                               const std::string& serverKeyPath,
                               const std::string& serverKeyPass,
                               bool verifyPeers) {
    OpflexConnection::initSSL();
    serverCtx.reset(ZeroCopyOpenSSL::Ctx::createCtx(caStorePath.c_str(),
                                                    serverKeyPath.c_str(),
                                                    serverKeyPass.c_str()));
    if (!serverCtx.get())
        throw std::runtime_error("Could not enable SSL");

    if (verifyPeers)
        serverCtx.get()->setVerify();
}

void OpflexListener::on_cleanup_async(uv_async_t* handle) {
    OpflexListener* listener = (OpflexListener*)handle->data;

    {
        util::RecursiveLockGuard guard(&listener->conn_mutex,
                                       &listener->conn_mutex_key);
        conn_map_t conns(listener->conns);
        for (auto& it: listener->conns) {
            OpflexServerConnection* conn = it.second;
            conn->close();
        }
        if (listener->conns.size() != 0) return;
    }

    uv_close((uv_handle_t*)&listener->writeq_async, NULL);
    uv_close((uv_handle_t*)handle, NULL);
    yajr::finiLoop(&listener->server_loop);
}

void OpflexListener::on_writeq_async(uv_async_t* handle) {
    OpflexListener* listener = (OpflexListener*)handle->data;
    util::RecursiveLockGuard guard(&listener->conn_mutex,
                                   &listener->conn_mutex_key);
    for (auto& it: listener->conns) {
        OpflexServerConnection* conn = it.second;
        conn->processWriteQueue();
    }
}

void OpflexListener::listen() {
    int rc;
    uv_loop_init(&server_loop);
    cleanup_async.data = this;
    writeq_async.data = this;
    uv_async_init(&server_loop, &cleanup_async, on_cleanup_async);
    uv_async_init(&server_loop, &writeq_async, on_writeq_async);

    yajr::initLoop(&server_loop);

    if (port < 0) {
        listener =
            yajr::Listener::create(socketName,
                                   OpflexServerConnection::on_state_change,
                                   on_new_connection,
                                   this,
                                   &server_loop,
                                   OpflexServerConnection::loop_selector);
    } else {
        listener =
            yajr::Listener::create("0.0.0.0", port,
                                   OpflexServerConnection::on_state_change,
                                   on_new_connection,
                                   this,
                                   &server_loop,
                                   OpflexServerConnection::loop_selector);
    }

    rc = uv_thread_create(&server_thread, server_thread_func, this);
    if (rc < 0) {
        throw std::runtime_error(string("Could not create server thread: ") +
                                 uv_strerror(rc));
    }
}

void OpflexListener::disconnect() {
    if (!active) return;
    active = false;

    uv_async_send(&cleanup_async);
    uv_thread_join(&server_thread);
    uv_loop_close(&server_loop);
}

void OpflexListener::server_thread_func(void* listener_) {
    OpflexListener* processor = (OpflexListener*)listener_;
    uv_run(&processor->server_loop, UV_RUN_DEFAULT);
}

void* OpflexListener::on_new_connection(yajr::Listener* ylistener,
                                        void* data, int error) {
    if (error < 0) {
        LOG(ERROR) << "Error on new connection: "
                   << uv_strerror(error);
        return NULL;
    }

    OpflexListener* listener = (OpflexListener*)data;
    util::RecursiveLockGuard guard(&listener->conn_mutex,
                                   &listener->conn_mutex_key);
    OpflexServerConnection* conn = new OpflexServerConnection(listener);
    listener->conns.insert({conn->getConnId(), conn});
    return conn;
}

void OpflexListener::connectionClosed(OpflexServerConnection* conn) {
    util::RecursiveLockGuard guard(&conn_mutex, &conn_mutex_key);
    conns.erase(conn->getConnId());
    delete conn;
    guard.release();
    if (!active)
        uv_async_send(&cleanup_async);
}

void OpflexListener::sendToAll(OpflexMessage* message) {
    boost::scoped_ptr<OpflexMessage> messagep(message);
    util::RecursiveLockGuard guard(&conn_mutex, &conn_mutex_key);
    if (!active) return;
    for (auto& it: conns) {
        OpflexServerConnection* conn = it.second;
        // this is inefficient but we only use this for testing
        conn->sendMessage(message->clone());
    }
}

void OpflexListener::resolvedUri(const std::string& uri, uint64_t conn_id) {
    conn_set_t& connset = resolv_uri_map[uri];
    if (connset.find(conn_id) != connset.end())
        return;

    connset.insert(conn_id);
}

void OpflexListener::unResolvedUri(const std::string& uri, uint64_t conn_id) {
    auto it1 = resolv_uri_map.find(uri);
    if (it1 == resolv_uri_map.end())
        return;
    conn_set_t& connset = it1->second;

    auto it2 = connset.find(conn_id);
    if (it2 != connset.end())
        connset.erase(it2);

    if (connset.empty())
        resolv_uri_map.erase(it1);
}

void OpflexListener::sendToListeners(const std::string& uri,
                                     OpflexMessage* message) {
    boost::scoped_ptr<OpflexMessage> messagep(message);
    util::RecursiveLockGuard guard(&conn_mutex, &conn_mutex_key);
    if (!active) return;
    auto it1 = resolv_uri_map.find(uri);
    if (it1 == resolv_uri_map.end())
        return;

    uint64_t conn_id;
    conn_set_t& connset = it1->second;
    BOOST_FOREACH(conn_id, connset) {
        auto it2 = conns.find(conn_id);
        if (it2 != conns.end()) {
            OpflexServerConnection* conn = it2->second;
            if (conn->getConnId() == conn_id) {
                conn->sendMessage(message->clone());
                continue;
            }
        }
        connset.erase(conn_id);
        if (connset.empty()) {
            resolv_uri_map.erase(it1);
            return;
        }
    }
}

void OpflexListener::sendToListeners(const std::vector<modb::reference_t>& mo_,
                                     OpflexMessage* message) {
    std::vector<modb::reference_t> mo(mo_);
    boost::scoped_ptr<OpflexMessage> messagep(message);
    conn_set_t cset;
    util::RecursiveLockGuard guard(&conn_mutex, &conn_mutex_key);
    if (!active) return;

    BOOST_FOREACH(modb::reference_t& p, mo) {
        auto it = resolv_uri_map.find(p.second.toString().c_str());
        if (it == resolv_uri_map.end())
            continue;

        conn_set_t& ucset = it->second;
        if (!ucset.empty()) {
            cset.insert(ucset.begin(), ucset.end());
        }
    }

    uint64_t conn_id;
    BOOST_FOREACH(conn_id, cset) {
        auto it = conns.find(conn_id);
        if (it != conns.end()) {
            OpflexServerConnection* conn = it->second;
            if (conn->getConnId() == conn_id) {
                conn->sendMessage(message->clone());
                continue;
            }
        }
    }
}

void OpflexListener::onCleanupTimer(void) {
    auto it1 = resolv_uri_map.begin();

    while(it1 != resolv_uri_map.end()) {
        uint64_t conn_id;
        conn_set_t& connset = it1->second;
        bool incr = true;

        BOOST_FOREACH(conn_id, connset) {
            auto it2 = conns.find(conn_id);
            if (it2 != conns.end()) {
                OpflexServerConnection* conn = it2->second;
                if (conn->getConnId() == conn_id) {
                    continue;
                }
            }
            LOG(DEBUG) << "CLEANUP URI :: " << it1->first
                       << "AGENT :: " << conn_id;
            // We come here if conn_id is not present in conns
            connset.erase(conn_id);
            // If connset for uri is empty, remove uri
            if (connset.empty()) {
                it1 = resolv_uri_map.erase(it1);
                incr = false;
                break;
            }
        }
        if (incr) { it1++; }
    }
}

bool OpflexListener::applyConnPred(conn_pred_t pred, void* user) {
    util::RecursiveLockGuard guard(&conn_mutex, &conn_mutex_key);
    for (auto& it: conns) {
        OpflexServerConnection* conn = it.second;
        if (!pred(conn, user)) return false;
    }
    return true;
}

void OpflexListener::messagesReady() {
    uv_async_send(&writeq_async);
}

bool OpflexListener::isListening() {
    using yajr::comms::internal::Peer;
    return Peer::LoopData::getPeerList(&server_loop,
                                       Peer::LoopData::LISTENING)->size() > 0;
}

} /* namespace internal */
} /* namespace engine */
} /* namespace opflex */
