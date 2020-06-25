/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for OpflexPool
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

#include <memory>
#include <boost/foreach.hpp>

#include "opflex/engine/internal/OpflexPool.h"
#include "opflex/engine/internal/OpflexMessage.h"
#include "opflex/logging/internal/logging.hpp"

namespace opflex {
namespace engine {
namespace internal {

using std::make_pair;
using std::string;
using ofcore::OFConstants;
using ofcore::PeerStatusListener;
using yajr::transport::ZeroCopyOpenSSL;

OpflexPool::OpflexPool(HandlerFactory& factory_,
                       util::ThreadManager& threadManager_)
    : factory(factory_), threadManager(threadManager_),
      active(false),
      client_mode(OFConstants::OpflexElementMode::STITCHED_MODE),
      transport_state(OFConstants::OpflexTransportModeState::SEEKING_PROXIES),
      ipv4_proxy(0), ipv6_proxy(0),
      mac_proxy(0), curHealth(PeerStatusListener::DOWN)
{
}

OpflexPool::~OpflexPool() {
}

void OpflexPool::addPendingItem(OpflexClientConnection* conn, const std::string& uri) {
    std::string hostName = conn->getHostname();
    std::unique_lock<std::mutex> lock(modify_uri_mutex);
    if(pendingResolution[hostName].insert(uri).second == true) {
       conn->getOpflexStats()->incrPolUnresolvedCount();
    }
}

void OpflexPool::removePendingItem(OpflexClientConnection* conn, const std::string& uri) {
    std::string hostName = conn->getHostname();
    std::unique_lock<std::mutex> lock(modify_uri_mutex);
    std::set<std::string>::iterator rem = pendingResolution[hostName].find(uri);
    if (rem != pendingResolution[hostName].end()) {
        pendingResolution[hostName].erase(rem);
        conn->getOpflexStats()->decrPolUnresolvedCount();
    }
}

boost::optional<string> OpflexPool::getLocation() {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    return location;
}

void OpflexPool::setLocation(const string& location) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    this->location = location;
}

void OpflexPool::enableSSL(const string& caStorePath,
                           const string& keyAndCertFilePath,
                           const string& passphrase,
                           bool verifyPeers) {
    OpflexConnection::initSSL();
    clientCtx.reset(ZeroCopyOpenSSL::Ctx::createCtx(caStorePath.c_str(),
                keyAndCertFilePath.c_str(),
                passphrase.c_str()));
    if (!clientCtx.get())
        throw std::runtime_error("Could not enable SSL");

    if (verifyPeers)
        clientCtx->setVerify();
    else
        clientCtx->setNoVerify();
}

void OpflexPool::enableSSL(const string& caStorePath,
                           bool verifyPeers) {
    OpflexConnection::initSSL();
    clientCtx.reset(ZeroCopyOpenSSL::Ctx::createCtx(caStorePath.c_str()));
    if (!clientCtx.get())
        throw std::runtime_error("Could not enable SSL");

    if (verifyPeers)
        clientCtx->setVerify();
    else
        clientCtx->setNoVerify();
}

void OpflexPool::on_conn_async(uv_async_t* handle) {
    OpflexPool* pool = (OpflexPool*)handle->data;
    if (pool->active) {
        const std::lock_guard<std::recursive_mutex> lock(pool->conn_mutex);
        BOOST_FOREACH(conn_map_t::value_type& v, pool->connections) {
            v.second.conn->connect();
        }
    }
}

void OpflexPool::on_cleanup_async(uv_async_t* handle) {
    OpflexPool* pool = (OpflexPool*)handle->data;
    {
        const std::lock_guard<std::recursive_mutex> lock(pool->conn_mutex);
        conn_map_t conns(pool->connections);
        BOOST_FOREACH(conn_map_t::value_type& v, conns) {
            v.second.conn->close();
        }
        if (!pool->connections.empty())
            return;
    }

    uv_close((uv_handle_t*)&pool->writeq_async, NULL);
    uv_close((uv_handle_t*)&pool->conn_async, NULL);
    uv_close((uv_handle_t*)handle, NULL);
    yajr::finiLoop(pool->client_loop);
}

void OpflexPool::on_writeq_async(uv_async_t* handle) {
    OpflexPool* pool = (OpflexPool*)handle->data;
    const std::lock_guard<std::recursive_mutex> lock(pool->conn_mutex);
    BOOST_FOREACH(conn_map_t::value_type& v, pool->connections) {
        v.second.conn->processWriteQueue();
    }
}

void OpflexPool::start() {
    if (active) return;
    active = true;

    client_loop = threadManager.initTask("connection_pool");
    yajr::initLoop(client_loop);

    conn_async.data = this;
    cleanup_async.data = this;
    writeq_async.data = this;
    uv_async_init(client_loop, &conn_async, on_conn_async);
    uv_async_init(client_loop, &cleanup_async, on_cleanup_async);
    uv_async_init(client_loop, &writeq_async, on_writeq_async);

    threadManager.startTask("connection_pool");
}

void OpflexPool::stop() {
    if (!active) return;
    active = false;

    uv_async_send(&cleanup_async);
    threadManager.stopTask("connection_pool");
}

void OpflexPool::setOpflexIdentity(const string& name,
                                   const string& domain) {
    this->name = name;
    this->domain = domain;
}

void OpflexPool::setOpflexIdentity(const string& name,
                                   const string& domain,
                                   const string& location) {
    this->name = name;
    this->domain = domain;
    this->location = location;
}

void
OpflexPool::registerPeerStatusListener(PeerStatusListener* listener) {
    peerStatusListeners.push_back(listener);
}

void OpflexPool::updatePeerStatus(const string& hostname, int port,
                                  PeerStatusListener::PeerStatus status) {
    PeerStatusListener::Health newHealth = PeerStatusListener::DOWN;
    bool notifyHealth = false;
    bool hasReadyConnection = false;
    bool hasDegradedConnection = false;
    {
        const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
        BOOST_FOREACH(conn_map_t::value_type& v, connections) {
            if (v.second.conn->isReady())
                hasReadyConnection = true;
            else
                hasDegradedConnection = true;

        }

        if (hasReadyConnection) {
            newHealth = PeerStatusListener::HEALTHY;
            if (hasDegradedConnection)
                newHealth = PeerStatusListener::DEGRADED;
        }

        if (newHealth != curHealth) {
            notifyHealth = true;
            curHealth = newHealth;
        }
    }

    BOOST_FOREACH(PeerStatusListener* l, peerStatusListeners) {
        l->peerStatusUpdated(hostname, port, status);
    }

    if (notifyHealth) {
        LOG(DEBUG) << "Health updated to: "
                   << ((newHealth == PeerStatusListener::HEALTHY)
                       ? "HEALTHY"
                       : ((newHealth == PeerStatusListener::DEGRADED)
                          ? "DEGRADED" : "DOWN"));
        BOOST_FOREACH(PeerStatusListener* l, peerStatusListeners) {
            l->healthUpdated(newHealth);
        }
    }
}

OpflexClientConnection* OpflexPool::getPeer(const string& hostname,
                                            int port) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    auto it = connections.find(make_pair(hostname, port));
    if (it != connections.end()) {
        return it->second.conn;
    }
    return NULL;
}

void OpflexPool::addPeer(const string& hostname, int port,
                         bool configured) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    if (configured)
        configured_peers.insert(make_pair(hostname, port));
    doAddPeer(hostname, port);
    uv_async_send(&conn_async);
}

void OpflexPool::doAddPeer(const string& hostname, int port) {
    if (!active) return;
    ConnData& cd = connections[make_pair(hostname, port)];
    if (cd.conn != NULL) {
        LOG(DEBUG) << "Connection for "
                   << hostname << ":" << port
                   << " already exists; not adding peer.";
    } else {
        LOG(INFO) << "Adding peer "
                  << hostname << ":" << port;

        OpflexClientConnection* conn =
            new OpflexClientConnection(factory, this, hostname, port);
        cd.conn = conn;
    }
}

void OpflexPool::addPeer(OpflexClientConnection* conn) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    ConnData& cd = connections[make_pair(conn->getHostname(), conn->getPort())];
    if (cd.conn != NULL) {
        LOG(ERROR) << "Connection for "
                   << conn->getHostname() << ":" << conn->getPort()
                   << " already exists";
    }
    cd.conn = conn;
}

void OpflexPool::doRemovePeer(const string& hostname, int port) {
    auto it = connections.find(make_pair(hostname, port));
    if (it != connections.end()) {
        if (it->second.conn) {
            doSetRoles(it->second, 0);
        }
        connections.erase(it);
    }
}

void OpflexPool::resetAllPeers() {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    conn_map_t conns(connections);
    BOOST_FOREACH(conn_map_t::value_type& v, conns) {
        v.second.conn->close();
    }
}

// must be called with conn_mutex held
void OpflexPool::updateRole(ConnData& cd,
                            uint8_t newroles,
                            OFConstants::OpflexRole role) {
    if (cd.roles & role) {
        if (!(newroles & role)) {
            auto it = roles.find(role);
            if (it != roles.end()) {
                it->second.conns.erase(cd.conn);
                if (it->second.conns.empty())
                    roles.erase(it);
            }
            cd.roles &= ~role;
        }
    } else if (newroles & role) {
        if (!(cd.roles & role)) {
            conn_set_t& cl = roles[role].conns;
            cl.insert(cd.conn);
            cd.roles |= role;
        }
    }
}

size_t OpflexPool::getRoleCount(ofcore::OFConstants::OpflexRole role) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);

    auto it = roles.find(role);
    if (it == roles.end()) return 0;
    return it->second.conns.size();
}


void OpflexPool::setRoles(OpflexClientConnection* conn,
                          uint8_t newroles) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    ConnData& cd = connections.at(make_pair(conn->getHostname(),
                                            conn->getPort()));
    doSetRoles(cd, newroles);
    cd.conn->setRoles(newroles);
}

// must be called with conn_mutex held
void OpflexPool::doSetRoles(ConnData& cd, uint8_t newroles) {
    updateRole(cd, newroles, OFConstants::POLICY_ELEMENT);
    updateRole(cd, newroles, OFConstants::POLICY_REPOSITORY);
    updateRole(cd, newroles, OFConstants::ENDPOINT_REGISTRY);
    updateRole(cd, newroles, OFConstants::OBSERVER);
}

void OpflexPool::connectionClosed(OpflexClientConnection* conn) {
    std::unique_lock<std::recursive_mutex> guard(conn_mutex);
    doConnectionClosed(conn);
    guard.unlock();
    if (!active)
        uv_async_send(&cleanup_async);
}

void OpflexPool::doConnectionClosed(OpflexClientConnection* conn) {
    doRemovePeer(conn->getHostname(), conn->getPort());
    delete conn;
}

void OpflexPool::messagesReady() {
    uv_async_send(&writeq_async);
}

void incrementMsgCounter(OpflexClientConnection* conn, OpflexMessage* msg)
{
    if (OpflexMessage::REQUEST == msg->getType()) {
        if ("send_identity" == msg->getMethod()) {
            conn->getOpflexStats()->incrIdentReqs();
        } else if ("policy_resolve" == msg->getMethod()) {
            conn->getOpflexStats()->incrPolResolves();
        } else if ("policy_unresolve" == msg->getMethod()) {
            conn->getOpflexStats()->incrPolUnresolves();
        } else if ("endpoint_declare" == msg->getMethod()) {
            conn->getOpflexStats()->incrEpDeclares();
        } else if ("endpoint_undeclare" == msg->getMethod()) {
            conn->getOpflexStats()->incrEpUndeclares();
        } else if ("state_report" == msg->getMethod()) {
            conn->getOpflexStats()->incrStateReports();
        } else {
            LOG(INFO) << "Unhandled request named " << msg->getMethod();
        }
    } else {
        LOG(INFO) << "Unhandled type named " << msg->getType();
    }
}

size_t OpflexPool::sendToRole(OpflexMessage* message,
                           OFConstants::OpflexRole role,
                           bool sync, const std::string& uri) {
    std::unique_ptr<OpflexMessage> messagep(message);
    if (!active) return 0;
    std::vector<OpflexClientConnection*> conns;

    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    auto it = roles.find(role);
    if (it == roles.end())
        return 0;

    size_t i = 0;
    OpflexMessage* m_copy = NULL;
    std::vector<OpflexClientConnection*> ready;
    BOOST_FOREACH(OpflexClientConnection* conn, it->second.conns) {
        if (!conn->isReady()) continue;
        ready.push_back(conn);
    }
    BOOST_FOREACH(OpflexClientConnection* conn, ready) {
        if (i < (ready.size() - 1)) {
            m_copy = message->clone();
        } else {
            m_copy = message;
            messagep.release();
        }
        incrementMsgCounter(conn, m_copy);
        conn->sendMessage(m_copy, sync);
        if (message->getMethod() == "policy_resolve" && uri != "") {
           addPendingItem(conn, uri);
        }
        i += 1;
    }
    // all allocated buffers should have been dispatched to
    // connections

    return i;
}

void OpflexPool::validatePeerSet(OpflexClientConnection * conn, const peer_name_set_t& peers) {
    peer_name_set_t to_remove;
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);

    conn_map_t conns(connections);
    BOOST_FOREACH(const conn_map_t::value_type& cv, conns) {
        OpflexClientConnection* c = cv.second.conn;
        OpflexClientConnection* srcPeer = getPeer(conn->getHostname(), conn->getPort());
        peer_name_t peer_name = make_pair(c->getHostname(), c->getPort());
        if ((peers.find(peer_name) == peers.end()) &&
            (configured_peers.find(peer_name) == configured_peers.end()) &&
            ((srcPeer->getRoles()==0) || (getClientMode() != AgentMode::TRANSPORT_MODE))) {
            LOG(INFO) << "Removing stale peer connection: "
                      << peer_name.first << ":" << peer_name.second
                      << " based on peer-list from "
                      << srcPeer->getHostname() << ":" << srcPeer->getPort();
            c->close();
        }
    }
}

bool OpflexPool::isConfiguredPeer(const string& hostname, int port) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    return configured_peers.find(make_pair(hostname, port)) !=
        configured_peers.end();
}

void OpflexPool::addConfiguredPeers() {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    BOOST_FOREACH(const peer_name_t& peer_name, configured_peers) {
        addPeer(peer_name.first, peer_name.second, false);
    }
}

void OpflexPool::getOpflexPeerStats(std::unordered_map<string, OF_SHARED_PTR<OFStats>>& stats) {
    const std::lock_guard<std::recursive_mutex> lock(conn_mutex);
    BOOST_FOREACH(conn_map_t::value_type& v, connections) {
        const string peername = v.first.first + ":" + std::to_string(v.first.second);
        stats.emplace(std::make_pair(peername, v.second.conn->getOpflexStats()));
    }
}


} /* namespace internal */
} /* namespace engine */
} /* namespace opflex */
