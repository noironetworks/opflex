/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for Processor class.
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


#include <boost/test/unit_test.hpp>

#include "opflex/ofcore/OFConstants.h"
#include "opflex/engine/internal/OpflexPool.h"

using namespace opflex::engine;
using namespace opflex::engine::internal;
using opflex::ofcore::OFConstants;

class EmptyHandlerFactory : public HandlerFactory {
public:
    virtual OpflexHandler* newHandler(OpflexConnection* conn) {
        return NULL;
    }
};

class MockClientConn : public OpflexClientConnection {
public:
    MockClientConn(HandlerFactory& handlerFactory,
                   OpflexPool* pool,
                   const std::string& hostname,
                   int port) :
        OpflexClientConnection(handlerFactory,
                               pool,
                               hostname,
                               port), ready(true),closed(false),close_delayed(false) {}

    virtual void connect() {}
    virtual void disconnect() {
        on_state_change(NULL, this, yajr::StateChange::DELETE, 0);
    }
    virtual bool isReady() { return ready; }
    virtual const std::string& getRemotePeer() {
        static std::string dummy("DUMMY");
        return dummy;
    }
    virtual void close() {
        closed = true;
        if (!close_delayed) {
            // Immediately trigger the disconnect callback
            disconnect();
        }
    }
    
    // Simulate delayed close completion for race condition testing
    void completeDelayedClose() {
        if (close_delayed && closed) {
            disconnect();
        }
    }
    
    bool ready;
    bool closed;
    bool close_delayed;
};

class PoolFixture {
public:
    PoolFixture() : pool(handlerFactory, threadManager) {
        pool.start();
    }

    ~PoolFixture() {
        pool.stop();
    }

    opflex::util::ThreadManager threadManager;
    EmptyHandlerFactory handlerFactory;
    OpflexPool pool;
};

BOOST_AUTO_TEST_SUITE(OpflexPool_test)

BOOST_FIXTURE_TEST_CASE( manage_roles , PoolFixture ) {
    MockClientConn* c1 = new MockClientConn(handlerFactory, &pool,
                                            "1.2.3.4", 1234);
    MockClientConn* c2 = new MockClientConn(handlerFactory, &pool,
                                            "1.2.3.4", 1235);
    MockClientConn* c3 = new MockClientConn(handlerFactory, &pool,
                                            "1.2.3.4", 1236);

    pool.addPeer(c1);
    pool.addPeer(c2);
    pool.addPeer(c3);

    pool.setRoles(c1,
                  OFConstants::POLICY_REPOSITORY |
                  OFConstants::OBSERVER |
                  OFConstants::ENDPOINT_REGISTRY);

    BOOST_CHECK_EQUAL(1, pool.getRoleCount(OFConstants::POLICY_REPOSITORY));
    BOOST_CHECK_EQUAL(1, pool.getRoleCount(OFConstants::OBSERVER));
    BOOST_CHECK_EQUAL(1, pool.getRoleCount(OFConstants::ENDPOINT_REGISTRY));

    pool.setRoles(c2,
                  OFConstants::POLICY_REPOSITORY |
                  OFConstants::ENDPOINT_REGISTRY);
    pool.setRoles(c3, OFConstants::OBSERVER);

    BOOST_CHECK_EQUAL(2, pool.getRoleCount(OFConstants::POLICY_REPOSITORY));
    BOOST_CHECK_EQUAL(2, pool.getRoleCount(OFConstants::OBSERVER));
    BOOST_CHECK_EQUAL(2, pool.getRoleCount(OFConstants::ENDPOINT_REGISTRY));

    c1->disconnect();
    BOOST_CHECK_EQUAL(1, pool.getRoleCount(OFConstants::POLICY_REPOSITORY));
    BOOST_CHECK_EQUAL(1, pool.getRoleCount(OFConstants::OBSERVER));
    BOOST_CHECK_EQUAL(1, pool.getRoleCount(OFConstants::ENDPOINT_REGISTRY));

    c2->disconnect();
    c3->disconnect();

    BOOST_CHECK_EQUAL(0, pool.getRoleCount(OFConstants::POLICY_REPOSITORY));
    BOOST_CHECK_EQUAL(0, pool.getRoleCount(OFConstants::OBSERVER));
    BOOST_CHECK_EQUAL(0, pool.getRoleCount(OFConstants::ENDPOINT_REGISTRY));
}

BOOST_FIXTURE_TEST_CASE( manage_ivxlan_roles , PoolFixture ) {
    MockClientConn* c1 = new MockClientConn(handlerFactory, &pool,
                                            "1.2.3.4", 1234);
    MockClientConn* c2 = new MockClientConn(handlerFactory, &pool,
                                            "1.2.3.4", 1235);
    MockClientConn* c3 = new MockClientConn(handlerFactory, &pool,
                                            "1.2.3.4", 1236);
    pool.setClientMode(opflex::ofcore::OFConstants::OpflexElementMode::TRANSPORT_MODE);
    pool.addPeer(c1);
    pool.addPeer(c2);
    pool.addPeer(c3);
    pool.setRoles(c1,
                  OFConstants::POLICY_REPOSITORY |
                  OFConstants::OBSERVER |
                  OFConstants::ENDPOINT_REGISTRY);
    OpflexPool::peer_name_set_t c1_peers, c2_peers;
    c1_peers.insert(std::make_pair<std::string, int>("1.2.3.4",1234));
    pool.validatePeerSet(c1,c1_peers);
    BOOST_CHECK_EQUAL(false, c1->closed);
    BOOST_CHECK_EQUAL(false, c2->closed);
    BOOST_CHECK_EQUAL(false, c3->closed);
    c2_peers.insert(std::make_pair<std::string, int>("1.2.3.4",1235));
    pool.validatePeerSet(c2,c2_peers);
    BOOST_CHECK_EQUAL(true, c1->closed);
    BOOST_CHECK_EQUAL(false, c2->closed);
    BOOST_CHECK_EQUAL(true, c3->closed);
    c1->disconnect();
    c2->disconnect();
    c3->disconnect();
}

BOOST_FIXTURE_TEST_CASE( configured_peer_race_condition, PoolFixture ) {
    // Test case: Race condition between OpflexPEHandler::handleSendIdentityRes 
    // closing a configured peer and resetAllUnconfiguredPeers re-adding it
    
    // Step 1: Create a mock configured peer with delayed close
    std::string hostname = "configured.peer.com";
    int port = 8009;
    
    MockClientConn* configuredConn = new MockClientConn(handlerFactory, &pool, hostname, port);
    configuredConn->close_delayed = true; // Enable delayed close to simulate race timing
    
    // Add as configured peer and add the connection to the pool
    pool.addPeer(hostname, port, true); // Mark as configured peer
    pool.addPeer(configuredConn);       // Add the mock connection
    
    // Verify the configured peer was added correctly
    OpflexClientConnection* foundConn = pool.getPeer(hostname, port);
    BOOST_REQUIRE(foundConn != nullptr);
    BOOST_CHECK(pool.isConfiguredPeer(hostname, port));
    
    // Step 2: Start closing the configured peer (simulating 
    // OpflexPEHandler::handleSendIdentityRes where peer is not found in peer list)
    configuredConn->close(); // This starts the close but doesn't complete due to delay
    
    // At this point: close has been called but connectionClosed hasn't happened yet
    BOOST_CHECK(configuredConn->closed == true);
    
    // Verify peer is still in the pool's connection list (this is key to the race)
    OpflexClientConnection* stillThere = pool.getPeer(hostname, port);
    BOOST_CHECK(stillThere == configuredConn);
    
    // Step 3: Simulate the race condition - resetAllUnconfiguredPeers is called
    // before the close operation completes, and call addConfiguredPeers() which
    // tries to re-add configured peers
    pool.resetAllUnconfiguredPeers();
    pool.addConfiguredPeers();
    
    // Step 4: At this point, doAddPeer sees the connection already exists 
    // (because connectionClosed hasn't been called yet) and skips re-adding
    // Verify the configured peer is still marked as configured
    BOOST_CHECK(pool.isConfiguredPeer(hostname, port));
    
    // Verify the connection is still there (demonstrating the race timing)
    OpflexClientConnection* stillThereAfterReset = pool.getPeer(hostname, port);
    BOOST_CHECK(stillThereAfterReset == configuredConn);
    
    // Step 5: Complete the delayed close operation
    // This simulates the original close() operation finally completing
    configuredConn->completeDelayedClose();
    
    // Step 6: Verify the race condition bug - peer should be gone and not re-added
    OpflexClientConnection* shouldBeNull = pool.getPeer(hostname, port);
    
    // This demonstrates the bug: the configured peer is gone but wasn't re-added
    // because doAddPeer skipped it when resetAllUnconfiguredPeers was called
    BOOST_CHECK(shouldBeNull == nullptr); 
    
    // The pool should still know about configured peers
    BOOST_CHECK(pool.isConfiguredPeer(hostname, port));
    
    // But there's no connection in the pool for the configured peer
    // This is the problematic final state - configured peer exists but no connection
    // and no mechanism to trigger re-addition of the configured peer
}

BOOST_AUTO_TEST_SUITE_END()
