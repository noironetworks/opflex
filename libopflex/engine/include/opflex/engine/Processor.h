/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file Processor.h
 * @brief Interface definition file for Processor
 */
/*
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_ENGINE_PROCESSOR_H
#define OPFLEX_ENGINE_PROCESSOR_H

#include <vector>
#include <utility>
#include <mutex>

#include <boost/atomic.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/random/linear_congruential.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>
#include <uv.h>

#include "opflex/modb/internal/ObjectStore.h"
#include "opflex/modb/mo-internal/StoreClient.h"

#include "opflex/engine/internal/OpflexPool.h"
#include "opflex/engine/internal/OpflexHandler.h"
#include "opflex/engine/internal/MOSerializer.h"
#include "opflex/engine/internal/AbstractObjectListener.h"

#include "opflex/util/ThreadManager.h"

namespace opflex {
namespace engine {

/**
 * @brief The processor synchronizes the state of the local MODB with
 * the Opflex server as needed.
 *
 * The processor also maintains an index containing protocol state
 * information for each of the managed objects in the MODB.
 */
class Processor : public internal::AbstractObjectListener,
                  public internal::HandlerFactory {
public:
    /**
     * Construct a processor associated with the given object store
     * @param store the modb::ObjectStore
     */
    Processor(modb::ObjectStore* store,
              util::ThreadManager& threadManager);

    /**
     * Destroy the processor
     */
    ~Processor();

    /**
     * Set the opflex identity information for this framework
     * instance.
     *
     * @param name the unique name for this opflex component within
     * the policy domain
     * @param domain the globally unique name for this policy domain
     * @see opflex::ofcore::OFFramework::addOpflexIdentity
     */
    void setOpflexIdentity(const std::string& name,
                           const std::string& domain);

    /**
     * Set the opflex identity information for this framework
     * instance.
     *
     * @param name the unique name for this opflex component within
     * the policy domain
     * @param domain the globally unique name for this policy domain
     * @param location the location string for this policy element.
     */
    void setOpflexIdentity(const std::string& name,
                           const std::string& domain,
                           const std::string& location);

    /**
     * Enable SSL for connections to opflex peers
     *
     * @param caStorePath the filesystem path to a directory
     * containing CA certificates, or to a file containing a specific
     * CA certificate.
     * @param verifyPeers set to true to verify that peer certificates
     * properly chain to a trusted root
     */
    void enableSSL(const std::string& caStorePath,
                   bool verifyPeers = true);

    /**
     * Enable SSL for connections to opflex peers
     *
     * @param caStorePath the filesystem path to a directory
     * containing CA certificates, or to a file containing a specific
     * CA certificate.
     * @param keyAndCertFilePath the path to the PEM file for this peer,
     * containing its certificate and its private key, possibly encrypted.
     * @param passphrase the passphrase to be used to decrypt the private
     * key within this peer's PEM file
     * @param verifyPeers set to true to verify that peer certificates
     * properly chain to a trusted root
     */
    void enableSSL(const std::string& caStorePath,
                   const std::string& keyAndCertFilePath,
                   const std::string& passphrase,
                   bool verifyPeers = true);

    /**
     * Add an OpFlex peer.
     *
     * @param hostname the hostname or IP address to connect to
     * @param port the TCP port to connect on
     * @see opflex::ofcore::OFFramework::addPeer
     */
    void addPeer(const std::string& hostname, int port);

    /**
     * Register the given peer status listener to get updates on the
     * health of the connection pool and on individual connections.
     *
     * @param listener the listener to register
     */
    void registerPeerStatusListener(ofcore::PeerStatusListener* listener);

    /**
     * Start the processor thread.  Should call only after the
     * underlying object store is started.
     */
    void start(ofcore::OFConstants::OpflexElementMode mode =
               ofcore::OFConstants::OpflexElementMode::STITCHED_MODE);

    /**
     * Stop the processor thread.  Should call before stopping the
     * underlying object store.
     */
    void stop();

    /**
     * Get the parent store
     */
    modb::ObjectStore* getStore() { return store; }

    /**
     * Get the MO serializer
     */
    internal::MOSerializer& getSerializer() { return serializer; }

    /**
     * Get the MO serializer
     */
    modb::mointernal::StoreClient* getSystemClient() { return client; }

    // See AbstractObjectListener::objectUpdated
    virtual void objectUpdated(modb::class_id_t class_id,
                               const modb::URI& uri);

    /**
     * Get the reference count for an object
     */
    size_t getRefCount(const modb::URI& uri);

    /**
     * Check whether the given object metadata is either nonexistent
     * or in state NEW
     */
    bool isObjNew(const modb::URI& uri);

    /**
     * Set the processing delay for unit tests
     */
    void setProcDelay(uint64_t delay) { processingDelay = delay; }

    /**
     * Set the message retry delay for unit tests
     */
    void setRetryDelay(uint64_t delay) { retryDelay = delay; }

    /**
     * Set the prr timer duration in secs
     */
    void setPrrTimerDuration(const uint64_t duration);

    /**
     * Get the peer handshake timeout
     */
    uint32_t getHandshakeTimeout() const {
        return peerHandshakeTimeout;
    }

    /**
     * Set the peer handshake timeout
     */
    void setHandshakeTimeout(const uint32_t timeout) {
        peerHandshakeTimeout = timeout;
    }

    /**
     * Get the keepalive timeout
     */
    uint32_t getKeepaliveTimeout() const {
        return keepaliveTimeout;
    }

    /**
     * Set the keepalive timeout
     */
    void setKeepaliveTimeout(const uint32_t timeout) {
        keepaliveTimeout = timeout;
    }
\
    /**
     * Set the prr timer duration in secs
     */
    uint64_t getPrrTimerDuration() { return prrTimerDuration; }

    // See HandlerFactory::newHandler
    virtual
    internal::OpflexHandler* newHandler(internal::OpflexConnection* conn);

    /**
     * Get the opflex connection pool for the processor
     */
    internal::OpflexPool& getPool() { return pool; }

    /**
     * A new client connection is ready and the resolver state must be
     * synchronized to the server.
     * @param conn the new connection object
     */
    void connectionReady(internal::OpflexConnection* conn);

    /**
     * Called when a response to a message sent from the processor is
     * received
     *
     * @param reqId the ID of the request
     */
    void responseReceived(uint64_t reqId);

    /**
     * Set the tunnelMac to send to opflex registries as the parent of
     * endpoints
     *
     * @param mac tunnelMac
     */
    void setTunnelMac(const opflex::modb::MAC &mac);

   /**
    * Wait for pending items
    * @param wait min wait time input and how long to wait as output
    * @return true wait, false no wait
    */
    bool waitForPendingItems(uint32_t& wait);

    /**
     * Set startup policy
     * @param file startup policy file name or boost::none
     * @param model the model for initializing startupdb
     * @param duration the amount of time in ms from new
     *  connection to continue using startupdb
     * @param enabled if the feature is enabled
     * @param resolve_after_connection resolve after leaf connection
     */
    void setStartupPolicy(boost::optional<std::string>& file,
                          const modb::ModelMetadata& model,
                          uint64_t& duration,
                          bool& enabled,
                          bool& resolve_after_connection);

    /**
     * set force ep undeclares boolean
     * @param enabled if we want to convert a redeclare to undeclare + declare
     */
    void setForceEndpointUndeclares(bool& enabled) { force_ep_undeclares = enabled; }

    /**
     * Enable/Disable reporting of observable changes to registered observers
     *
     * @param class_id Observable class ID
     * @param enabled Should reporting be enabled/disabled to observers
     */
    void overrideObservableReporting(modb::class_id_t class_id, bool enabled);

    /**
     * Should changes for specified observable class be reported
     *
     * @param class_id Observable class ID
     * @return If observable changes should be reported
     */
    bool isObservableReportable(modb::class_id_t class_id);

    /**
     * Disable reporting of all observables
     */
    void disableObservableReporting();

private:
    /**
     * The system store client
     */
    modb::mointernal::StoreClient* client;

    /**
     * an MO serializer
     */
    internal::MOSerializer serializer;

    /**
     * Thread manager
     */
    util::ThreadManager& threadManager;

    /**
     * The pool of Opflex connections
     */
    internal::OpflexPool pool;

    /**
     * Request ID counter
     */
    uint64_t nextXid;

    /**
     * Override whether observable is reportable
     */
     std::map<modb::class_id_t, bool> overrideReportable;

     /**
      * Should reporting of observables be completely disabled.
      */
     bool reportObservables;

    /**
     * The status of items in the MODB with respect to the opflex
     * protocol
     */
    enum ItemState {
        /** a new item written locally */
        NEW,
        /** a local item that's been updated */
        UPDATED,
        /** a local item that's been sent to the server */
        IN_SYNC,
        /** A remote item that does not get resolved */
        REMOTE,
        /** an unresolved remote reference */
        UNRESOLVED,
        /** a remote reference with resolve request sent to server */
        RESOLVED,
        /** An orphaned item that will be deleted unless something
            references it in the current queue.  This is used for
            newly-added items that are only orphaned transiently. */
        PENDING_DELETE,
        /** A deleted item tombstone. */
        DELETED
    };

    /**
     * map of ItemState to String
     */
    std::map<int, std::string> ItemStateMap = {
        { NEW, "new" },
        { UPDATED, "updated" },
        { IN_SYNC, "in_sync" },
        { REMOTE, "remote" },
        { UNRESOLVED, "unresolved" },
        { RESOLVED, "resolved" },
        { PENDING_DELETE, "pending_delete" },
        { DELETED, "deleted" }
    };

    class item_details {
    public:
        /**
         * The class ID of the MO
         */
        modb::class_id_t class_id;
        /**
         * The update interval that controls expiration of the object
         * in milliseconds.
         */
        uint64_t refresh_rate;
        /**
         * State of the managed object
         */
        ItemState state;

        /**
         * The number of times the object has been referenced in the
         * system.
         */
        size_t refcount;

        /**
         * Outgoing URI references
         */
        std::unordered_set<modb::reference_t> urirefs;

        /**
         * Whether the item was written locally
         */
        bool local;

        /**
         * The last time a resolve request was made for the item
         */
        uint64_t resolve_time;

        /**
         * The number of pending requests associated with the
         * transaction ID
         */
        size_t pending_reqs;

        /**
         * Number of retries for this item
         */
        uint16_t retry_count;
    };

    /**
     * The data stored in the object state index
     */
    class item {
    public:
        item() : uri(""), expiration(0), last_xid(0), details(NULL) {}
        item(const item& i) : uri(i.uri), expiration(i.expiration),
                              last_xid(i.last_xid) {
            details = new item_details(*i.details);
        }
        item(const modb::URI& uri_, modb::class_id_t class_id_,
             uint64_t expiration_, uint64_t refresh_rate_,
             ItemState state_, bool local_)
            : uri(uri_), expiration(expiration_), last_xid(0) {
            details = new item_details();
            details->class_id = class_id_;
            details->refresh_rate = refresh_rate_;
            details->state = state_;
            details->refcount = 0;
            details->local = local_;
            details->resolve_time = 0;
            details->pending_reqs = 0;
            details->retry_count = 0;
        }
        ~item() { if (details) delete details; }
        item& operator=( const item& rhs ) {
            uri = rhs.uri;
            expiration = rhs.expiration;
            details = new item_details(*rhs.details);
            return *this;
        }

        /**
         * The URI of the MO
         */
        modb::URI uri;
        /**
         * The next expiration interval when an action needs to be
         * taken, such as refreshing the object resolution.  The value
         * is the time when the event should be processed.  A value of
         * 0 means that it should be processed immediately, while a
         * value of UINT64_MAX means that there is no pending event to
         * process.
         */
        uint64_t expiration;

        /**
         * The last Opflex request transaction ID related to this item
         */
        uint64_t last_xid;

        /**
         * Detailed item information
         */
        item_details* details;
    };

    // tag for expiration index
    struct expiration_tag{};
    // tag for expiration index
    struct uri_tag{};
    // tag for xid index
    struct xid_tag{};

    typedef boost::multi_index::multi_index_container<
        item,
        boost::multi_index::indexed_by<
            boost::multi_index::hashed_unique<
                boost::multi_index::tag<uri_tag>,
                boost::multi_index::member<item,
                                           modb::URI,
                                           &item::uri> > ,
            boost::multi_index::hashed_non_unique<
                boost::multi_index::tag<xid_tag>,
                boost::multi_index::member<item,
                                           uint64_t,
                                           &item::last_xid> > ,
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<expiration_tag>,
                boost::multi_index::member<item,
                                           uint64_t,
                                           &item::expiration> >
            >
        > object_state_t;

    typedef object_state_t::index<expiration_tag>::type obj_state_by_exp;
    typedef object_state_t::index<uri_tag>::type obj_state_by_uri;
    typedef object_state_t::index<xid_tag>::type obj_state_by_xid;

    /**
     * Functor for updating the expiration in the object state index
     */
    class change_expiration {
    public:
        change_expiration(uint64_t new_exp);

        void operator()(Processor::item& i);
    private:
        uint64_t new_exp;
    };

    /**
     * Functor for updating the transaction ID in the object state
     * index
     */
    class change_last_xid {
    public:
        change_last_xid(uint64_t new_last_xid);

        void operator()(Processor::item& i);
    private:
        uint64_t new_last_xid;
    };

    class PrngManager {
        // Change typedef for different generator type
        typedef boost::minstd_rand base_generator_type;
        typedef boost::uniform_int<> distribution_type;
        typedef boost::variate_generator<base_generator_type&, distribution_type> gen_type;
    public:
        PrngManager();
        // Define a uniform random number distribution of integer values between
        // -delta and delta inclusive.
        int getRandDelta(int delta);
    private:
        base_generator_type generator;
    } prng_manager;

    /**
     * Return a dithered version of a backoff value
     */
    int ditherBackoff(int backoff, int ditherPercent);

    /**
     * Store and index the state of managed objects
     */
    object_state_t obj_state;
    std::mutex item_mutex;

    /**
     * Processing delay to allow batching updates
     */
    uint64_t processingDelay;

    /**
     * Amount of time to wait before retrying policy
     * requests, in milliseconds
     */
    static const uint64_t DEFAULT_RETRY_DELAY = 1000*10;
    uint64_t retryDelay = DEFAULT_RETRY_DELAY;

    /**
     * prr timer duration in secs
     */
    static const uint64_t DEFAULT_PRR_TIMER_DURATION = 7200;
    uint64_t prrTimerDuration = DEFAULT_PRR_TIMER_DURATION;

    uint32_t peerHandshakeTimeout = 45000;
    uint32_t keepaliveTimeout = 120000;

    /**
     *  policy refresh timer duration in msecs
     */
    uint64_t policyRefTimerDuration = 1000*DEFAULT_PRR_TIMER_DURATION/2;

    /**
     * new connection timestamp in msecs
     */
    volatile int64_t newConnectiontime = 0;

   /**
    * is startup policy enabled
    */
    volatile bool startupPolicyEnabled = false;

    /**
     * local resolves only after a new connection till startupPolicyDuration
     */
    volatile bool local_resolve_after_connection;

    /**
     * Startup policy timeout in ms. This is the amount of time
     * from new connection that we would continue using the startup
     * policy to resolve Mos from startupdb.
     */
    uint64_t startupPolicyDuration;

    /**
     * If true convert EP redeclares to undeclare + declare
     */
    volatile bool force_ep_undeclares;

    /**
     * Processing thread
     */
    uv_loop_t* proc_loop;
    boost::atomic<bool> proc_active;
    /* Persistent policy from disk */
    boost::optional<std::string> opflexPolicyFile;
    util::ThreadManager s_threadManager;
    modb::ObjectStore startupdb;

    uv_async_t cleanup_async;
    uv_async_t proc_async;
    uv_async_t connect_async;
    uv_timer_t proc_timer;

    static void timer_callback(uv_timer_t* handle);
    static void cleanup_async_cb(uv_async_t *handle);
    static void proc_async_cb(uv_async_t *handle);
    static void connect_async_cb(uv_async_t *handle);

    bool hasWork(/* out */ obj_state_by_exp::iterator& it);
    void addRef(obj_state_by_exp::iterator& it,
                const modb::reference_t& up);
    void removeRef(obj_state_by_exp::iterator& it,
                   const modb::reference_t& up);
    void processItem(obj_state_by_exp::iterator& it);
    bool isOrphan(const item& item);
    bool isParentSyncObject(const item& item);
    void doProcess();
    void sendToRole(const item& it, uint64_t& newexp,
                    internal::OpflexMessage* req,
                    ofcore::OFConstants::OpflexRole role);
    bool resolveObj(modb::ClassInfo::class_type_t type, const item& it,
                    uint64_t& newexp, bool checkTime = true);
    bool declareObj(modb::ClassInfo::class_type_t type, const item& it,
                    uint64_t& newexp);
    void handleNewConnections();
    size_t readStartupPolicy();
    bool shouldResolveLocal();
    void resolveObjLocal(const modb::class_id_t& class_id,
                         const modb::URI& uri,
                         modb::mointernal::StoreClient::notif_t& notifs);
};

} /* namespace engine */
} /* namespace opflex */

#endif /* OPFLEX_ENGINE_PROCESSOR_H */
