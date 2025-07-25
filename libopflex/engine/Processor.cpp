/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for Processor class.
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


#include <ctime>
#include <uv.h>
#include <limits>
#include <cmath>
#include <random>
#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>

#include <boost/generator_iterator.hpp>
#include <boost/tuple/tuple.hpp>
#include "opflex/engine/internal/OpflexPEHandler.h"
#include "opflex/engine/internal/ProcessorMessage.h"
#include "opflex/engine/Processor.h"
#include "opflex/logging/internal/logging.hpp"

namespace opflex {
namespace engine {

using std::vector;
using std::pair;
using std::make_pair;
using modb::ObjectStore;
using modb::ClassInfo;
using modb::PropertyInfo;
using modb::class_id_t;
using modb::prop_id_t;
using modb::reference_t;
using modb::URI;
using modb::mointernal::StoreClient;
using modb::mointernal::ObjectInstance;
using modb::hash_value;
using ofcore::OFConstants;
using util::ThreadManager;

using namespace internal;

static const uint64_t DEFAULT_PROC_DELAY = 250;
static const uint64_t FIRST_XID = (uint64_t)1 << 63;
static const uint32_t MAX_PROCESS = 1024;

std::random_device rd;
std::mt19937 gen(rd());

Processor::Processor(ObjectStore* store_, ThreadManager& threadManager_)
    : AbstractObjectListener(store_),
      client(nullptr),
      serializer(store_),
      threadManager(threadManager_),
      pool(*this, threadManager_), nextXid(FIRST_XID),
      reportObservables(true),
      processingDelay(DEFAULT_PROC_DELAY),
      retryDelay(DEFAULT_RETRY_DELAY),
      proc_loop(nullptr),
      proc_active(false),
      startupdb(s_threadManager) {
    cleanup_async = {};
    proc_async = {};
    connect_async = {};
    proc_timer = {};
    // Invoke the generator once to spread entropy
    prng_manager.getRandDelta(10);
}

Processor::~Processor() {
    stop();
}

// get the current time in milliseconds since something
inline uint64_t now(uv_loop_t* loop) {
    return uv_now(loop);
}

Processor::change_expiration::change_expiration(uint64_t new_exp_)
    : new_exp(new_exp_) {}

Processor::PrngManager::PrngManager(void) {
    // Set the seed using time. This normally isn't a great
    // seed, but the entropy is quickly spread across the
    // bits with a few iterations.
    generator.seed(static_cast<unsigned long long>(std::time(0)));
}

void Processor::change_expiration::operator()(Processor::item& i) {
    i.expiration = new_exp;
}

Processor::change_last_xid::change_last_xid(uint64_t new_last_xid_)
    : new_last_xid(new_last_xid_) {}

void Processor::change_last_xid::operator()(Processor::item& i) {
    i.last_xid = new_last_xid;
}

void Processor::setPrrTimerDuration(uint64_t duration) {
    prrTimerDuration = duration;
    policyRefTimerDuration = 1000*prrTimerDuration/2;
}

// check whether the object state index has work for us
bool Processor::hasWork(/* out */ obj_state_by_exp::iterator& it) {
    if (obj_state.empty()) return false;
    obj_state_by_exp& exp_index = obj_state.get<expiration_tag>();
    it = exp_index.begin();
    if (it->expiration == 0 || now(proc_loop) >= it->expiration) return true;
    return false;
}

// add a reference if it doesn't already exist
void Processor::addRef(obj_state_by_exp::iterator& it,
                       const reference_t& up) {
    if (it->details->urirefs.find(up) == it->details->urirefs.end()) {
        obj_state_by_uri& uri_index = obj_state.get<uri_tag>();
        obj_state_by_uri::iterator uit = uri_index.find(up.second);

        if (uit == uri_index.end()) {
            LOG(DEBUG) << "Tracking new nonlocal item " << up.second << " from reference";
            obj_state.insert(item(up.second, up.first,
                                  0, policyRefTimerDuration,
                                  UNRESOLVED, false));
            uit = uri_index.find(up.second);
        }
        uit->details->refcount += 1;
        LOG(DEBUG) << "addref " << uit->uri.toString()
                   << " (from " << it->uri.toString() << ")"
                   << " " << uit->details->refcount
                   << " state " << ItemStateMap[uit->details->state];

        it->details->urirefs.insert(up);
    }
}

// remove a reference if it already exists.  If refcount is zero,
// schedule the reference for collection
void Processor::removeRef(obj_state_by_exp::iterator& it,
                          const reference_t& up) {
    if (it->details->urirefs.find(up) != it->details->urirefs.end()) {
        obj_state_by_uri& uri_index = obj_state.get<uri_tag>();
        obj_state_by_uri::iterator uit = uri_index.find(up.second);
        if (uit != uri_index.end()) {
            uit->details->refcount -= 1;
            LOG(DEBUG) << "removeref " << uit->uri.toString()
                       << " (from " << it->uri.toString() << ")"
                       << " " << uit->details->refcount
                       << " state " << ItemStateMap[uit->details->state];
            if (uit->details->refcount <= 0) {
                uint64_t nexp = now(proc_loop)+processingDelay;
                uri_index.modify(uit, Processor::change_expiration(nexp));
            }
        }
        it->details->urirefs.erase(up);
    }
}

size_t Processor::getRefCount(const URI& uri) {
    const std::lock_guard<std::mutex> lock(item_mutex);
    obj_state_by_uri& uri_index = obj_state.get<uri_tag>();
    obj_state_by_uri::iterator uit = uri_index.find(uri);
    if (uit != uri_index.end()) {
        return uit->details->refcount;
    }
    return 0;
}

bool Processor::isObjNew(const URI& uri) {
    const std::lock_guard<std::mutex> lock(item_mutex);
    obj_state_by_uri& uri_index = obj_state.get<uri_tag>();
    obj_state_by_uri::iterator uit = uri_index.find(uri);
    if (uit != uri_index.end()) {
        return uit->details->state == NEW;
    }
    return true;
}

// check if the object has a zero refcount and it has no remote
// ancestor that has a zero refcount.
bool Processor::isOrphan(const item& item) {
    // simplest case: refcount is nonzero or item is local
    // since startupdb is known state skip orphan check when using it
    if (item.details->local || item.details->refcount > 0 || shouldResolveLocal())
        return false;

    try {
        std::pair<URI, prop_id_t> parent(URI::ROOT, 0);
        if (client->getParent(item.details->class_id, item.uri, parent)) {
            obj_state_by_uri& uri_index = obj_state.get<uri_tag>();
            obj_state_by_uri::iterator uit = uri_index.find(parent.first);
            // parent missing
            if (uit == uri_index.end())
                return true;

            // the parent is local, so there can be no remote parent with
            // a nonzero refcount
            if (uit->details->local)
                return true;

            return isOrphan(*uit);
        }
    } catch (const std::out_of_range& e) {}
    return true;
}

// Check if an object is the highest-rank ancestor for objects that
// are synced to the server.  We don't bother syncing child objects
// since those will get synced when we sync the parent.
bool Processor::isParentSyncObject(const item& item) {
    try {
        const ClassInfo& ci = store->getClassInfo(item.details->class_id);
        std::pair<URI, prop_id_t> parent(URI::ROOT, 0);
        if (client->getParent(item.details->class_id, item.uri, parent)) {
            const ClassInfo& parent_ci = store->getPropClassInfo(parent.second);

            // The parent object will be synchronized
            if (ci.getType() == parent_ci.getType()) return false;

            return true;
        }
    } catch (const std::out_of_range& e) {}
    // possibly an unrooted object; sync anyway since it won't be
    // garbage-collected
    return true;
}

void Processor::sendToRole(const item& i, uint64_t& newexp,
                           OpflexMessage* req,
                           ofcore::OFConstants::OpflexRole role) {
    uint64_t xid = req->getReqXid();
    size_t pending = pool.sendToRole(req, role, false, i.uri.toString());
    i.details->pending_reqs = pending;

    obj_state_by_uri& uri_index = obj_state.get<uri_tag>();
    obj_state_by_uri::iterator uit = uri_index.find(i.uri);
    uri_index.modify(uit, change_last_xid(xid));

    if (pending > 0) {
        uint64_t nextRetryDelay =
            (uint64_t)std::pow(2, i.details->retry_count) * retryDelay;

	// Randomize the backoff by plus or minus ten percent
	nextRetryDelay = ditherBackoff(nextRetryDelay, 10);

        if (nextRetryDelay > policyRefTimerDuration)
            nextRetryDelay = policyRefTimerDuration;

        if (i.details->retry_count > 0) {
            LOG(DEBUG) << "Retrying dropped message for item "
                       << i.uri
                       << " (next attempt in " << nextRetryDelay << " ms)";
        }

        if (i.details->retry_count < 16)
            i.details->retry_count += 1;

        newexp = now(proc_loop) + nextRetryDelay;
    } else {
        i.details->retry_count = 0;
    }
}

bool Processor::shouldResolveLocal() {
    if (!startupPolicyEnabled) return false;

    uint64_t curtime = now(proc_loop);
    // check >= for duration 0 because now wont update till next uv_loop
    if (!opflexPolicyFile
       || ((newConnectiontime != 0)
           && (curtime >= (newConnectiontime + startupPolicyDuration)))
       || ((newConnectiontime == 0)
           && local_resolve_after_connection))
       return false;
    else
       return true;
}

void Processor::resolveObjLocal(const modb::class_id_t& class_id,
                                const modb::URI& uri,
                                StoreClient::notif_t& notifs) {
    if (!shouldResolveLocal()) return;
    std::shared_ptr<const modb::mointernal::ObjectInstance> oi;
    StoreClient& s_client = startupdb.getReadOnlyStoreClient();
    // Get from startupdb
    s_client.get(class_id, uri, oi);
    if (!oi) {
        LOG(DEBUG) << "Local policy missing for " << class_id
                   << " "  << uri;
    } else {
        LOG(DEBUG) << "Local policy resolved for " << class_id
                   << " " << uri;
        // Put in activedb
        if (client->putIfModified(class_id, uri, oi)) {
            client->queueNotification(class_id, uri, notifs);
            LOG(DEBUG) << "QUEUE NOTIF for " << class_id
                       << " : " << uri;
        }
        // check if this mo has a parent
        try {
            std::pair<modb::URI, modb::prop_id_t> parent(modb::URI::ROOT, 0);
            if (s_client.getParent(class_id, uri, parent)) {
                const modb::ClassInfo& parent_class =
                    startupdb.getPropClassInfo(parent.second);
                const modb::PropertyInfo& parent_prop =
                    parent_class.getProperty(parent.second);
                if (client->isPresent(parent_class.getId(), parent.first)) {
                    if (client->addChild(parent_class.getId(),
                                         parent.first,
                                         parent_prop.getId(),
                                         class_id,
                                         uri)) {
                        client->queueNotification(parent_class.getId(),
                                                  parent.first,
                                                  notifs);
                    }
                }
            }
        } catch (const std::out_of_range& e) {
            // no parent class or property found
            LOG(ERROR) << "Invalid parent or property for "
                       << uri;
        }
        // recursively add children
        const ClassInfo& ci = startupdb.getClassInfo(class_id);
        const ClassInfo::property_map_t& pmap = ci.getProperties();
        ClassInfo::property_map_t::const_iterator it;
        for (it = pmap.begin(); it != pmap.end(); ++it) {
            if (it->second.getType() == PropertyInfo::COMPOSITE) {
                class_id_t prop_class = it->second.getClassId();
                prop_id_t prop_id = it->second.getId();
                std::vector<URI> children;
                s_client.getChildren(class_id, uri, prop_id, prop_class, children);
                std::vector<URI>::iterator cit;
                for (cit = children.begin(); cit != children.end(); ++cit) {
                    resolveObjLocal(prop_class, *cit, notifs);
                }
            }
        }
    }
}

bool Processor::resolveObj(ClassInfo::class_type_t type, const item& i,
                           uint64_t& newexp, bool checkTime) {
    uint64_t curTime = now(proc_loop);
    bool shouldRefresh =
        (i.details->resolve_time == 0) ||
        (curTime > (i.details->resolve_time + i.details->refresh_rate/2));
    bool shouldRetry =
        (i.details->pending_reqs != 0) &&
        (curTime > (i.details->resolve_time + retryDelay/2));

    if (checkTime && !shouldRefresh && !shouldRetry)
        return false;

    switch (type) {
    case ClassInfo::POLICY:
        {
            LOG(DEBUG) << "Resolving policy " << i.uri;
            if (checkTime && shouldResolveLocal()) {
                StoreClient::notif_t notifs;
                resolveObjLocal(i.details->class_id, i.uri, notifs);
                client->deliverNotifications(notifs);
            }
            i.details->resolve_time = curTime;
            vector<reference_t> refs;
            refs.emplace_back(i.details->class_id, i.uri);
            PolicyResolveReq* req =
                new PolicyResolveReq(this, nextXid++, refs);
            sendToRole(i, newexp, req, OFConstants::POLICY_REPOSITORY);
            return true;
        }
        break;
    case ClassInfo::REMOTE_ENDPOINT:
        {
            LOG(DEBUG) << "Resolving remote endpoint " << i.uri;
            if (checkTime && shouldResolveLocal()) {
                StoreClient::notif_t notifs;
                resolveObjLocal(i.details->class_id, i.uri, notifs);
                client->deliverNotifications(notifs);
            }
            i.details->resolve_time = curTime;
            vector<reference_t> refs;
            refs.emplace_back(i.details->class_id, i.uri);
            EndpointResolveReq* req =
                new EndpointResolveReq(this, nextXid++, refs);
            sendToRole(i, newexp, req, OFConstants::ENDPOINT_REGISTRY);
            return true;
        }
        break;
    default:
        // do nothing
        return false;
        break;
    }
}

void Processor::overrideObservableReporting(class_id_t class_id, bool reportable) {
    overrideReportable[class_id] = reportable;
}

bool Processor::isObservableReportable(class_id_t class_id) {
    auto iter = overrideReportable.find(class_id);
    if (iter != overrideReportable.end()) {
        return iter->second;
    }
    // all observables are reportable by default
    return true;
}

void Processor::disableObservableReporting() {
    reportObservables = false;
}

bool Processor::declareObj(ClassInfo::class_type_t type, const item& i,
                           uint64_t& newexp) {
    uint64_t curTime = now(proc_loop);
    switch (type) {
    case ClassInfo::LOCAL_ENDPOINT:
        if (isParentSyncObject(i)) {
            LOG(DEBUG) << "Declaring local endpoint " << i.uri;
            i.details->resolve_time = curTime;
            vector<reference_t> refs;
            refs.emplace_back(i.details->class_id, i.uri);
            EndpointDeclareReq* req =
                new EndpointDeclareReq(this, nextXid++, refs);
            sendToRole(i, newexp, req, OFConstants::ENDPOINT_REGISTRY);
        }
        return true;
    case ClassInfo::OBSERVABLE:
        if (isParentSyncObject(i) && reportObservables && isObservableReportable(i.details->class_id)) {
            LOG(TRACE) << "Declaring local observable " << i.uri;
            i.details->resolve_time = curTime;
            vector<reference_t> refs;
            refs.emplace_back(i.details->class_id, i.uri);
            StateReportReq* req = new StateReportReq(this, nextXid++, refs);
            sendToRole(i, newexp, req, OFConstants::OBSERVER);
        }
        return true;
    default:
        // do nothing
        return false;
    }
}

// Process the item.  This is where we do most of the actual work of
// syncing the managed object over opflex
void Processor::processItem(obj_state_by_exp::iterator& it) {
    StoreClient::notif_t notifs;

    std::unique_lock<std::mutex> guard(item_mutex);
    ItemState curState = it->details->state;
    size_t curRefCount = it->details->refcount;
    bool local = it->details->local;
    bool undeclare = false;

    obj_state_by_exp& exp_index = obj_state.get<expiration_tag>();
    uint64_t newexp = std::numeric_limits<uint64_t>::max();
    if (it->details->refresh_rate > 0) {
        if (it->details->pending_reqs > 0)
            newexp = now(proc_loop) + retryDelay;
        else
            newexp = now(proc_loop) + it->details->refresh_rate;
    }

    const ClassInfo& ci = store->getClassInfo(it->details->class_id);
    if (ci.getType() != ClassInfo::OBSERVABLE) {
        LOG(DEBUG) << "Processing " << (local ? "local" : "nonlocal")
                   << " item " << it->uri.toString()
                   << " of class " << ci.getName()
                   << " and type " << ci.getType()
                   << " in state " << ItemStateMap[curState];
    }

    ItemState newState;

    switch (curState) {
    case NEW:
        newState = IN_SYNC;
        break;
    case UPDATED:
        newState = IN_SYNC;
        if (ci.getType() == ClassInfo::LOCAL_ENDPOINT) {
            undeclare = force_ep_undeclares;
        }
        break;
    case PENDING_DELETE:
        if (local)
            newState = IN_SYNC;
        else
            newState = REMOTE;
        break;
    default:
        newState = curState;
        break;
    }

    std::shared_ptr<const ObjectInstance> oi;
    if (!client->get(it->details->class_id, it->uri, oi)) {
        // item removed
        switch (curState) {
        case UNRESOLVED:
            break;
        default:
            newState = DELETED;
            break;
        }
    }

    // Check whether this item needs to be garbage collected
    if (oi && isOrphan(*it)) {
        switch (curState) {
        case NEW:
        case REMOTE:
            {
                // requeue new items so if there are any pending references
                // we won't remove them right away
                LOG(DEBUG) << "Queuing delete for orphan " << it->uri.toString();
                newState = PENDING_DELETE;
                newexp = now(proc_loop) + processingDelay;
                obj_state_by_exp& exp_index = obj_state.get<expiration_tag>();
                exp_index.modify(it, change_expiration(newexp));
                break;
            }
        default:
            {
                // Remove object from store and dispatch a notification
                LOG(DEBUG) << "Removing orphan object " << it->uri.toString();
                client->remove(it->details->class_id,
                               it->uri,
                               false, &notifs);
                client->queueNotification(it->details->class_id, it->uri,
                                          notifs);
                oi.reset();
                newState = DELETED;
                break;
            }
        }
    }

    // check for references to other objects and update the reference
    // count.  Create a new state object or clear the object as
    // needed.
    std::unordered_set<reference_t> visited;
    if (oi) {
        for (const ClassInfo::property_map_t::value_type& p : ci.getProperties()) {
            if (p.second.getType() == PropertyInfo::REFERENCE) {
                if (p.second.getCardinality() == PropertyInfo::SCALAR) {
                    if (oi->isSet(p.first,
                                  PropertyInfo::REFERENCE,
                                  PropertyInfo::SCALAR)) {
                        reference_t u = oi->getReference(p.first);
                        visited.insert(u);
                        addRef(it, u);
                    }
                } else {
                    size_t c = oi->getReferenceSize(p.first);
                    for (size_t i = 0; i < c; ++i) {
                        reference_t u = oi->getReference(p.first, i);
                        visited.insert(u);
                        addRef(it, u);
                    }
                }
            }
        }
    }
    std::unordered_set<reference_t> existing(it->details->urirefs);
    for (const reference_t& up : existing) {
        if (visited.find(up) == visited.end()) {
            removeRef(it, up);
        }
    }

    if (curRefCount > 0) {
        resolveObj(ci.getType(), *it, newexp);
        newState = RESOLVED;
    } else if (oi) {
        // Force undeclare before declaring the same object
        if (undeclare) {
                LOG(DEBUG) << "Undeclaring " << it->uri.toString();
                vector<reference_t> refs;
                refs.emplace_back(it->details->class_id, it->uri);
                EndpointUndeclareReq* req =
                    new EndpointUndeclareReq(this, nextXid++, refs);
                pool.sendToRole(req, OFConstants::ENDPOINT_REGISTRY);
        }
        if (declareObj(ci.getType(), *it, newexp))
            newState = IN_SYNC;
    }

    if (newState == DELETED) {
        client->removeChildren(it->details->class_id,
                               it->uri,
                               &notifs);

        switch (ci.getType()) {
        case ClassInfo::POLICY:
            if (it->details->resolve_time > 0) {
                LOG(DEBUG) << "Unresolving " << it->uri.toString();
                vector<reference_t> refs;
                refs.emplace_back(it->details->class_id, it->uri);
                PolicyUnresolveReq* req =
                    new PolicyUnresolveReq(this, nextXid++, refs);
                pool.sendToRole(req, OFConstants::POLICY_REPOSITORY);
            }
            break;
        case ClassInfo::REMOTE_ENDPOINT:
            if (it->details->resolve_time > 0) {
                LOG(DEBUG) << "Unresolving " << it->uri.toString();
                vector<reference_t> refs;
                refs.emplace_back(it->details->class_id, it->uri);
                EndpointUnresolveReq* req =
                    new EndpointUnresolveReq(this, nextXid++, refs);
                pool.sendToRole(req, OFConstants::ENDPOINT_REGISTRY);
            }
            break;
        case ClassInfo::LOCAL_ENDPOINT:
            {
                LOG(DEBUG) << "Undeclaring " << it->uri.toString();
                vector<reference_t> refs;
                refs.emplace_back(it->details->class_id, it->uri);
                EndpointUndeclareReq* req =
                    new EndpointUndeclareReq(this, nextXid++, refs);
                pool.sendToRole(req, OFConstants::ENDPOINT_REGISTRY);
            }
            break;
        default:
            // do nothing
            break;
        }

        if (ci.getType() != ClassInfo::OBSERVABLE) {
            LOG(DEBUG) << "Purging state for " << it->uri.toString()
                       << " in state " << ItemStateMap[it->details->state];
        }
        exp_index.erase(it);
    } else {
        it->details->state = newState;
        exp_index.modify(it, Processor::change_expiration(newexp));
    }

    guard.unlock();

    if (!notifs.empty())
        client->deliverNotifications(notifs);
}

void Processor::doProcess() {
    obj_state_by_exp::iterator it;
    uint32_t proc_count = 0;
    while (proc_active) {
        {
            const std::lock_guard<std::mutex> lock(item_mutex);
            if (!hasWork(it))
                break;
        }
        processItem(it);
        proc_count += 1;
        if (proc_count >= MAX_PROCESS && proc_active) {
            uv_async_send(&proc_async);
            break;
        }
    }
}

void Processor::proc_async_cb(uv_async_t* handle) {
    Processor* processor = (Processor*)handle->data;
    processor->doProcess();
}

void Processor::connect_async_cb(uv_async_t* handle) {
    Processor* processor = (Processor*)handle->data;
    processor->handleNewConnections();
}

static void register_listeners(void* processor, const modb::ClassInfo& ci) {
    Processor* p = (Processor*)processor;
    p->listen(ci.getId());
}

void Processor::timer_callback(uv_timer_t* handle) {
    Processor* processor = (Processor*)handle->data;
    processor->doProcess();
}

void Processor::cleanup_async_cb(uv_async_t* handle) {
    Processor* processor = (Processor*)handle->data;
    uv_timer_stop(&processor->proc_timer);
    uv_close((uv_handle_t*)&processor->proc_timer, NULL);
    uv_close((uv_handle_t*)&processor->proc_async, NULL);
    uv_close((uv_handle_t*)&processor->connect_async, NULL);
    uv_close((uv_handle_t*)handle, NULL);
}

void Processor::setTunnelMac(const opflex::modb::MAC &mac) {
    pool.setTunnelMac(mac);
}

bool Processor::waitForPendingItems(uint32_t& wait) {
    return pool.waitForPendingItems(wait);
}

void Processor::setStartupPolicy(boost::optional<std::string>& file,
                                 const modb::ModelMetadata& model,
                                 uint64_t& duration,
                                 bool& enabled,
                                 bool& resolve_after_connection) {
    if (enabled == false) {
        LOG(INFO) << "Startup policy disabled";
        return;
    }

    startupPolicyEnabled = enabled;
    opflexPolicyFile = file;
    if (file) {
        startupdb.init(model);
        startupPolicyDuration = duration;
        local_resolve_after_connection = resolve_after_connection;
    }
}

size_t Processor::readStartupPolicy() {
    if (!opflexPolicyFile) {
        LOG(DEBUG) << "Skip missing startup policy read";
        return 0;
    }

    FILE* pfile = fopen(opflexPolicyFile.get().c_str(), "r");
    if (pfile == NULL) {
        LOG(ERROR) << "Could not open policy file "
                   << opflexPolicyFile.get() << " for reading";
        return 0;
    }

    startupdb.start();
    MOSerializer s_serializer(&startupdb);
    StoreClient& s_client = startupdb.getStoreClient("_SYSTEM_");
    return s_serializer.readMOs(pfile, s_client, true);
}

void Processor::start(ofcore::OFConstants::OpflexElementMode agent_mode) {
    if (proc_active) return;
    proc_active = true;
    pool.setClientMode(agent_mode);

    LOG(DEBUG) << "Starting OpFlex Processor";

    if (startupPolicyEnabled) {
        size_t objs = readStartupPolicy();
        LOG(DEBUG) << "Read " << objs << " objects from startup policy";
        if (objs == 0) {
           LOG(INFO) << "Disabling startup policy due to read failure";
           startupPolicyEnabled = false;
        }
    }

    client = &store->getStoreClient("_SYSTEM_");
    store->forEachClass(&register_listeners, this);

    proc_loop = threadManager.initTask("processor");
    uv_timer_init(proc_loop, &proc_timer);
    cleanup_async.data = this;
    uv_async_init(proc_loop, &cleanup_async, cleanup_async_cb);
    proc_async.data = this;
    uv_async_init(proc_loop, &proc_async, proc_async_cb);
    connect_async.data = this;
    uv_async_init(proc_loop, &connect_async, connect_async_cb);
    proc_timer.data = this;
    uv_timer_start(&proc_timer, &timer_callback,
                   processingDelay, processingDelay);
    threadManager.startTask("processor");

    pool.start();
}

void Processor::stop() {
    if (!proc_active) return;

    LOG(DEBUG) << "Stopping OpFlex Processor";
    {
        const std::lock_guard<std::mutex> lock(item_mutex);
        proc_active = false;
    }

    unlisten();

    uv_async_send(&cleanup_async);
    threadManager.stopTask("processor");

    pool.stop();
}

void Processor::objectUpdated(modb::class_id_t class_id,
                              const modb::URI& uri) {
    const std::lock_guard<std::mutex> lock(item_mutex);
    if (!proc_active) return;

    obj_state_by_uri& uri_index = obj_state.get<uri_tag>();
    obj_state_by_uri::iterator uit = uri_index.find(uri);

    uint64_t curtime = now(proc_loop);

    bool present;
    bool local = false;
    std::shared_ptr<const ObjectInstance> oi;
    if ((present = client->get(class_id, uri, oi))) {
        local = oi->isLocal();
    }

    if (uit == uri_index.end()) {
        if (present) {
            const ClassInfo& ci = store->getClassInfo(class_id);
            if (ci.getType() != ClassInfo::OBSERVABLE) {
                LOG(DEBUG) << "Tracking new " << (local ? "local" : "nonlocal")
                           << " item " << uri << " from update";
            }
            uint64_t nexp = 0;
            if (local) nexp = curtime+processingDelay;
            double prrRange1 = prrTimerDuration/3;
            double prrRange2 = prrTimerDuration/2;
            std::uniform_int_distribution<> distribution(prrRange1,prrRange2);
            uint64_t prrRandVal = distribution(gen);
            policyRefTimerDuration = prrRandVal*1000;
            obj_state.insert(item(uri, class_id,
                                  nexp, policyRefTimerDuration,
                                  local ? NEW : REMOTE, local));
        }
    } else {
        if (uit->details->local) {
            uit->details->state = UPDATED;
            uri_index.modify(uit, change_expiration(curtime+processingDelay));
            uri_index.modify(uit, change_last_xid(0));
        } else  {
            uri_index.modify(uit, change_expiration(curtime));
        }
    }
    uv_async_send(&proc_async);
}

void Processor::setOpflexIdentity(const std::string& name,
                                  const std::string& domain) {
    pool.setOpflexIdentity(name, domain);
}

void Processor::setOpflexIdentity(const std::string& name,
                                  const std::string& domain,
                                  const std::string& location) {
    pool.setOpflexIdentity(name, domain, location);
}

void Processor::enableSSL(const std::string& caStorePath,
                          bool verifyPeers) {
    pool.enableSSL(caStorePath,
                   verifyPeers);
}

void Processor::enableSSL(const std::string& caStorePath,
                          const std::string& keyAndCertFilePath,
                          const std::string& passphrase,
                          bool verifyPeers) {
    pool.enableSSL(caStorePath,
                   keyAndCertFilePath,
                   passphrase,
                   verifyPeers);
}

void Processor::addPeer(const std::string& hostname,
                        int port) {
    pool.addPeer(hostname, port);
}

void
Processor::registerPeerStatusListener(ofcore::PeerStatusListener* listener) {
    pool.registerPeerStatusListener(listener);
}

OpflexHandler* Processor::newHandler(OpflexConnection* conn) {
    return new OpflexPEHandler(conn, this);
}

void Processor::handleNewConnections() {
    const std::lock_guard<std::mutex> lock(item_mutex);
    obj_state_by_uri& uri_index = obj_state.get<uri_tag>();

    // Only set this for the first connection after startup
    if (newConnectiontime == 0) {
        newConnectiontime = now(proc_loop);
    }

    for (const item& i : obj_state) {
        uint64_t newexp = i.expiration;
        const ClassInfo& ci = store->getClassInfo(i.details->class_id);
	obj_state_by_uri::iterator uit = uri_index.find(i.uri);
        if (i.details->state == IN_SYNC) {
            declareObj(ci.getType(), i, newexp);
        }
        if (i.details->state == RESOLVED) {
            resolveObj(ci.getType(), i, newexp, false);
        }
	if (newexp != i.expiration) {
            uri_index.modify(uit, Processor::change_expiration(newexp));
        }
    }
}

void Processor::connectionReady(OpflexConnection* conn) {
    uv_async_send(&connect_async);
}

void Processor::responseReceived(uint64_t reqId) {
    const std::lock_guard<std::mutex> lock(item_mutex);
    obj_state_by_xid& xid_index = obj_state.get<xid_tag>();
    obj_state_by_xid::iterator xi0,xi1;
    boost::tuples::tie(xi0,xi1)=xid_index.equal_range(reqId);

    std::unordered_set<URI> items;
    while (xi0 != xi1) {
        items.insert(xi0->uri);
        ++xi0;
    }

    obj_state_by_uri& uri_index = obj_state.get<uri_tag>();

    for (const URI& uri : items) {
        obj_state_by_uri::iterator uit = uri_index.find(uri);
        if (uit == uri_index.end()) continue;

        if (uit->details->pending_reqs > 0)
            uit->details->pending_reqs -= 1;

        if (uit->details->pending_reqs == 0) {
            // All peers responded to the message
            uit->details->retry_count = 0;
            uri_index.modify(uit,
                             change_expiration(uit->details->resolve_time +
                                               uit->details->refresh_rate));
        }
    }
}

int Processor::PrngManager::getRandDelta(int delta) {
    gen_type die_gen(generator, distribution_type(-delta, delta));
    boost::generator_iterator<gen_type> die(&die_gen);
    return *die;
}

int Processor::ditherBackoff(int backoff, int ditherPercent) {
    return backoff + prng_manager.getRandDelta((backoff*ditherPercent)/100);
}

} /* namespace engine */
} /* namespace opflex */
