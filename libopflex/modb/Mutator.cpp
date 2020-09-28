/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for Mutator class.
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


#include <utility>
#include <stdexcept>
#include <unordered_set>

#include "opflex/ofcore/OFFramework.h"
#include "opflex/modb/Mutator.h"
#include "opflex/modb/mo-internal/StoreClient.h"
#include "opflex/modb/internal/ObjectStore.h"

namespace opflex {
namespace modb {

using std::pair;
using std::make_pair;

using mointernal::StoreClient;
using mointernal::ObjectInstance;

typedef std::unordered_set<reference_t > uri_set_t;
typedef std::unordered_map<prop_id_t, uri_set_t> prop_uri_map_t;
typedef std::unordered_map<reference_t, prop_uri_map_t> uri_prop_uri_map_t;
typedef std::unordered_map<URI, std::shared_ptr<ObjectInstance> > obj_map_t;

class Mutator::MutatorImpl {
public:
    MutatorImpl(ofcore::OFFramework& framework_,
                const std::string& owner)
        : framework(framework_),
          client(framework.getStore().getStoreClient(owner)) { }

    ofcore::OFFramework& framework;
    StoreClient& client;

    // modified objects
    obj_map_t obj_map;

    // removed objects
    std::unordered_set<pair<class_id_t, URI> > removed_objects;

    // added children
    uri_prop_uri_map_t added_children;
};

Mutator::Mutator(ofcore::OFFramework& framework,
                 const std::string& owner)
    : pimpl(new MutatorImpl(framework, owner)) {
    pimpl->framework.registerTLMutator(*this);
}

Mutator::~Mutator() {
    pimpl->framework.clearTLMutator();
    delete pimpl;
}

std::shared_ptr<ObjectInstance>& Mutator::addChild(class_id_t parent_class,
                                                  const URI& parent_uri,
                                                  prop_id_t parent_prop,
                                                  class_id_t child_class,
                                                  const URI& child_uri) {
    pimpl->added_children
        [make_pair(child_class,child_uri)]
        [parent_prop].insert(make_pair(parent_class,parent_uri));
    return modify(child_class, child_uri);
}

std::shared_ptr<ObjectInstance>& Mutator::modify(class_id_t class_id,
                                               const URI& uri) {
    // check for copy in mutator
    auto it = pimpl->obj_map.find(uri);
    if (it != pimpl->obj_map.end()) return it->second;
    std::shared_ptr<ObjectInstance> copy;
    std::shared_ptr<const ObjectInstance> oi;
    if (pimpl->client.get(class_id, uri, oi)) {
        copy = std::make_shared<ObjectInstance>(*oi.get());
    } else {
        // create new object
        copy = std::make_shared<ObjectInstance>(class_id);
    }

    pair<obj_map_t::iterator, bool> r =
        pimpl->obj_map.insert(obj_map_t::value_type(uri, copy));
    return r.first->second;
}

void Mutator::remove(class_id_t class_id, const URI& uri) {
    pimpl->removed_objects.insert(make_pair(class_id, uri));
}

void Mutator::commit() {
    StoreClient::notif_t raw_notifs;
    StoreClient::notif_t notifs;
    for (obj_map_t::value_type& objt : pimpl->obj_map) {
        if (pimpl->client.putIfModified(objt.second->getClassId(),
                                        objt.first,
                                        objt.second))
            raw_notifs[objt.first] = objt.second->getClassId();

    }
    for (uri_prop_uri_map_t::value_type& upt : pimpl->added_children) {
        for (prop_uri_map_t::value_type& pt : upt.second) {
            for (const reference_t& ut : pt.second) {
                if (pimpl->client.addChild(ut.first, ut.second, pt.first,
                                           upt.first.first, upt.first.second))
                    raw_notifs[upt.first.second] = upt.first.first;

            }
        }
    }

    for (const StoreClient::notif_t::value_type& nt : raw_notifs) {
        pimpl->client.queueNotification(nt.second, nt.first, notifs);
    }

    for (const reference_t& rt : pimpl->removed_objects) {
        if (pimpl->client.remove(rt.first, rt.second, false))
            pimpl->client.queueNotification(rt.first, rt.second, notifs);
    }

    pimpl->obj_map.clear();
    pimpl->removed_objects.clear();
    pimpl->added_children.clear();

    pimpl->client.deliverNotifications(notifs);
}

} /* namespace modb */
} /* namespace opflex */
