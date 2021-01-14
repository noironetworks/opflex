/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for all maps for OpflexAgent GBP
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_GBPBPFMAPS_H
#define OPFLEXAGENT_GBPBPFMAPS_H

#include <linux/if_ether.h>
#include <boost/asio/ip/address.hpp>
#include <opflexagent/BpfMap.h>
#include <gbp.h>

namespace opflexagent {

class Conntrack4Map : public BpfMap {
public:
    Conntrack4Map() : BpfMap("conntrack4_map",
                             TC,
                             BPF_MAP_TYPE_HASH,
                             sizeof(struct ip4_tuple),
                             sizeof(struct flow_state),
                             CONNTRACK4_MAP_SIZE,
                             0) {};
    ~Conntrack4Map() {};
    virtual void dumpElem(std::ostream &out, const void *key, const void *value);
};

class Conntrack6Map : public BpfMap {
public:
    Conntrack6Map() : BpfMap("conntrack6_map",
                             TC,
                             BPF_MAP_TYPE_HASH,
                             sizeof(struct ip6_tuple),
                             sizeof(struct flow_state),
                             CONNTRACK6_MAP_SIZE,
                             0) {};
    ~Conntrack6Map() {};
    virtual void dumpElem(std::ostream &out, const void *key, const void *value);
};

class NextHop4Map : public BpfMap {
public:
    NextHop4Map() : BpfMap("nexthop4_map",
                           TC,
                           BPF_MAP_TYPE_HASH,
                           sizeof(__be32),
                           sizeof(struct next_hop),
                           NEXTHOP4_MAP_SIZE,
                           0) {};
    ~NextHop4Map() {};
    virtual void dumpElem(std::ostream &out, const void *key, const void *value);
};

class NextHop6Map : public BpfMap {
public:
    NextHop6Map() : BpfMap("nexthop6_map",
                           TC,
                           BPF_MAP_TYPE_HASH,
                           sizeof(struct ip6_addr),
                           sizeof(struct next_hop),
                           NEXTHOP6_MAP_SIZE,
                           0) {};
    ~NextHop6Map() {};
    virtual void dumpElem(std::ostream &out, const void *key, const void *value);
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_GBPBPFMAPS_H */
