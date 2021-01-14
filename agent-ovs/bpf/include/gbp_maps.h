/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * gbp_maps defines
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __GBP_MAPS_H__
#define __GBP_MAPS_H__

#include <linux/bpf_helpers.h>
#include "bpf_elf.h"
#include "gbp.h"

struct bpf_elf_map SEC("maps") nexthop4_map = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__be32),
	.size_value = sizeof(struct next_hop),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = NEXTHOP4_MAP_SIZE,
};

struct bpf_elf_map SEC("maps") nexthop6_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct ip6_addr),
        .size_value = sizeof(struct next_hop),
        .pinning = PIN_GLOBAL_NS,
        .max_elem = NEXTHOP6_MAP_SIZE,
};

/* conntrack ip4 */
struct bpf_elf_map SEC("maps") conntrack4_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct ip4_tuple),
        .size_value = sizeof(struct flow_state),
        .pinning = PIN_GLOBAL_NS,
        .max_elem = CONNTRACK4_MAP_SIZE,
};

/* conntrack ip6 */
struct bpf_elf_map SEC("maps") conntrack6_map = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct ip6_tuple),
        .size_value = sizeof(struct flow_state),
        .pinning = PIN_GLOBAL_NS,
        .max_elem = CONNTRACK6_MAP_SIZE,
};

#endif /* __GBP_MAPS_H__ */
