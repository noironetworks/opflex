/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * gbp struct defines common to ebpf maps and agent code
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef __GBP_H__
#define __GBP_H__

#ifdef __cplusplus
#include <iostream>
#endif

#define CONNTRACK4_MAP_SIZE 65535
#define CONNTRACK6_MAP_SIZE 65535
#define NEXTHOP4_MAP_SIZE 65535
#define NEXTHOP6_MAP_SIZE 65535

struct l4_ports {
    __be16 dport;
    __be16 sport;
#ifdef __cplusplus
   friend std::ostream& operator <<(std::ostream& out,
                                    const struct l4_ports& v) {
        return out << std::hex << "{" << ntohs(v.dport)
                               << ',' << ntohs(v.sport) << '}';
   }
#endif
};

struct ip4_tuple {
    __be32 dip;
    __be32 sip;
    struct l4_ports l4;
    __u8 proto;
#ifdef __cplusplus
        friend std::ostream& operator <<(std::ostream& out,
                                         const struct ip4_tuple& v) {
                return out << std::hex << '{' << ntohl(v.dip)
                           << ',' << ntohl(v.sip) << ','
                           << v.l4 << ',' << (int)v.proto << '}';
        }
#endif
};

struct ip6_tuple {
    __be32 dip[4];
    __be32 sip[4];
    struct l4_ports l4;
    __u8 proto;
#ifdef __cplusplus
        friend std::ostream& operator <<(std::ostream& out,
                                         const struct ip6_tuple& v) {
                out << std::hex << '{' << '[';
                for (int i = 0; i < 4; i++) {
                        out << std::hex << v.dip[i];
                        if (i < 3)
                                out << ',';
                }
                out << ']' << ',' << '[';
                for (int i = 0; i < 4; i++) {
                        out << std::hex << v.sip[i];
                        if (i < 3)
                                out << ',';
                }
                out << ']' << ',' << v.l4 << ',' << (int)v.proto << '}';

                return out;
        }
#endif
};

struct ip6_addr {
    __be32 addr[4];
#ifdef __cplusplus
    friend std::ostream& operator <<(std::ostream& out,
                                     const struct ip6_addr& v) {
        out << std::hex << '{' << '[';
        for (int i = 0; i < 4; i++) {
                out << std::hex << v.addr[i];
                if (i < 3)
                        out << ',';
        }
        out << ']' << '}';
        return out;
    }
#endif
};

union macaddr {
        struct {
                __u32 p1;
                __u16 p2;
        } tuple;
        unsigned char addr[6];
#ifdef __cplusplus
    friend std::ostream& operator <<(std::ostream& out,
                                     const union macaddr& v) {
        out << std::hex << '{'
            << v.tuple.p1 << ',' << v.tuple.p2
            << '}';
        return out;
    }
#endif
};

#define GW_MAC { .addr = { 0x0, 0x22, 0xbd, 0xf8, 0x19, 0xff } }

struct next_hop_local {
    union macaddr mac;
};

struct next_hop_remote {
    struct bpf_tunnel_key tunnel_key;
};

struct next_hop {
    int ifindex;
    __u8 is_local:1,
         reserve:7;
    union {
        struct next_hop_local local;
        struct next_hop_remote remote;
    };
#ifdef __cplusplus
    friend std::ostream& operator <<(std::ostream& out,
                                     const struct next_hop& n) {
        out << '{' << n.ifindex << ',';
        if (n.is_local) {
            out << std::hex << '{' << n.local.mac << '}';
        } else {
            out << std::hex << '{' << n.remote.tunnel_key.tunnel_id << ','
                                   << n.remote.tunnel_key.remote_ipv4 << '}';
        }
        out << '}';
        return out;
    }
#endif
};

struct flow_state {
    __u16 estb:1,
          rev:1,      /* tuple was swapped on creation */
          allow:1,    /* allow both dir */
          allow_reflexive:1, /* allow reply */
          kill:1, /* schedule this flow for faster termination */
          reserve:11;
    struct next_hop next_hop[2];
    __u64 packets[2];
    __u64 bytes[2];
    __u64 lasttime;
    __u32 flags;
#ifdef __cplusplus
        friend std::ostream& operator <<(std::ostream& out,
                                         const struct flow_state& v) {
                out << '{'
                    << '{' << v.estb
                    << v.rev << v.allow << v.allow_reflexive
                    << v.kill << '}' << ','
                    << '{' << v.next_hop[0] << '}' << ','
                    << '{' << v.next_hop[1] << '}' << ','
                    << v.packets[0] << ',' << v.packets[1] << ','
                    << v.bytes[0] << ',' << v.bytes[1] << ','
                    << v.lasttime << '}';

                return out;
        }
#endif
};

#endif /* __GBP_H__ */
