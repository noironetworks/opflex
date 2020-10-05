/* Copyright (c) 2020 Cisco Systems
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <linux/bpf_helpers.h>
#include <linux/bpf_endian.h>
#include <linux/checksum.h>
#include <linux/pkt_cls.h>
#include <linux/bool.h>
#include <gbp_maps.h>
#include <ip.h>

static __always_inline
int process_flow(struct flow_state *flow, int rev, struct __sk_buff *skb)
{
    /* explicity drop the packet */
    if (!flow->allow)
        return TC_ACT_SHOT;

    /* allow reply */
    if (flow->rev ^ rev) {
        if (!flow->allow_reflexive)
            return TC_ACT_SHOT;
    }

    if (!flow->estb) {
        if (flow->rev ^ rev)
            flow->estb = 1;
    }
    
    flow->packets[rev]++;
    flow->bytes[rev] += skb->len;
    flow->lasttime = bpf_ktime_get_ns();

    return 0;
}
    
static __always_inline
int process_ip4(void *data, __u64 off, void *data_end, struct __sk_buff *skb, bool from_ep)
{
    struct pktmeta meta = {};
    struct ip4_tuple ip4 = {};
    struct flow_state *existing_flow, flow = {};
    int rev, ret;

    ret = parse_ip4(data, off, data_end, &ip4, &meta);
    if (ret < 0)
        return 0;

    rev = ip4_tuple_normalize(&ip4);
    existing_flow = bpf_map_lookup_elem(&conntrack4_map, &ip4);
    if (existing_flow)
        return process_flow(existing_flow, rev, skb);

    flow.rev = rev;
    flow.allow = 1;
    flow.allow_reflexive = 1;
    flow.protocol = meta.ip_proto;
    flow.packets[rev]++;
    flow.bytes[rev] += skb->len;
    flow.lasttime = bpf_ktime_get_ns();

    bpf_map_update_elem(&conntrack4_map, &ip4, &flow, BPF_ANY);
    
    return 0;
}

static __always_inline
int process_ip6(void *data, __u64 off, void *data_end, struct __sk_buff *skb, bool from_ep)
{
    struct pktmeta meta = {};
    struct ip6_tuple ip6 = {};
    struct flow_state *existing_flow, flow = {};
    int rev, ret;

    ret = parse_ip6(data, off, data_end, &ip6, &meta);
    if (ret < 0)
        return 0;

    rev = ip6_tuple_normalize(&ip6);
    existing_flow = bpf_map_lookup_elem(&conntrack6_map, &ip6);
    if (existing_flow)
        return process_flow(existing_flow, rev, skb);

    flow.rev = rev;
    flow.allow = 1;
    flow.allow_reflexive = 1;
    flow.protocol = meta.ip_proto;
    flow.packets[rev]++;
    flow.bytes[rev] += skb->len;
    flow.lasttime = bpf_ktime_get_ns();

    bpf_map_update_elem(&conntrack6_map, &ip6, &flow, BPF_ANY);

    return 0;
}

/* from endpoint */
SEC("ep-ingress")
int ep_ingress(struct __sk_buff *ctx)
{
    void *data, *data_end;
    struct ethhdr *eth;
    __u32 eth_proto;
    __u32 nh_off;
    bool from_ep = true;
    int ret = 0;

    bpf_clear_cb(ctx);
    bpf_set_eth(ctx, data, data_end, nh_off, eth);

    eth_proto = eth->h_proto;
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        ret = process_ip4(data, nh_off, data_end, ctx, from_ep);
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ret = process_ip6(data, nh_off, data_end, ctx, from_ep);
    } else {
        return 0;
    }

    return ret;
}

/* to endpoint */
SEC("ep-egress")
int ep_egress(struct __sk_buff *ctx)
{
    void *data, *data_end;
    struct ethhdr *eth;
    __u32 eth_proto;
    __u32 nh_off;
    bool from_ep = false;
    int ret = 0;

    bpf_clear_cb(ctx);
    bpf_set_eth(ctx, data, data_end, nh_off, eth);

    eth_proto = eth->h_proto;
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        ret = process_ip4(data, nh_off, data_end, ctx, from_ep);
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        ret = process_ip6(data, nh_off, data_end, ctx, from_ep);
    } else {
        return 0;
    }

    return ret;
}

char _license[] SEC("license") = "GPL";
