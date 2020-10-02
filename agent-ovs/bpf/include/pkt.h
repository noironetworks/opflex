#ifndef __PKT_H__
#define __PKT_H__

#define bpf_set_eth(skb, data, data_end, nh_off, eth) { \
        nh_off = sizeof(struct ethhdr);                 \
        data_end = (void *)(long)skb->data_end;         \
        data = (void *)(long)skb->data;                 \
        if (data + nh_off > data_end)                   \
                return TC_ACT_SHOT;                     \
        eth = data;                                     \
}

struct tcp_flags {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16   res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16   doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#endif
};

struct pktmeta {
	int l3_off;
	int l4_off;
	__u16 l3_csum_off;
	__u16 l4_csum_off;
	int ip_proto;
	union {
		struct tcp_flags tcp_flags;
		__u16 udp_flags;
		__u16 icmp_flags;
		__u16 flags;
	};
};

static inline void bpf_clear_cb(struct __sk_buff *skb)
{
    __u32 zero = 0;
    skb->cb[0] = zero;
    skb->cb[1] = zero;
    skb->cb[2] = zero;
    skb->cb[3] = zero;
    skb->cb[4] = zero;
}

#endif
