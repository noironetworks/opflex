#ifndef __LIB_ETH__
#define __LIB_ETH__

#include "gbp.h"

static inline int eth_addrcmp(const union macaddr *a, const union macaddr *b)
{
	int tmp;

	tmp = a->tuple.p1 - b->tuple.p1;
	if (!tmp)
		tmp = a->tuple.p2 - b->tuple.p2;

	return tmp;
}

static inline int eth_is_bcast(const union macaddr *a)
{
	union macaddr bcast;

	bcast.tuple.p1 = 0xffffffff;
	bcast.tuple.p2 = 0xffff;

	if (!eth_addrcmp(a, &bcast))
		return 1;
	else
		return 0;
}

static inline int eth_load_saddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return bpf_skb_load_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN);
}

static inline int eth_store_saddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return bpf_skb_store_bytes(skb, off + ETH_ALEN, mac, ETH_ALEN, 0);
}

static inline int eth_load_daddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return bpf_skb_load_bytes(skb, off, mac, ETH_ALEN);
}

static inline int eth_store_daddr(struct __sk_buff *skb, __u8 *mac, int off)
{
	return bpf_skb_store_bytes(skb, off, mac, ETH_ALEN, 0);
}

#endif /* __LIB_ETH__ */
