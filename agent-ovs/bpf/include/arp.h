#ifndef __LIB_ARP__
#define __LIB_ARP__

#include "eth.h"
/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_ETHER    1               /* Ethernet 10Mbps              */

/* ARP protocol opcodes. */
#define ARPOP_REQUEST   1               /* ARP request                  */
#define ARPOP_REPLY     2               /* ARP reply                    */

struct arphdr {
        __be16          ar_hrd;         /* format of hardware address   */
        __be16          ar_pro;         /* format of protocol address   */
        unsigned char   ar_hln;         /* length of hardware address   */
        unsigned char   ar_pln;         /* length of protocol address   */
        __be16          ar_op;          /* ARP opcode (command)         */

#if 0
         /*
          *      Ethernet looks like this : This bit is variable sized however...
          */
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];              /* sender IP address            */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];              /* target IP address            */
#endif

};

struct arp_eth {
	unsigned char		ar_sha[ETH_ALEN];
	__be32                  ar_sip;
	unsigned char		ar_tha[ETH_ALEN];
	__be32                  ar_tip;
} __attribute__((packed));

/* Check if packet is ARP request for IP */
static __always_inline
int arp_check(struct ethhdr *eth, struct arphdr *arp,
	      struct arp_eth *arp_eth, __be32 ip,
	      union macaddr *mac)
{
	union macaddr *dmac = (union macaddr *) &eth->h_dest;

	return arp->ar_op  == bpf_htons(ARPOP_REQUEST) &&
	       arp->ar_hrd == bpf_htons(ARPHRD_ETHER) &&
	       (eth_is_bcast(dmac) || !eth_addrcmp(dmac, mac)) &&
	       arp_eth->ar_tip == ip;
}

static __always_inline
int arp_prepare_response(struct __sk_buff *skb, struct ethhdr *eth,
		         struct arp_eth *arp_eth, __be32 ip,
		         union macaddr *mac)
{
	union macaddr smac = *(union macaddr *) &eth->h_source;
	__be32 sip = arp_eth->ar_sip;
	__be16 arpop = bpf_htons(ARPOP_REPLY);

	if (eth_store_saddr(skb, mac->addr, 0) < 0 ||
	    eth_store_daddr(skb, smac.addr, 0) < 0 ||
	    bpf_skb_store_bytes(skb, 20, &arpop, sizeof(arpop), 0) < 0 ||
	    bpf_skb_store_bytes(skb, 22, mac, 6, 0) < 0 ||
	    bpf_skb_store_bytes(skb, 28, &ip, 4, 0) < 0 ||
	    bpf_skb_store_bytes(skb, 32, &smac, sizeof(smac), 0) < 0 ||
	    bpf_skb_store_bytes(skb, 38, &sip, sizeof(sip), 0) < 0)
		return TC_ACT_SHOT;

	return 0;
}

static __always_inline
int process_arp(void *data, __u64 off, void *data_end, struct __sk_buff * skb,
		union macaddr *mac, __be32 ip)
{
	struct arphdr *arp = data + ETH_HLEN;
	struct ethhdr *eth = data;
	struct arp_eth *arp_eth = (struct arp_eth *)(arp + 1);
	int ret;

	if (arp_eth + 1 > data_end)
		return TC_ACT_OK;

	if (arp_check(eth, arp, arp_eth, ip, mac)) {
		ret = arp_prepare_response(skb, eth, arp_eth, ip, mac);
		if (unlikely(ret != 0))
			goto error;

		return bpf_redirect(skb->ifindex, 0);
	}

	/* Pass any unknown ARP requests to the Linux stack */
	return TC_ACT_OK;

error:
	return TC_ACT_SHOT;
}

#endif /* __LIB_ARP__ */
