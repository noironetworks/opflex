#ifndef __IP_H__
#define __IP_H__

#include "gbp.h"
#include "pkt.h"

#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

static __always_inline
int ip4_tuple_normalize(struct ip4_tuple *tuple)
{
	__be32 tmp_addr;
	__be16 tmp_port;

	if (tuple->sip > tuple->dip) {
		tmp_addr = tuple->sip;
		tuple->sip = tuple->dip;
		tuple->dip = tmp_addr;

		tmp_port = tuple->l4.sport;
		tuple->l4.sport = tuple->l4.dport;
		tuple->l4.dport = tmp_port;

		return 1;
	}
	return 0;
}

static __always_inline
int ip6_addrcmp(__be32 src[], __be32 dst[])
{
	int tmp;

	tmp = src[0] - dst[0];
	if (!tmp) {
		tmp = src[1] - dst[1];
		if (!tmp) {
			tmp = src[2] - dst[2];
			if (!tmp)
				tmp = src[3] - dst[3];
		}
	}

	return tmp;
}

static __always_inline
int ip6_tuple_normalize(struct ip6_tuple *tuple)
{
	__be32 tmp_addr[4];
	__be16 tmp_port;

	if (ip6_addrcmp(tuple->sip, tuple->dip) > 0) {
		__builtin_memcpy(tmp_addr, tuple->sip, 16);
		__builtin_memcpy(tuple->sip, tuple->dip, 16);
		__builtin_memcpy(tuple->dip, tmp_addr, 16);

		tmp_port = tuple->l4.sport;
		tuple->l4.sport = tuple->l4.dport;
		tuple->l4.dport = tmp_port;

		return 1;
	}
	return 0;
}

static __always_inline
int parse_tcp(void *data, __u64 off, void *data_end, struct l4_ports *l4,
	      struct pktmeta *meta)
{
	struct tcphdr *tcp = data + off;

	if (tcp + 1 > data_end)
		return -1;

        meta->flags = *(__u16 *)((void *)tcp + 12);
	l4->sport = tcp->source;
	l4->dport = tcp->dest;
	meta->l4_off = off;
	meta->l4_csum_off = off + offsetof(struct tcphdr, check);
	meta->flags = *(__u16 *)(data + off + 12);

	return 0;
}

static __always_inline
int parse_udp(void *data, __u64 off, void *data_end, struct l4_ports *l4,
	      struct pktmeta *meta)
{
	struct udphdr *udp = data + off;
	if (udp + 1 > data_end)
		return -1;

	l4->sport = udp->source;
	l4->dport = udp->dest;
	meta->l4_off = off;
	meta->l4_csum_off = off + offsetof(struct udphdr, check);
	return 0;
}

static __always_inline
int parse_icmp6(void *data, __u64 off, void *data_end, struct l4_ports *l4,
		struct pktmeta *meta)
{
	return 0;
}

static __always_inline
int parse_icmp(void *data, __u64 off, void *data_end, struct l4_ports *l4,
	       struct pktmeta *meta)
{
	return 0;
}

static __always_inline
int parse_ip4(void *data, __u64 off, void *data_end, struct ip4_tuple *tuple,
              struct pktmeta *meta)
{
 	struct iphdr *iph = data + off;

	if (iph + 1 > data_end)
		return -1;

	tuple->sip = iph->saddr;
	tuple->dip = iph->daddr;
	tuple->proto = iph->protocol;
	meta->ip_proto = tuple->proto;
	meta->l3_off = off;
	meta->l3_csum_off = off + offsetof(struct iphdr, check);
	off += iph->ihl << 2;

	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return 0;

	if (tuple->proto == IPPROTO_ICMP)
		return parse_icmp(data, off, data_end, &tuple->l4, meta);
	else if (tuple->proto == IPPROTO_TCP)
		return parse_tcp(data, off, data_end, &tuple->l4, meta);
	else if (tuple->proto == IPPROTO_UDP)
		return parse_udp(data, off, data_end, &tuple->l4, meta);
	else
		return -1;
}

static __always_inline
int parse_ip6(void *data, __u64 off, void *data_end, struct ip6_tuple *tuple,
	      struct pktmeta *meta)
{
	struct ipv6hdr *ip6h = data + off;

	if (ip6h + 1 > data_end)
		return -1;
	__builtin_memcpy(tuple->sip, ip6h->saddr.s6_addr32, 16);
	__builtin_memcpy(tuple->dip, ip6h->daddr.s6_addr32, 16);
	tuple->proto = ip6h->nexthdr;
	meta->ip_proto = tuple->proto;
	meta->l3_off = off;
	off += sizeof(struct ipv6hdr);

	if (tuple->proto == IPPROTO_ICMPV6)
		return parse_icmp6(data, off, data_end, &tuple->l4, meta);
	else if (tuple->proto == IPPROTO_TCP)
		return parse_tcp(data, off, data_end, &tuple->l4, meta);
	else if (tuple->proto == IPPROTO_UDP)
		return parse_udp(data, off, data_end, &tuple->l4, meta);
	else
		return -1;
}

#endif
