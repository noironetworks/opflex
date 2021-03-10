/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Headers for the IP protocol
 *
 * Copyright (c) 2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_IP_H
#define OPFLEXAGENT_IP_H

namespace opflexagent {
namespace ip {
namespace type {
/**
 * IP UDP type
 */
const uint8_t UDP = 0x11;
const uint8_t TCP = 0x6;

} /* namespace type */

} /* namespace ip */

namespace udp {
namespace type {
/**
 * UDP DNS type
 */
const uint8_t DNS = 0x35;

} /* namespace type */

#define UDP_HDR_LEN 8
    struct udp_header {
	    uint16_t  source;
	    uint16_t  dest;
	    uint16_t  len;
	    uint16_t check;
    };
} /* namespace udp */

namespace tcp {
namespace type {
/**
 * TCP DNS type
 */
const uint8_t DNS = 0x35;

} /* namespace type */

struct tcp_header {
        uint16_t  source;
        uint16_t  dest;
        uint32_t  seq;
        uint32_t  ack_seq;
        uint16_t  doff:4,
                  res1:4,
                  cwr:1,
                  ece:1,
                  urg:1,
                  ack:1,
                  psh:1,
                  rst:1,
                  syn:1,
                  fin:1;
        uint16_t  window;
        uint16_t  check;
        uint16_t  urg_ptr;
};

} /* namespace tcp */

namespace dns {

#define DNS_HDR_LEN 12
#define DNS_QR_MASK 0x80
#define DNS_QR_QUERY 0
#define DNS_QR_RESPONSE 0x80
#define DNS_OPCODE_MASK 0x78
#define DNS_OPCODE_SQUERY 0
#define DNS_AA 0x04
#define DNS_TC 0x02
#define DNS_RD 0x01
#define DNS_RA 0x80
#define DNS_RCODE_MASK 0x0F

    struct dns_hdr {
	uint16_t id;
	uint8_t lo_flag; /* QR (1), OPCODE (4), AA (1), TC (1) and RD (1) */
	uint8_t hi_flag; /* RA (1), Z (3) and RCODE (4) */
	uint16_t qdcount; /* Num of entries in the question section. */
	uint16_t ancount; /* Num of resource records in the answer section. */
	/* Num of name server records in the authority record section. */
	uint16_t nscount;
	/* Num of resource records in the additional records section. */
	uint16_t arcount;
    };

} /* namespace dns */

} /* namespace opflexagent */

#endif
