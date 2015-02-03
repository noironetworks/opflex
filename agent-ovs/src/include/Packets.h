/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Utility functions for packet generation/manipulation
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OVSAGENT_PACKETS_H
#define OVSAGENT_PACKETS_H

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>

#include <boost/asio/ip/address.hpp>

#include "ovs.h"
#include "PolicyManager.h"
#include "Endpoint.h"

namespace ovsagent {
namespace packets {

/**
 * Compute an internet checksum over the specified data.  chksum
 * should be first initialized to zero, then chksum_accum called for
 * each block of data, and finally call chksum_finalize to get the
 * result
 *
 * @param chksum the checksum to accumulate
 * @param addr the data
 * @param len the length of the data
 */
void chksum_accum(uint32_t& chksum, uint16_t* addr, size_t len);
    
/**
 * Finalize the computation of a checksum.  Does not change the
 * intermediate state, so can be used to compute a partial
 * checksum.
 *
 * @param chksum the value of the sum before finalization
 * @return The final checksum value.
 */
uint16_t chksum_finalize(uint32_t chksum);

/**
 * For a subnet with prefix length 64, construct an IP address
 * using the EUI-64 format in the lower 64 bits.
 * @param prefix the prefix address
 * @param srcMac the MAC address of the interface
 * @param dstAddr the in6_addr struct in which the result will be stored
 */
void construct_auto_ip(boost::asio::ip::address_v6 prefix,
                       const uint8_t* srcMac,
                       /* out */ struct in6_addr* dstAddr);

/**
 * Compose an ICMP6 neighbor advertisement ethernet frame
 *
 * @param naFlags the flags to set in the NA
 * @param srcMac the source MAC
 * @param dstMac the target MAC
 * @param srcIp the source IP
 * @param dstIp the destination Ip
 * @return a ofpbuf containing the message
 */
ofpbuf* compose_icmp6_neigh_ad(uint32_t naFlags,
                               const uint8_t* srcMac,
                               const uint8_t* dstMac,
                               const struct in6_addr* srcIp,
                               const struct in6_addr* dstIp);

/**
 * Compose an ICMP6 router advertisement ethernet frame
 *
 * @param srcMac the source MAC
 * @param dstMac the dst MAC
 * @param dstIp the destination Ip
 * @param egUri the endpoint group associated with the request
 * @param polMgr the policy manager
 * @return a ofpbuf containing the message
 */
ofpbuf* compose_icmp6_router_ad(const uint8_t* srcMac,
                                const uint8_t* dstMac,
                                const struct in6_addr* dstIp,
                                const opflex::modb::URI& egUri,
                                PolicyManager& polMgr);

/**
 * A convenience typedef for static routes
 */
typedef Endpoint::DHCPConfig::static_route_t static_route_t;

/**
 * Compose a DHCPv4 offer, ACK, or NACK
 *
 * @param message_type the message type of the reply
 * @param xid the transaction ID for the message
 * @param srcMac the MAC address for the DHCP server
 * @param clientMac the MAC address for the requesting client
 * @param clientIp the IP address to return to the client
 * @param prefixLen the length of the prefix for use in the subnet
 * mask
 * @param routers the list of routers to return to the client
 * @param dnsServers the list of DNS servers to return to the client
 * @param dnsSearchPath the DNS search path to return to the client
 * @param staticRoutes classless static routes to return to the client
 */
ofpbuf* compose_dhcpv4_reply(uint8_t message_type,
                             uint32_t xid,
                             const uint8_t* srcMac,
                             const uint8_t* clientMac,
                             uint32_t clientIp,
                             uint8_t prefixLen,
                             const std::vector<std::string>& routers,
                             const std::vector<std::string>& dnsServers,
                             const boost::optional<std::string>& domain,
                             const std::vector<static_route_t>& staticRoutes);
                             


} /* namespace packets */
} /* namespace ovsagent */

#endif /* OVSAGENT_PACKETS_H */
