/*
 * Test suite for class PacketDecoder
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <boost/test/unit_test.hpp>
#include "MockPacketLogHandler.h"
BOOST_AUTO_TEST_SUITE(PacketDecoder_test)

using namespace opflexagent;

/*Dummy io_service objects for constructor*/
static boost::asio::io_service io_1,io_2;

class PacketDecoderFixture {
public:
    PacketDecoderFixture():pktLogger(io_1,io_2) {
     pktLogger.startListener();
    };
    MockPacketLogHandler pktLogger;
};

static const uint8_t arp_buf[] = {
0x06, 0x00, 0x65, 0x58, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
0xff, 0xff, 0x0c, 0x01, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x01,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x9e, 0x72, 0xa6, 0x94, 0x18, 0xaf, 0x08, 0x06, 0x01, 0x01,
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x9e, 0x72, 0xa6, 0x94, 0x18, 0xaf, 0x0d, 0x00, 0x00, 0x03,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x05};

static const uint8_t icmp_buf[] = {
0x06, 0x00, 0x65, 0x58, 0x00, 0x00, 0x02, 0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
0xff, 0xff, 0x0c, 0x01, 0x00, 0x00, 0x00, 0x01, 0xff, 0xff, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00,
0x5a, 0x08, 0x66, 0xce, 0x0b, 0x49, 0x9e, 0x72, 0xa6, 0x94, 0x18, 0xaf, 0x08, 0x00, 0x45, 0x00,
0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x2e, 0x61, 0x0e, 0x00, 0x00, 0x02, 0x64, 0x00,
0x00, 0x01, 0x08, 0x00, 0xe9, 0x57, 0x00, 0x00, 0x00, 0x00};

static const uint8_t tcp_buf[] = {
0x06, 0x00, 0x65, 0x58, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
0xff, 0xff, 0x0c, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x02,
0x5a, 0x08, 0x66, 0xce, 0x0b, 0x49, 0x9e, 0x72, 0xa6, 0x94, 0x18, 0xaf, 0x08, 0x00, 0x45, 0x00,
0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x06, 0x2e, 0x61, 0x0e, 0x00, 0x00, 0x02, 0x64, 0x00,
0x00, 0x01, 0xa2, 0xa2, 0x00, 0xb3, 0xaf, 0x3b, 0x93, 0x8f, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
0x72, 0x10, 0xc9, 0x41, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x07, 0x72,
0x09, 0x15, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x09};

static const uint8_t udp_buf[] = {0x04, 0x00, 0x65, 0x58, 0x00, 0x00, 0x02,
0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0c, 0x01,
0x00, 0x00, 0x00, 0x03, 0x5a, 0x08, 0x66, 0xce, 0x0b, 0x49, 0x9e, 0x72, 0xa6,
0x94, 0x18, 0xaf, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
0xff, 0x11, 0x2e, 0x61, 0x0e, 0x00, 0x00, 0x02, 0x64, 0x00, 0x00, 0x01, 0xeb,
0xd8, 0x00, 0xa1, 0x00, 0x4a, 0xbc, 0x86};

static const uint8_t udpv6_buf[] = {0x04, 0x00, 0x65, 0x58, 0x00, 0x00, 0x01,
0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0c, 0x01,
0x00, 0x00, 0x00, 0x04, 0x5a, 0x08, 0x66, 0xce, 0x0b, 0x49, 0x9e, 0x72, 0xa6,
0x94, 0x18, 0xaf, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x11, 0x01,
0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, 0xfe,
0xfe, 0x8f, 0x95, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x02, 0x22, 0x02, 0x23, 0x00, 0x3c, 0xad,
0x08};

static const uint8_t tcpv6_buf[] = {0x04, 0x00, 0x65, 0x58, 0x00, 0x00, 0x01,
0x00, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0c, 0x01,
0x00, 0x00, 0x00, 0x05, 0x5a, 0x08, 0x66, 0xce, 0x0b, 0x49, 0x9e, 0x72, 0xa6,
0x94, 0x18, 0xaf, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x06, 0x01,
0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, 0xfe,
0xfe, 0x8f, 0x95, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xa2, 0xa2, 0x00, 0xb3, 0xaf, 0x3b, 0x93,
0x8f, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0xc9, 0x41, 0x00, 0x00,
0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x07, 0x72, 0x09, 0x15, 0x00,
0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x09 };

BOOST_FIXTURE_TEST_CASE(arp_test, PacketDecoderFixture) {
    auto pktDecoder = pktLogger.getDecoder();
    ParseInfo p(&pktDecoder);
    PacketTuple expectedTuple("", "Int-PORT_SECURITY_TABLE DENY", "9e:72:a6:94:18:af", "ff:ff:ff:ff:ff:ff", "ARP", "13.0.0.3", "13.0.0.5" ,"", "", "");
    std::string expected(" MAC=ff:ff:ff:ff:ff:ff:9e:72:a6:94:18:af:ARP ARP_SPA=13.0.0.3 ARP_TPA=13.0.0.5 ARP_OP=1");
    pktDecoder.decode(arp_buf, 74, p);
    std::string dropReason;
    pktLogger.getDropReason(p, dropReason);
    p.packetTuple.setField(0, dropReason);
    BOOST_CHECK(p.parsedString == expected);
    BOOST_CHECK(p.packetTuple == expectedTuple);
}

BOOST_FIXTURE_TEST_CASE(icmp_test, PacketDecoderFixture) {
    auto pktDecoder = pktLogger.getDecoder();
    ParseInfo p(&pktDecoder);
    PacketTuple expectedTuple("", "Acc-GROUP_MAP_TABLE MISS", "9e:72:a6:94:18:af", "5a:08:66:ce:0b:49", "IPv4", "14.0.0.2", "100.0.0.1" ,"ICMP", "", "");
    std::string expected(" MAC=5a:08:66:ce:0b:49:9e:72:a6:94:18:af:IPv4 SRC=14.0.0.2 DST=100.0.0.1 LEN=28 DSCP=0 TTL=255 ID=0 FLAGS=0 FRAG=0 PROTO=ICMP TYPE=8 CODE=0 ID=0 SEQ=0");
    pktDecoder.decode(icmp_buf, 74, p);
    std::string dropReason;
    pktLogger.getDropReason(p, dropReason);
    p.packetTuple.setField(0, dropReason);
    BOOST_CHECK(p.parsedString == expected);
    BOOST_CHECK(p.packetTuple == expectedTuple);
}

BOOST_FIXTURE_TEST_CASE(tcp_test, PacketDecoderFixture) {
    auto pktDecoder = pktLogger.getDecoder();
    ParseInfo p(&pktDecoder);
    PacketTuple expectedTuple("", "Int-SOURCE_TABLE PERMIT", "9e:72:a6:94:18:af", "5a:08:66:ce:0b:49", "IPv4", "14.0.0.2", "100.0.0.1" ,"TCP", "41634", "179");
    std::string expected(" MAC=5a:08:66:ce:0b:49:9e:72:a6:94:18:af:IPv4 SRC=14.0.0.2 DST=100.0.0.1 LEN=28 DSCP=0 TTL=255 ID=0 FLAGS=0 FRAG=0 PROTO=TCP SPT=41634 DPT=179 SEQ=2939917199 ACK=0 LEN=10 WINDOWS=29200 SYN  URGP=0");
    pktDecoder.decode(tcp_buf, 106, p);
    std::string dropReason;
    pktLogger.getDropReason(p, dropReason);
    p.packetTuple.setField(0, dropReason);
    BOOST_CHECK(p.parsedString == expected);
    BOOST_CHECK(p.packetTuple == expectedTuple);
}

BOOST_FIXTURE_TEST_CASE(udp_test, PacketDecoderFixture) {
    auto pktDecoder = pktLogger.getDecoder();
    ParseInfo p(&pktDecoder);
    PacketTuple expectedTuple("", "Acc-SEC_GROUP_OUT_TABLE", "9e:72:a6:94:18:af", "5a:08:66:ce:0b:49", "IPv4", "14.0.0.2", "100.0.0.1" ,"UDP", "60376", "161");
    std::string expected(" MAC=5a:08:66:ce:0b:49:9e:72:a6:94:18:af:IPv4 SRC=14.0.0.2 DST=100.0.0.1 LEN=28 DSCP=0 TTL=255 ID=0 FLAGS=0 FRAG=0 PROTO=UDP SPT=60376 DPT=161 LEN=74");
    pktDecoder.decode(udp_buf, 66, p);
    std::string dropReason;
    pktLogger.getDropReason(p, dropReason);
    p.packetTuple.setField(0, dropReason);
    BOOST_CHECK(p.parsedString == expected);
    BOOST_CHECK(p.packetTuple == expectedTuple);
}

BOOST_FIXTURE_TEST_CASE(udp_over_v6_test, PacketDecoderFixture) {
    auto pktDecoder = pktLogger.getDecoder();
    ParseInfo p(&pktDecoder);
    PacketTuple expectedTuple("", "Int-SERVICE_REV_TABLE", "9e:72:a6:94:18:af", "5a:08:66:ce:0b:49", "IPv6", "fe80::a00:27ff:fefe:8f95", "ff02::1:2" ,"UDP", "546", "547");
    std::string expected(" MAC=5a:08:66:ce:0b:49:9e:72:a6:94:18:af:IPv6 SRC=fe80::a00:27ff:fefe:8f95 DST=ff02::1:2 LEN=60 TC=0 HL=1 FL=0 PROTO=UDP SPT=546 DPT=547 LEN=60");
    pktDecoder.decode(udpv6_buf, 86, p);
    std::string dropReason;
    pktLogger.getDropReason(p, dropReason);
    p.packetTuple.setField(0, dropReason);
    BOOST_CHECK(p.parsedString == expected);
    BOOST_CHECK(p.packetTuple == expectedTuple);
}

BOOST_FIXTURE_TEST_CASE(tcp_over_v6_test, PacketDecoderFixture) {
    auto pktDecoder = pktLogger.getDecoder();
    ParseInfo p(&pktDecoder);
    PacketTuple expectedTuple("", "Int-BRIDGE_TABLE", "9e:72:a6:94:18:af", "5a:08:66:ce:0b:49", "IPv6", "fe80::a00:27ff:fefe:8f95", "ff02::1:2" ,"TCP", "41634", "179");
    std::string expected(" MAC=5a:08:66:ce:0b:49:9e:72:a6:94:18:af:IPv6 SRC=fe80::a00:27ff:fefe:8f95 DST=ff02::1:2 LEN=60 TC=0 HL=1 FL=0 PROTO=TCP SPT=41634 DPT=179 SEQ=2939917199 ACK=0 LEN=10 WINDOWS=29200 SYN  URGP=0");
    pktDecoder.decode(tcpv6_buf, 118, p);
    std::string dropReason;
    pktLogger.getDropReason(p, dropReason);
    p.packetTuple.setField(0, dropReason);
    BOOST_CHECK(p.parsedString == expected);
    BOOST_CHECK(p.packetTuple == expectedTuple);
}

BOOST_AUTO_TEST_SUITE_END()
