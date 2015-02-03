/*
 * Test suite for class PacketInHandler
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "PacketInHandler.h"
#include "ModbFixture.h"
#include "MockSwitchConnection.h"
#include "FlowManager.h"
#include "udp.h"
#include "dhcp.h"

class PacketInHandlerFixture : public ModbFixture {
public:
    PacketInHandlerFixture()
        : ModbFixture(), flowManager(agent),
          pktInHandler(agent, flowManager),
          proto(ofputil_protocol_from_ofp_version(conn.GetProtocolVersion())) {
        flowManager.SetEncapIface("br0_vxlan0");
        flowManager.SetTunnelRemoteIp("10.11.12.13");
        flowManager.SetVirtualRouter(true, true, "aa:bb:cc:dd:ee:ff");
    }

    void setDhcpConfig() {
        Endpoint::DHCPConfig c;
        c.setIpAddress("10.20.44.2");
        c.setPrefixLen(24);
        c.addRouter("10.20.44.1");
        c.addRouter("1.2.3.4");
        c.addDnsServer("8.8.8.8");
        c.addDnsServer("4.3.2.1");
        c.setDomain("example.com");
        c.addStaticRoute("169.254.169.254", 32, "4.3.2.1");
        ep0->addDhcpConfig(c);
        epSrc.updateEndpoint(*ep0);
        WAIT_FOR(agent.getPolicyManager().getGroupForVnid(0xA0A), 500);
    }

    MockSwitchConnection conn;
    FlowManager flowManager;
    PacketInHandler pktInHandler;
    ofputil_protocol proto;
};

static const uint8_t pkt_dhcpv4_discover[] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
     0x08, 0x00, 0x45, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
     0x79, 0xae, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x44,
     0x00, 0x43, 0x01, 0x2c, 0x5a, 0xa7, 0x01, 0x01, 0x06, 0x00, 0xe0, 0xe2,
     0x52, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0x3d, 0x07, 0x01,
     0xfa, 0x16, 0x3e, 0x63, 0x13, 0x8b, 0x39, 0x02, 0x02, 0x40, 0x37, 0x09,
     0x01, 0x03, 0x06, 0x0c, 0x0f, 0x1a, 0x1c, 0x2a, 0x79, 0x3c, 0x0c, 0x75,
     0x64, 0x68, 0x63, 0x70, 0x20, 0x31, 0x2e, 0x32, 0x30, 0x2e, 0x31, 0x0c,
     0x08, 0x77, 0x65, 0x62, 0x2d, 0x76, 0x6d, 0x2d, 0x31, 0xff};

static const uint8_t pkt_dhcpv4_request[] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
     0x08, 0x00, 0x45, 0x00, 0x01, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11,
     0x79, 0xa2, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x44,
     0x00, 0x43, 0x01, 0x38, 0x6f, 0x30, 0x01, 0x01, 0x06, 0x00, 0xe0, 0xe2,
     0x52, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x03, 0x3d, 0x07, 0x01,
     0xfa, 0x16, 0x3e, 0x63, 0x13, 0x8b, 0x32, 0x04, 0x0a, 0x14, 0x2c, 0x02,
     0x36, 0x04, 0x09, 0xfe, 0x20, 0x20, 0x39, 0x02, 0x02, 0x40, 0x37, 0x09,
     0x01, 0x03, 0x06, 0x0c, 0x0f, 0x1a, 0x1c, 0x2a, 0x79, 0x3c, 0x0c, 0x75,
     0x64, 0x68, 0x63, 0x70, 0x20, 0x31, 0x2e, 0x32, 0x30, 0x2e, 0x31, 0x0c,
     0x08, 0x77, 0x65, 0x62, 0x2d, 0x76, 0x6d, 0x2d, 0x31, 0xff};

static const uint8_t opt_subnet_mask[] =
    {DHCP_OPTION_SUBNET_MASK,
     4, 0xff, 0xff, 0xff, 0x00};

static const uint8_t opt_router[] =
    {DHCP_OPTION_ROUTER,
     8, 10, 20, 44, 1, 1, 2, 3, 4};

static const uint8_t opt_dns[] =
    {DHCP_OPTION_DNS,
     8, 8, 8, 8, 8, 4, 3, 2, 1};

static const uint8_t opt_domain[] =
    {DHCP_OPTION_DOMAIN_NAME,
     11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};

static const uint8_t opt_lease_time[] =
    {DHCP_OPTION_LEASE_TIME,
     4, 0x00, 0x01, 0x51, 0x80};

static const uint8_t opt_server_id[] =
    {DHCP_OPTION_SERVER_IDENTIFIER,
     4, 169, 254, 32, 32};

static const uint8_t opt_route[] =
    {DHCP_OPTION_CLASSLESS_STATIC_ROUTE,
     9, 32, 169, 254, 169, 254, 4, 3, 2, 1};

BOOST_AUTO_TEST_SUITE(PacketInHandler_test)

static void init_packet_in(ofputil_packet_in& pin,
                           const void* packet_buf, size_t len,
                           uint64_t cookie = 0,
                           uint8_t table_id = 3,
                           uint32_t in_port = 42,
                           uint32_t dstReg = 0) {
    pin.reason = OFPR_ACTION;
    pin.cookie = cookie;
    pin.packet = packet_buf;
    pin.packet_len = len;
    pin.total_len = len;
    pin.buffer_id = UINT32_MAX;
    pin.table_id = table_id;
    pin.fmd.in_port = in_port;
    pin.fmd.regs[0] = 0xA0A;
    pin.fmd.regs[5] = 10;
    pin.fmd.regs[7] = dstReg;
}

BOOST_FIXTURE_TEST_CASE(learn, PacketInHandlerFixture) {
    char packet_buf[512];
    ofputil_packet_in pin1;
    memset(packet_buf, 0xdeadbeef, sizeof(packet_buf));
    memset(&pin1, 0, sizeof(pin1));

    // initialize just the first part of the ethernet header
    char mac1[6] = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    char mac2[6] = {0xf, 0xe, 0xd, 0xc, 0xb, 0xa};
    memcpy(packet_buf, mac1, sizeof(mac1));
    memcpy(packet_buf + sizeof(mac1), mac2, sizeof(mac2));

    // stage 1
    init_packet_in(pin1, &packet_buf, sizeof(packet_buf),
                   FlowManager::GetProactiveLearnEntryCookie());

    ofpbuf* b = ofputil_encode_packet_in(&pin1,
                                          OFPUTIL_P_OF10_NXM,
                                          NXPIF_NXM);
    pktInHandler.Handle(&conn, OFPTYPE_PACKET_IN, b);
    ofpbuf_delete(b);

    BOOST_CHECK(conn.sentMsgs.size() == 3);
    uint64_t ofpacts_stub1[1024 / 8];
    uint64_t ofpacts_stub2[1024 / 8];
    uint64_t ofpacts_stub3[1024 / 8];
    struct ofpbuf ofpacts1, ofpacts2, ofpacts3;
    struct ofputil_flow_mod fm1, fm2;
    struct ofputil_packet_out po;

    ofpbuf_use_stub(&ofpacts1, ofpacts_stub1, sizeof ofpacts_stub1);
    ofpbuf_use_stub(&ofpacts2, ofpacts_stub2, sizeof ofpacts_stub2);
    ofpbuf_use_stub(&ofpacts3, ofpacts_stub3, sizeof ofpacts_stub3);
    ofputil_decode_flow_mod(&fm1, (ofp_header*)ofpbuf_data(conn.sentMsgs[0]),
                            proto, &ofpacts1, u16_to_ofp(64), 8);
    ofputil_decode_flow_mod(&fm2, (ofp_header*)ofpbuf_data(conn.sentMsgs[1]),
                            proto, &ofpacts2, u16_to_ofp(64), 8);
    ofputil_decode_packet_out(&po, (ofp_header*)ofpbuf_data(conn.sentMsgs[2]),
                              &ofpacts3);

    BOOST_CHECK(0 == memcmp(fm1.match.flow.dl_dst, mac2, sizeof(mac2)));
    BOOST_CHECK_EQUAL(10, fm1.match.flow.regs[5]);
    BOOST_CHECK_EQUAL(FlowManager::GetLearnEntryCookie(), fm1.new_cookie);
    struct ofpact* a;
    int i;
    i = 0;
    OFPACT_FOR_EACH (a, fm1.ofpacts, fm1.ofpacts_len) {
        if (i == 0) BOOST_CHECK_EQUAL(OFPACT_SET_FIELD, a->type);
        if (i == 1) BOOST_CHECK_EQUAL(OFPACT_SET_FIELD, a->type);
        if (i == 2) BOOST_CHECK_EQUAL(OFPACT_OUTPUT, a->type);
        if (i == 3) BOOST_CHECK_EQUAL(OFPACT_CONTROLLER, a->type);
        ++i;
    }
    BOOST_CHECK_EQUAL(4, i);

    BOOST_CHECK(0 == memcmp(fm2.match.flow.dl_src, mac2, sizeof(mac2)));
    BOOST_CHECK_EQUAL(42, ofp_to_u16(fm2.match.flow.in_port.ofp_port));
    i = 0;
    OFPACT_FOR_EACH (a, fm2.ofpacts, fm2.ofpacts_len) {
        if (i == 0) BOOST_CHECK_EQUAL(OFPACT_GROUP, a->type);
        ++i;
    }
    BOOST_CHECK_EQUAL(1, i);

    BOOST_CHECK_EQUAL(sizeof(packet_buf), po.packet_len);
    BOOST_CHECK(0 == memcmp(po.packet, packet_buf, sizeof(packet_buf)));
    i = 0;
    OFPACT_FOR_EACH (a, po.ofpacts, po.ofpacts_len) {
        if (i == 0) BOOST_CHECK_EQUAL(OFPACT_GROUP, a->type);
        ++i;
    }
    BOOST_CHECK_EQUAL(1, i);
    
    conn.clear();

    // stage2
    init_packet_in(pin1, &packet_buf, sizeof(packet_buf),
                   FlowManager::GetLearnEntryCookie(), 3, 24, 42);

    b = ofputil_encode_packet_in(&pin1,
                                 OFPUTIL_P_OF10_NXM,
                                 NXPIF_NXM);
    pktInHandler.Handle(&conn, OFPTYPE_PACKET_IN, b);
    ofpbuf_delete(b);

    BOOST_CHECK(conn.sentMsgs.size() == 2);
    ofputil_decode_flow_mod(&fm1, (ofp_header *)ofpbuf_data(conn.sentMsgs[0]),
                            proto, &ofpacts1, u16_to_ofp(64), 8);
    ofputil_decode_flow_mod(&fm2, (ofp_header *)ofpbuf_data(conn.sentMsgs[1]),
                            proto, &ofpacts2, u16_to_ofp(64), 8);
    BOOST_CHECK(0 == memcmp(fm1.match.flow.dl_dst, mac2, sizeof(mac2)));
    BOOST_CHECK_EQUAL(10, fm1.match.flow.regs[5]);

    BOOST_CHECK(0 == memcmp(fm2.match.flow.dl_dst, mac1, sizeof(mac1)));
    BOOST_CHECK(0 == memcmp(fm2.match.flow.dl_src, mac2, sizeof(mac2)));
    BOOST_CHECK_EQUAL(10, fm2.match.flow.regs[5]);
    i = 0;
    OFPACT_FOR_EACH (a, fm2.ofpacts, fm2.ofpacts_len) {
        if (i == 0) BOOST_CHECK_EQUAL(OFPACT_SET_FIELD, a->type);
        if (i == 1) BOOST_CHECK_EQUAL(OFPACT_SET_FIELD, a->type);
        if (i == 2) BOOST_CHECK_EQUAL(OFPACT_GOTO_TABLE, a->type);
        ++i;
    }
    BOOST_CHECK_EQUAL(3, i);
}

static void verify_dhcpv4(ofpbuf* msg, uint8_t message_type) {
    using namespace dhcp;
    using namespace udp;

    struct ofputil_packet_out po;
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpact;
    ofpbuf_use_stub(&ofpact, ofpacts_stub, sizeof ofpacts_stub);
    ofputil_decode_packet_out(&po, 
                              (ofp_header*)ofpbuf_data(msg),
                              &ofpact);
    struct ofpbuf pkt;
    struct flow flow;
    ofpbuf_use_const(&pkt, po.packet, po.packet_len);
    flow_extract(&pkt, NULL, &flow);

    size_t l4_size = ofpbuf_l4_size(&pkt);
    BOOST_REQUIRE(l4_size > (sizeof(struct udp_hdr) +
                             sizeof(struct dhcp_hdr) + 1));

    struct dhcp_hdr* dhcp_pkt =
        (struct dhcp_hdr*) ((char*)ofpbuf_l4(&pkt) + sizeof(struct udp_hdr));
    BOOST_CHECK_EQUAL(2, dhcp_pkt->op);
    BOOST_CHECK_EQUAL(99, dhcp_pkt->cookie[0]);
    BOOST_CHECK_EQUAL(130, dhcp_pkt->cookie[1]);
    BOOST_CHECK_EQUAL(83, dhcp_pkt->cookie[2]);
    BOOST_CHECK_EQUAL(99, dhcp_pkt->cookie[3]);

    char* cur = (char*)dhcp_pkt + sizeof(struct dhcp_hdr);
    size_t remaining = l4_size - sizeof(struct dhcp_hdr);

    unordered_set<uint8_t> foundOptions;

    while (remaining > 0) {
        struct dhcp_option_hdr* hdr = (struct dhcp_option_hdr*)cur;
        foundOptions.insert(hdr->code);

        if (hdr->code == DHCP_OPTION_END)
            break;
        if (hdr->code == DHCP_OPTION_PAD) {
            cur += 1;
            remaining -= 1;
            continue;
        }

        if (remaining <= ((size_t)hdr->len + 2))
            break;

        switch (hdr->code) {
        case DHCP_OPTION_MESSAGE_TYPE:
            {
                uint8_t mt = ((uint8_t*)cur)[2];
                BOOST_CHECK_EQUAL(message_type, mt);
            }
            break;
        case DHCP_OPTION_SUBNET_MASK:
            BOOST_CHECK(0 == memcmp(opt_subnet_mask, cur,
                                    sizeof(opt_subnet_mask)));
            break;
        case DHCP_OPTION_ROUTER:
            BOOST_CHECK(0 == memcmp(opt_router, cur, sizeof(opt_router)));
            break;
        case DHCP_OPTION_DNS:
            BOOST_CHECK(0 == memcmp(opt_dns, cur, sizeof(opt_dns)));
            break;
        case DHCP_OPTION_DOMAIN_NAME:
            BOOST_CHECK(0 == memcmp(opt_domain, cur, sizeof(opt_domain)));
            break;
        case DHCP_OPTION_LEASE_TIME:
            BOOST_CHECK(0 == memcmp(opt_lease_time, cur,
                                    sizeof(opt_lease_time)));
            break;
        case DHCP_OPTION_SERVER_IDENTIFIER:
            BOOST_CHECK(0 == memcmp(opt_server_id, cur,
                                    sizeof(opt_server_id)));
            break;
        case DHCP_OPTION_CLASSLESS_STATIC_ROUTE:
            BOOST_CHECK(0 == memcmp(opt_route, cur, sizeof(opt_route)));
            break;
        }

        cur += hdr->len + 2;
        remaining -= hdr->len + 2;
    }

#define CONTAINS(x, y) (x.find(y) != x.end())
    BOOST_CHECK(CONTAINS(foundOptions, DHCP_OPTION_MESSAGE_TYPE));
    BOOST_CHECK(CONTAINS(foundOptions, DHCP_OPTION_ROUTER));
    BOOST_CHECK(CONTAINS(foundOptions, DHCP_OPTION_DOMAIN_NAME));
    BOOST_CHECK(CONTAINS(foundOptions, DHCP_OPTION_LEASE_TIME));
    BOOST_CHECK(CONTAINS(foundOptions, DHCP_OPTION_SERVER_IDENTIFIER));
    BOOST_CHECK(CONTAINS(foundOptions, DHCP_OPTION_CLASSLESS_STATIC_ROUTE));

#undef CONTAINS
}

BOOST_FIXTURE_TEST_CASE(dhcpv4_noconfig, PacketInHandlerFixture) {
    ofputil_packet_in pin;
    init_packet_in(pin, &pkt_dhcpv4_discover, sizeof(pkt_dhcpv4_discover),
                   FlowManager::GetDHCPCookie(true));

    ofpbuf* b = ofputil_encode_packet_in(&pin,
                                          OFPUTIL_P_OF10_NXM,
                                          NXPIF_NXM);
    pktInHandler.Handle(&conn, OFPTYPE_PACKET_IN, b);
    ofpbuf_delete(b);

    BOOST_CHECK_EQUAL(0, conn.sentMsgs.size());
}

BOOST_FIXTURE_TEST_CASE(dhcpv4_discover, PacketInHandlerFixture) {
    setDhcpConfig();

    ofputil_packet_in pin;
    init_packet_in(pin, &pkt_dhcpv4_discover, sizeof(pkt_dhcpv4_discover),
                   FlowManager::GetDHCPCookie(true));

    ofpbuf* b = ofputil_encode_packet_in(&pin,
                                          OFPUTIL_P_OF10_NXM,
                                          NXPIF_NXM);

    pktInHandler.Handle(&conn, OFPTYPE_PACKET_IN, b);
    BOOST_REQUIRE_EQUAL(1, conn.sentMsgs.size());
    ofpbuf_delete(b);

    verify_dhcpv4(conn.sentMsgs[0], DHCP_MESSAGE_TYPE_OFFER);
}

BOOST_FIXTURE_TEST_CASE(dhcpv4_request, PacketInHandlerFixture) {
    setDhcpConfig();

    ofputil_packet_in pin;
    init_packet_in(pin, &pkt_dhcpv4_request, sizeof(pkt_dhcpv4_request),
                   FlowManager::GetDHCPCookie(true));

    ofpbuf* b = ofputil_encode_packet_in(&pin,
                                          OFPUTIL_P_OF10_NXM,
                                          NXPIF_NXM);
    pktInHandler.Handle(&conn, OFPTYPE_PACKET_IN, b);
    ofpbuf_delete(b);

    BOOST_REQUIRE_EQUAL(1, conn.sentMsgs.size());

    verify_dhcpv4(conn.sentMsgs[0], DHCP_MESSAGE_TYPE_ACK);
}

BOOST_FIXTURE_TEST_CASE(dhcpv4_request_inv, PacketInHandlerFixture) {
    setDhcpConfig();

    char* buf = (char*)malloc(sizeof(pkt_dhcpv4_request));
    memcpy(buf, &pkt_dhcpv4_request, sizeof(pkt_dhcpv4_request));

    // request invalid IP
    buf[0x12a] = 5;

    ofputil_packet_in pin;
    init_packet_in(pin, buf, sizeof(pkt_dhcpv4_request),
                   FlowManager::GetDHCPCookie(true));

    ofpbuf* b = ofputil_encode_packet_in(&pin,
                                          OFPUTIL_P_OF10_NXM,
                                          NXPIF_NXM);
    pktInHandler.Handle(&conn, OFPTYPE_PACKET_IN, b);
    ofpbuf_delete(b);
    free(buf);

    BOOST_REQUIRE_EQUAL(1, conn.sentMsgs.size());

    verify_dhcpv4(conn.sentMsgs[0], DHCP_MESSAGE_TYPE_NAK);
}

BOOST_AUTO_TEST_SUITE_END()
