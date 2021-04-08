/*
 * Test suite for class DnsManager
 *
 * Copyright (c) 2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflex/modb/Mutator.h>
#include <openvswitch/ofp-msgs.h>

#include "CtZoneManager.h"
#include "PacketInHandler.h"
#include <opflexagent/test/ModbFixture.h>
#include "MockSwitchManager.h"
#include "IntFlowManager.h"
#include "AccessFlowManager.h"
#include "FlowConstants.h"
#include "DnsManager.h"
#include <modelgbp/epdr/DnsEntry.hpp>
#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>

#define MAX_BUF_LEN 512

using opflex::modb::Mutator;
/*Parse in a hex dump of the packet*/
static unsigned parseHexDump( std::string hexdump, unsigned char *buf) {
    const unsigned char *c = (const unsigned char *)hexdump.c_str(), *b=c;
    unsigned j=0;
    bool nibbleStarted = false;
    for(unsigned i=0; i<hexdump.length(); i++,b++) {
        unsigned char curr=0;
        bool validChar = true;
	if(j == MAX_BUF_LEN) {
            break;
	}
        if( *b>='0' && *b<='9') {
            curr = *b-'0';
        } else if(*b>='a' && *b<='f') {
            curr = *b-'a'+10;
        } else {
            validChar = false;
            nibbleStarted = false;
        }
        if(nibbleStarted) {
            buf[j] = (buf[j]<<4)|(curr&0x0f);
            j++;
            nibbleStarted=false;
        } else {
            buf[j] = curr&0x0f;
            if(validChar)
                nibbleStarted=true;
        }
    }
    return j;
}

enum PacketDesc {
DNS_RESP_WITH_MULTIPLE_TYPE_A,
DNS_RESP_WITH_SINGLE_TYPE_A,
DNS_RESP_WITH_TWO_TYPE_A,
DNS_RESP_WITH_A4_RECORD
};
static const std::string PacketDef[] = {
"\
ba ba ba ba ba ba 48 f8  b3 26 df 49 08 00 45 08\
00 e8 b2 ef 00 00 37 11  fe 21 08 08 08 08 c0 a8\
01 34 00 35 d5 39 00 d4  28 a2 00 03 81 80 00 01\
00 0b 00 00 00 00 06 67  6f 6f 67 6c 65 03 63 6f\
6d 00 00 01 00 01 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 23 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 25 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 27 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 20 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 28 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 21 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 29 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 22 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 24 c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 2e c0 0c  00 01 00 01 00 00 00 04\
00 04 4a 7d ec 26",
"\
d8 f2 ca f8 16 b4 60 b7 6e 95 33 7a 08 00 45 00\
00 4a c5 80 40 00 39 11 b8 40 d0 43 dc dc c0 a8\
56 19 00 35 88 11 00 36 7c 64 0e 6e 81 80 00 01\
00 01 00 00 00 00 08 66 61 63 65 62 6f 6f 6b 03\
63 6f 6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00\
00 01 00 04 9d f0 ce 23",
"\
d8 f2 ca f8 16 b4 60 b7 6e 95 33 7a 08 00 45 00\
00 59 dc a1 40 00 39 11 a1 10 d0 43 dc dc c0 a8\
56 19 00 35 87 5d 00 45 1e 0c da 16 81 80 00 01\
00 02 00 00 00 00 07 74 77 69 74 74 65 72 03 63\
6f 6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 06\
ee 00 04 68 f4 2a 81 c0 0c 00 01 00 01 00 00 00\
01 00 04 68 f4 2a 01",
"\
d8 f2 ca f8 16 b4 60 b7 6e 95 33 7a 08 00 45 00\
00 56 4c a4 40 00 39 11 31 11 d0 43 dc dc c0 a8\
56 19 00 35 98 f2 00 42 4f 25 81 51 81 80 00 01\
00 01 00 00 00 00 08 66 61 63 65 62 6f 6f 6b 03\
63 6f 6d 00 00 1c 00 01 c0 0c 00 1c 00 01 00 00\
00 f7 00 10 2a 03 28 80 f1 4b 00 82 fa ce b0 0c\
00 00 25 de"
};

BOOST_AUTO_TEST_SUITE(DnsManager_test)

using namespace opflexagent;

class DnsManagerFixture : public ModbFixture
{
public:
    DnsManagerFixture() :
          ModbFixture(), ctZoneManager(idGen),
          switchManager(agent, flowExecutor, flowReader, intPortMapper),
          intFlowManager(agent, switchManager, idGen,
                         ctZoneManager, tunnelEpManager),
          dnsManager(agent),
          pktInHandler(agent, intFlowManager, dnsManager),
          proto(ofputil_protocol_from_ofp_version
                ((ofp_version)intConn.GetProtocolVersion())) {
        createObjects();
        dnsManager.start();
    }
    ~DnsManagerFixture() {
        dnsManager.stop();
    }
    typedef std::unordered_set<std::string> str_set_t;
private:
    IdGenerator idGen;
    CtZoneManager ctZoneManager;
    MockSwitchConnection intConn;
    MockSwitchConnection accConn;
    MockFlowReader flowReader;
    MockFlowExecutor flowExecutor;
    MockPortMapper intPortMapper;
    MockPortMapper accPortMapper;
    MockSwitchManager switchManager;
    IntFlowManager intFlowManager;
    DnsManager dnsManager;
    PacketInHandler pktInHandler;
    ofputil_protocol proto;
protected:
    void testHandleDnsResponsePacket(bool is_v4, PacketDesc pd);
    void getResolvedAddressesFromAnswer(std::shared_ptr<modelgbp::epdr::DnsAnswer>&, str_set_t&);
};

static void init_packet_in(ofputil_packet_in_private& pin,
                           void* packet_buf, size_t len,
                           uint64_t cookie = opflexagent::flow::cookie::DNS_RESPONSE_V4,
                           uint8_t table_id = AccessFlowManager::TAP_TABLE_ID)
{
    memset(&pin, 0, sizeof(pin));
    pin.base.reason = OFPR_ACTION;
    pin.base.cookie = cookie;
    pin.base.packet = packet_buf;
    pin.base.packet_len = len;
    pin.base.table_id = table_id;
}

void DnsManagerFixture::testHandleDnsResponsePacket(bool is_v4, PacketDesc pd) {
    unsigned char buf[MAX_BUF_LEN];
    unsigned maxLen = parseHexDump( PacketDef[pd], buf);
    ofputil_packet_in_private pin;
    init_packet_in(pin, buf, maxLen,
	       is_v4 ? opflexagent::flow::cookie::DNS_RESPONSE_V4 : opflexagent::flow::cookie::DNS_RESPONSE_V6,
	       AccessFlowManager::TAP_TABLE_ID);

    OfpBuf b(ofputil_encode_packet_in_private(&pin,
					  OFPUTIL_P_OF13_OXM,
					  OFPUTIL_PACKET_IN_NXT));

    pktInHandler.Handle(&accConn, OFPTYPE_PACKET_IN, b.get());
}

void DnsManagerFixture::getResolvedAddressesFromAnswer(std::shared_ptr<modelgbp::epdr::DnsAnswer> &dnsAnswer,
        str_set_t &out) {
    using namespace modelgbp::epdr;
    out.clear();
    std::vector<std::shared_ptr<DnsAnswerToResultRSrc> > result;
    dnsAnswer.get()->resolveEpdrDnsAnswerToResultRSrc(result);
    for(auto &res :result) {
        if(!res->isTargetSet() ||
           (res->getTargetClass().get() != DnsEntry::CLASS_ID)) {
            continue;
        }
        optional<shared_ptr<DnsEntry> > dnsEntry =
            DnsEntry::resolve(framework, res->getTargetURI().get());
        if(dnsEntry) {
            std::vector<std::shared_ptr<DnsMappedAddress>> mappedAddresses;
            dnsEntry.get()->resolveEpdrDnsMappedAddress(mappedAddresses);
            for(auto &mappedAddress: mappedAddresses) {
                out.insert(mappedAddress->getAddress().get());
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(handleDnsResponsePacket, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_MULTIPLE_TYPE_A);
    std::string domainName("google.com");
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
   auto ddU = DnsDemand::resolve(framework);
   Mutator m0(framework, "policyelement");
   std::string askDomainName("*google.com");
   auto dnsAsk = ddU.get()->addEpdrDnsAsk(askDomainName);
   m0.commit();
   //Check for an answer based on cached dns response
   auto dnsAnswer = DnsAnswer::resolve(framework, askDomainName);
   WAIT_FOR_DO(dnsAnswer,
	       500,
	       (dnsAnswer = DnsAnswer::resolve(framework, askDomainName)));
   str_set_t out;
   getResolvedAddressesFromAnswer(dnsAnswer.get(),out);
   //Check resolved address list against packet
   std::unordered_set<std::string> expectedResolved = {"74.125.236.35","74.125.236.37","74.125.236.39","74.125.236.32",
	"74.125.236.40","74.125.236.33","74.125.236.41","74.125.236.34","74.125.236.36","74.125.236.38","74.125.236.46"};
   BOOST_CHECK(expectedResolved==out);
   //Remove demand and ensure answer goes away
   dnsAsk.get()->remove();
   m0.commit();
   auto dnsAnswer2 = DnsAnswer::resolve(framework, askDomainName);
   WAIT_FOR_DO(!dnsAnswer2,
	       500,
	       (dnsAnswer2 = DnsAnswer::resolve(framework, askDomainName)));
}


BOOST_FIXTURE_TEST_CASE(testExpiryAgeOut, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    std::string domainName("facebook.com");
    auto ddU = DnsDemand::resolve(framework);
    Mutator m0(framework, "policyelement");
    auto dnsAsk = ddU.get()->addEpdrDnsAsk(domainName);
    m0.commit();
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_SINGLE_TYPE_A);
    auto dnsAnswer = DnsAnswer::resolve(framework, domainName);
    WAIT_FOR_DO(dnsAnswer,
	        500,
	        (dnsAnswer = DnsAnswer::resolve(framework, domainName)));
    str_set_t out;
    getResolvedAddressesFromAnswer(dnsAnswer.get(),out);
    std::unordered_set<std::string> expectedResolved = {"157.240.206.35"};
    BOOST_CHECK(expectedResolved==out);
    //Check expiry
    WAIT_FOR_DO(!dnsAnswer,
                1000,
                (dnsAnswer = DnsAnswer::resolve(framework, domainName)));
}

BOOST_FIXTURE_TEST_CASE(testExpiryAgeUpdate, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    auto ddU = DnsDemand::resolve(framework);
    Mutator m0(framework, "policyelement");
    std::string askDomainName("*twitter.com");
    auto dnsAsk = ddU.get()->addEpdrDnsAsk(askDomainName);
    m0.commit();
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_TWO_TYPE_A);
    std::string domainName("twitter.com");
    auto dnsAnswer = DnsAnswer::resolve(framework, askDomainName);
    WAIT_FOR_DO(dnsAnswer,
	        500,
	       (dnsAnswer = DnsAnswer::resolve(framework, askDomainName)));
    str_set_t out;
    getResolvedAddressesFromAnswer(dnsAnswer.get(),out);
    std::unordered_set<std::string> expectedResolved = {"104.244.42.129","104.244.42.1"};
    BOOST_CHECK(expectedResolved==out);
    out.clear();
    //Check expiry
    std::unordered_set<std::string> expectedResolved2 = {"104.244.42.129"};
    auto dnsAnswer2 = DnsAnswer::resolve(framework, askDomainName);
    WAIT_FOR_DO((out == expectedResolved2),
 	        1000,
	        (dnsAnswer2 = DnsAnswer::resolve(framework, askDomainName));
                getResolvedAddressesFromAnswer(dnsAnswer2.get(),out));
}

BOOST_FIXTURE_TEST_CASE(handleDnsv6Record, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_A4_RECORD);
    std::string domainName("facebook.com");
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
   auto ddU = DnsDemand::resolve(framework);
   Mutator m0(framework, "policyelement");
   std::string askDomainName("facebook.com");
   auto dnsAsk = ddU.get()->addEpdrDnsAsk(askDomainName);
   m0.commit();
   //Check for an answer based on cached dns response
   auto dnsAnswer = DnsAnswer::resolve(framework, askDomainName);
   WAIT_FOR_DO(dnsAnswer,
	       500,
	       (dnsAnswer = DnsAnswer::resolve(framework, askDomainName)));
   str_set_t out;
   getResolvedAddressesFromAnswer(dnsAnswer.get(),out);
   //Check resolved address list against packet
   std::unordered_set<std::string> expectedResolved = {"2a03:2880:f14b:82:face:b00c:0:25de"};
   BOOST_CHECK(expectedResolved==out);
   //Remove demand and ensure answer goes away
   dnsAsk.get()->remove();
   m0.commit();
   auto dnsAnswer2 = DnsAnswer::resolve(framework, askDomainName);
   WAIT_FOR_DO(!dnsAnswer2,
	       500,
	       (dnsAnswer2 = DnsAnswer::resolve(framework, askDomainName)));
}
BOOST_AUTO_TEST_SUITE_END()
