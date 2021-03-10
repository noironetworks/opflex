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
DNS_RESP_WITH_MULTIPLE_TYPE_A
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
00 04 4a 7d ec 26"
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
};

static void init_packet_in(ofputil_packet_in_private& pin,
                           void* packet_buf, size_t len,
                           uint64_t cookie = flow::cookie::DNS_RESPONSE_V4,
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


BOOST_FIXTURE_TEST_CASE(handleDnsResponsePacket, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    typedef std::unordered_set<std::string> str_set_t;
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
   std::vector<std::shared_ptr<DnsAnswerToResultRSrc> > result;
   str_set_t out;
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

BOOST_AUTO_TEST_SUITE_END()
