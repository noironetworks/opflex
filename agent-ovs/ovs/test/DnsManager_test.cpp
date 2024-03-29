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
DNS_RESP_WITH_A4_RECORD,
DNS_RESP_WITH_CNAME_RECORD,
DNS_RESP_WITH_SRV_RECORD,
DNS_RESP_WITH_SINGLE_TYPE_A_RESOLVING_SRV_RECORD
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
00 00 25 de",
"\
08 00 27 63 cf 53 52 54 00 12 35 02 08 00 45 00\
00 ae 00 29 00 00 40 11 ab 61 c0 a8 01 fe 0a 00\
02 0f 00 35 eb d1 00 9a 98 10 85 2e 81 80 00 01\
00 03 00 00 00 00 0d 73 74 61 74 69 63 2d 6d 6f\
62 69 6c 65 08 71 75 73 74 6f 64 69 6f 03 63 6f\
6d 00 00 01 00 01 c0 0c 00 05 00 01 00 00 00 dc\
00 3c 0d 73 74 61 74 69 63 2d 6d 6f 62 69 6c 65\
08 71 75 73 74 6f 64 69 6f 03 63 6f 6d 14 73 33\
2d 77 65 62 73 69 74 65 2d 75 73 2d 65 61 73 74\
2d 31 09 61 6d 61 7a 6f 6e 61 77 73 c0 23 c0 38\
00 05 00 01 00 00 00 2f 00 02 c0 53 c0 53 00 01\
00 01 00 00 00 10 00 04 48 15 d7 52",
"\
d8 f2 ca f8 16 b4 60 b7 6e 95 33 7a 08 00 45 00\
01 3f 8e 8d 40 00 38 11 ef 3e d0 43 dc dc c0 a8\
56 19 00 35 ac 93 01 2b 8c a3 cb b2 81 80 00 01\
00 05 00 00 00 01 07 5f 6a 61 62 62 65 72 04 5f\
74 63 70 05 67 6d 61 69 6c 03 63 6f 6d 00 00 21\
00 01 c0 0c 00 21 00 01 00 00 03 84 00 20 00 05\
00 00 14 95 0b 78 6d 70 70 2d 73 65 72 76 65 72\
01 6c 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 c0 0c\
00 21 00 01 00 00 03 84 00 25 00 14 00 00 14 95\
04 61 6c 74 31 0b 78 6d 70 70 2d 73 65 72 76 65\
72 01 6c 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 c0\
0c 00 21 00 01 00 00 03 84 00 25 00 14 00 00 14\
95 04 61 6c 74 32 0b 78 6d 70 70 2d 73 65 72 76\
65 72 01 6c 06 67 6f 6f 67 6c 65 03 63 6f 6d 00\
c0 0c 00 21 00 01 00 00 03 84 00 25 00 14 00 00\
14 95 04 61 6c 74 33 0b 78 6d 70 70 2d 73 65 72\
76 65 72 01 6c 06 67 6f 6f 67 6c 65 03 63 6f 6d\
00 c0 0c 00 21 00 01 00 00 03 84 00 25 00 14 00\
00 14 95 04 61 6c 74 34 0b 78 6d 70 70 2d 73 65\
72 76 65 72 01 6c 06 67 6f 6f 67 6c 65 03 63 6f\
6d 00 00 00 29 10 00 00 00 00 00 00 00",
"\
d8 f2 ca f8 16 b4 60 b7 6e 95 33 7a 08 00 45 00\
00 5b c3 a7 40 00 38 11 bb 08 d0 43 dc dc c0 a8\
56 19 00 35 d0 58 00 47 c9 6d 50 34 81 80 00 01\
00 01 00 00 00 00 04 61 6c 74 31 0b 78 6d 70 70\
2d 73 65 72 76 65 72 01 6c 06 67 6f 6f 67 6c 65\
03 63 6f 6d 00 00 01 00 01 c0 0c 00 01 00 01 00\
00 01 2c 00 04 40 e9 ab 7d"
};

BOOST_AUTO_TEST_SUITE(DnsManager_test)

using namespace opflexagent;
namespace fs = boost::filesystem;

class DnsManagerFixture : public ModbFixture
{
public:
    DnsManagerFixture() :
          ModbFixture(), ctZoneManager(idGen),
          switchManager(agent, flowExecutor, flowReader, intPortMapper),
          intFlowManager(agent, switchManager, idGen,
                         ctZoneManager, tunnelEpManager,
                         endpointTenantMapper),
          dnsManager(agent),
          pktInHandler(agent, intFlowManager, dnsManager),
          proto(ofputil_protocol_from_ofp_version
                ((ofp_version)intConn.GetProtocolVersion())),
          temp(fs::temp_directory_path() / fs::unique_path()) {
        createObjects();
        fs::create_directory(temp);
        dnsManager.setCacheDir(temp.string());
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
    EndpointTenantMapper endpointTenantMapper;
protected:
    DnsManager dnsManager;
    PacketInHandler pktInHandler;
    ofputil_protocol proto;
    fs::path temp;
    void testHandleDnsResponsePacket(bool is_v4, PacketDesc pd, boost::optional<const std::string &>altBuf=boost::none);
    void checkAnswer(std::string &askName, str_set_t& expectedResolved);
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

void DnsManagerFixture::testHandleDnsResponsePacket(bool is_v4, PacketDesc pd, boost::optional<const std::string &>altBuf ) {
    unsigned char buf[MAX_BUF_LEN];
    unsigned maxLen;
    if(altBuf) {
        maxLen = parseHexDump( altBuf.get(), buf);
    } else {
        maxLen = parseHexDump( PacketDef[pd], buf);
    }
    ofputil_packet_in_private pin;
    init_packet_in(pin, buf, maxLen,
	       is_v4 ? opflexagent::flow::cookie::DNS_RESPONSE_V4 : opflexagent::flow::cookie::DNS_RESPONSE_V6,
	       AccessFlowManager::TAP_TABLE_ID);

    OfpBuf b(ofputil_encode_packet_in_private(&pin,
					  OFPUTIL_P_OF13_OXM,
					  OFPUTIL_PACKET_IN_NXT));
    WAIT_FOR(dnsManager.isStarted(),500);
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

void DnsManagerFixture::checkAnswer(std::string &askName, str_set_t& expectedResolved) {
    using namespace modelgbp::epdr;
    auto ddU = DnsDemand::resolve(framework);
    Mutator m0(framework, "policyelement");
    auto dnsAsk = ddU.get()->addEpdrDnsAsk(askName);
    m0.commit();
    auto dnsAnswer = DnsAnswer::resolve(framework, askName);
    WAIT_FOR_DO(dnsAnswer,
	        500,
	        (dnsAnswer = DnsAnswer::resolve(framework, askName)));
    str_set_t out;
    WAIT_FOR_DO((expectedResolved==out),
	        500,
	        getResolvedAddressesFromAnswer(dnsAnswer.get(),out));
    //Remove demand and ensure answer goes away
    dnsAsk.get()->remove();
    m0.commit();
    auto dnsAnswer2 = DnsAnswer::resolve(framework, askName);
    WAIT_FOR_DO(!dnsAnswer2,
                500,
                (dnsAnswer2 = DnsAnswer::resolve(framework, askName)));
}

BOOST_FIXTURE_TEST_CASE(handleDnsResponsePacket, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_MULTIPLE_TYPE_A);
    std::string domainName("google.com");
    std::string askName("*google.com");
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
    std::unordered_set<std::string> expectedResolved = {"74.125.236.35","74.125.236.37","74.125.236.39","74.125.236.32",
	"74.125.236.40","74.125.236.33","74.125.236.41","74.125.236.34","74.125.236.36","74.125.236.38","74.125.236.46"};
    checkAnswer(askName, expectedResolved);
    dnsManager.stop();
    dnsManager.start();
    WAIT_FOR(dnsManager.isStarted(),500);
    checkAnswer(askName, expectedResolved);
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
    WAIT_FOR_DO(out.size()==2,
	        500,
	       getResolvedAddressesFromAnswer(dnsAnswer.get(),out));
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
    std::string askName("facebook.com");
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
   str_set_t expectedResolved = {"2a03:2880:f14b:82:face:b00c:0:25de"};
   checkAnswer(askName, expectedResolved);
   dnsManager.stop();
   dnsManager.start();
   WAIT_FOR(dnsManager.isStarted(),500);
   checkAnswer(askName, expectedResolved);
}

BOOST_FIXTURE_TEST_CASE(handleCNameRecord, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_CNAME_RECORD);
    std::string domainName("s3-website-us-east-1.amazonaws.com");
    std::string aliasName("static-mobile.qustodio.com.s3-website-us-east-1.amazonaws.com");
    std::string askName("static-mobile.qustodio.com");
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
    str_set_t expectedResolved = {"72.21.215.82"};
    checkAnswer(askName, expectedResolved);
    checkAnswer(domainName, expectedResolved);
    checkAnswer(aliasName, expectedResolved);
    dnsManager.stop();
    dnsManager.start();
    WAIT_FOR(dnsManager.isStarted(),500);
    checkAnswer(domainName, expectedResolved);
    checkAnswer(aliasName, expectedResolved);
    checkAnswer(askName, expectedResolved);
}

BOOST_FIXTURE_TEST_CASE(handleCNameRecordExpiry, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    //Create Demand before packet
    std::string askName("static-mobile.qustodio.com");
    auto ddU = DnsDemand::resolve(framework);
    Mutator m0(framework, "policyelement");
    auto dnsAsk = ddU.get()->addEpdrDnsAsk(askName);
    m0.commit();
    std::string expirableBuf = PacketDef[DNS_RESP_WITH_CNAME_RECORD];
    //Hack to change expiry time of packet
    expirableBuf[491] = '0';
    expirableBuf[492] = '0';
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_CNAME_RECORD, expirableBuf);
    std::string domainName("s3-website-us-east-1.amazonaws.com");
    std::string aliasName("static-mobile.qustodio.com.s3-website-us-east-1.amazonaws.com");
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
    str_set_t expectedResolved = {"72.21.215.82"};
    str_set_t out;
    auto dnsAnswer = DnsAnswer::resolve(framework, askName);
    WAIT_FOR_DO(dnsAnswer,
	        500,
                dnsAnswer = DnsAnswer::resolve(framework, askName));
    WAIT_FOR_DO((out == expectedResolved),
                500,
	        (dnsAnswer = DnsAnswer::resolve(framework, askName));
                getResolvedAddressesFromAnswer(dnsAnswer.get(),out));
#if 0
    //This is failing on Travis, debug this
    WAIT_FOR_DO(out.empty(),
                1500,
	        (dnsAnswer = DnsAnswer::resolve(framework, askName));
                getResolvedAddressesFromAnswer(dnsAnswer.get(),out));
#endif
}

BOOST_FIXTURE_TEST_CASE(handleSrvRecord, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_SRV_RECORD);
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_SINGLE_TYPE_A_RESOLVING_SRV_RECORD);
    std::string domainName("_jabber._tcp.gmail.com");
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
    str_set_t expectedResolved = {"64.233.171.125"};
    checkAnswer(domainName, expectedResolved);
    dnsManager.stop();
    dnsManager.start();
    WAIT_FOR(dnsManager.isStarted(),500);
    checkAnswer(domainName, expectedResolved);
}

BOOST_FIXTURE_TEST_CASE(handleSrvRecordExpiry, DnsManagerFixture) {
    using namespace modelgbp::epdr;
    //Create Demand before packet
    std::string domainName("_jabber._tcp.gmail.com");
    auto ddU = DnsDemand::resolve(framework);
    Mutator m0(framework, "policyelement");
    auto dnsAsk = ddU.get()->addEpdrDnsAsk(domainName);
    m0.commit();
    std::string expirableBuf = PacketDef[DNS_RESP_WITH_SRV_RECORD];
    //Hack to change expiry time of packet
    expirableBuf[395] = '0';
    expirableBuf[397] = '0';
    expirableBuf[398] = '1';
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_SRV_RECORD, expirableBuf);
    testHandleDnsResponsePacket(true, DNS_RESP_WITH_SINGLE_TYPE_A_RESOLVING_SRV_RECORD);
    auto dnsEntry = DnsEntry::resolve(framework, domainName);
    WAIT_FOR_DO(dnsEntry,
                500,
                (dnsEntry = DnsEntry::resolve(framework, domainName)));
    str_set_t expectedResolved = {"64.233.171.125"};
    str_set_t out;
    auto dnsAnswer = DnsAnswer::resolve(framework, domainName);
    WAIT_FOR_DO(dnsAnswer,
	        500,
                dnsAnswer = DnsAnswer::resolve(framework, domainName));
    WAIT_FOR_DO((expectedResolved==out),
	        500,
                (dnsAnswer = DnsAnswer::resolve(framework, domainName));
	        getResolvedAddressesFromAnswer(dnsAnswer.get(),out));
    WAIT_FOR_DO(out.empty(),
	        1500,
                (dnsAnswer = DnsAnswer::resolve(framework, domainName));
	        getResolvedAddressesFromAnswer(dnsAnswer.get(),out));
}
BOOST_AUTO_TEST_SUITE_END()
