/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for DnsManager
 *
 * Copyright (c) 2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_DNSMANAGER_H
#define OPFLEXAGENT_DNSMANAGER_H

#include <opflexagent/Agent.h>
#include "PortMapper.h"
#include <functional>
#include <boost/noncopyable.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/system/error_code.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/local_time/local_time.hpp>
#include <list>
#include <unordered_set>
#include <mutex>
#include <random>
#include <queue>
#include "ip.h"

namespace opflexagent {
    class DnsCachedAddress;
}

namespace std {

template<> struct hash<opflexagent::DnsCachedAddress>
{
    std::size_t operator()(const opflexagent::DnsCachedAddress& cA) const;
};

}

namespace opflexagent {

class DnsListener {
    public:
        /**
         * Update Listeners about an available DNS Answer
         * @param cid DnsDemand::CLASS_ID
         * @param dnsDemand URI of the original demand
         */
        virtual void dnsDemandUpdated(opflex::modb::class_id_t cid, opflex::modb::URI dnsDemand);
};


class DnsParsingContext {
public:
    DnsParsingContext(dns::dns_hdr *hdr, uint32_t _tailRoom):
        dptr((char *)hdr + DNS_HDR_LEN),
        qdCount(ntohs(hdr->qdcount)), anCount(ntohs(hdr->ancount)),
        nsCount(ntohs(hdr->nscount)), arCount(ntohs(hdr->arcount)),
        tailRoom(_tailRoom), labelOffset(DNS_HDR_LEN),
        labelPtrHi(0), labelState(seekingLabel), parsingSection(baseSection){}
    char *dptr;
    uint16_t qdCount, anCount, nsCount, arCount;
    uint32_t tailRoom, labelOffset;
    uint8_t labelPtrHi;
    //RFC-1035
    enum LabelState {
        seekingLabel=0,
        accumulatingPtr,
        accumulatingLabel,
        terminatingLabel
    } labelState;
    enum ParsingSection {
        baseSection=0,
        questionSection,
        answerSection,
        authoritySection,
        additionalSection
    } parsingSection;
    //RFC-883
    enum RRClass {
        RRClassIN=1,
        RRClassCS=2,
        RRClassAny=255
    };
    enum RRType {
        //V4 Host Address
        RRTypeA=1,
        RRTypeNS=2,
        RRTypeMD=3,
        RRTypeMF=4,
        //Canonical Name
        RRTypeCName=5,
        RRTypeSOA=6,
        RRTypeMB=7,
        RRTypeMG=8,
        RRTypeMR=9,
        RRTypeNULL=10,
        RRTypeWKS=11,
        RRTypePTR=12,
        RRTypeHINFO=13,
        RRTypeMINFO=14,
        //V6 Host Address
        RRTypeA4=28,
        //V6 Host Address
        RRTypeA6=38
    };
    class DnsQuestion {
    public:
        std::string domainName;
        RRType qType;
        RRClass qClass;
    };
    class DnsRR {
    public:
        DnsRR():currTime(boost::posix_time::second_clock::local_time()),
        rType(RRTypeA),rClass(RRClassIN),ttl(0),rdLen(0)
        {
        }
        std::string domainName;
        boost::posix_time::ptime currTime;
        RRType rType;
        RRClass rClass;
        uint16_t ttl;
        uint16_t rdLen;
        //std::variant available only in C++17
        union {
            uint32_t rrTypeAData;
            //RFC-2874
            struct {
                uint8_t prefixLen;
                //Could be a max of 255 bytes
                void *data;
            } rrTypeA6Data;
            //RFC-1886,RFC-3596
            struct {
                uint8_t v6Bytes[16];
            } rrTypeA4Data;
            struct {
                void *data;
            } rrTypeCNameData;
        };
    };

    typedef std::list<std::list<std::string>>::iterator LabelSetIterator;
    typedef std::list<std::string>::iterator LabelStringIterator;
    std::unordered_map<uint32_t, std::pair<LabelSetIterator,LabelStringIterator>> labelMap;
    std::list<std::list<std::string>> labelSet;
    std::list<DnsQuestion> questions;
    std::list<DnsRR> answers;
};

class DnsCachedAddress {
public:
    DnsCachedAddress(DnsParsingContext::DnsRR dnsRR);
    DnsCachedAddress(const std::string &addrStr):
	expiryTime(boost::posix_time::second_clock::local_time()) {
	boost::system::error_code ec;
	addr = boost::asio::ip::address::from_string(addrStr, ec);
    };
    boost::posix_time::ptime expiryTime;
    boost::asio::ip::address addr;
};

bool operator==(const DnsCachedAddress& lhs, const DnsCachedAddress& rhs);

class DnsManager;

class DnsCacheEntry {
public:
    DnsCacheEntry(DnsParsingContext::DnsRR &dnsRR):
        domainName(dnsRR.domainName),
        lastUpdated(dnsRR.currTime) {
        DnsCachedAddress cachedAddr(dnsRR);
        Ips.insert(cachedAddr);
    }
    DnsCacheEntry():lastUpdated(boost::posix_time::second_clock::local_time()){};
    std::string domainName;
    std::unordered_set<DnsCachedAddress> Ips;
    std::unordered_set<opflex::modb::URI> linkedAnswers;
    boost::posix_time::ptime lastUpdated;
    /**
     * Update cache entry
     * @param dnsRR DNS resource record
     * @return whether a new address was added
     */
    bool update(DnsParsingContext::DnsRR &dnsRR);
    /**
     * Age cache entry
     * @param mgr DNS Manager instance
     * @return whether cache entry is aged out
     * and can be removed
     */
    bool age(DnsManager &mgr);
};

class DnsDemandState {
public:
    std::unordered_set<std::string> resolved;
    std::unordered_set<std::string> linkedEntries;
};

class DnsManager : public opflex::modb::ObjectListener, private boost::noncopyable {
public:
    /**
     * Construct a DnsManager
     * @param agent the agent object
     */
    DnsManager(Agent& agent);
    /**
     * Start DnsManager
     */
    void start();
    /**
     * Stop DnsManager
     */
    void stop();
    /**
     * Handle packet in
     * @param qElem Packet in buffer contained in a shared pointer
     */
    void handlePacketIn(void *qElem);
    /**
     * Register listener
     * @param listener
     */
    void registerListener(DnsListener *listener);
    /**
     * Unregister listener
     * @param listener
     */
    void unregisterListener(DnsListener *listener);
    /**
     * getResolvedAddresses
     * @param name domain name to be resolved
     * @param addr_set set of resolved addresses
     * @return whether atleast one resolved address exists
     */
    bool getResolvedAddresses(const std::string& name, std::unordered_set<std::string> &addr_set);
    /**
     * MODB listener interface
     */
    virtual void objectUpdated (opflex::modb::class_id_t class_id,
                                    const opflex::modb::URI& uri);
    friend DnsCacheEntry;
private:
    boost::asio::io_service io_ctxt;
    std::unique_ptr<boost::asio::io_service::work> work;
    Agent& agent;
    /*Map of domainName to DNS Entry*/
    std::unordered_map<std::string, DnsCacheEntry> learntMappings;
    /*Map of dns demand to resolved addresses*/
    std::unordered_map<std::string, DnsDemandState> demandMappings;
    std::list<DnsListener *> dnsListeners;
    std::mutex listenerMutex,packetQMutex,askQMutex,stateMutex;
    std::recursive_mutex timerMutex;
    std::queue<void *> packetInQ;
    std::queue<URI> askQ;
    std::unique_ptr<boost::asio::deadline_timer> expiryTimer;
    std::unique_ptr<std::thread> parserThread;
    std::unique_ptr<boost::uuids::basic_random_generator<boost::mt19937>> uuidGen;
    std::atomic<bool> started;
    boost::mt19937 randomSeed;
    void notifyListeners(class_id_t cid, const URI& notifyURI);
    void updateMOs(DnsCacheEntry &entry, bool updated);
    void updateCache(DnsParsingContext &ctxt);
    void handleDnsAsk(URI &askUri, std::unordered_set<URI> &notifySet);
    void processURI(class_id_t class_id,
                    std::mutex &qMutex, std::queue<URI> &uriQ,
                    std::function<void (URI&, std::unordered_set<URI>&)> func);
    bool handlePacket(struct dp_packet *pkt);
    void processPacket();
    void onExpiryTimer(const boost::system::error_code &e);
};

/**
 * Print parsing context to an ostream
 */
std::ostream & operator <<(std::ostream &os, const DnsParsingContext::RRType &rType);
std::ostream & operator <<(std::ostream &os, const DnsParsingContext::RRClass &rClass);
std::ostream & operator <<(std::ostream &os, const DnsParsingContext& dnsCtxt);

}
#endif /* OPFLEXAGENT_DNSMANAGER_H */
