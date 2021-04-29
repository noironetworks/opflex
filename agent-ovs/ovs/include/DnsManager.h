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
#include <string>
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

//RFC-883
enum DnsRRClass {
    RRClassIN=1,
    RRClassCS=2,
    RRClassAny=255
};

enum DnsRRType {
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

class DnsRR {
public:
    DnsRR(const std::string &_domainName, DnsRRType _rType,
          DnsRRClass _rclass=DnsRRClass::RRClassIN,
          uint16_t _ttl=0, uint16_t _rdLen=0):
        domainName(_domainName),
        currTime(boost::posix_time::second_clock::local_time()),
        rType(_rType),rClass(_rclass),ttl(_ttl),rdLen(_rdLen)
    {
        if(rType == RRTypeCName) {
            new (&rrTypeCNameData.cName) std::string;
        }
    }
    DnsRR(const DnsRR& dnsRR);
    ~DnsRR() {
        if(rType == RRTypeCName) {
            rrTypeCNameData.cName.~basic_string();
        }
    }
    std::string domainName;
    boost::posix_time::ptime currTime;
    DnsRRType rType;
    DnsRRClass rClass;
    uint16_t ttl;
    uint16_t rdLen;
    inline bool hasDirectAddress() const {
        return ((rType == DnsRRType::RRTypeA) ||
            (rType == DnsRRType::RRTypeA4));
    }
    inline bool isCName() const {
        return (rType == DnsRRType::RRTypeCName);
    }
    inline std::string getCName() const {
        if(rType == DnsRRType::RRTypeCName) {
            return rrTypeCNameData.cName;
        }
        return std::string();
    }
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
            std::string cName;
        } rrTypeCNameData;
    };
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
    class DnsQuestion {
    public:
        std::string domainName;
        DnsRRType qType;
        DnsRRClass qClass;
    };
    typedef std::list<std::list<std::string>>::iterator LabelSetIterator;
    typedef std::list<std::string>::iterator LabelStringIterator;
    std::unordered_map<uint32_t, std::pair<LabelSetIterator,LabelStringIterator>> labelMap;
    std::list<std::list<std::string>> labelSet;
    std::list<DnsQuestion> questions;
    std::list<DnsRR> answers;
};

class DnsCachedCName {
public:
    DnsCachedCName(const DnsRR &dnsRR);
    DnsCachedCName():
	expiryTime(boost::posix_time::second_clock::local_time()) {
    }
    boost::posix_time::ptime expiryTime;
    std::string cName;
};

class DnsCachedAddress {
public:
    DnsCachedAddress(const DnsRR &dnsRR);
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

/**
 * Class to hold a cached DNS entry
 * Note that there is no explicit flag to call out
 * a CName entry vs A/A4 entry.
 * According to RFC-1034,a CName record is exclusive
 * and we should not expect A/A4 params. In the event
 * that we get both, we will honor the CName record
 * for chained resolution and A/A4 entry for exclusive
 * resolution of this specific name
 */
class DnsCacheEntry {
public:
    DnsCacheEntry(const DnsRR &dnsRR);
    DnsCacheEntry(const std::string &name);
    DnsCacheEntry();
    typedef std::unordered_set<std::string> str_set_t;
    std::string domainName;
    DnsCachedCName cachedCName;
    str_set_t aNames;
    bool isHolder;
    std::unordered_set<DnsCachedAddress> Ips;
    std::unordered_set<opflex::modb::URI> linkedAnswers;
    boost::posix_time::ptime lastUpdated;
    /**
     * Update cache entry
     * @param dnsRR DNS resource record
     * @return whether a new address was added
     */
    bool update(DnsRR &dnsRR);
    /**
     * Age cache entry
     * @param mgr DNS Manager instance
     * @return whether cache entry is aged out
     * and can be removed
     */
    bool age(DnsManager &mgr);
    /**
     * Add alias
     * @param aName alternate name for this domainName
     * @return whether it is a loop free definition
     */
    bool addAlias(DnsManager &mgr, const std::string &aName);
    /**
     * Validate Canonical name
     * @param _cName canonical name for this domainName
     * @return whether it is a loop free definition
     */
    bool validateCName(const std::string &_cName);
    void setCName(const std::string &_cName) {
        cachedCName.cName = _cName;
    }
    std::string getCName() const {
        return cachedCName.cName;
    }
    bool isCName() const {
        return !cachedCName.cName.empty();
    }
    bool canExpire() const {
        if(isCName()) {
            return (!isHolder && aNames.empty());
        } else {
            return Ips.empty();
        }
    }
    bool matchesAliases(const std::string &askName,
            std::string &matchingAlias);
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
     * expireCName
     * Recurse cname chains to adjust for expired entry
     * @param entry expired cname entry
     */
    void expireCName(DnsCacheEntry &entry);
    /**
     * MODB listener interface
     */
    virtual void objectUpdated (opflex::modb::class_id_t class_id,
                                    const opflex::modb::URI& uri);
    /* *
     * Set the path to store learnt dns cache entries.
     * On restart, used to restore cache.
     */
    void setCacheDir(const std::string &_cacheDir) {
        cacheDir = _cacheDir;
    };
    bool isStarted() const {
        return started;
    }
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
    std::string cacheDir;
    void notifyListeners(class_id_t cid, const URI& notifyURI);
    void updateMOs(DnsCacheEntry &entry, bool updated);
    void updateMOs(const std::string &alias);
    DnsCacheEntry *getTerminalNode(DnsCacheEntry &startNode);
    bool validateCName(DnsRR &ctxt, DnsCacheEntry *existingEntry=NULL);
    void updateCache(DnsParsingContext &ctxt);
    void handleDnsAsk(URI &askUri, std::unordered_set<URI> &notifySet);
    void processURI(class_id_t class_id,
                    std::mutex &qMutex, std::queue<URI> &uriQ,
                    std::function<void (URI&, std::unordered_set<URI>&)> func);
    bool handlePacket(const struct dp_packet *pkt);
    void processPacket();
    void onExpiryTimer(const boost::system::error_code &e);
    std::string getStorePath(const DnsCacheEntry &entry) {
        return (cacheDir + "/" + entry.domainName + ".dns");
    }
    void commitToStore(const DnsCacheEntry &entry, bool erase=false);
    void restoreFromStore();
};

/**
 * Print parsing context to an ostream
 */
std::ostream & operator <<(std::ostream &os, const DnsRRType &rType);
std::ostream & operator <<(std::ostream &os, const DnsRRClass &rClass);
std::ostream & operator <<(std::ostream &os, const DnsParsingContext& dnsCtxt);

}
#endif /* OPFLEXAGENT_DNSMANAGER_H */
