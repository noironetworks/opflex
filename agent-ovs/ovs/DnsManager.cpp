/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for DNSManager
 *
 * Copyright (c) 2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include "DnsManager.h"
#include "Packets.h"
#include <opflexagent/logging.h>
#include <modelgbp/epdr/DnsDiscovered.hpp>
#include <modelgbp/epdr/DnsDemand.hpp>
#include <modelgbp/epdr/DnsAsk.hpp>
#include <thread>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/placeholders.hpp>
#include "ovs-shim.h"
#include "ovs-ofputil.h"
#include "eth.h"

namespace opflexagent {

    using opflex::modb::URI;
    using opflex::modb::class_id_t;
    DnsManager::DnsManager(Agent &agent):
    agent(agent),started(false)
    {
    }

    void DnsManager::start() {
        using boost::uuids::basic_random_generator;
        if(started)
            return;
        uuidGen.reset(new basic_random_generator<boost::mt19937>(&randomSeed));
        modelgbp::epdr::DnsAsk::registerListener(agent.getFramework(),this);
        work.reset(new boost::asio::io_service::work(io_ctxt));
        {
            lock_guard<recursive_mutex> lk(timerMutex);
            expiryTimer.reset( new boost::asio::deadline_timer(io_ctxt));
            expiryTimer->expires_from_now(boost::posix_time::seconds(1));
            expiryTimer->async_wait(boost::bind(&DnsManager::onExpiryTimer,this,_1));
        }
        parserThread.reset(new std::thread([this]() {
           started = true;
           io_ctxt.run();
        }));
    }

    bool DnsCacheEntry::age(DnsManager &mgr) {
        using namespace boost::posix_time;
        using namespace boost::gregorian;
        using namespace modelgbp::epdr;
        bool moChanged = false;
        ptime currTime = second_clock::local_time();
        for(auto cAItr = Ips.begin(); cAItr != Ips.end();) {
            if(currTime >= cAItr->expiryTime) {
                LOG(DEBUG) << domainName << "->" << cAItr->addr << " expired " <<
                    to_simple_string(cAItr->expiryTime);
                cAItr = Ips.erase(cAItr);
                moChanged=true;
            } else {
                cAItr++;
            }
        }
        if(!moChanged) {
            return Ips.empty();
        }
        opflex::modb::Mutator mutator(mgr.agent.getFramework(), "policyelement");
        //Handle DnsEntry
        if (Ips.empty()) {
            DnsEntry::remove(mgr.agent.getFramework(), domainName);
        } else {
            auto dnsEntry = DnsEntry::resolve(mgr.agent.getFramework(),domainName);
            std::vector<std::shared_ptr<modelgbp::epdr::DnsMappedAddress>> out;
            dnsEntry.get()->resolveEpdrDnsMappedAddress(out);
            for(const auto &mA:out) {
                if(!mA->getAddress())
                    continue;
                DnsCachedAddress cachedAddr(mA->getAddress().get());
                if(Ips.find(cachedAddr) == Ips.end()) {
                    dnsEntry.get()->addEpdrDnsMappedAddress(
                        mA->getAddress().get())->remove();
                }
            }
            dnsEntry.get()->setUpdated(to_simple_string(currTime));
        }
        //Handle DnsAnswer
        for(auto lAItr= linkedAnswers.begin(); lAItr != linkedAnswers.end();) {
            auto dnsAnswer = DnsAnswer::resolve(mgr.agent.getFramework(), *lAItr);
            if(!dnsAnswer) {
                lAItr = linkedAnswers.erase(lAItr);
                continue;
            }
            if (Ips.empty()) {
                auto buildDnsEntryUri = [](const std::string &name){
                   return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
                   .addElement("EpdrDnsEntry").addElement(name).build();
                };
                if (dnsAnswer.get()->getName().get() == domainName) {
                    mgr.demandMappings[domainName].resolved.clear();
                    mgr.demandMappings[domainName].linkedEntries.erase(domainName);
                    dnsAnswer.get()->remove();
                } else {
                    mgr.demandMappings[dnsAnswer.get()->getName().get()].resolved.clear();
                    mgr.demandMappings[dnsAnswer.get()->getName().get()].linkedEntries.erase(domainName);
                    dnsAnswer.get()->addEpdrDnsAnswerToResultRSrc(
                        buildDnsEntryUri(domainName).toString())->remove();
                }
                lAItr = linkedAnswers.erase(lAItr);
                continue;
            } else {
                DnsDemandState &demandState = mgr.demandMappings[dnsAnswer.get()->getName().get()];
                for(auto rItr = demandState.resolved.begin();
                        rItr != demandState.resolved.end();) {
                    DnsCachedAddress cachedAddr(*rItr);
                    if(Ips.find(cachedAddr) == Ips.end()) {
                        rItr = demandState.resolved.erase(rItr);
                        continue;
                    }
                    rItr++;
                }
                dnsAnswer.get()->setUuid(boost::uuids::to_string((*mgr.uuidGen)()));
            }
            lAItr++;
        }
        mutator.commit();
        return Ips.empty();
    }

    void DnsManager::onExpiryTimer(const boost::system::error_code &e) {
        using namespace boost::posix_time;
        using namespace boost::gregorian;
        using modelgbp::epdr::DnsAnswer;
        using modelgbp::epdr::DnsEntry;
        if(e == boost::asio::error::operation_aborted) {
            return;
        }
        {
            std::unique_lock<std::mutex> lk(stateMutex);
            for(auto itr = learntMappings.begin();
                itr != learntMappings.end();) {
                if (itr->second.age(*this)) {
                    itr = learntMappings.erase(itr);
                } else {
                    itr++;
                }
            }
        }
        lock_guard<recursive_mutex> lk(timerMutex);
        expiryTimer->expires_from_now(seconds(1));
        expiryTimer->async_wait(boost::bind(&DnsManager::onExpiryTimer,this,_1));
    }

    bool DnsCacheEntry::update(DnsParsingContext::DnsRR &dnsRR) {
        using namespace boost::posix_time;
        using namespace boost::gregorian;

        DnsCachedAddress cA(dnsRR);
        auto pr = Ips.insert(cA);
        if(pr.second)
            return true;
        if (cA.expiryTime > pr.first->expiryTime) {
            Ips.erase(pr.first);
            Ips.insert(cA);
        }
        return false;
    }

    bool DnsManager::getResolvedAddresses(const std::string& name, std::unordered_set<std::string> &addr_set) {
        if(demandMappings.find(name) != demandMappings.end()) {
            addr_set = demandMappings[name].resolved;
            return true;
        }
        return false;
    }

    void DnsManager::handlePacketIn(void *qElem) {
        {
            std::unique_lock<std::mutex> lk(packetQMutex);
            packetInQ.push(qElem);
        }
        io_ctxt.post([=]() {this->processPacket();});
    }

    static bool ValidateDnsPacket(struct dp_packet *pkt,
                                  dns::dns_hdr **hdr,
                                  size_t &dnsOffset)
    {
        eth::eth_header *eth_hdr;
        if(pkt == NULL) {
            return false;
        }
        char* pkt_data = (char*)dpp_data(pkt);
        size_t l3_offset = (char*)dpp_l3(pkt)-pkt_data;
        size_t l4_offset = (char*)dpp_l4(pkt)-pkt_data;
        uint8_t ip_proto=0;
        if (!(eth_hdr = (eth::eth_header *)dpp_at(pkt, 0,
                    sizeof(eth::eth_header)))) {
            return false;
        }
        switch(ntohs(eth_hdr->eth_type)) {
            case eth::type::IP:
            {
                struct iphdr *ip_header;
                if(!(ip_header = (struct iphdr *)dpp_at(pkt,l3_offset,
                   sizeof(struct iphdr)))){
                    return false;
                }
                ip_proto = ip_header->protocol;
                break;
            }
            case eth::type::IPV6:
            {
                struct ip6_hdr* ip6_header;
                if(!(ip6_header = (struct ip6_hdr*)dpp_at(pkt,l3_offset,
                   sizeof(struct ip6_hdr)))){
                    return false;
                }
                ip_proto = ip6_header->ip6_nxt;
                break;
            }
            default:
                return false;
        }
        switch(ip_proto) {
            case ip::type::UDP:
            {
                udp::udp_header* udp_hdr;
                if(!(udp_hdr = (udp::udp_header *)dpp_at(pkt, l4_offset,
                   UDP_HDR_LEN))){
                    return false;
                }
                if((ntohs(udp_hdr->source) != udp::type::DNS) &&
                   (ntohs(udp_hdr->dest) != udp::type::DNS)) {
                    return false;
                }
                dnsOffset = l4_offset + UDP_HDR_LEN;
                break;
            }
            case ip::type::TCP:
            {
                tcp::tcp_header* tcp_hdr;
                if(!(tcp_hdr = (tcp::tcp_header*)dpp_at(pkt, l4_offset,
                   sizeof(tcp::tcp_header)))){
                     return false;
                }
                if((ntohs(tcp_hdr->source) != tcp::type::DNS) &&
                   (ntohs(tcp_hdr->dest) != tcp::type::DNS)) {
                    return false;
                }
                dnsOffset = l4_offset + (uint16_t)tcp_hdr->doff*4;
                break;
            }
            default:
                return false;
        }
        if(!(*hdr = (dns::dns_hdr*)dpp_at(pkt, dnsOffset,
           DNS_HDR_LEN))){
            return false;
        }
        return true;
    }

    static void ParseDomainName(DnsParsingContext &ctxt, std::string &domainName) {
        uint32_t oldLabelOffset = ctxt.labelOffset;
        std::list<std::string> emptyList;
        ctxt.labelSet.emplace_back(emptyList);
        DnsParsingContext::LabelSetIterator labelSetItr = std::prev(ctxt.labelSet.end());
        std::string label;
        uint8_t labelLen = 0;
        for(; ((ctxt.tailRoom>0) && (ctxt.labelState != DnsParsingContext::terminatingLabel));
             ctxt.dptr++, ctxt.tailRoom--) {
            switch(ctxt.labelState){
                case DnsParsingContext::seekingLabel:
                {
                    labelLen = (unsigned)*ctxt.dptr;
                    if(labelLen == 0) {
                        ctxt.labelState = DnsParsingContext::terminatingLabel;
                        break;
                    }
                    if((labelLen & 0xc0) == 0xc0) {
                        ctxt.labelState = DnsParsingContext::accumulatingPtr;
                        ctxt.labelPtrHi = labelLen & 0x3f;
                        break;
                    }
                    ctxt.labelOffset += labelLen+1;
                    ctxt.labelState = DnsParsingContext::accumulatingLabel;
                    break;
                }
                case DnsParsingContext::accumulatingPtr:
                {
                    uint32_t labelPtr = ((uint16_t)((((uint16_t)ctxt.labelPtrHi>>2)
                         << 8)+ ((uint16_t)*ctxt.dptr)));
                    if(ctxt.labelMap.find(labelPtr) != ctxt.labelMap.end()) {
                        ctxt.labelMap[oldLabelOffset] = ctxt.labelMap[labelPtr];
                        for(auto itr=ctxt.labelMap[labelPtr].second;
                                itr!=ctxt.labelMap[labelPtr].first->end();itr++) {
                            labelSetItr->push_back(*itr);
                        }
                    }
                    ctxt.labelOffset += 2;
                    oldLabelOffset = ctxt.labelOffset;
                    ctxt.labelState = DnsParsingContext::terminatingLabel;
                    break;
                }
                case DnsParsingContext::accumulatingLabel:
                {
                    label += *ctxt.dptr;
                    labelLen--;
                    if(labelLen == 0) {
                        labelSetItr->push_back(label);
                        DnsParsingContext::LabelStringIterator labelStringItr = std::prev(labelSetItr->end());
                        ctxt.labelMap[oldLabelOffset] = std::make_pair(labelSetItr,labelStringItr);
                        oldLabelOffset = ctxt.labelOffset;
                        label.clear();
                        ctxt.labelState = DnsParsingContext::seekingLabel;
                    }
                    break;
                }
                case DnsParsingContext::terminatingLabel:
                {
                    //Terminal state. cannot come here
                    break;
                }
           }
      }
        /* Reset domainname parsing state*/
        ctxt.labelState = DnsParsingContext::seekingLabel;
        for(auto itr=labelSetItr->begin(); itr!= labelSetItr->end(); itr++) {
            domainName += *itr;
            if(std::next(itr) != labelSetItr->end()){
                domainName += ".";
            }
        }
    }

    /* Debug printing*/
    std::ostream & operator <<(std::ostream &os,const DnsParsingContext::RRType &rType) {
        switch(rType){
            case DnsParsingContext::RRTypeA:
                os << "A";
                break;
            case DnsParsingContext::RRTypeA4:
                os << "AAAA";
                break;
            default:
                os << (unsigned)rType;
                break;
        }
        return os;
    }

    std::ostream & operator <<(std::ostream &os,const DnsParsingContext::RRClass &rClass) {
        switch(rClass){
            case DnsParsingContext::RRClassIN:
                os << "IN";
                break;
            case DnsParsingContext::RRClassCS:
                os << "CS";
                break;
            case DnsParsingContext::RRClassAny:
                os << "Any";
                break;
            default:
                os << (unsigned)rClass;
                break;
        }
        return os;
    }

    std::ostream & operator<<(std::ostream &os, const DnsParsingContext& dnsCtxt) {
        typedef DnsParsingContext::RRType RRType;
        os << endl;
        os << "Questions: " << dnsCtxt.qdCount << ", Answer RRs: " << dnsCtxt.anCount <<
           ", Authority RRs: " << dnsCtxt.nsCount << ", Additional RRs: " << dnsCtxt.arCount << endl;
        os << "Queries:" << endl;
        for(const auto &q: dnsCtxt.questions){
            os << q.domainName << ":  " << "type " << q.qType << ", class " << q.qClass;
        }
        os << endl;
        os << "Answers: " << endl;
        for(const auto &rr: dnsCtxt.answers){
            os << rr.domainName << ":  " << "type " << rr.rType << ", class " << rr.rClass;
            os << ", ttl: " << rr.ttl;
            switch(rr.rType){
                case RRType::RRTypeA:
                    os << ", addr " <<
                    boost::asio::ip::address_v4(rr.rrTypeAData).to_string();
                    break;
                case RRType::RRTypeA4:
                    std::array<unsigned char, IP6_ADDR_LEN> bytes;
                    for(int i=0; i<IP6_ADDR_LEN; i++) {
                        bytes[i] = rr.rrTypeA4Data.v6Bytes[i];
                    }
                    os << ", addr " <<
                    boost::asio::ip::address_v6(bytes).to_string();
                    break;
                default:
                    break;
            }
            os << endl;
        }
        return os;
    }

    /**
     * domain name restricted regex matching
     * Note alternatives are using boost::algorithm::ends_with
     * @param a domain name with no wildcards allowed
     * @param b can start with a * for prefix wildcard match but otherwise
     * is a domain name.
     * @return whether there is a regex match
     */
    static bool DomainNameMatch(const std::string &a, const std::string &b) {
        if(a.empty() || b.empty()) {
            return false;
        }
        if(b.data()[0] != '*'){
            return a == b;
        }
        if(b.size()==1) {
            return true;
        }
        if(b.size() > (a.size()+1)) {
            return false;
        }
        for(int i=b.size()-1,j=a.size()-1;i!=0;i--,j--){
            if(b.data()[i] != a.data()[j]) {
                return false;
            }
        }
        return true;
    }

    void DnsManager::updateMOs(DnsCacheEntry &entry, bool changed) {
        auto dDiscoveredU = modelgbp::epdr::DnsDiscovered::resolve(agent.getFramework());
        opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
        auto dnsEntry = dDiscoveredU.get()->addEpdrDnsEntry(entry.domainName);
        dnsEntry->setUpdated(boost::posix_time::to_simple_string(entry.lastUpdated));
        for(const auto& cA: entry.Ips) {
            auto mA = dnsEntry->addEpdrDnsMappedAddress(cA.addr.to_string());
            mA->setExpiry(boost::posix_time::to_simple_string(cA.expiryTime));
        }
        mutator.commit();
        for(auto demandItr : demandMappings) {
            if(DomainNameMatch(entry.domainName,demandItr.first)){
                auto dnsAnswer = dDiscoveredU.get()->addEpdrDnsAnswer(demandItr.first);
                if(changed) {
                    dnsAnswer->setUuid(boost::uuids::to_string((*uuidGen)()));
                }
                dnsAnswer->addEpdrDnsAnswerToResultRSrc(dnsEntry->getURI().toString());
                entry.linkedAnswers.insert(dnsAnswer->getURI());
                demandItr.second.linkedEntries.insert(entry.domainName);
            }
        }
        mutator.commit();
    }

    DnsCachedAddress::DnsCachedAddress(DnsParsingContext::DnsRR dnsRR)
    {
        using namespace boost::posix_time;
        boost::system::error_code ec;
        //Resolve addresses using the RRs here
        switch(dnsRR.rType) {
            case DnsParsingContext::RRTypeA:
            {
                addr = boost::asio::ip::address_v4(dnsRR.rrTypeAData);
                break;
            }
            case DnsParsingContext::RRTypeA4:
            {
                std::array<unsigned char, IP6_ADDR_LEN> bytes;
                for(int i=0; i<IP6_ADDR_LEN; i++) {
                    bytes[i] = dnsRR.rrTypeA4Data.v6Bytes[i];
                }
                addr = boost::asio::ip::address_v6(bytes);
                break;
            }
            default:
                break;
        }
        expiryTime = dnsRR.currTime + seconds(dnsRR.ttl);
    }

    void DnsManager::updateCache(DnsParsingContext &ctxt) {
        bool changed = false;
        std::unique_lock<std::mutex> lk(stateMutex);
        for(auto itr=ctxt.answers.begin(); itr != ctxt.answers.end(); itr++) {
            if(itr->domainName.empty()) {
                continue;
            }
            if(learntMappings.find(itr->domainName) != learntMappings.end()){
                learntMappings[itr->domainName].lastUpdated = itr->currTime;
                changed = learntMappings[itr->domainName].update(*itr);
            } else {
                if(!itr->domainName.empty()) {
                    DnsCacheEntry entry(*itr);
                    learntMappings.emplace(std::make_pair(itr->domainName,entry));
                    learntMappings[itr->domainName].lastUpdated = itr->currTime;
                    changed = true;
                }
            }
            updateMOs(learntMappings[itr->domainName], changed);
        }
    }

    bool DnsManager::handlePacket(struct dp_packet *pkt) {
        struct dns::dns_hdr *hdr;
        size_t l5_offset = 0;
        if(!ValidateDnsPacket(pkt, &hdr, l5_offset)) {
            LOG(ERROR) << "Failed lower layer validation";
            return false;
        }
        uint32_t tailroom = dpp_size(pkt) - l5_offset - DNS_HDR_LEN;
        DnsParsingContext ctxt(hdr, tailroom);
        if((hdr->hi_flag & DNS_RCODE_MASK) != 0) {
            //Ignore erroneous packets
            LOG(DEBUG) << "Ignoring server error";
            return true;
        }
        if((hdr->lo_flag & DNS_OPCODE_MASK) != 0) {
            //Only handle standard query packets for now
            LOG(DEBUG) << "Ignoring query packet";
            return true;
        }
        if((hdr->lo_flag & DNS_QR_MASK) == DNS_QR_RESPONSE) {
            //Check for AA?
            //Need to have atleast one question and answer section
            if((ntohs(hdr->qdcount)==0) || (ntohs(hdr->ancount)==0)) {
                return true;
            }
            //Question Section
            ctxt.parsingSection = DnsParsingContext::questionSection;
            for(int qdc = ctxt.qdCount; qdc>0; qdc--) {
                DnsParsingContext::DnsQuestion dnsQuestion;
                ParseDomainName(ctxt, dnsQuestion.domainName);
                if((ctxt.labelState != DnsParsingContext::seekingLabel) ||
                   (ctxt.tailRoom < 4)) {
                LOG(ERROR) << "Incorrect question section";
                return false;
            }
                dnsQuestion.qType = (DnsParsingContext::RRType)(ntohs(*(uint16_t *)(ctxt.dptr)));
                ctxt.dptr += 2;
                dnsQuestion.qClass = (DnsParsingContext::RRClass)(ntohs(*(uint16_t *)(ctxt.dptr)));
                ctxt.dptr += 2;
                ctxt.tailRoom -= 4;
                ctxt.questions.emplace_back(dnsQuestion);
            }
            //Answer section
            ctxt.parsingSection = DnsParsingContext::answerSection;
            for(int anc = ctxt.anCount; anc>0; anc--) {
                DnsParsingContext::DnsRR dnsRR;
                ParseDomainName(ctxt,dnsRR.domainName);
                if((ctxt.labelState != DnsParsingContext::seekingLabel) ||
                   (ctxt.tailRoom < 10)) {
                    LOG(ERROR) << "Incorrect answer section";
                    return false;
                }
                dnsRR.rType = (DnsParsingContext::RRType)ntohs((*(uint16_t *)ctxt.dptr));
                ctxt.dptr += 2;
                dnsRR.rClass = (DnsParsingContext::RRClass)ntohs(*((uint16_t *)ctxt.dptr));
                ctxt.dptr += 2;
                dnsRR.ttl = ntohl(*(uint32_t *)ctxt.dptr);
                ctxt.dptr += 4;
                dnsRR.rdLen = ntohs(*(uint16_t *)ctxt.dptr);
                ctxt.dptr += 2;
                ctxt.tailRoom -= 10;
                if (ctxt.tailRoom < dnsRR.rdLen) {
                    LOG(ERROR) << "Incorrect answer record";
                    return false;
                }
                switch(dnsRR.rType) {
                    case DnsParsingContext::RRTypeA:
                    {
                        if(dnsRR.rdLen < 4) {
                            LOG(ERROR) << "Incorrect A record";
                            return false;
                        }
                        dnsRR.rrTypeAData = ntohl(*(uint32_t *)ctxt.dptr);
                        break;
                    }
                    case DnsParsingContext::RRTypeA4:
                    {
                        if(dnsRR.rdLen < IP6_ADDR_LEN) {
                            LOG(ERROR) << "Incorrect AAAA record";
                            return false;
                        }
                        memcpy(dnsRR.rrTypeA4Data.v6Bytes, ctxt.dptr, IP6_ADDR_LEN);
                        break;
                    }
                    default:
                    {
                        LOG(DEBUG) << "Unhandled record type " << dnsRR.rType;
                        break;
                    }
                }
                ctxt.dptr += dnsRR.rdLen;
                ctxt.tailRoom -= dnsRR.rdLen;
                ctxt.answers.emplace_back(dnsRR);
            }
            LOG(DEBUG) << ctxt;
            //Authority section: not processing this as of now
            //Additional records section: not processing this as of now
       } else {
       //Not handling pure queries as of now
       }
       updateCache(ctxt);
       return true;
    }

    void DnsManager::processPacket() {
        struct dp_packet *qElem = NULL;
        {
            std::unique_lock<std::mutex> lk(packetQMutex);
            if(!packetInQ.empty()) {
                qElem = (struct dp_packet *)packetInQ.front();
                packetInQ.pop();
            }
        }
        if(!handlePacket(qElem)) {
            LOG(ERROR) << "DNS packet parsing failed!";
        }
        dpp_delete(qElem);
    }

    void DnsManager::handleDnsAsk(URI &askUri, std::unordered_set<URI> &notifySet) {
       auto ask = modelgbp::epdr::DnsAsk::resolve(agent.getFramework(),askUri);
       auto buildDnsAnswerUri = [](const std::string &name){
           return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsAnswer").addElement(name).build();
        };
       auto buildDnsEntryUri = [](const std::string &name){
           return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsEntry").addElement(name).build();
        };
       auto addCacheEntryToAnswer = [](std::string &askName, URI &askUri,
                                       DnsCacheEntry & cacheEntry, DnsDemandState &demandState,
                                       std::unordered_set<std::string> &cacheSet,
                                       std::unordered_set<URI> &notifySet) {
           for(const auto &mappedIp: cacheEntry.Ips) {
               demandState.resolved.insert(mappedIp.addr.to_string());
           }
           demandState.linkedEntries.insert(cacheEntry.domainName);
           URI dnsAnswerUri = opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsAnswer").addElement(askName).build();
           cacheEntry.linkedAnswers.insert(dnsAnswerUri);
           cacheSet.insert(cacheEntry.domainName);
           notifySet.insert(askUri);
        };
       if(ask) {
           std::unordered_set<std::string> cacheSet;
           std::string askName = ask.get()->getName().get();
           DnsDemandState emptySet;
           std::unique_lock<std::mutex> lk(stateMutex);
           auto p = demandMappings.insert(std::make_pair(askName,emptySet));
           if(askName.data()[0] =='*') {
               for(auto lm: learntMappings) {
                   if(DomainNameMatch(lm.first,askName)) {
                       addCacheEntryToAnswer(askName, askUri,
                        lm.second, p.first->second, cacheSet, notifySet);
                   }
               }
           } else {
               if (learntMappings.find(askName) != learntMappings.end()) {
                   addCacheEntryToAnswer(askName, askUri,
                    learntMappings[askName], p.first->second, cacheSet, notifySet);
               }
           }
           if(!notifySet.empty()) {
               auto dDiscoveredU = modelgbp::epdr::DnsDiscovered::resolve(agent.getFramework());
               opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
               auto dnsAnswer = dDiscoveredU.get()->addEpdrDnsAnswer(askName);
               for(const auto &cacheStr:cacheSet) {
                   dnsAnswer->addEpdrDnsAnswerToResultRSrc(buildDnsEntryUri(cacheStr).toString());
               }
               dnsAnswer->setUuid(boost::uuids::to_string((*uuidGen)()));
               mutator.commit();
           }
       } else {
           std::unique_lock<std::mutex> lk(stateMutex);
           vector<string> elements;
           askUri.getElements(elements);
           if( elements.size()<1 ) {
               return;
           }
           if (demandMappings.find(elements.back()) != demandMappings.end()) {
               for(const auto &entryStr: demandMappings[elements.back()].linkedEntries) {
                   auto dnsAnswerUri = buildDnsAnswerUri(entryStr);
                   learntMappings[entryStr].linkedAnswers.erase(dnsAnswerUri);
               }
               opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
               modelgbp::epdr::DnsAnswer::remove(agent.getFramework(),elements.back());
               mutator.commit();
               demandMappings.erase(demandMappings.find(elements.back()));
               notifySet.insert(askUri);
           }
       }
    }

    void DnsManager::notifyListeners(class_id_t cid, const URI& notifyURI) {
        std::lock_guard<std::mutex> guard(listenerMutex);
        for (DnsListener* listener : dnsListeners) {
            listener->dnsDemandUpdated(cid, notifyURI);
        }
    }

    void DnsManager::processURI(class_id_t class_id,
                        std::mutex &qMutex, std::queue<URI> &uriQ,
                        std::function<void (URI&, std::unordered_set<URI>&)> func) {
        boost::optional <opflex::modb::URI &> uri;
        {
            std::unique_lock<std::mutex> qLk(qMutex);
            if(!uriQ.empty()) {
               uri = uriQ.front();
               uriQ.pop();
            }
        }
        if(!uri){
            return;
        }
        std::unordered_set<URI> notifySet;
        func(uri.get(),notifySet);
        for(const auto &notifyUri: notifySet) {
            notifyListeners(class_id, notifyUri);
        }
    }

    void DnsManager::objectUpdated (class_id_t class_id,
                        const opflex::modb::URI& uri) {
       std::function<void (URI &,std::unordered_set<URI>&)> func;
       {
           std::unique_lock<std::mutex> lk(askQMutex);
           askQ.push(uri);
       }
       switch(class_id) {
           case modelgbp::epdr::DnsAsk::CLASS_ID:
           {
               func = boost::bind(&DnsManager::handleDnsAsk,this,_1,_2);
               break;
           }
       }
       io_ctxt.post([=]() {processURI(class_id, askQMutex, askQ, func);});
    }

    void DnsManager::stop() {
        if(!started)
            return;
        boost::system::error_code ec;
        {
            lock_guard<recursive_mutex> lk(timerMutex);
            expiryTimer->cancel(ec);
        }
        work.reset();
        parserThread->join();
    }

    bool operator==(const DnsCachedAddress& lhs, const DnsCachedAddress& rhs) {
        return lhs.addr == rhs.addr;
    }
}

namespace std {

size_t hash<opflexagent::DnsCachedAddress>::operator()(const opflexagent::DnsCachedAddress& cA) const
{
    return hash<string>{}( cA.addr.to_string());
}

}
