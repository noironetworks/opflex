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
#include <boost/system/error_code.hpp>
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
        std::random_device randomDevice;
        boost::mt19937 randomSeed(randomDevice());
        uuidGen.reset(new basic_random_generator<boost::mt19937>(randomSeed));
        modelgbp::epdr::DnsAsk::registerListener(agent.getFramework(),this);
        work.reset(new boost::asio::io_service::work(io_ctxt));
        parserThread.reset(new std::thread([this]() {
           started = true;
           io_ctxt.run();
        }));
    }

    bool DnsManager::getResolvedAddresses(const std::string& name, std::unordered_set<std::string> &addr_set) {
        if(demandMappings.find(name) != demandMappings.end()) {
            addr_set = demandMappings[name];
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
        char* pkt_data = (char*)dpp_data(pkt);
        size_t l3_offset = (char*)dpp_l3(pkt)-pkt_data;
        size_t l4_offset = (char*)dpp_l4(pkt)-pkt_data;
        uint8_t ip_proto=0;
        if(pkt == NULL) {
            return false;
        }
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
            case DnsParsingContext::RRTypeA6:
                os << "A6";
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
        for(auto &q: dnsCtxt.questions){
            os << q.domainName << ":  " << "type " << q.qType << ", class " << q.qClass;
        }
        os << endl;
        os << "Answers: " << endl;
        for(auto &rr: dnsCtxt.answers){
            os << rr.domainName << ":  " << "type " << rr.rType << ", class " << rr.rClass;
            switch(rr.rType){
                case RRType::RRTypeA:
                    os << ", addr " <<((rr.rType == RRType::RRTypeA)?
                    boost::asio::ip::address_v4(rr.rrTypeAData).to_string():"");
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
        dnsEntry->setUpdated(entry.lastUpdated);
        dnsEntry->setExpiry(entry.ttl);
        for(const auto& addr: entry.Ips) {
            dnsEntry->addEpdrDnsMappedAddress(addr);
        }
        mutator.commit();
        for(const auto &demandItr : demandMappings) {
            if(DomainNameMatch(entry.domainName,demandItr.first)){
                auto dnsAnswer = dDiscoveredU.get()->addEpdrDnsAnswer(demandItr.first);
                if(changed) {
                    dnsAnswer->setUuid(boost::uuids::to_string((*uuidGen)()));
                }
                dnsAnswer->addEpdrDnsAnswerToResultRSrc(dnsEntry->getURI().toString());
            }
        }
        mutator.commit();
    }

    void DnsManager::updateCache(DnsParsingContext &ctxt) {
        bool changed = false;
        std::unique_lock<std::mutex> lk(stateMutex);
        for(auto itr=ctxt.answers.begin(); itr != ctxt.answers.end(); itr++) {
            if(learntMappings.find(itr->domainName) != learntMappings.end()){
                learntMappings[itr->domainName].lastUpdated = itr->timeStamp;
                learntMappings[itr->domainName].ttl = itr->ttl;
                if(itr->rType == DnsParsingContext::RRTypeA) {
                    std::string pA(boost::asio::ip::address_v4(itr->rrTypeAData).to_string());
                    if(learntMappings[itr->domainName].Ips.find(pA) ==
                       learntMappings[itr->domainName].Ips.end()) {
                       changed = true;
                    }
                    learntMappings[itr->domainName].Ips.insert(pA);
                }
            } else {
                DnsCacheEntry entry(*itr);
                learntMappings.emplace(std::make_pair(itr->domainName,entry));
                changed = true;
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
                //Support v4 host address records only as of now
                switch(dnsRR.rType) {
                    case DnsParsingContext::RRTypeA:
                    {
                        dnsRR.rrTypeAData = ntohl(*(uint32_t *)ctxt.dptr);
                        break;
                    }
                    default:
                        break;
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
       auto buildDnsAskUri = [](std::string &name){
           return opflex::modb::URIBuilder().addElement("EpdrDnsDemand")
           .addElement("EpdrDnsAsk").addElement(name).build();
        };
       auto buildDnsEntryUri = [](const std::string &name){
           return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsEntry").addElement(name).build();
        };
       if(ask) {
           std::unordered_set<std::string> cacheSet;
           std::string askName = ask.get()->getName().get();
           std::unordered_set<std::string> emptySet;
           std::unique_lock<std::mutex> lk(stateMutex);
           auto p = demandMappings.insert(std::make_pair(askName,emptySet));
           if(askName.data()[0] =='*') {
               for(const auto &lm: learntMappings) {
                   if(DomainNameMatch(lm.first,askName)) {
                       for(auto &mappedIp: lm.second.Ips) {
                           p.first->second.insert(mappedIp);
                       }
                       cacheSet.insert(lm.first);
                       notifySet.insert(buildDnsAskUri(askName));
                   }
               }
           } else {
               if (learntMappings.find(askName) != learntMappings.end()) {
                   p.first->second = learntMappings[askName].Ips;
                   cacheSet.insert(askName);
                   notifySet.insert(buildDnsAskUri(askName));
               }
           }
           if(!notifySet.empty()) {
               auto dDiscoveredU = modelgbp::epdr::DnsDiscovered::resolve(agent.getFramework());
               opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
               auto dnsAnswer = dDiscoveredU.get()->addEpdrDnsAnswer(askName);
               for(auto &cacheStr:cacheSet) {
                   dnsAnswer->addEpdrDnsAnswerToResultRSrc(buildDnsEntryUri(cacheStr).toString());
               }
               dnsAnswer->setUuid(boost::uuids::to_string((*uuidGen)()));
               mutator.commit();
           }
       } else {
           vector<string> elements;
           askUri.getElements(elements);
           if( elements.size()<1 ) {
               return;
           }
           if (demandMappings.find(elements.back()) != demandMappings.end()) {
               opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
               modelgbp::epdr::DnsAnswer::remove(agent.getFramework(),elements.back());
               mutator.commit();
               demandMappings.erase(demandMappings.find(elements.back()));
               notifySet.insert(buildDnsAskUri(elements.back()));
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
        for(auto &notifyUri: notifySet) {
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
        work.reset();
        parserThread->join();
    }
}
