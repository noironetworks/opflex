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
#include <fstream>
#include <opflexagent/logging.h>
#include <modelgbp/epdr/DnsDiscovered.hpp>
#include <modelgbp/epdr/DnsAsk.hpp>
#include <thread>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <boost/asio/deadline_timer.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "ovs-shim.h"
#include "ovs-ofputil.h"
#include "eth.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

namespace opflexagent {

    using opflex::modb::URI;
    using opflex::modb::class_id_t;
    DnsManager::DnsManager(Agent &agent):
    agent(agent),started(false)
    {
    }

    void DnsManager::start() {
        using boost::uuids::basic_random_generator;
        namespace fs = boost::filesystem;
        boost::system::error_code ec;
        if(started)
            return;

        bool storeExists = fs::exists(fs::path(cacheDir),ec);
        if(ec || !storeExists ) {
            LOG(ERROR) << "Cache storage directory dns-cache-dir(renderer config) " << cacheDir
                       << " missing/non-existent, not starting " << ec;
            return;
        }
        bool storeIsDir = fs::is_directory(fs::path(cacheDir), ec);
        if(ec || !storeIsDir ) {
            LOG(ERROR) << "Cache storage path dns-cache-dir(renderer config) " << cacheDir
                       << " is not a directory, not starting " << ec;
            return;
        }
        restoreFromStore();

        uuidGen.reset(new basic_random_generator<boost::mt19937>(&randomSeed));
        modelgbp::epdr::DnsAsk::registerListener(agent.getFramework(),this);
        /*Needed for restart test cases*/
        if(io_ctxt.stopped()) {
            io_ctxt.reset();
        }
        work.reset(new boost::asio::io_service::work(io_ctxt));
        {
            lock_guard<recursive_mutex> lk(timerMutex);
            expiryTimer.reset( new boost::asio::deadline_timer(io_ctxt));
            expiryTimer->expires_from_now(boost::posix_time::seconds(1));
            expiryTimer->async_wait(boost::bind(&DnsManager::onExpiryTimer,this,boost::arg<1>()));
        }
        parserThread.reset(new std::thread([this]() {
           started = true;
           io_ctxt.run();
        }));
    }

    void DnsManager::expireCName(DnsCacheEntry &entry) {
        using namespace modelgbp::epdr;
        const std::string &cName = entry.getCName();
        if(cName.empty()) {
            return;
        }
        /* Unlink resolution of cname for aliases of this node*/
        auto buildDnsEntryUri = [](const std::string &name){
           return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsEntry").addElement(name).build();
        };
        DnsCacheEntry *terminalNode = getTerminalNode(entry);
        if((terminalNode != NULL) && !terminalNode->isCName()) {
            for(auto &aName: entry.aNames) {
                auto learntItr = learntMappings.find(aName);
                if(learntItr != learntMappings.end()) {
                    auto &aEntry = learntItr->second;
                    for(auto lAItr= aEntry.linkedAnswers.begin();
                            lAItr != aEntry.linkedAnswers.end();) {
                        opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
                        auto dnsAnswer = DnsAnswer::resolve(agent.getFramework(), *lAItr);
                        if(!dnsAnswer) { 
                            lAItr = aEntry.linkedAnswers.erase(lAItr);
                            continue;
                        }
                        dnsAnswer.get()->addEpdrDnsAnswerToResultRSrc(
                            buildDnsEntryUri(terminalNode->domainName).toString())->remove();
                        mutator.commit();
                        lAItr++;
                    }
                }
            }
        }
        auto learntItr = learntMappings.find(cName);
        while(learntItr != learntMappings.end()) {
            learntItr->second.aNames.erase(entry.domainName);
            commitToStore(learntItr->second);
            learntItr = learntMappings.find(learntItr->second.getCName());
        }
        /*Current entry is committed to store in the caller*/
        entry.setCName(std::string(""));
    }

    bool DnsCacheEntry::age(DnsManager &mgr) {
        using namespace boost::posix_time;
        using namespace boost::gregorian;
        using namespace modelgbp::epdr;
        bool moChanged = false,cNameAged = false;
        str_set_t expiredAddresses;
        std::unordered_set<DnsCachedSrv> expiredSrvs;
        ptime currTime = second_clock::local_time();
        if(isHolder) {
            return false;
        }
        for(auto cAItr = Ips.begin(); cAItr != Ips.end();) {
            if(currTime >= cAItr->expiryTime) {
                LOG(DEBUG) << domainName << "->" << cAItr->addr << " expired " <<
                    to_simple_string(cAItr->expiryTime);
                expiredAddresses.insert(cAItr->addr.to_string());
                cAItr = Ips.erase(cAItr);
                moChanged=true;
            } else {
                cAItr++;
            }
        }
        for(auto srvItr = Srvs.begin(); srvItr != Srvs.end();) {
            if(currTime >= srvItr->expiryTime) {
                LOG(DEBUG) << domainName << "->" << srvItr->hostName << " expired " <<
                    to_simple_string(srvItr->expiryTime);
                expiredSrvs.insert(*srvItr);
                srvItr = Srvs.erase(srvItr);
                moChanged=true;
            } else {
                srvItr++;
            }
        }
        if(isCName()) {
            if(currTime >= cachedCName.expiryTime) {
                LOG(DEBUG) << domainName << "->" << cachedCName.cName << " expired " <<
                to_simple_string(cachedCName.expiryTime);
                cNameAged=true;
            }
        }
        if(!moChanged && !cNameAged) {
            return canExpire();
        }
        opflex::modb::Mutator mutator(mgr.agent.getFramework(), "policyelement");
        //Handle DnsEntry
        if(((isCName() && cNameAged) || !isCName()) && Ips.empty() && Srvs.empty()) {
            DnsEntry::remove(mgr.agent.getFramework(), domainName);
        } else {
            auto dnsEntry = DnsEntry::resolve(mgr.agent.getFramework(),domainName);
            std::vector<std::shared_ptr<modelgbp::epdr::DnsMappedAddress>> out;
            std::vector<std::shared_ptr<modelgbp::epdr::DnsSrv>> out2;
            dnsEntry.get()->resolveEpdrDnsMappedAddress(out);
            dnsEntry.get()->resolveEpdrDnsSrv(out2);
            for(const auto &mA:out) {
                if(!mA->getAddress())
                    continue;
                DnsCachedAddress cachedAddr(mA->getAddress().get());
                if(Ips.find(cachedAddr) == Ips.end()) {
                    dnsEntry.get()->addEpdrDnsMappedAddress(
                        mA->getAddress().get())->remove();
                }
            }
            for(const auto &srv:out2) {
                DnsCachedSrv cachedSrv( 0, 0, srv->getPort().get(),
                                        srv->getHostName().get(),
                                        ptime(currTime));
                if(Srvs.find(cachedSrv) == Srvs.end()) {
                    dnsEntry.get()->addEpdrDnsSrv(
                        cachedSrv.hostName,cachedSrv.port)->remove();
                }
            }
            if(moChanged) {
                dnsEntry.get()->setUpdated(to_simple_string(currTime));
            }
        }
        //Handle DnsAnswer
        for(auto lAItr= linkedAnswers.begin(); lAItr != linkedAnswers.end();) {
            auto dnsAnswer = DnsAnswer::resolve(mgr.agent.getFramework(), *lAItr);
            if(!dnsAnswer) {
                lAItr = linkedAnswers.erase(lAItr);
                continue;
            }
            std::vector<std::shared_ptr<DnsAnswerToResultRSrc>> out;
            dnsAnswer.get()->resolveEpdrDnsAnswerToResultRSrc(out);
            auto buildDnsEntryUri = [](const std::string &name){
               return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
               .addElement("EpdrDnsEntry").addElement(name).build();
            };
            if(((isCName() && cNameAged) || !isCName()) && Ips.empty() && Srvs.empty()) {
                // A direct match means answer is non-wildcard
                if (dnsAnswer.get()->getName().get() == domainName) {
                    mgr.demandMappings[domainName].resolved.clear();
                    mgr.demandMappings[domainName].linkedEntries.erase(domainName);
                    dnsAnswer.get()->remove();
                } else {
                    //An indirect match could mean answer is wild-card or alias
                    for(auto &expiredAddress: expiredAddresses) {
                        mgr.demandMappings[dnsAnswer.get()->getName().get()].resolved.erase(expiredAddress);
                    }
                    mgr.demandMappings[dnsAnswer.get()->getName().get()].linkedEntries.erase(domainName);
                    if(out.size()<=1) {
                        dnsAnswer.get()->remove();
                    } else {
                        dnsAnswer.get()->addEpdrDnsAnswerToResultRSrc(
                            buildDnsEntryUri(domainName).toString())->remove();
                    }
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
                /*Remove expired endpoints of Srvs*/
                for(auto &expiredSrv:expiredSrvs) {
                    dnsAnswer.get()->addEpdrDnsAnswerToResultRSrc(
                        buildDnsEntryUri(expiredSrv.hostName).toString())->remove();
                }
                dnsAnswer.get()->setUuid(boost::uuids::to_string((*mgr.uuidGen)()));
            }
            lAItr++;
        }
        mutator.commit();
        //Update CName chain
        if(isCName() && cNameAged) {
            mgr.expireCName(*this);
        }
        //Holder decision
        if(Ips.empty() && getCName().empty() && (!aNames.empty()
                || !parentSrv.empty())) {
            isHolder = true;
        }
        if(!canExpire()) {
            mgr.commitToStore(*this);
            return false;
        }
        return true;
    }

    void DnsManager::onExpiryTimer(const boost::system::error_code &e) {
        using namespace boost::posix_time;
        using namespace boost::gregorian;
        using modelgbp::epdr::DnsAnswer;
        using modelgbp::epdr::DnsEntry;
        if(e) {
            lock_guard<recursive_mutex> guard(timerMutex);
            expiryTimer.reset();
            return;
        }
        {
            std::unique_lock<std::mutex> lk(stateMutex);
            for(auto itr = learntMappings.begin();
                itr != learntMappings.end();) {
                if (itr->second.age(*this)) {
                    commitToStore(itr->second,true);
                    itr = learntMappings.erase(itr);
                } else {
                    itr++;
                }
            }
        }
        if(started) {
            lock_guard<recursive_mutex> lk(timerMutex);
            expiryTimer->expires_from_now(seconds(1));
            expiryTimer->async_wait(boost::bind(&DnsManager::onExpiryTimer,this,boost::arg<1>()));
        }
    }

    bool DnsCacheEntry::update(DnsRR &dnsRR) {
        using namespace boost::posix_time;
        using namespace boost::gregorian;
        /**
         * Regardless of rType, getting a real RR
         * makes the entry not a holder anymore
         */
        isHolder = false;
        if(dnsRR.hasDirectAddress()) {
            DnsCachedAddress cA(dnsRR);
            auto pr = Ips.insert(cA);
            if(pr.second)
                return true;
            if (cA.expiryTime > pr.first->expiryTime) {
                Ips.erase(pr.first);
                Ips.insert(cA);
            }
        } else if(dnsRR.rType == RRTypeSrv) {
            using namespace boost::posix_time;
            using namespace boost::gregorian;
            DnsCachedSrv cachedSrv(dnsRR);
            auto srvItr = Srvs.insert(cachedSrv);
            if(!srvItr.second && (ptime(dnsRR.currTime + seconds(dnsRR.ttl)) >=
               srvItr.first->expiryTime)) {
                Srvs.erase(srvItr.first);
                Srvs.insert(cachedSrv);
            }
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

    void DnsManager::handlePacketIn(void *pkt) {
        if(!started)
            return;
        struct dp_packet *copiedPkt = dp_packet_clone((struct dp_packet *)pkt);
        {
            std::unique_lock<std::mutex> lk(packetQMutex);
            packetInQ.push((void *)copiedPkt);
        }
        io_ctxt.post([=]() {this->processPacket();});
    }

    static bool ValidateDnsPacket(const struct dp_packet *pkt,
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
                        ctxt.labelOffset++;
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
                    } else {
                        LOG(ERROR) << "Failed to find label at offset " << std::hex << labelPtr;
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
    std::ostream & operator <<(std::ostream &os,const DnsRRType &rType) {
        switch(rType){
            case RRTypeA:
                os << "A";
                break;
            case RRTypeA4:
                os << "AAAA";
                break;
            case RRTypeCName:
                os << "CNAME";
                break;
            case RRTypeSrv:
                os << "SRV";
                break;
            default:
                os << (unsigned)rType;
                break;
        }
        return os;
    }

    std::ostream & operator <<(std::ostream &os,const DnsRRClass &rClass) {
        switch(rClass){
            case RRClassIN:
                os << "IN";
                break;
            case RRClassCS:
                os << "CS";
                break;
            case RRClassAny:
                os << "Any";
                break;
            default:
                os << (unsigned)rClass;
                break;
        }
        return os;
    }

    std::ostream & operator<<(std::ostream &os, const DnsRR& rr) {
        os << rr.domainName << ":  " << "type " << rr.rType << ", class " << rr.rClass;
        os << ", ttl: " << rr.ttl;
        switch(rr.rType){
            case DnsRRType::RRTypeA:
                os << ", addr " <<
                boost::asio::ip::address_v4(rr.rrTypeAData).to_string();
                break;
            case DnsRRType::RRTypeA4:
                std::array<unsigned char, IP6_ADDR_LEN> bytes;
                for(int i=0; i<IP6_ADDR_LEN; i++) {
                    bytes[i] = rr.rrTypeA4Data.v6Bytes[i];
                }
                os << ", addr " <<
                boost::asio::ip::address_v6(bytes).to_string();
                break;
            case DnsRRType::RRTypeCName:
                os << ", cname " << rr.rrTypeCNameData.cName;
                break;
            case DnsRRType::RRTypeSrv:
                os << ", srv " << rr.rrTypeSrvData.priority << " "
                   << rr.rrTypeSrvData.weight << " " << rr.rrTypeSrvData.port
                   << " " << rr.rrTypeSrvData.hostName;
                break;
            default:
                break;
        }
        return os;
    }

    std::ostream & operator<<(std::ostream &os, const DnsParsingContext::ParsingSection &section) {
        switch(section) {
            case DnsParsingContext::baseSection:
                os << "header section";
                break;
            case DnsParsingContext::questionSection:
                os << "question section";
                break;
            case DnsParsingContext::answerSection:
                os << "answer section";
                break;
            case DnsParsingContext::authoritySection:
                os << "authority section";
                break;
            case DnsParsingContext::additionalSection:
                os << "additional section";
                break;
            default:
               break;
        }
        return os;
    }

    std::ostream & operator<<(std::ostream &os, const DnsParsingContext& dnsCtxt) {
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
            os << rr << endl;
        }
        os << "Authorities: " << endl;
        for(const auto &rr: dnsCtxt.authorities){
            os << rr << endl;
        }
        os << "Additional Records: " << endl;
        for(const auto &rr: dnsCtxt.additionalRecords){
            os << rr << endl;
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

    DnsCacheEntry *DnsManager::getTerminalNode(DnsCacheEntry &startNode) {
        DnsCacheEntry *terminalNode = &startNode;
        while(!terminalNode->getCName().empty()) {
            auto learntItr = learntMappings.find(terminalNode->getCName());
            if(learntItr == learntMappings.end()) {
                break;
            }
            terminalNode = &learntItr->second;
        }
        return terminalNode;
    }

    bool DnsCacheEntry::matchesAliases(const std::string &askName, std::string &matchingAlias) {
        auto itr = std::find_if(aNames.begin(),aNames.end(),
                                [&](const std::string &aName){return DomainNameMatch(aName,askName);});
        if(itr != std::end(aNames)) {
            matchingAlias = *itr;
            return true;
        }
        return false;
    }

    bool DnsCacheEntry::matchesSrv(const std::string &askName,
            std::string &matchingSrv) {
        auto itr = std::find_if(parentSrv.begin(),parentSrv.end(),
                                [&](const std::string &pSrv){return DomainNameMatch(pSrv,askName);});
        if(itr != std::end(parentSrv)) {
            matchingSrv = *itr;
            return true;
        }
        return false;
    }

    void DnsManager::addSrvEndpoints(DnsCacheEntry &entry,
            std::shared_ptr<modelgbp::epdr::DnsAnswer> &dnsAnswer,
            DnsDemandState& demandState) {
        for(const auto &srv: entry.Srvs) {
            auto learntItr = learntMappings.find(srv.hostName);
            if((learntItr != learntMappings.end()) &&
                    !learntItr->second.Ips.empty()) {
                linkEntryToAnswer(learntItr->second, dnsAnswer, demandState);
            }
        }
    }

    void DnsManager::linkEntryToAnswer(DnsCacheEntry &entry,
            std::shared_ptr<modelgbp::epdr::DnsAnswer> &dnsAnswer,
            DnsDemandState &demandState) {
        using namespace modelgbp::epdr;
        auto dnsEntry = DnsEntry::resolve(agent.getFramework(), entry.domainName);
        if(!dnsEntry) return;
        dnsAnswer->addEpdrDnsAnswerToResultRSrc(dnsEntry.get()->getURI().toString());
        entry.linkedAnswers.insert(dnsAnswer->getURI());
        demandState.linkedEntries.insert(entry.domainName);
    }

    void DnsManager::updateMOs(DnsCacheEntry &entry, bool changed) {
        auto dDiscoveredU = modelgbp::epdr::DnsDiscovered::resolve(agent.getFramework());
        opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
        auto dnsEntry = dDiscoveredU.get()->addEpdrDnsEntry(entry.domainName);
        dnsEntry->setUpdated(boost::posix_time::to_simple_string(entry.lastUpdated));
        if(entry.isCName()) {
            auto dnsCName = dnsEntry->addEpdrDnsCName(entry.getCName());
            dnsCName->setExpiry(boost::posix_time::to_simple_string(entry.cachedCName.expiryTime));
        }
        for(const auto &cS: entry.Srvs) {
            auto dnsSrv = dnsEntry->addEpdrDnsSrv(cS.hostName,cS.port);
            dnsSrv->setExpiry(boost::posix_time::to_simple_string(cS.expiryTime));
        }
        for(const auto& cA: entry.Ips) {
            auto mA = dnsEntry->addEpdrDnsMappedAddress(cA.addr.to_string());
            mA->setExpiry(boost::posix_time::to_simple_string(cA.expiryTime));
        }
        mutator.commit();
        /* Resolve logic
         * RegularMatch-> return the entry directly
         * Matches a headless service -> return original SRV entry, resolved endpoints
         * Matches an aliased name -> return aliased entry, terminal entry
         * Note that the entries returned may not contain an address.
         * Allow for returning all matching entries regardless of whether they
         * contain direct addresses.This simplifies logic.
         * */
        for(auto& demandItr : demandMappings) {
            DnsCacheEntry *terminalNode=NULL;
            std::string matchingAlias, matchingSrv;
            bool regularMatch = DomainNameMatch(entry.domainName, demandItr.first);
            if(regularMatch || entry.matchesAliases(demandItr.first, matchingAlias)
               || entry.matchesSrv(demandItr.first, matchingSrv)) {
                if(entry.isCName()) {
                    terminalNode = getTerminalNode(entry);
                }
                auto dnsAnswer = dDiscoveredU.get()->addEpdrDnsAnswer(demandItr.first);
                if(changed) {
                    dnsAnswer->setUuid(boost::uuids::to_string((*uuidGen)()));
                }
                if(regularMatch) {
                    linkEntryToAnswer(entry, dnsAnswer, demandItr.second);
                }
                if(!entry.Srvs.empty()) {
                    addSrvEndpoints(entry, dnsAnswer,demandItr.second);
                }
                if((terminalNode != NULL) && (terminalNode->domainName != entry.domainName)
                        && !terminalNode->isCName()) {
                    linkEntryToAnswer(*terminalNode, dnsAnswer, demandItr.second);
                }
                if(!matchingAlias.empty()) {
                    auto learntItr = learntMappings.find(entry.domainName);
                    linkEntryToAnswer(learntItr->second, dnsAnswer, demandItr.second);
                }
                if(!matchingSrv.empty()) {
                    auto learntItr = learntMappings.find(matchingSrv);
                    addSrvEndpoints(learntItr->second, dnsAnswer, demandItr.second);
                    linkEntryToAnswer(learntItr->second, dnsAnswer, demandItr.second);
                }
            }
        }
        mutator.commit();
    }

    DnsRR::DnsRR(const DnsRR &dnsRR):
        domainName(dnsRR.domainName),
        currTime(dnsRR.currTime),
        rType(dnsRR.rType),rClass(dnsRR.rClass),ttl(dnsRR.ttl),rdLen(dnsRR.rdLen)
    {
        switch(rType) {
            case RRTypeSrv:
            {
                new (&rrTypeSrvData.hostName) std::string;
                rrTypeSrvData.hostName = dnsRR.rrTypeSrvData.hostName;
                rrTypeSrvData.priority = dnsRR.rrTypeSrvData.priority;
                rrTypeSrvData.weight = dnsRR.rrTypeSrvData.weight;
                rrTypeSrvData.port = dnsRR.rrTypeSrvData.port;
                break;
            }
            case RRTypeCName:
            {
                new (&rrTypeCNameData.cName) std::string;
                rrTypeCNameData.cName = dnsRR.rrTypeCNameData.cName;
                break;
            }
            case RRTypeA:
            {
                rrTypeAData = dnsRR.rrTypeAData;
                break;
            }
            case RRTypeA4:
            {
                memcpy(rrTypeA4Data.v6Bytes,
                       dnsRR.rrTypeA4Data.v6Bytes,
                       IP6_ADDR_LEN);
                break;
            }
            default:
                break;
        }
    }

    DnsCachedSrv::DnsCachedSrv(const DnsRR &dnsRR):
        DnsCachedRecordData(dnsRR)
    {
        using namespace boost::posix_time;
        if(dnsRR.rType == DnsRRType::RRTypeSrv) {
            hostName = dnsRR.rrTypeSrvData.hostName;
            priority = dnsRR.rrTypeSrvData.priority;
            weight = dnsRR.rrTypeSrvData.weight;
            port = dnsRR.rrTypeSrvData.port;
        }
    }

    DnsCachedSrv::DnsCachedSrv(
            uint16_t _prio, uint16_t _wt, uint16_t _port,
            const std::string &_hostName,
            const boost::posix_time::ptime &expTime):
        DnsCachedRecordData(expTime),
        priority(_prio),weight(_wt),
        port(_port),hostName(_hostName){}

    DnsCachedCName::DnsCachedCName(const DnsRR &dnsRR):
        DnsCachedRecordData(dnsRR)
    {
        using namespace boost::posix_time;
        if(dnsRR.rType == DnsRRType::RRTypeCName) {
            cName = dnsRR.rrTypeCNameData.cName;
        }
    }

    DnsCachedAddress::DnsCachedAddress(const DnsRR &dnsRR):
        DnsCachedRecordData(dnsRR)
    {
        using namespace boost::posix_time;
        //Resolve addresses using the RRs here
        switch(dnsRR.rType) {
            case RRTypeA:
            {
                addr = boost::asio::ip::address_v4(dnsRR.rrTypeAData);
                break;
            }
            case RRTypeA4:
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
    }

    DnsCacheEntry::DnsCacheEntry(const DnsRR &dnsRR):
        domainName(dnsRR.domainName),
        cachedCName(dnsRR),isHolder(false),
        lastUpdated(dnsRR.currTime) {
        if(dnsRR.hasDirectAddress()) {
            DnsCachedAddress cachedAddr(dnsRR);
            Ips.insert(cachedAddr);
        } else if(dnsRR.rType == RRTypeSrv) {
            using namespace boost::posix_time;
            using namespace boost::gregorian;
            DnsCachedSrv cachedSrv(dnsRR);
            Srvs.insert(cachedSrv);
        }
    }

    DnsCacheEntry::DnsCacheEntry(const std::string &name):
        domainName(name), isHolder(true),
        lastUpdated(boost::posix_time::second_clock::local_time()) {
    }

    DnsCacheEntry::DnsCacheEntry():
        isHolder(true),
        lastUpdated(boost::posix_time::second_clock::local_time()) {
    }

    bool DnsCacheEntry::validateCName(const std::string &_cName) {
        if(!isCName()) {
            if(aNames.find(_cName) == aNames.end()) {
                return true;
            }
            return false;
        }
        return false;
    }

    bool DnsCacheEntry::addAlias(DnsManager &mgr, const std::string &aName) {
        if(!isCName()) {
            aNames.insert(aName);
            return true;
        }
        if(getCName() == aName) {
            return false;
        }
        auto learntItr = mgr.learntMappings.find(getCName());
        while(learntItr != mgr.learntMappings.end()){
            if(learntItr->second.getCName() == aName) {
                return false;
            }
            learntItr = mgr.learntMappings.find(learntItr->second.getCName());
        }
        /*Now add the alias recursively*/
        learntItr = mgr.learntMappings.find(getCName());
        while(learntItr != mgr.learntMappings.end()){
            learntItr->second.aNames.insert(aName);
            learntItr = mgr.learntMappings.find(learntItr->second.getCName());
        }
        aNames.insert(aName);
        return true;
    }

    bool DnsManager::validateCName(DnsRR &dnsRR,
            DnsCacheEntry *existingEntry) {
        if(!dnsRR.isCName()) {
            return true;
        }
        if(existingEntry != NULL) {
            if(!existingEntry->validateCName(dnsRR.getCName())) {
                return false;
            }
        }
        auto cNameItr = learntMappings.find(dnsRR.getCName());
        if(cNameItr != learntMappings.end()) {
            if(!cNameItr->second.addAlias(*this, dnsRR.domainName)) {
                return false;
            }
        } else {
            DnsCacheEntry entry2(dnsRR.getCName());
            auto p = learntMappings.emplace(
                         std::make_pair(dnsRR.getCName(),entry2));
            if(existingEntry != NULL) {
                for(const auto &aName: existingEntry->aNames) {
                    (void)p.first->second.addAlias(*this, aName);
                }
            }
            (void)p.first->second.addAlias(*this, dnsRR.domainName);
            commitToStore(p.first->second);
        }
        if(existingEntry != NULL) {
            existingEntry->setCName(dnsRR.getCName());
        }
        return true;
    }

    void DnsManager::restoreFromStore() {
        using namespace boost::posix_time;
        using namespace boost::gregorian;
        using namespace boost::filesystem;
        using boost::property_tree::ptree;
        using boost::property_tree::json_parser::read_json;
        using boost::optional;
        path cacheRoot(cacheDir);
        for(directory_iterator cacheFile=directory_iterator(cacheDir);
                cacheFile != directory_iterator(); cacheFile++) {
            if(is_directory(*cacheFile) ||
               !boost::algorithm::ends_with(cacheFile->path().filename().string(), ".dns")) {
                continue;
            }
            LOG(DEBUG) << "Restoring " << cacheFile->path().filename().string();
            try {
                ptree properties;
                static const std::string DOMAIN_NAME("DomainName");
                static const std::string HOLDER("isHolder");
                static const std::string CNAME("cName");
                static const std::string EXPIRY("expiryTime");
                static const std::string ALIASES("Aliases");
                static const std::string ADDRESSES("Addresses");
                static const std::string ADDRESS("addr");
                static const std::string SERVICES("Srvs");
                static const std::string PRIO("prio");
                static const std::string WEIGHT("weight");
                static const std::string PORT("port");
                static const std::string HOSTNAME("hostName");
                static const std::string PARENTSRV("ParentSrv");
                read_json(cacheFile->path().string(),properties);
                if(!properties.get_optional<string>(std::string("DomainName"))) {
                    continue;
                }
                DnsCacheEntry entry(properties.get<string>(std::string("DomainName")));
                if(properties.get_optional<string>(HOLDER)) {
                    if(properties.get<string>(HOLDER) == "0") {
                        entry.isHolder = false;
                    }
                }
                if(properties.get_optional<string>(CNAME) &&
                       properties.get_optional<string>(EXPIRY)) {
                    entry.cachedCName.cName = properties.get<string>(CNAME);
                    entry.cachedCName.expiryTime = time_from_string(properties.get<string>(EXPIRY));
                }
                if(properties.get_optional<string>(ALIASES)) {
                    for(auto &v : properties.get_child(ALIASES)) {
                        entry.aNames.insert(v.second.data());
                    }
                }
                if(properties.get_optional<string>(PARENTSRV)) {
                    for(auto &v : properties.get_child(PARENTSRV)) {
                        entry.parentSrv.insert(v.second.data());
                    }
                }
                if(properties.get_optional<string>(SERVICES)) {
                    for(auto &child : properties.get_child(SERVICES)) {
                        uint16_t _prio = child.second.get<uint16_t>(PRIO);
                        uint16_t _weight = child.second.get<uint16_t>(WEIGHT);
                        uint16_t _port = child.second.get<uint16_t>(PORT);
                        std::string _hostName = child.second.get<string>(HOSTNAME);
                        ptime _expTime = time_from_string(child.second.get<string>(EXPIRY));
                        DnsCachedSrv cS(_prio, _weight, _port, _hostName, _expTime);
                        entry.Srvs.insert(cS);
                    }
                }
                if(properties.get_optional<string>(ADDRESSES)) {
                    for (auto &child:
                            properties.get_child(ADDRESSES)) {
                        DnsCachedAddress cA(child.second.get<string>(ADDRESS));
                        cA.expiryTime = time_from_string(child.second.get<string>(EXPIRY));
                        entry.Ips.insert(cA);
                    }
                }
                {
                    std::unique_lock<std::mutex> lk(stateMutex);
                    learntMappings.insert(std::make_pair(entry.domainName, entry));
                    updateMOs(entry, true);
                }
            } catch (const std::exception& ex) {
                LOG(ERROR) << "Could not load dns entry: "
                           << ex.what();
            }
        }
    }

    void DnsManager::commitToStore(const DnsCacheEntry &entry, bool erase) {
        using namespace boost::posix_time;
        using namespace boost::gregorian;
        using namespace boost::filesystem;
        using rapidjson::Writer;
        using rapidjson::StringBuffer;
        namespace fs = boost::filesystem;
        if(erase) {
            boost::system::error_code ec;
            if(!fs::remove(fs::path(getStorePath(entry)), ec)){
                LOG(ERROR) << "Failed to remove " << entry.domainName << " " << ec;
            }
            return;
        }
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        writer.StartObject();
        writer.String("DomainName");
        writer.String(entry.domainName.c_str());
        writer.String("isHolder");
        writer.String((entry.isHolder?"1":"0"));
        if(entry.isCName()) {
            writer.String("cName");
            writer.String(entry.cachedCName.cName.c_str());
            writer.String("expiryTime");
            writer.String(to_simple_string(entry.cachedCName.expiryTime).c_str());
        }
        writer.String("Aliases");
        writer.StartArray();
        for(auto &aName: entry.aNames) {
            writer.String(aName.c_str());
        }
        writer.EndArray();
        writer.String("ParentSrv");
        writer.StartArray();
        for(auto &srv: entry.parentSrv) {
            writer.String(srv.c_str());
        }
        writer.EndArray();
        writer.String("Srvs");
        writer.StartArray();
        for(auto &srv: entry.Srvs) {
            writer.StartObject();
            writer.String("prio");
            writer.Uint(srv.priority);
            writer.String("weight");
            writer.Uint(srv.weight);
            writer.String("port");
            writer.Uint(srv.port);
            writer.String("hostName");
            writer.String(srv.hostName.c_str());
            writer.String("expiryTime");
            writer.String(to_simple_string(srv.expiryTime).c_str());
            writer.EndObject();
        }
        writer.EndArray();
        writer.String("Addresses");
        writer.StartArray();
        for(auto& cA:entry.Ips) {
            writer.StartObject();
            writer.String("addr");
            writer.String(cA.addr.to_string().c_str());
            writer.String("expiryTime");
            writer.String(to_simple_string(cA.expiryTime).c_str());
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
        std::fstream dnsFile(getStorePath(entry), dnsFile.out);
        if(!dnsFile.is_open()) {
            LOG(ERROR) << "Failed to open storeFile for " << entry.domainName;
            return;
        }
        dnsFile << buffer.GetString();
        dnsFile.flush();
    }

    void DnsManager::createSrvEntries(DnsCacheEntry &entry) {
        for(auto &srv: entry.Srvs) {
            auto learntMapItr = learntMappings.find(srv.hostName);
            if(learntMapItr != learntMappings.end()) {
                learntMapItr->second.parentSrv.insert(entry.domainName);
            } else {
                DnsCacheEntry additionalEntry(srv.hostName);
                additionalEntry.parentSrv.insert(entry.domainName);
                learntMappings.insert(std::make_pair(srv.hostName,additionalEntry));
                LOG(DEBUG) << "Adding SRV mapping " << srv.hostName <<" to " << entry.domainName;
            }
        }
    }

    void DnsManager::updateCacheForRR(DnsRR &dnsRR) {
        bool changed = false;
        if(dnsRR.domainName.empty()) {
            return;
        }
        auto learntMapItr = learntMappings.find(dnsRR.domainName);
        if(learntMapItr != learntMappings.end()){
            if(!validateCName(dnsRR, &learntMapItr->second)) {
                return;
            }
            learntMapItr->second.lastUpdated = dnsRR.currTime;
            changed = learntMapItr->second.update(dnsRR);
        } else {
            DnsCacheEntry entry(dnsRR);
            if(!validateCName(dnsRR)) {
                return;
            }
            learntMappings.emplace(std::make_pair(dnsRR.domainName,entry));
            changed = true;
        }
        createSrvEntries(learntMappings[dnsRR.domainName]);
        commitToStore(learntMappings[dnsRR.domainName]);
        updateMOs(learntMappings[dnsRR.domainName], changed);
    }

    void DnsManager::updateCache(DnsParsingContext &ctxt) {
        std::unique_lock<std::mutex> lk(stateMutex);
        for(auto itr=ctxt.answers.begin(); itr != ctxt.answers.end(); itr++) {
            updateCacheForRR(*itr);
        }
        for(auto itr=ctxt.additionalRecords.begin(); 
                itr != ctxt.additionalRecords.end(); itr++) {
            updateCacheForRR(*itr);
        }
    }

    bool DnsManager::parseRR(DnsParsingContext &ctxt, std::list<DnsRR> &result) {
        DnsRRType rType;
        DnsRRClass rClass;
        std::string rrDomainName;
        uint16_t ttl,rdLen;
        ParseDomainName(ctxt,rrDomainName);
        if((ctxt.labelState != DnsParsingContext::seekingLabel) ||
           (ctxt.tailRoom < 10)) {
            LOG(ERROR) << "Incorrect "<< ctxt.parsingSection;
            return false;
        }
        rType = (DnsRRType)ntohs((*(uint16_t *)ctxt.dptr));
        ctxt.dptr += 2;
        rClass = (DnsRRClass)ntohs(*((uint16_t *)ctxt.dptr));
        ctxt.dptr += 2;
        ttl = ntohl(*(uint32_t *)ctxt.dptr);
        ctxt.dptr += 4;
        rdLen = ntohs(*(uint16_t *)ctxt.dptr);
        ctxt.dptr += 2;
        ctxt.tailRoom -= 10;
        ctxt.labelOffset += 10;
        if (ctxt.tailRoom < rdLen) {
            LOG(ERROR) << "Incorrect "<< ctxt.parsingSection <<" record";
            return false;
        }
        DnsRR dnsRR(rrDomainName, rType, rClass, ttl, rdLen);
        switch(dnsRR.rType) {
            case RRTypeA:
            {
                if(dnsRR.rdLen < 4) {
                    LOG(ERROR) << "Incorrect A record";
                    return false;
                }
                dnsRR.rrTypeAData = ntohl(*(uint32_t *)ctxt.dptr);
                ctxt.dptr += dnsRR.rdLen;
                ctxt.labelOffset += dnsRR.rdLen;
                ctxt.tailRoom -= dnsRR.rdLen;
                break;
            }
            case RRTypeA4:
            {
                if(dnsRR.rdLen < IP6_ADDR_LEN) {
                    LOG(ERROR) << "Incorrect AAAA record";
                    return false;
                }
                memcpy(dnsRR.rrTypeA4Data.v6Bytes, ctxt.dptr, IP6_ADDR_LEN);
                ctxt.dptr += dnsRR.rdLen;
                ctxt.labelOffset += dnsRR.rdLen;
                ctxt.tailRoom -= dnsRR.rdLen;
                break;
            }
            case RRTypeCName:
            {
                ParseDomainName(ctxt, dnsRR.rrTypeCNameData.cName);
                break;
            }
            case RRTypeSrv:
            {
                if(dnsRR.rdLen < 8) {
                    LOG(ERROR) << "Incorrect SRV record";
                    return false;
                }
                dnsRR.rrTypeSrvData.priority = ntohs(*(uint32_t *)ctxt.dptr);
                ctxt.dptr += 2;
                dnsRR.rrTypeSrvData.weight = ntohs(*(uint32_t *)ctxt.dptr);
                ctxt.dptr += 2;
                dnsRR.rrTypeSrvData.port = ntohs(*(uint32_t *)ctxt.dptr);
                ctxt.dptr += 2;
                ctxt.labelOffset += 6;
                ctxt.tailRoom -= 6;
                ParseDomainName(ctxt, dnsRR.rrTypeSrvData.hostName);
                break;
            }
            default:
            {
                LOG(DEBUG) << "Unhandled record type " << dnsRR.rType;
                ctxt.dptr += dnsRR.rdLen;
                ctxt.labelOffset += dnsRR.rdLen;
                ctxt.tailRoom -= dnsRR.rdLen;
                break;
            }
        }
        result.emplace_back(dnsRR);
        return true;
    }

    bool DnsManager::handlePacket(const struct dp_packet *pkt) {
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
                dnsQuestion.qType = (DnsRRType)(ntohs(*(uint16_t *)(ctxt.dptr)));
                ctxt.dptr += 2;
                dnsQuestion.qClass = (DnsRRClass)(ntohs(*(uint16_t *)(ctxt.dptr)));
                ctxt.dptr += 2;
                ctxt.tailRoom -= 4;
                ctxt.labelOffset += 4;
                ctxt.questions.emplace_back(dnsQuestion);
            }
            //Answer section
            ctxt.parsingSection = DnsParsingContext::answerSection;
            for(int anc = ctxt.anCount; anc>0; anc--) {
                if(!parseRR(ctxt,ctxt.answers))
                    return false;
            }
            //Authority section
            ctxt.parsingSection = DnsParsingContext::authoritySection;
            for(int auc = ctxt.nsCount; auc>0; auc--) {
                if(!parseRR(ctxt,ctxt.authorities))
                    return false;
            }
            //Additional records section
            ctxt.parsingSection = DnsParsingContext::additionalSection;
            for(int arc = ctxt.arCount; arc>0; arc--) {
                if(!parseRR(ctxt,ctxt.additionalRecords))
                    return false;
            }
            LOG(DEBUG) << ctxt;
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
       LOG(DEBUG) << "Handling Dns Ask " << askUri;
       auto ask = modelgbp::epdr::DnsAsk::resolve(agent.getFramework(),askUri);
       auto buildDnsAnswerUri = [](const std::string &name){
           return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsAnswer").addElement(name).build();
        };
       auto buildDnsEntryUri = [](const std::string &name){
           return opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsEntry").addElement(name).build();
        };
       auto addCacheEntryToAnswer = [this](std::string &askName, URI &askUri,
                                       DnsCacheEntry &cacheEntry, DnsDemandState &demandState,
                                       std::unordered_set<std::string> &cacheSet,
                                       std::unordered_set<URI> &notifySet) {
           URI dnsAnswerUri = opflex::modb::URIBuilder().addElement("EpdrDnsDiscovered")
           .addElement("EpdrDnsAnswer").addElement(askName).build();
           if(cacheEntry.isCName()) {
               DnsCacheEntry *terminalNode = getTerminalNode(cacheEntry);
               if((terminalNode != NULL) && (terminalNode->domainName != cacheEntry.domainName)
                       && !terminalNode->isCName()) {
                   terminalNode->linkedAnswers.insert(dnsAnswerUri);
                   demandState.linkedEntries.insert(terminalNode->domainName);
                   cacheSet.insert(terminalNode->domainName);
               }
           }
           for(const auto &srv: cacheEntry.Srvs) {
               auto learntItr = learntMappings.find(srv.hostName);
               if((learntItr != learntMappings.end()) &&
                       !learntItr->second.Ips.empty()) {
                   demandState.linkedEntries.insert(srv.hostName);
                   cacheEntry.linkedAnswers.insert(dnsAnswerUri);
                   cacheSet.insert(srv.hostName);
               }
           }
           for(const auto &mappedIp: cacheEntry.Ips) {
               demandState.resolved.insert(mappedIp.addr.to_string());
           }
           demandState.linkedEntries.insert(cacheEntry.domainName);
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
               for(auto& lm: learntMappings) {
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
                   LOG(DEBUG) << "Adding " << cacheStr << " to " << dnsAnswer->getURI();
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
               func = boost::bind(&DnsManager::handleDnsAsk,this,boost::arg<1>(),boost::arg<2>());
               break;
           }
       }
       io_ctxt.post([=]() {processURI(class_id, askQMutex, askQ, std::move(func));});
    }

    void DnsManager::stop() {
        if(!started)
            return;
        started = false;
        modelgbp::epdr::DnsAsk::unregisterListener(agent.getFramework(),this);
        {
            lock_guard<recursive_mutex> lk(timerMutex);
            boost::system::error_code ec;
            if(expiryTimer) {
                expiryTimer->cancel(ec);
            }
        }
        work.reset();
        parserThread->join();
        io_ctxt.stop();
        {
            lock_guard<std::mutex> lk(stateMutex);
            learntMappings.clear();
            demandMappings.clear();
        }
        {
            lock_guard<std::mutex> lk(listenerMutex);
            dnsListeners.clear();
        }
    }

    bool operator==(const DnsCachedAddress& lhs, const DnsCachedAddress& rhs) {
        return lhs.addr == rhs.addr;
    }

    bool operator==(const DnsCachedSrv& lhs, const DnsCachedSrv& rhs) {
        return ((lhs.hostName == rhs.hostName) && (lhs.port == rhs.port));
    }
}

namespace std {

size_t hash<opflexagent::DnsCachedAddress>::operator()(const opflexagent::DnsCachedAddress& cA) const
{
    return hash<string>{}( cA.addr.to_string());
}

size_t hash<opflexagent::DnsCachedSrv>::operator()(const opflexagent::DnsCachedSrv& cS) const
{
    std::size_t seed=0;
    boost::hash_combine(seed, cS.hostName);
    boost::hash_combine(seed, cS.port);
    return seed;
}
}
