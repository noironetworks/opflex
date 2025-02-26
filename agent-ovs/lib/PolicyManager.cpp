/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for PolicyManager class.
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <algorithm>

#include <modelgbp/gbp/UnknownFloodModeEnumT.hpp>
#include <modelgbp/gbp/RoutingModeEnumT.hpp>
#include <modelgbp/gbp/DirectionEnumT.hpp>
#include <modelgbp/gbp/HashingAlgorithmEnumT.hpp>
#include <modelgbp/epdr/DnsEntry.hpp>
#include <modelgbp/epdr/DnsDemand.hpp>
#include <opflex/modb/URIBuilder.h>

#include <opflexagent/logging.h>
#include <opflexagent/PolicyManager.h>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/asio/ip/address.hpp>

namespace opflexagent {

using std::vector;
using std::string;
using std::shared_ptr;
using std::make_shared;
using std::unordered_set;
using std::unique_lock;
using std::list;
using std::lock_guard;
using std::mutex;
using opflex::modb::Mutator;
using opflex::ofcore::OFFramework;
using opflex::modb::class_id_t;
using opflex::modb::URI;
using opflex::modb::URIBuilder;
using boost::optional;
using boost::asio::ip::address;
using modelgbp::gbpe::LocalL24Classifier;

#define POLICYMANAGER_STATIC_ROUTE_COST 1
//TODO: This should depend on the EGP being used.
#define POLICYMANAGER_DYNAMIC_ROUTE_COST 140

PolicyManager::PolicyManager(OFFramework& framework_,
                             boost::asio::io_service& agent_io_)
    : framework(framework_), opflexDomain("default"), taskQueue(agent_io_),
      domainListener(*this), contractListener(*this),
      secGroupListener(*this), localSecGroupListener(*this),
      configListener(*this), routeListener(*this) {

}

PolicyManager::~PolicyManager() {

}

const uint16_t PolicyManager::MAX_POLICY_RULE_PRIORITY = 8192;

void PolicyManager::start() {
    LOG(DEBUG) << "Starting policy manager";

    using namespace modelgbp;
    using namespace modelgbp::gbp;
    using namespace modelgbp::gbpe;
    using namespace modelgbp::epdr;

    platform::Config::registerListener(framework, &configListener);

    BridgeDomain::registerListener(framework, &domainListener);
    FloodDomain::registerListener(framework, &domainListener);
    FloodContext::registerListener(framework, &domainListener);
    RoutingDomain::registerListener(framework, &domainListener);
    Subnets::registerListener(framework, &domainListener);
    Subnet::registerListener(framework, &domainListener);
    EpGroup::registerListener(framework, &domainListener);
    L3ExternalNetwork::registerListener(framework, &domainListener);
    ExternalInterface::registerListener(framework, &domainListener);
    ExternalL3BridgeDomain::registerListener(framework, &domainListener);

    EpGroup::registerListener(framework, &contractListener);
    L3ExternalNetwork::registerListener(framework, &contractListener);
    RoutingDomain::registerListener(framework, &contractListener);
    Contract::registerListener(framework, &contractListener);
    Subject::registerListener(framework, &contractListener);
    Rule::registerListener(framework, &contractListener);
    L24Classifier::registerListener(framework, &contractListener);
    RedirectDestGroup::registerListener(framework, &contractListener);
    RedirectDest::registerListener(framework, &contractListener);
    RedirectAction::registerListener(framework, &contractListener);

    SecGroup::registerListener(framework, &secGroupListener);
    SecGroupSubject::registerListener(framework, &secGroupListener);
    SecGroupRule::registerListener(framework, &secGroupListener);
    L24Classifier::registerListener(framework, &secGroupListener);
    Subnets::registerListener(framework, &secGroupListener);
    Subnet::registerListener(framework, &secGroupListener);
    DnsAnswer::registerListener(framework, &secGroupListener);

    LocalSecGroup::registerListener(framework, &localSecGroupListener);
    LocalSecGroupSubject::registerListener(framework, &localSecGroupListener);
    LocalSecGroupRule::registerListener(framework, &localSecGroupListener);
    LocalL24Classifier::registerListener(framework, &localSecGroupListener);
    LocalSubnets::registerListener(framework, &localSecGroupListener);
    LocalSubnet::registerListener(framework, &localSecGroupListener);

    ExternalNode::registerListener(framework, &routeListener);
    StaticRoute::registerListener(framework, &routeListener);
    StaticNextHop::registerListener(framework, &routeListener);
    RoutingDomain::registerListener(framework, &routeListener);
    RemoteRoute::registerListener(framework, &routeListener);
    RemoteNextHop::registerListener(framework, &routeListener);
    L3ExternalNetwork::registerListener(framework, &routeListener);
    // resolve platform config
    Mutator mutator(framework, "init");
    optional<shared_ptr<dmtree::Root> >
        root(dmtree::Root::resolve(framework, URI::ROOT));
    if (root)
        root.get()->addDomainConfig()
            ->addDomainConfigToConfigRSrc()
            ->setTargetConfig(opflexDomain);
    mutator.commit();

    if (useLocalNetpol()) {
        Mutator mutator_policy_reg(framework, "policyreg");
        shared_ptr<modelgbp::policy::Universe> universe =
            modelgbp::policy::Universe::resolve(framework).get();
        optional<shared_ptr<modelgbp::policy::Space>> common =
            universe->resolvePolicySpace("common");
        if (!common) {
            common = universe->addPolicySpace("common");
        }
        mutator_policy_reg.commit();

        Mutator mutator_policy_element(framework, "policyelement");
        /* Add LocalAllowDenyAction */
        shared_ptr<modelgbp::gbp::LocalAllowDenyAction> action =
           common.get()->addGbpLocalAllowDenyAction("allow");
        action->setAllow(1);
        action = common.get()->addGbpLocalAllowDenyAction("deny");
        action->setAllow(0);
        /* Add LocalLogAction */
        common.get()->addGbpLocalLogAction("log");
        mutator_policy_element.commit();
    }
}

void PolicyManager::stop() {
    LOG(DEBUG) << "Stopping policy manager";

    using namespace modelgbp;
    using namespace modelgbp::gbp;
    using namespace modelgbp::gbpe;
    using namespace modelgbp::epdr;
    BridgeDomain::unregisterListener(framework, &domainListener);
    FloodDomain::unregisterListener(framework, &domainListener);
    FloodContext::unregisterListener(framework, &domainListener);
    RoutingDomain::unregisterListener(framework, &domainListener);
    Subnets::unregisterListener(framework, &domainListener);
    Subnet::unregisterListener(framework, &domainListener);
    EpGroup::unregisterListener(framework, &domainListener);
    L3ExternalNetwork::unregisterListener(framework, &domainListener);
    ExternalInterface::unregisterListener(framework, &domainListener);
    ExternalL3BridgeDomain::unregisterListener(framework, &domainListener);

    EpGroup::unregisterListener(framework, &contractListener);
    L3ExternalNetwork::unregisterListener(framework, &contractListener);
    RoutingDomain::unregisterListener(framework, &contractListener);
    Contract::unregisterListener(framework, &contractListener);
    Subject::unregisterListener(framework, &contractListener);
    Rule::unregisterListener(framework, &contractListener);
    L24Classifier::unregisterListener(framework, &contractListener);
    RedirectDestGroup::unregisterListener(framework, &contractListener);
    RedirectDest::unregisterListener(framework, &contractListener);
    RedirectAction::unregisterListener(framework, &contractListener);

    SecGroup::unregisterListener(framework, &secGroupListener);
    SecGroupSubject::unregisterListener(framework, &secGroupListener);
    SecGroupRule::unregisterListener(framework, &secGroupListener);
    L24Classifier::unregisterListener(framework, &secGroupListener);
    Subnets::unregisterListener(framework, &secGroupListener);
    Subnet::unregisterListener(framework, &secGroupListener);
    DnsAnswer::unregisterListener(framework, &secGroupListener);

    LocalSecGroup::unregisterListener(framework, &localSecGroupListener);
    LocalSecGroupSubject::unregisterListener(framework, &localSecGroupListener);
    LocalSecGroupRule::unregisterListener(framework, &localSecGroupListener);
    LocalL24Classifier::unregisterListener(framework, &localSecGroupListener);
    LocalSubnets::unregisterListener(framework, &localSecGroupListener);
    LocalSubnet::unregisterListener(framework, &localSecGroupListener);

    ExternalNode::unregisterListener(framework, &routeListener);
    StaticRoute::unregisterListener(framework, &routeListener);
    StaticNextHop::unregisterListener(framework, &routeListener);
    RoutingDomain::unregisterListener(framework, &routeListener);
    RemoteRoute::unregisterListener(framework, &routeListener);
    RemoteNextHop::unregisterListener(framework, &routeListener);

    lock_guard<mutex> guard(state_mutex);
    group_map.clear();
    vnid_map.clear();
    redirGrpMap.clear();
}

void PolicyManager::registerListener(PolicyListener* listener) {
    lock_guard<mutex> guard(listener_mutex);
    policyListeners.push_back(listener);
}

void PolicyManager::unregisterListener(PolicyListener* listener) {
    lock_guard<mutex> guard(listener_mutex);
    policyListeners.remove(listener);
}

void PolicyManager::notifyEPGDomain(const URI& egURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener* listener : policyListeners) {
        listener->egDomainUpdated(egURI);
    }
}

void PolicyManager::notifyExternalInterface(const URI& extIntfURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener* listener : policyListeners) {
        listener->externalInterfaceUpdated(extIntfURI);
    }
}

void PolicyManager::notifyStaticRoute(const URI& staticRtURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener* listener : policyListeners) {
        listener->staticRouteUpdated(staticRtURI);
    }
}

void PolicyManager::notifyRemoteRoute(const URI& remoteRtURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener* listener : policyListeners) {
        listener->remoteRouteUpdated(remoteRtURI);
    }
}

void PolicyManager::notifyLocalRoute(const URI& localRtURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener* listener : policyListeners) {
        listener->localRouteUpdated(localRtURI);
    }
}

void PolicyManager::notifyDomain(class_id_t cid, const URI& domURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener* listener : policyListeners) {
        listener->domainUpdated(cid, domURI);
    }
}

void PolicyManager::notifyContract(const URI& contractURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener *listener : policyListeners) {
        listener->contractUpdated(contractURI);
    }
}

void PolicyManager::notifySecGroup(const URI& secGroupURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener *listener : policyListeners) {
        listener->secGroupUpdated(secGroupURI);
    }
}

void PolicyManager::notifyConfig(const URI& configURI) {
    lock_guard<mutex> guard(listener_mutex);
    for (PolicyListener *listener : policyListeners) {
        listener->configUpdated(configURI);
    }
}

optional<shared_ptr<modelgbp::gbp::RoutingDomain> >
PolicyManager::getRDForGroup(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    if (it == group_map.end()) return boost::none;
    return it->second.routingDomain;
}

optional<shared_ptr<modelgbp::gbp::RoutingDomain> >
PolicyManager::getRDForL3ExtNet(const opflex::modb::URI& l3n) {
    lock_guard<mutex> guard(state_mutex);
    l3n_map_t::const_iterator it = l3n_map.find(l3n);
    if (it == l3n_map.end()) return boost::none;
    return it->second.routingDomain;
}

optional<shared_ptr<modelgbp::gbp::BridgeDomain> >
PolicyManager::getBDForGroup(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    if (it == group_map.end()) return boost::none;
    return it->second.bridgeDomain;
}

optional<shared_ptr<modelgbp::gbp::FloodDomain> >
PolicyManager::getFDForGroup(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    if (it == group_map.end()) return boost::none;
    return it->second.floodDomain;
}

optional<shared_ptr<modelgbp::gbpe::FloodContext> >
PolicyManager::getFloodContextForGroup(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    if (it == group_map.end()) return boost::none;
    return it->second.floodContext;
}

void PolicyManager::getSubnetsForGroup(const opflex::modb::URI& eg,
                                       /* out */ subnet_vector_t& subnets) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    if (it == group_map.end()) return;
    for (const subnet_map_t::value_type& v :
             it->second.subnet_map) {
        subnets.push_back(v.second);
    }
}

optional<shared_ptr<modelgbp::gbp::Subnet> >
PolicyManager::findSubnetForEp(const opflex::modb::URI& eg,
                               const address& ip) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    if (it == group_map.end()) return boost::none;
    boost::system::error_code ec;
    for (const subnet_map_t::value_type& v :
             it->second.subnet_map) {
        if (!v.second->isAddressSet() || !v.second->isPrefixLenSet())
            continue;
        address netAddr =
            address::from_string(v.second->getAddress().get(), ec);
        uint8_t prefixLen = v.second->getPrefixLen().get();

        if (netAddr.is_v4() != ip.is_v4()) continue;

        if (netAddr.is_v4()) {
            if (prefixLen > 32) prefixLen = 32;

            uint32_t mask = (prefixLen != 0)
                ? (~((uint32_t)0) << (32 - prefixLen))
                : 0;
            uint32_t net_addr = netAddr.to_v4().to_ulong() & mask;
            uint32_t ip_addr = ip.to_v4().to_ulong() & mask;

            if (net_addr == ip_addr)
                return v.second;
        } else {
            if (prefixLen > 128) prefixLen = 128;

            struct in6_addr mask;
            struct in6_addr net_addr;
            struct in6_addr ip_addr;
            memcpy(&ip_addr, ip.to_v6().to_bytes().data(), sizeof(ip_addr));
            network::compute_ipv6_subnet(netAddr.to_v6(), prefixLen,
                                         &mask, &net_addr);

            ((uint64_t*)&ip_addr)[0] &= ((uint64_t*)&mask)[0];
            ((uint64_t*)&ip_addr)[1] &= ((uint64_t*)&mask)[1];

            if (((uint64_t*)&ip_addr)[0] == ((uint64_t*)&net_addr)[0] &&
                ((uint64_t*)&ip_addr)[1] == ((uint64_t*)&net_addr)[1])
                return v.second;
        }
    }
    return boost::none;
}

template<class T>
inline bool compare_shared_ptr(const boost::optional<std::shared_ptr<T> > &p,
                               const boost::optional<std::shared_ptr<T> > &q)
{
    if ((p == boost::none) || (q == boost::none)) return false;
    if(p.get() == q.get()) return true;
    if(p.get() && q.get()) return *p.get() == *q.get();
    return false;
}

bool PolicyManager::updateEPGDomains(const URI& egURI, bool& toRemove) {
    using namespace modelgbp;
    using namespace modelgbp::gbp;
    using namespace modelgbp::gbpe;

    GroupState& gs = group_map[egURI];

    optional<shared_ptr<EpGroup> > epg =
        EpGroup::resolve(framework, egURI);
    if (!epg) {
        toRemove = true;
        return true;
    }
    toRemove = false;

    optional<shared_ptr<InstContext> > newInstCtx =
        epg.get()->resolveGbpeInstContext();
    if (gs.instContext && gs.instContext.get()->getEncapId()) {
        vnid_map.erase(gs.instContext.get()->getEncapId().get());
    }
    if (newInstCtx && newInstCtx.get()->getEncapId()) {
        vnid_map.insert(std::make_pair(newInstCtx.get()->getEncapId().get(),
                                       egURI));
    }

    optional<shared_ptr<RoutingDomain> > newrd =
        boost::make_optional<shared_ptr<RoutingDomain>>(false, nullptr);
    optional<shared_ptr<BridgeDomain> > newbd =
        boost::make_optional<shared_ptr<BridgeDomain>>(false, nullptr);
    optional<shared_ptr<FloodDomain> > newfd =
        boost::make_optional<shared_ptr<FloodDomain>>(false, nullptr);
    optional<shared_ptr<FloodContext> > newfdctx =
        boost::make_optional<shared_ptr<FloodContext>>(false, nullptr);
    optional<shared_ptr<EndpointRetention> > newl2epretpolicy =
        boost::make_optional<shared_ptr<EndpointRetention>>(false, nullptr);
    optional<shared_ptr<EndpointRetention> > newl3epretpolicy =
        boost::make_optional<shared_ptr<EndpointRetention>>(false, nullptr);
    optional<URI> nEpRetURI = boost::none;
    subnet_map_t newsmap;

    optional<opflex::modb::class_id_t> domainClass = boost::none;
    optional<URI> domainURI = boost::none;
    optional<shared_ptr<EpGroupToNetworkRSrc> > ref =
        epg.get()->resolveGbpEpGroupToNetworkRSrc();
    if (ref) {
        domainClass = ref.get()->getTargetClass();
        domainURI = ref.get()->getTargetURI();
    }

    // Update the subnet map for the group with the subnets directly
    // referenced by the group.
    optional<shared_ptr<EpGroupToSubnetsRSrc> > egSns =
        epg.get()->resolveGbpEpGroupToSubnetsRSrc();
    if (egSns && egSns.get()->isTargetSet()) {
        optional<shared_ptr<Subnets> > sns =
            Subnets::resolve(framework,
                             egSns.get()->getTargetURI().get());
        if (sns) {
            vector<shared_ptr<Subnet> > csns;
            sns.get()->resolveGbpSubnet(csns);
            for (shared_ptr<Subnet>& csn : csns) {
                if (gs.subnet_map[csn->getURI()] &&
                    (*gs.subnet_map[csn->getURI()] == *csn)) {
                    newsmap[csn->getURI()] = gs.subnet_map[csn->getURI()];
                } else {
                    newsmap[csn->getURI()] = csn;
                }
            }
        }
    }

    optional<shared_ptr<InstContext> > newBDInstCtx =
        epg.get()->resolveGbpeInstContext();
    optional<shared_ptr<InstContext> > newRDInstCtx =
        epg.get()->resolveGbpeInstContext();

    // walk up the chain of forwarding domains
    while (domainURI && domainClass) {
        URI du = domainURI.get();
        optional<class_id_t> ndomainClass = boost::none;
        optional<URI> ndomainURI = boost::none;

        optional<shared_ptr<ForwardingBehavioralGroupToSubnetsRSrc> > fwdSns;
        switch (domainClass.get()) {
        case RoutingDomain::CLASS_ID:
            {
                newrd = RoutingDomain::resolve(framework, du);
                if (newrd) {
                    fwdSns = newrd.get()->
                        resolveGbpForwardingBehavioralGroupToSubnetsRSrc();
                    newRDInstCtx = newrd.get()->resolveGbpeInstContext();
                    if(newRDInstCtx) {
                        optional<shared_ptr<InstContextToEpRetentionRSrc> > dref2 =
                            newRDInstCtx.get()->resolveGbpeInstContextToEpRetentionRSrc();
                        if(dref2) {
                            nEpRetURI = dref2.get()->getTargetURI();
                            newl3epretpolicy =
                                EndpointRetention::resolve(framework, nEpRetURI.get());
                        }
                    }
                }
            }
            break;
        case BridgeDomain::CLASS_ID:
            {
                newbd = BridgeDomain::resolve(framework, du);
                if (newbd) {
                    optional<shared_ptr<BridgeDomainToNetworkRSrc> > dref =
                        newbd.get()->resolveGbpBridgeDomainToNetworkRSrc();
                    if (dref) {
                        ndomainClass = dref.get()->getTargetClass();
                        ndomainURI = dref.get()->getTargetURI();
                    }
                    fwdSns = newbd.get()->
                        resolveGbpForwardingBehavioralGroupToSubnetsRSrc();
                    newBDInstCtx = newbd.get()->resolveGbpeInstContext();
                    if(newBDInstCtx) {
                        optional<shared_ptr<InstContextToEpRetentionRSrc> > dref2 =
                            newBDInstCtx.get()->resolveGbpeInstContextToEpRetentionRSrc();
                        if(dref2) {
                            nEpRetURI = dref2.get()->getTargetURI();
                            newl2epretpolicy =
                                EndpointRetention::resolve(framework, nEpRetURI.get());
                        }
                    }
                }
            }
            break;
        case FloodDomain::CLASS_ID:
            {
                newfd = FloodDomain::resolve(framework, du);
                if (newfd) {
                    optional<shared_ptr<FloodDomainToNetworkRSrc> > dref =
                        newfd.get()->resolveGbpFloodDomainToNetworkRSrc();
                    if (dref) {
                        ndomainClass = dref.get()->getTargetClass();
                        ndomainURI = dref.get()->getTargetURI();
                    }
                    newfdctx = newfd.get()->resolveGbpeFloodContext();
                    fwdSns = newfd.get()->
                        resolveGbpForwardingBehavioralGroupToSubnetsRSrc();
                }
            }
            break;
        default:
            LOG(ERROR) << "Unhandled classid: " << domainClass.get();
        }

        // Update the subnet map for the group with all the subnets it
        // could access.
        if (fwdSns && fwdSns.get()->isTargetSet()) {
            optional<shared_ptr<Subnets> > sns =
                Subnets::resolve(framework,
                                 fwdSns.get()->getTargetURI().get());
            if (sns) {
                vector<shared_ptr<Subnet> > csns;
                sns.get()->resolveGbpSubnet(csns);
                for (shared_ptr<Subnet>& csn : csns) {
                    if (gs.subnet_map[csn->getURI()] &&
                        (*gs.subnet_map[csn->getURI()] == *csn)) {
                        newsmap[csn->getURI()] = gs.subnet_map[csn->getURI()];
                    } else {
                        newsmap[csn->getURI()] = csn;
                    }
                }
            }
        }

        domainClass = std::move(ndomainClass);
        domainURI = std::move(ndomainURI);
    }

    bool updated = false;
    if (!compare_shared_ptr(epg, gs.epGroup)) {
        gs.epGroup = std::move(epg);
        updated = true;
    }
    if (!compare_shared_ptr(newInstCtx, gs.instContext)) {
        gs.instContext = std::move(newInstCtx);
        updated = true;
    }
    if (!compare_shared_ptr(newfd, gs.floodDomain)) {
        gs.floodDomain = std::move(newfd);
        updated = true;
    }
    if (!compare_shared_ptr(newfdctx, gs.floodContext)) {
        gs.floodContext = std::move(newfdctx);
        updated = true;
    }
    if (!compare_shared_ptr(newbd, gs.bridgeDomain)) {
        gs.bridgeDomain = std::move(newbd);
        updated = true;
    }
    if (!compare_shared_ptr(newrd, gs.routingDomain)) {
        gs.routingDomain = std::move(newrd);
        updated = true;
    }
    if (!compare_shared_ptr(newBDInstCtx, gs.instBDContext)) {
        gs.instBDContext = std::move(newBDInstCtx);
        updated = true;
    }
    if (!compare_shared_ptr(newRDInstCtx, gs.instRDContext)) {
        gs.instRDContext = std::move(newRDInstCtx);
        updated = true;
    }
    if (!compare_shared_ptr(newl2epretpolicy, gs.l2EpRetPolicy)) {
        gs.l2EpRetPolicy = std::move(newl2epretpolicy);
        updated = true;
    }
    if (!compare_shared_ptr(newl3epretpolicy, gs.l3EpRetPolicy)) {
        gs.l3EpRetPolicy = std::move(newl3epretpolicy);
        updated = true;
    }
    if (newsmap != gs.subnet_map) {
        gs.subnet_map = std::move(newsmap);
        updated = true;
    }

    if (updated) {
        LOG(DEBUG) << "updateEPGDomains: " << egURI << " true";
    }

    return updated;
}

boost::optional<uint32_t>
PolicyManager::getVnidForGroup(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    return it != group_map.end() && it->second.instContext &&
        it->second.instContext.get()->getEncapId()
        ? it->second.instContext.get()->getEncapId().get()
        : optional<uint32_t>();
}

boost::optional<uint32_t>
PolicyManager::getBDVnidForExternalInterface(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    ext_int_map_t::const_iterator it = ext_int_map.find(eg);
    return it != ext_int_map.end() && it->second.instContext &&
    it->second.instContext.get()->getEncapId()
    ? it->second.instContext.get()->getEncapId().get()
    : optional<uint32_t>();
}

boost::optional<shared_ptr<modelgbp::gbp::RoutingDomain>>
PolicyManager::getRDForExternalInterface(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    ext_int_map_t::const_iterator it = ext_int_map.find(eg);
    return it != ext_int_map.end() ? it->second.routingDomain
    : optional<shared_ptr<modelgbp::gbp::RoutingDomain>>();
}

void PolicyManager::getSubnetsForExternalInterface(const opflex::modb::URI& eg,
                                         /* out */ subnet_vector_t& subnets) {
    lock_guard<mutex> guard(state_mutex);
    ext_int_map_t::const_iterator it = ext_int_map.find(eg);
    if (it == ext_int_map.end()) return;
    for (const subnet_map_t::value_type& v :
         it->second.subnet_map) {
        subnets.push_back(v.second);
    }
}

boost::optional<opflex::modb::URI>
PolicyManager::getGroupForVnid(uint32_t vnid) {
    lock_guard<mutex> guard(state_mutex);
    vnid_map_t::const_iterator it = vnid_map.find(vnid);
    return it != vnid_map.end() ? optional<URI>(it->second) : boost::none;
}

optional<string> PolicyManager::getMulticastIPForGroup(const URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    return it != group_map.end() && it->second.instContext &&
        it->second.instContext.get()->getMulticastGroupIP()
        ? it->second.instContext.get()->getMulticastGroupIP().get()
        : optional<string>();
}

optional<uint32_t> PolicyManager::getSclassForGroup(const opflex::modb::URI& eg)
{
    lock_guard<mutex> guard(state_mutex);
    group_map_t::const_iterator it = group_map.find(eg);
    return it != group_map.end() && it->second.instContext
        ? it->second.instContext.get()->getClassid()
        : optional<uint32_t>();
}

optional<uint32_t> PolicyManager::getSclassForExternalNet(
const opflex::modb::URI& ei) {
    lock_guard<mutex> guard(state_mutex);
    l3n_map_t::const_iterator it = l3n_map.find(ei);
    return it != l3n_map.end() && it->second.instContext
    ? it->second.instContext.get()->getClassid()
    : optional<uint32_t>();
}

optional<uint32_t> PolicyManager::getSclassForExternalInterface(
const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    ext_int_map_t::const_iterator it = ext_int_map.find(eg);
    return it != ext_int_map.end() && it->second.instContext
    ? it->second.instContext.get()->getClassid()
    : optional<uint32_t>();
}

bool PolicyManager::groupExists(const opflex::modb::URI& eg) {
    lock_guard<mutex> guard(state_mutex);
    return group_map.find(eg) != group_map.end();
}

void PolicyManager::getGroups(uri_set_t& epURIs) {
    lock_guard<mutex> guard(state_mutex);
    for (const group_map_t::value_type& kv : group_map) {
        epURIs.insert(kv.first);
    }
}

void PolicyManager::getRoutingDomains(uri_set_t& rdURIs) {
    lock_guard<mutex> guard(state_mutex);
    for (const rd_map_t::value_type& kv : rd_map) {
        rdURIs.insert(kv.first);
    }
}

bool PolicyManager::removeContractIfRequired(const URI& contractURI) {
    using namespace modelgbp::gbp;
    auto itr = contractMap.find(contractURI);
    optional<shared_ptr<Contract> > contract =
        Contract::resolve(framework, contractURI);
    if (!contract && itr != contractMap.end() &&
        itr->second.providerGroups.empty() &&
        itr->second.consumerGroups.empty() &&
        itr->second.intraGroups.empty()) {
        LOG(DEBUG) << "Removing index for contract " << contractURI;
        contractMap.erase(itr);
        return true;
    }
    return false;
}

void PolicyManager::updateGroupContracts(class_id_t groupType,
                                         const URI& groupURI,
                                         uri_set_t& updatedContracts) {
    using namespace modelgbp::gbp;
    GroupContractState& gcs = groupContractMap[groupURI];

    uri_set_t provAdded, provRemoved;
    uri_set_t consAdded, consRemoved;
    uri_set_t intraAdded, intraRemoved;

    uri_sorted_set_t newProvided;
    uri_sorted_set_t newConsumed;
    uri_sorted_set_t newIntra;

    bool remove = true;
    if (groupType == EpGroup::CLASS_ID) {
        optional<shared_ptr<EpGroup> > epg =
            EpGroup::resolve(framework, groupURI);
        if (epg) {
            remove = false;
            vector<shared_ptr<EpGroupToProvContractRSrc> > provRel;
            epg.get()->resolveGbpEpGroupToProvContractRSrc(provRel);
            vector<shared_ptr<EpGroupToConsContractRSrc> > consRel;
            epg.get()->resolveGbpEpGroupToConsContractRSrc(consRel);
            vector<shared_ptr<EpGroupToIntraContractRSrc> > intraRel;
            epg.get()->resolveGbpEpGroupToIntraContractRSrc(intraRel);

            for (shared_ptr<EpGroupToProvContractRSrc>& rel : provRel) {
                if (rel->isTargetSet()) {
                    newProvided.insert(rel->getTargetURI().get());
                }
            }
            for (shared_ptr<EpGroupToConsContractRSrc>& rel : consRel) {
                if (rel->isTargetSet()) {
                    newConsumed.insert(rel->getTargetURI().get());
                }
            }
            for (shared_ptr<EpGroupToIntraContractRSrc>& rel : intraRel) {
                if (rel->isTargetSet()) {
                    newIntra.insert(rel->getTargetURI().get());
                }
            }
        }
    } else if (groupType == L3ExternalNetwork::CLASS_ID) {
        optional<shared_ptr<L3ExternalNetwork> > l3n =
            L3ExternalNetwork::resolve(framework, groupURI);
        if (l3n) {
            remove = false;
            vector<shared_ptr<L3ExternalNetworkToProvContractRSrc> > provRel;
            l3n.get()->resolveGbpL3ExternalNetworkToProvContractRSrc(provRel);
            vector<shared_ptr<L3ExternalNetworkToConsContractRSrc> > consRel;
            l3n.get()->resolveGbpL3ExternalNetworkToConsContractRSrc(consRel);

            for (shared_ptr<L3ExternalNetworkToProvContractRSrc>& rel :
                     provRel) {
                if (rel->isTargetSet()) {
                    newProvided.insert(rel->getTargetURI().get());
                }
            }
            for (shared_ptr<L3ExternalNetworkToConsContractRSrc>& rel :
                     consRel) {
                if (rel->isTargetSet()) {
                    newConsumed.insert(rel->getTargetURI().get());
                }
            }
        }
    }
    if (remove) {
        provRemoved.insert(gcs.contractsProvided.begin(),
                           gcs.contractsProvided.end());
        consRemoved.insert(gcs.contractsConsumed.begin(),
                           gcs.contractsConsumed.end());
        intraRemoved.insert(gcs.contractsIntra.begin(),
                            gcs.contractsIntra.end());
        groupContractMap.erase(groupURI);
    } else {

#define CALC_DIFF(olds, news, added, removed)                                  \
        std::set_difference(olds.begin(), olds.end(),                          \
                news.begin(), news.end(), inserter(removed, removed.begin())); \
        std::set_difference(news.begin(), news.end(),                          \
                olds.begin(), olds.end(), inserter(added, added.begin()));

        CALC_DIFF(gcs.contractsProvided, newProvided, provAdded, provRemoved);
        CALC_DIFF(gcs.contractsConsumed, newConsumed, consAdded, consRemoved);
        CALC_DIFF(gcs.contractsIntra, newIntra, intraAdded, intraRemoved);
#undef CALC_DIFF
        gcs.contractsProvided.swap(newProvided);
        gcs.contractsConsumed.swap(newConsumed);
        gcs.contractsIntra.swap(newIntra);
    }

#define INSERT_ALL(dst, src) dst.insert(src.begin(), src.end());
    INSERT_ALL(updatedContracts, provAdded);
    INSERT_ALL(updatedContracts, provRemoved);
    INSERT_ALL(updatedContracts, consAdded);
    INSERT_ALL(updatedContracts, consRemoved);
    INSERT_ALL(updatedContracts, intraAdded);
    INSERT_ALL(updatedContracts, intraRemoved);
#undef INSERT_ALL

    for (const URI& u : provAdded) {
        contractMap[u].providerGroups.insert(groupURI);
        LOG(DEBUG) << u << ": prov add: " << groupURI;
    }
    for (const URI& u : consAdded) {
        contractMap[u].consumerGroups.insert(groupURI);
        LOG(DEBUG) << u << ": cons add: " << groupURI;
    }
    for (const URI& u : intraAdded) {
        contractMap[u].intraGroups.insert(groupURI);
        LOG(DEBUG) << u << ": intra add: " << groupURI;
    }
    for (const URI& u : provRemoved) {
        contractMap[u].providerGroups.erase(groupURI);
        LOG(DEBUG) << u << ": prov remove: " << groupURI;
        removeContractIfRequired(u);
    }
    for (const URI& u : consRemoved) {
        contractMap[u].consumerGroups.erase(groupURI);
        LOG(DEBUG) << u << ": cons remove: " << groupURI;
        removeContractIfRequired(u);
    }
    for (const URI& u : intraRemoved) {
        contractMap[u].intraGroups.erase(groupURI);
        LOG(DEBUG) << u << ": intra remove: " << groupURI;
        removeContractIfRequired(u);
    }
}

bool operator==(const PolicyRule& lhs, const PolicyRule& rhs) {
    return ((lhs.getDirection() == rhs.getDirection()) &&
            (lhs.getAllow() == rhs.getAllow()) &&
            (lhs.getRemoteSubnets() == rhs.getRemoteSubnets()) &&
            (*lhs.getL24Classifier() == *rhs.getL24Classifier()) &&
            (lhs.getRedirectDestGrpURI() == rhs.getRedirectDestGrpURI()) && 
            (lhs.getLog() == rhs.getLog()) &&
            (lhs.egressDnsResolved == rhs.egressDnsResolved));
}

bool operator!=(const PolicyRule& lhs, const PolicyRule& rhs) {
    return !operator==(lhs,rhs);
}

std::ostream & operator<<(std::ostream &os, const PolicyRule& rule) {
    using modelgbp::gbp::DirectionEnumT;
    using network::operator<<;

    os << "PolicyRule[classifier="
       << rule.getL24Classifier()->getURI()
       << ",allow=" << rule.getAllow()
       << ",redirect=" << rule.getRedirect()
       << ",Log=" << rule.getLog()
       << ",prio=" << rule.getPriority()
       << ",direction=";

    switch (rule.getDirection()) {
    case DirectionEnumT::CONST_BIDIRECTIONAL:
        os << "bi";
        break;
    case DirectionEnumT::CONST_IN:
        os << "in";
        break;
    case DirectionEnumT::CONST_OUT:
        os << "out";
        break;
    }

    if (!rule.getRemoteSubnets().empty())
        os << ",remoteSubnets=" << rule.getRemoteSubnets();
    if (rule.getRedirectDestGrpURI())
        os << ",redirectGroup=" << rule.getRedirectDestGrpURI().get();
    if(!rule.getNamedServicePorts().empty()) {
        os << ",resolved DNS addresses=" << rule.getNamedServicePorts();
    }
    os << "]";
    return os;
}

bool operator==(const PolicyRedirectDest& lhs,
                const PolicyRedirectDest& rhs) {
    return ((lhs.getIp()==rhs.getIp()) &&
            (lhs.getMac()==rhs.getMac()) &&
            (lhs.getRD()->getURI()==rhs.getRD()->getURI()) &&
            (lhs.getBD()->getURI()==rhs.getBD()->getURI()));
}

bool operator!=(const PolicyRedirectDest& lhs, const PolicyRedirectDest& rhs) {
    return !operator==(lhs,rhs);
}

bool PolicyManager::getPolicyDestGroup(const URI& redirURI,
                                       redir_dest_list_t &redirList,
                             uint8_t &hashParam_, uint8_t &hashOpt_)
{
    lock_guard<mutex> guard(state_mutex);
    redir_dst_grp_map_t::const_iterator it = redirGrpMap.find(redirURI);
    if(it == redirGrpMap.end()){
        return false;
    }
    hashParam_ = it->second.resilientHashEnabled;
    hashOpt_ = it->second.hashAlgo;
    redirList.insert(redirList.end(),
                     it->second.redirDstList.begin(),
                     it->second.redirDstList.end());
    return true;
}

static bool compareRedirects(const shared_ptr<PolicyRedirectDest>& lhs,
                             const shared_ptr<PolicyRedirectDest>& rhs)
{
    return (lhs->getIp() < rhs->getIp())?true:false;
}

void PolicyManager::updateRedirectDestGroup(const URI& uri,
                                            uri_set_t &notifyGroup) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::gbpe;
    typedef shared_ptr<RedirectDestToDomainRSrc> redir_domp_t;
    boost::optional<shared_ptr<RedirectDestGroup>> redirDstGrp =
    RedirectDestGroup::resolve(framework,uri);
    RedirectDestGrpState &redirState = redirGrpMap[uri];
    if(!redirDstGrp) {
        notifyGroup.insert(redirState.ctrctSet.begin(),
                           redirState.ctrctSet.end());
        redirGrpMap.erase(uri);
        return;
    }
    std::vector<shared_ptr<RedirectDest>> redirDests;
    redirDstGrp.get()->resolveGbpRedirectDest(redirDests);
    PolicyManager::redir_dest_list_t newRedirDests;

    LOG(DEBUG) << uri;
    for(shared_ptr<RedirectDest>& redirDest : redirDests) {
        /*Redirect Destination should be completely resolved
         in order to be useful for forwarding*/
        std::vector<redir_domp_t> redirDoms;
        redirDest->resolveGbpRedirectDestToDomainRSrc(redirDoms);
        boost::optional<shared_ptr<BridgeDomain>> bd;
        boost::optional<shared_ptr<RoutingDomain>> rd;
        boost::optional<shared_ptr<InstContext>> bdInst,rdInst;
        for(const redir_domp_t &redirDom: redirDoms) {
            if(!redirDom->getTargetURI() || !redirDom->getTargetClass())
                continue;
            class_id_t redirDomClass = redirDom->getTargetClass().get();
            if(redirDomClass == BridgeDomain::CLASS_ID) {
                bd = BridgeDomain::resolve(framework,
                                           redirDom->getTargetURI().get());
                if(!bd) {
                    break;
		}
                bdInst = bd.get()->resolveGbpeInstContext();
            }
            if(redirDomClass == RoutingDomain::CLASS_ID) {
                rd = RoutingDomain::resolve(framework,
                                            redirDom->getTargetURI().get());
                if(!rd){
                   break;
                }
                rdInst = rd.get()->resolveGbpeInstContext();
            }
        }
        if(!bdInst || !rdInst || !redirDest->isIpSet() ||
           !redirDest->isMacSet()) {
            continue;
        }
        boost::system::error_code ec;
        boost::asio::ip::address addr = address::from_string(
                                            redirDest->getIp().get(),ec);
        if(ec) {
            continue;
        }
        newRedirDests.push_back(
            make_shared<PolicyRedirectDest>(redirDest,addr,
                                            redirDest->getMac().get(),
                                            rd.get(), bd.get()));
    }
    redir_dest_list_t::const_iterator li = redirState.redirDstList.begin();
    redir_dest_list_t::const_iterator ri = newRedirDests.begin();
    while ((li != redirState.redirDstList.end()) &&
           (ri != newRedirDests.end()) &&
           (li->get() == ri->get())) {
        ++li;
        ++ri;
    }
    if((li != redirState.redirDstList.end()) ||
       (ri != newRedirDests.end()) ||
       (redirDstGrp.get()->getHashAlgo(HashingAlgorithmEnumT::CONST_SYMMETRIC)
        != redirState.hashAlgo) ||
       (redirDstGrp.get()->getResilientHashEnabled(1) != redirState.resilientHashEnabled)) {
        notifyGroup.insert(redirState.ctrctSet.begin(),
                           redirState.ctrctSet.end());
    }
    /* Order in which the next-hops are inserted may not be the order of
     * resolution. Return in ascending order
     */
    newRedirDests.sort(compareRedirects);
    redirState.redirDstList.swap(newRedirDests);
    redirState.hashAlgo = redirDstGrp.get()->getHashAlgo(
                             HashingAlgorithmEnumT::CONST_SYMMETRIC);
    redirState.resilientHashEnabled = redirDstGrp.get()->getResilientHashEnabled(1);
}

void PolicyManager::updateRedirectDestGroups(uri_set_t &notifyGroup) {
    for (auto& itr : redirGrpMap) {
        updateRedirectDestGroup(itr.first, notifyGroup);
    }
}

void PolicyManager::addRoutingDomainToSubnets(const URI& subnets,
                                              const URI& rd) {
    lock_guard<mutex> guard(subnets_rd_mutex);

    uri_set_t& rdset = subnets_rd_map[subnets];
    if (rdset.find(rd) != rdset.end())
        return;

    rdset.insert(rd);
}

void PolicyManager::deleteRoutingDomain(const URI& rd) {
    lock_guard<mutex> guard(subnets_rd_mutex);

    auto it1 = subnets_rd_map.begin();
    while (it1 != subnets_rd_map.end()) {
        uri_set_t& rdset = it1->second;

        auto it2 = rdset.find(rd);
        if (it2 != rdset.end())
            rdset.erase(it2);

        if (rdset.empty())
            it1 = subnets_rd_map.erase(it1);
        else
           ++it1;
    }
}

void PolicyManager::deleteSubnets(const URI& subnets) {
    lock_guard<mutex> guard(subnets_rd_mutex);

    auto it = subnets_rd_map.find(subnets);

    if (it != subnets_rd_map.end()) {
        uri_set_t& rdset = it->second;
        rdset.clear();
        subnets_rd_map.erase(it);
    }
}

template <typename Subnets, typename Subnet>
void resolveSubnet(shared_ptr<Subnets>& subnets_obj, vector<shared_ptr<Subnet> >& subnets) { }

template <>
void resolveSubnet(shared_ptr<modelgbp::gbp::Subnets>& subnets_obj,
                   vector<shared_ptr<modelgbp::gbp::Subnet> >& subnets) {
    subnets_obj.get()->resolveGbpSubnet(subnets);
}
template <>
void resolveSubnet(shared_ptr<modelgbp::gbp::LocalSubnets>& subnets_obj,
                   vector<shared_ptr<modelgbp::gbp::LocalSubnet> >& subnets) {
    subnets_obj.get()->resolveGbpLocalSubnet(subnets);
}

template <typename Subnets, typename Subnet>
void PolicyManager::resolveSubnets(OFFramework& framework,
                                   const optional<URI>& subnets_uri,
                                   /* out */ network::subnets_t& subnets_out) {
    if (!subnets_uri) return;
    optional<shared_ptr<Subnets> > subnets_obj =
        Subnets::resolve(framework, subnets_uri.get());
    if (!subnets_obj) {
        LOG(DEBUG) << "subnets_obj is nil for subnet " << subnets_uri.get();
        return;
    }

    vector<shared_ptr<Subnet> > subnets;
    resolveSubnet(subnets_obj.get(), subnets);

    boost::system::error_code ec;

    for (shared_ptr<Subnet>& subnet : subnets) {
        if (!subnet->isAddressSet() || !subnet->isPrefixLenSet())
            continue;
        address addr = address::from_string(subnet->getAddress().get(), ec);
        if (ec) continue;
        addr = network::mask_address(addr, subnet->getPrefixLen().get());
        subnets_out.insert(make_pair(addr.to_string(),
                                     subnet->getPrefixLen().get()));
    }
}

template void PolicyManager::resolveSubnets
    <modelgbp::gbp::Subnets, modelgbp::gbp::Subnet>(
        OFFramework& framework, const optional<URI>& subnets_uri,
        /* out */ network::subnets_t& subnets_out);
template void PolicyManager::resolveSubnets
    <modelgbp::gbp::LocalSubnets, modelgbp::gbp::LocalSubnet>(
        OFFramework& framework, const optional<URI>& subnets_uri,
        /* out */ network::subnets_t& subnets_out);

template <typename Parent, typename Child>
void resolveChildren(shared_ptr<Parent>& parent,
                     /* out */ vector<shared_ptr<Child> > &children) { }
template <>
void resolveChildren(shared_ptr<modelgbp::gbp::Subject>& subject,
                     vector<shared_ptr<modelgbp::gbp::Rule> > &rules) {
    subject->resolveGbpRule(rules);
}
template <>
void resolveChildren(shared_ptr<modelgbp::gbp::SecGroupSubject>& subject,
                     vector<shared_ptr<modelgbp::gbp::SecGroupRule> > &rules) {
    subject->resolveGbpSecGroupRule(rules);
}
template <>
void resolveChildren(shared_ptr<modelgbp::gbp::LocalSecGroupSubject>& subject,
                     vector<shared_ptr<modelgbp::gbp::LocalSecGroupRule> > &rules) {
    subject->resolveGbpLocalSecGroupRule(rules);
}
template <>
void resolveChildren(shared_ptr<modelgbp::gbp::Contract>& contract,
                     vector<shared_ptr<modelgbp::gbp::Subject> > &subjects) {
    contract->resolveGbpSubject(subjects);
}
template <>
void resolveChildren(shared_ptr<modelgbp::gbp::SecGroup>& secgroup,
                     vector<shared_ptr<modelgbp::gbp::SecGroupSubject> > &subjects) {
    secgroup->resolveGbpSecGroupSubject(subjects);
}
template <>
void resolveChildren(shared_ptr<modelgbp::gbp::LocalSecGroup>& secgroup,
                     vector<shared_ptr<modelgbp::gbp::LocalSecGroupSubject> > &subjects) {
    secgroup->resolveGbpLocalSecGroupSubject(subjects);
}
template <typename Rule>
void resolveRemoteSubnets(OFFramework& framework,
                          shared_ptr<Rule>& parent,
                          /* out */ network::subnets_t &remoteSubnets) {}
template <>
void resolveRemoteSubnets(OFFramework& framework,
                          shared_ptr<modelgbp::gbp::SecGroupRule>& rule,
                          /* out */ network::subnets_t &remoteSubnets) {
    using modelgbp::gbp::Subnets;
    using modelgbp::gbp::Subnet;

    typedef modelgbp::gbp::SecGroupRuleToRemoteAddressRSrc RASrc;
    vector<shared_ptr<RASrc> > raSrcs;
    rule->resolveGbpSecGroupRuleToRemoteAddressRSrc(raSrcs);
    for (const shared_ptr<RASrc>& ra : raSrcs) {
        optional<URI> subnets_uri = ra->getTargetURI();
        PolicyManager::resolveSubnets<Subnets, Subnet>
            (framework, subnets_uri, remoteSubnets);
    }
}
template <>
void resolveRemoteSubnets(OFFramework& framework,
                          shared_ptr<modelgbp::gbp::LocalSecGroupRule>& rule,
                          /* out */ network::subnets_t &remoteSubnets) {
    using modelgbp::gbp::LocalSubnets;
    using modelgbp::gbp::LocalSubnet;

    typedef modelgbp::gbp::LocalSecGroupRuleToRemoteAddressRSrc RASrc;
    vector<shared_ptr<RASrc> > raSrcs;
    rule->resolveGbpLocalSecGroupRuleToRemoteAddressRSrc(raSrcs);
    for (const shared_ptr<RASrc>& ra : raSrcs) {
        optional<URI> subnets_uri = ra->getTargetURI();
        PolicyManager::resolveSubnets<LocalSubnets, LocalSubnet>
            (framework, subnets_uri, remoteSubnets);
    }
}

template <typename Rule, typename RuleToClassifier>
void resolveGbpRuleToClassifierResource(shared_ptr<Rule>& rule,
                                        vector<shared_ptr<RuleToClassifier> >& clsRel) { }

template <>
void resolveGbpRuleToClassifierResource(shared_ptr<modelgbp::gbp::Rule>& rule,
                                        vector<shared_ptr<modelgbp::gbp::RuleToClassifierRSrc> >& clsRel) {
    rule->resolveGbpRuleToClassifierRSrc(clsRel);
}

template <>
void resolveGbpRuleToClassifierResource(shared_ptr<modelgbp::gbp::SecGroupRule>& rule,
                                        vector<shared_ptr<modelgbp::gbp::RuleToClassifierRSrc> >& clsRel) {
    rule->resolveGbpRuleToClassifierRSrc(clsRel);
}

template <>
void resolveGbpRuleToClassifierResource(shared_ptr<modelgbp::gbp::LocalSecGroupRule>& rule,
                                        vector<shared_ptr<modelgbp::gbp::LocalSecGroupRuleToClassifierRSrc> >& clsRel) {
   rule->resolveGbpLocalSecGroupRuleToClassifierRSrc(clsRel);
}

template <typename Rule, typename RuleToAction>
void resolveGbpRuleToActionResource(shared_ptr<Rule>& rule,
                                    vector<shared_ptr<RuleToAction> >& clsAct) { }

template <>
void resolveGbpRuleToActionResource(shared_ptr<modelgbp::gbp::Rule>& rule,
                                    vector<shared_ptr<modelgbp::gbp::RuleToActionRSrc> >& clsAct) {
    rule->resolveGbpRuleToActionRSrc(clsAct);
}

template <>
void resolveGbpRuleToActionResource(shared_ptr<modelgbp::gbp::SecGroupRule>& rule,
                                    vector<shared_ptr<modelgbp::gbp::RuleToActionRSrc> >& clsAct) {
    rule->resolveGbpRuleToActionRSrc(clsAct);
}

template <>
void resolveGbpRuleToActionResource(shared_ptr<modelgbp::gbp::LocalSecGroupRule>& rule,
                                    vector<shared_ptr<modelgbp::gbp::LocalSecGroupRuleToActionRSrc> >&clsAct) {
    rule->resolveGbpLocalSecGroupRuleToActionRSrc(clsAct);
}

template <typename Rule>
bool resolveNamedAddress(PolicyManager &pMgr,
                         OFFramework& framework,
                         shared_ptr<Rule>& parent,
                         /* out */PolicyManager::named_addr_set_t &newDnsRefs,
                         /* out */network::service_ports_t  &namedSvcPorts) {
    return true;
}

template <>
bool resolveNamedAddress(PolicyManager &pMgr,
                         OFFramework& framework,
                         shared_ptr<modelgbp::gbp::SecGroupRule>& rule,
                         /* out */PolicyManager::named_addr_set_t &newDnsRefs,
                         /* out */network::service_ports_t &namedSvcPorts) {
    using modelgbp::gbp::DnsName;
    vector<shared_ptr<DnsName>> dnsNames;
    rule->resolveGbpDnsName(dnsNames);
    for (const shared_ptr<DnsName>& dnsName : dnsNames) {
        if (dnsName->getName()) {
            newDnsRefs.insert(dnsName->getName().get());
            pMgr.getDnsResolvedNamedServicePorts(dnsName->getName().get(), namedSvcPorts);
        }
    }
    return (dnsNames.empty() || !namedSvcPorts.empty());
}

template <typename Classifier>
void sortOrderOfSameRange(vector<shared_ptr<Classifier>>& classifiers) {
     using modelgbp::gbpe::L24Classifier;
     typename vector<shared_ptr<Classifier>>::iterator begin = classifiers.begin();
     typename vector<shared_ptr<Classifier>>::iterator end = classifiers.begin();
     PriorityComparator<shared_ptr<Classifier> > classifierPrioComp;
     int set=0;

     for (auto it = classifiers.begin(); it != classifiers.end(); it ++){
         const shared_ptr<Classifier>& currClsr = *it;
         if (*it != *(--classifiers.end())){
             const shared_ptr<Classifier>& nextClsr = *(it+1) ;
             if (currClsr->getOrder(0) == nextClsr->getOrder(0)) {
                if (set == 0){
                   begin = it;
                   set = 1;
                }
                end = it+1;
                if (*end == *(--classifiers.end())){
                   auto range = std::make_pair(begin, end);
                   stable_sort(range.first, range.second+1, classifierPrioComp);
                   end = classifiers.begin();
                   set = 0;
                }

             } else  {
                   if (end != classifiers.begin()){
                      auto range = std::make_pair(begin, end);
                      stable_sort(range.first, range.second+1, classifierPrioComp);
                      end = classifiers.begin();
                      set = 0;
                   }
               }
         }

      }
}

//Given a DNS Name of the format _service._protocol.target
//Return the protocol
static uint8_t getProtoFromDnsName(const std::string &srvName) {
    using namespace boost::algorithm;
    typedef vector< string > split_vector_type;
    split_vector_type splitVec;
    split( splitVec, srvName, is_any_of("."), token_compress_on );
    if(splitVec.size() < 3){
        return 0;
    }
    if(splitVec[1][0] != '_') {
        return 0;
    }
    std::string protoStr;
    protoStr.assign(splitVec[1], 1, splitVec[1].length()-1);
    uint8_t proto = 0;
    if(protoStr == "tcp") {
        proto=6;
    } else if(protoStr == "udp") {
        proto=17;
    } else if(protoStr == "sctp") {
        proto=132;
    } else {
        proto=0;
    }
    return proto;
}

static void getDirectResolvedAddresses(std::shared_ptr<modelgbp::epdr::DnsEntry> &dnsEntry,
        network::service_ports_t &newResolved, uint8_t proto=0, uint16_t dport=0) {
    using namespace modelgbp::epdr;
    std::vector<shared_ptr<DnsMappedAddress>> mappedAddresses;
    dnsEntry.get()->resolveEpdrDnsMappedAddress(mappedAddresses);
    for(auto &mappedAddress: mappedAddresses) {
        boost::system::error_code ec;
        address addr =
            address::from_string(mappedAddress->getAddress().get(), ec);
        if(ec) {
            LOG(ERROR) << "Failed to add mapped address" <<
                mappedAddress->getAddress().get();
            continue;
        }
        network::service_port_t srvPort;
        srvPort.address = addr.to_string();
        srvPort.prefixLen = (addr.is_v4()?32:128);
        srvPort.port = 0;
        srvPort.proto = 0;
        auto itr = newResolved.find(srvPort);
        if((itr != newResolved.end()) && (dport != 0 )) {
            newResolved.erase(srvPort);
            srvPort.proto = proto;
            srvPort.port = dport;
        }
        newResolved.insert(srvPort);
    }
}

void PolicyManager::updateDnsPolicies(const class_id_t class_id,const URI &uri, uri_set_t &notifyContracts) {
    using modelgbp::epdr::DnsAnswer;
    using modelgbp::epdr::DnsAsk;
    using modelgbp::epdr::DnsAnswerToResultRSrc;
    using modelgbp::epdr::DnsEntry;
    using modelgbp::epdr::DnsSrv;
    using modelgbp::epdr::DnsMappedAddress;
    using network::operator<<;

    if(class_id != DnsAnswer::CLASS_ID) {
        return;
    }
    auto dnsAnswer = DnsAnswer::resolve(framework, uri);
    if(!dnsAnswer) {
        vector<string> elements;
        uri.getElements(elements);
        if(elements.empty()) {
            return;
        }
        LOG(DEBUG) << "Clear DNS cache for " << elements.back();
        auto itr = dns_demand_map.find(elements.back());
        if(itr != dns_demand_map.end()) {
            itr->second.resolved.clear();
            notifyContracts = itr->second.secGrpSet;
            for(auto &secGrp: notifyContracts) {
                bool notFound;
                updateSecGrpRules(secGrp, notFound);
            }
        }
        return;
    }
    auto itr = dns_demand_map.find(dnsAnswer.get()->getName().get());
    if(itr == dns_demand_map.end()) {
        return;
    }
    network::service_ports_t newResolved;
    std::vector<std::shared_ptr<DnsAnswerToResultRSrc>> result;
    dnsAnswer.get()->resolveEpdrDnsAnswerToResultRSrc(result);
    std::unordered_map<std::string, std::shared_ptr<DnsEntry>> resolvedMap;
    for(auto &res :result) {
        if(!res->isTargetSet() ||
           (res->getTargetClass().get() != DnsEntry::CLASS_ID)) {
            continue;
        }
        optional<shared_ptr<DnsEntry> > dnsEntry =
            DnsEntry::resolve(framework, res->getTargetURI().get());
        if(dnsEntry) {
            resolvedMap.insert(std::make_pair(dnsEntry.get()->getName().get(),dnsEntry.get()));
            getDirectResolvedAddresses(dnsEntry.get(), newResolved);
        }
    }
    auto resolvedItr = resolvedMap.find(dnsAnswer.get()->getName().get());
    if(resolvedItr != resolvedMap.end()) {
        optional<shared_ptr<DnsEntry> > dnsEntry =
            DnsEntry::resolve(framework, resolvedItr->first);
        if(dnsEntry) {
            std::vector<shared_ptr<DnsSrv>> mappedSrvs;
            dnsEntry.get()->resolveEpdrDnsSrv(mappedSrvs);
            if(!mappedSrvs.empty()){
                uint8_t proto = getProtoFromDnsName(dnsAnswer.get()->getName().get());
                if(proto != 0) {
                    /*Fixup the lookup with service endpoint ports*/
                    for(auto &mappedSrv: mappedSrvs) {
                        uint16_t dport = mappedSrv->getPort().get();
                        auto srvItr = resolvedMap.find(mappedSrv->getHostName().get());
                        if(srvItr != resolvedMap.end()) {
                            optional<shared_ptr<DnsEntry> > dnsSrvEntry =
                                DnsEntry::resolve(framework, srvItr->first);
                            if(dnsSrvEntry) {
                                getDirectResolvedAddresses(dnsSrvEntry.get(), newResolved,
                                        proto, dport);
                            }
                        }
                    }
                } else {
                    newResolved.clear();
                }
            }
        }
    }

    if(itr->second.resolved != newResolved) {
        itr->second.resolved = newResolved;
        notifyContracts = itr->second.secGrpSet;
	for(auto &secGrp: notifyContracts) {
	    bool notFound;
	    updateSecGrpRules(secGrp, notFound);
	}
	LOG(DEBUG) << "Update DNS cache for " << dnsAnswer.get()->getName().get() << string(" ") << newResolved;
    }
}

/*Call this while holding the stateMutex*/
void PolicyManager::getDnsResolvedNamedServicePorts(
        const std::string &domainName,
        network::service_ports_t &egressDnsResolved)
{
    auto itr = dns_demand_map.find(domainName);
    if(itr != dns_demand_map.end()) {
        boost::optional<const network::service_ports_t &> res(itr->second.resolved);
        network::append(egressDnsResolved,res);
    }
}

/*Call this while holding the stateMutex*/
void PolicyManager::createDnsAsk(const URI &uri, const std::string &domainName)
{
    dns_demand_map[domainName];
    dns_demand_map[domainName].secGrpSet.insert(uri);
    auto dDemandU = modelgbp::epdr::DnsDemand::resolve(framework);
    opflex::modb::Mutator mutator(framework,"policyelement");
    dDemandU.get()->addEpdrDnsAsk(domainName);
    mutator.commit();
    LOG(DEBUG) << "Added DNS ask for " << domainName ;
}

void PolicyManager::deleteDnsAsk(const URI &uri, const std::string &domainName)
{
    if(dns_demand_map.find(domainName) == dns_demand_map.end()) {
        return;
    }
    dns_demand_map[domainName].secGrpSet.erase(uri);
    if(dns_demand_map[domainName].secGrpSet.empty()) {
        opflex::modb::Mutator mutator(framework,"policyelement");
        modelgbp::epdr::DnsAsk::remove(framework,domainName);
        mutator.commit();
	LOG(DEBUG) << "Removed DNS ask for " << domainName ;
    }
}

template <typename Parent, typename Subject, typename Rule,
          typename Classifier, typename Action,
          typename RuleToClassifier, typename RuleToAction>
static bool updatePolicyRules(PolicyManager &pMgr, OFFramework& framework,
                              const URI& parentURI, bool& notFound,
                              PolicyManager::rule_list_t& oldRules,
                              PolicyManager::uri_set_t &oldRedirGrps, bool log,
                              bool local, PolicyManager::uri_set_t &newRedirGrps,
                              PolicyManager::named_addr_set_t &newDnsRefs)
{
    using modelgbp::gbp::RuleToClassifierRSrc;
    using modelgbp::gbp::RuleToActionRSrc;
    using modelgbp::gbp::LocalSecGroupRuleToClassifierRSrc;
    using modelgbp::gbp::LocalSecGroupRuleToActionRSrc;
    using modelgbp::gbp::AllowDenyAction;
    using modelgbp::gbp::LocalAllowDenyAction;
    using modelgbp::gbp::RedirectAction;
    using modelgbp::gbp::RedirectDestGroup;
    using modelgbp::gbp::LogAction;
    using modelgbp::gbp::LocalLogAction;

    optional<shared_ptr<Parent> > parent =
        Parent::resolve(framework, parentURI);
    if (!parent) {
        notFound = true;
        return false;
    }
    notFound = false;

    /* get all classifiers for this parent as an ordered-list */
    PolicyManager::rule_list_t newRules;
    OrderComparator<shared_ptr<Rule> > ruleComp;
    OrderComparator<shared_ptr<Classifier> > classifierComp;
    vector<shared_ptr<Subject> > subjects;
    resolveChildren(parent.get(), subjects);
    for (shared_ptr<Subject>& sub : subjects) {
        vector<shared_ptr<Rule> > rules;
        resolveChildren(sub, rules);
        stable_sort(rules.begin(), rules.end(), ruleComp);

        uint16_t rulePrio = PolicyManager::MAX_POLICY_RULE_PRIORITY;

        for (shared_ptr<Rule>& rule : rules) {
            if (!rule->isDirectionSet()) {
                continue;       // ignore rules with no direction
            }
            uint8_t dir = rule->getDirection().get();
            network::subnets_t remoteSubnets;
            network::service_ports_t namedSvcPorts;
            resolveRemoteSubnets<Rule>(framework, rule, remoteSubnets);
            if(!resolveNamedAddress(pMgr, framework, rule, newDnsRefs, namedSvcPorts)) {
               continue;  //ignore policies with DNS names that do not have atleast one name resolved.
            }
            vector<shared_ptr<Classifier> > classifiers;
            vector<shared_ptr<RuleToClassifier> > clsRel;
            resolveGbpRuleToClassifierResource(rule, clsRel);

            for (shared_ptr<RuleToClassifier>& r : clsRel) {
                if (!r->isTargetSet() ||
                    r->getTargetClass().get() != Classifier::CLASS_ID) {
                    continue;
                }
                optional<shared_ptr<Classifier> > cls =
                    Classifier::resolve(framework, r->getTargetURI().get());
                if (cls) {
                    classifiers.push_back(cls.get());
                }
            }
            stable_sort(classifiers.begin(), classifiers.end(), classifierComp);

            vector<shared_ptr<RuleToAction> > actRel;
            resolveGbpRuleToActionResource(rule, actRel);
            bool ruleAllow = true;
            bool ruleRedirect = false;
            bool ruleLog = false;
            uint32_t minOrder = UINT32_MAX;
            optional<shared_ptr<RedirectDestGroup>> redirDstGrp;
            optional<URI> destGrpUri;
            for (shared_ptr<RuleToAction>& r : actRel) {
                if (!r->isTargetSet()) {
                    continue;
                }
                if(r->getTargetClass().get() == AllowDenyAction::CLASS_ID ||
                   r->getTargetClass().get() == LocalAllowDenyAction::CLASS_ID) {
                    optional<shared_ptr<Action> > act =
                        Action::resolve(framework, r->getTargetURI().get());
                    if (act) {
                        if (act.get()->getOrder(UINT32_MAX-1) < minOrder) {
                            minOrder = act.get()->getOrder(UINT32_MAX-1);
                            ruleAllow = act.get()->getAllow(0) != 0;
                        }
                    }
                }
                else if(r->getTargetClass().get() ==
                        RedirectAction::CLASS_ID) {
                    optional<shared_ptr<RedirectAction> > act =
                    RedirectAction::resolve(framework, r->getTargetURI().get());
                    ruleRedirect = true;
                    ruleAllow = false;
                    if (!act) {
                        continue;
                    }
                    optional<shared_ptr<modelgbp::gbp::RedirectActionToDestGrpRSrc>>
                        destRef = act.get()->resolveGbpRedirectActionToDestGrpRSrc();
                    if(!destRef){
                        continue;
                    }
                    destGrpUri = destRef.get()->getTargetURI();
                    if(!destGrpUri) {
                        continue;
                    }
                    redirDstGrp =
                    RedirectDestGroup::resolve(framework, destGrpUri.get());
                    newRedirGrps.insert(destGrpUri.get());
                }
                else if(r->getTargetClass().get() == LogAction::CLASS_ID) {
                        optional<shared_ptr<LogAction> > resolveLog = 
                           LogAction::resolve(framework,r->getTargetURI().get());
                    if (resolveLog) {
                        ruleLog = true;
                    }
                }
                else if (r->getTargetClass().get() == LocalLogAction::CLASS_ID) {
                         optional<shared_ptr<LocalLogAction> > resolveLog =
                            LocalLogAction::resolve(framework,r->getTargetURI().get());
                    if (resolveLog) {
                        ruleLog = true;
                    }
                }
            }

            sortOrderOfSameRange<Classifier>(classifiers);
            uint16_t clsPrio = 0;
            for (const shared_ptr<Classifier>& c : classifiers) {
                newRules.push_back(std::make_shared<PolicyRule>(dir,
                                                    rulePrio - clsPrio,
                                                    c, ruleAllow,
                                                    remoteSubnets,
                                                    ruleRedirect, ruleLog,
                                                    destGrpUri,
                                                    namedSvcPorts));
                if (clsPrio < 127)
                    clsPrio += 1;
            }
            if (rulePrio > 128)
                rulePrio -= 128;
        }
    }
    PolicyManager::rule_list_t::const_iterator oi = oldRules.begin();
    while(oi != oldRules.end()) {
        if(oi->get()->getRedirectDestGrpURI()) {
            oldRedirGrps.insert(oi->get()->getRedirectDestGrpURI().get());
        }
        ++oi;
    }
    PolicyManager::rule_list_t::const_iterator li = oldRules.begin();
    PolicyManager::rule_list_t::const_iterator ri = newRules.begin();
    while (li != oldRules.end() && ri != newRules.end() &&
           li->get() == ri->get()) {
        ++li;
        ++ri;
    }
    bool updated = (li != oldRules.end() || ri != newRules.end());
    if (updated) {
        oldRules.swap(newRules);
        for (shared_ptr<PolicyRule>& c : oldRules) {
            LOG(DEBUG) << parentURI << ": " << *c
                       << " local: " << local;
        }
    }
    return updated;
}

bool PolicyManager::updateSecGrpRules(const URI& secGrpURI, bool& notFound, bool local) {
    using namespace modelgbp::gbp;
    using modelgbp::gbpe::L24Classifier;
    uri_set_t oldRedirGrps, newRedirGrps;
    PolicyManager::named_addr_set_t newDnsRefs;
    PolicyManager::named_addr_set_t &oldDnsRefs = secGrpMap[secGrpURI].dnsAsks;
    bool log = false;
    bool updated;

    if (!local) {
        updated = updatePolicyRules<SecGroup, SecGroupSubject,
                      SecGroupRule, L24Classifier, AllowDenyAction,
                      RuleToClassifierRSrc, RuleToActionRSrc>(*this,
                          framework, secGrpURI, notFound,
                          secGrpMap[secGrpURI].rules,
                          oldRedirGrps, log, local, newRedirGrps, newDnsRefs);
    } else {
        updated = updatePolicyRules<LocalSecGroup, LocalSecGroupSubject,
                      LocalSecGroupRule, LocalL24Classifier, LocalAllowDenyAction,
                      LocalSecGroupRuleToClassifierRSrc, LocalSecGroupRuleToActionRSrc>(*this,
                              framework, secGrpURI, notFound,
                              secGrpMap[secGrpURI].rules,
                              oldRedirGrps, log, local, newRedirGrps, newDnsRefs);
    }

    for (const auto& s : oldDnsRefs) {
        /*lost Dns Ref*/
        if(dns_demand_map.find(s) != dns_demand_map.end() && (newDnsRefs.find(s) == newDnsRefs.end())) {
            deleteDnsAsk(secGrpURI, s);
        }
    }
    for (const auto& s : newDnsRefs) {
        /*new Dns Ref*/
        if(oldDnsRefs.find(s) == oldDnsRefs.end()) {
            createDnsAsk(secGrpURI, s);
        }
    }
    secGrpMap[secGrpURI].dnsAsks = std::move(newDnsRefs);
    return updated;
}

bool PolicyManager::updateContractRules(const URI& contrURI, bool& notFound) {
    using namespace modelgbp::gbp;
    using modelgbp::gbpe::L24Classifier;
    uri_set_t oldRedirGrps, newRedirGrps;
    ContractState& cs = contractMap[contrURI];
    named_addr_set_t newDnsRef;
    bool log = false;
    bool updated = updatePolicyRules<Contract, Subject,
                                     Rule, L24Classifier,
                                     AllowDenyAction,
                                     RuleToClassifierRSrc,
                                     RuleToActionRSrc>(*this, framework, contrURI,
                                           notFound, cs.rules,
                                           oldRedirGrps, log, false,
                                           newRedirGrps,
                                           newDnsRef);
    for (const URI& u : oldRedirGrps) {
        if(redirGrpMap.find(u) != redirGrpMap.end()) {
            redirGrpMap[u].ctrctSet.erase(contrURI);
        }
    }
    for (const URI& u : newRedirGrps) {
        redirGrpMap[u].ctrctSet.insert(contrURI);
    }
    return updated;
}

void PolicyManager::updateContracts() {
    unique_lock<mutex> guard(state_mutex);
    uri_set_t contractsToNotify;

    /* recompute the rules for all contracts if a policy
       object changed */
    for (auto itr = contractMap.begin();
         itr != contractMap.end();) {

        bool notFound = false;
        if (updateContractRules(itr->first, notFound)) {
            contractsToNotify.insert(itr->first);
        }
        /*
         * notFound == true may happen if the contract was
         * removed or there is a reference from a group to
         * a contract that has not been received yet.
         */
        if (notFound) {
            contractsToNotify.insert(itr->first);
            // if contract has providers/consumers, only
            // clear the rules
            if (itr->second.providerGroups.empty() &&
                itr->second.consumerGroups.empty() &&
                itr->second.intraGroups.empty()) {
                itr = contractMap.erase(itr);
            } else {
                itr->second.rules.clear();
                ++itr;
            }
        } else {
            ++itr;
        }
    }
    guard.unlock();

    for (const URI& u : contractsToNotify) {
        notifyContract(u);
    }
}

void PolicyManager::updateSecGrps(bool local) {
    /* recompute the rules for all security groups if a policy
       object changed */
    unique_lock<mutex> guard(state_mutex);

    uri_set_t toNotify;
    auto it = secGrpMap.begin();
    while (it != secGrpMap.end()) {
        bool notfound = false;
        /* Skip rules that are not relevant for this computation */
        if (it->second.isLocal != local) {
            ++it;
            continue;
        }
        if (updateSecGrpRules(it->first, notfound, local)) {
            toNotify.insert(it->first);
        }
        if (notfound) {
            toNotify.insert(it->first);
            it = secGrpMap.erase(it);
        } else {
            ++it;
        }
    }
    guard.unlock();

    for (const URI& u : toNotify) {
        notifySecGroup(u);
    }
}

void PolicyManager::getContractProviders(const URI& contractURI,
                                         /* out */ uri_set_t& epgURIs) {
    lock_guard<mutex> guard(state_mutex);
    contract_map_t::const_iterator it = contractMap.find(contractURI);
    if (it != contractMap.end()) {
        epgURIs.insert(it->second.providerGroups.begin(),
                       it->second.providerGroups.end());
    }
}

void PolicyManager::getContractConsumers(const URI& contractURI,
                                         /* out */ uri_set_t& epgURIs) {
    lock_guard<mutex> guard(state_mutex);
    contract_map_t::const_iterator it = contractMap.find(contractURI);
    if (it != contractMap.end()) {
        epgURIs.insert(it->second.consumerGroups.begin(),
                       it->second.consumerGroups.end());
    }
}

void PolicyManager::getContractIntra(const URI& contractURI,
                                         /* out */ uri_set_t& epgURIs) {
    lock_guard<mutex> guard(state_mutex);
    contract_map_t::const_iterator it = contractMap.find(contractURI);
    if (it != contractMap.end()) {
        epgURIs.insert(it->second.intraGroups.begin(),
                       it->second.intraGroups.end());
    }
}

void PolicyManager::getContractsForGroup(const URI& eg,
                                         /* out */ uri_set_t& contractURIs) {
    using namespace modelgbp::gbp;
    optional<shared_ptr<EpGroup> > epg = EpGroup::resolve(framework, eg);
    if (!epg) return;

    vector<shared_ptr<EpGroupToProvContractRSrc> > provRel;
    epg.get()->resolveGbpEpGroupToProvContractRSrc(provRel);
    vector<shared_ptr<EpGroupToConsContractRSrc> > consRel;
    epg.get()->resolveGbpEpGroupToConsContractRSrc(consRel);
    vector<shared_ptr<EpGroupToIntraContractRSrc> > intraRel;
    epg.get()->resolveGbpEpGroupToIntraContractRSrc(intraRel);

    for (shared_ptr<EpGroupToProvContractRSrc>& rel : provRel) {
        if (rel->isTargetSet()) {
            contractURIs.insert(rel->getTargetURI().get());
        }
    }
    for (shared_ptr<EpGroupToConsContractRSrc>& rel : consRel) {
        if (rel->isTargetSet()) {
            contractURIs.insert(rel->getTargetURI().get());
        }
    }
    for (shared_ptr<EpGroupToIntraContractRSrc>& rel : intraRel) {
        if (rel->isTargetSet()) {
            contractURIs.insert(rel->getTargetURI().get());
        }
    }
}

void PolicyManager::getContractRules(const URI& contractURI,
                                     /* out */ rule_list_t& rules) {
    lock_guard<mutex> guard(state_mutex);
    contract_map_t::const_iterator it = contractMap.find(contractURI);
    if (it != contractMap.end()) {
        rules.insert(rules.end(), it->second.rules.begin(),
                     it->second.rules.end());
    }
}

void PolicyManager::getSecGroupRules(const URI& secGroupURI,
                                     /* out */ rule_list_t& rules) {
    lock_guard<mutex> guard(state_mutex);
    secgrp_map_t::const_iterator it = secGrpMap.find(secGroupURI);
    if (it != secGrpMap.end()) {
        rules.insert(rules.end(), it->second.rules.begin(), it->second.rules.end());
    }
}

bool PolicyManager::contractExists(const opflex::modb::URI& cURI) {
    lock_guard<mutex> guard(state_mutex);
    return contractMap.find(cURI) != contractMap.end();
}

bool PolicyManager::secGroupExists(const opflex::modb::URI& secGroupURI) {
    lock_guard<mutex> guard(state_mutex);
    return secGrpMap.find(secGroupURI) != secGrpMap.end();
}

void PolicyManager::updateRemoteRouteChildrenForPolicyPrefix(
                 const URI& rdURI,
                 const URI& extNetURI,
                 const URI& extSubURI,
                 const std::string &pfx,
                 const uint32_t  pfxLen,
                 optional<shared_ptr<modelgbp::gbp::L3ExternalNetwork>> newNet,
                 optional<shared_ptr<modelgbp::gbp::ExternalSubnet>> newExtSub,
                 uri_set_t& notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::epdr;
    boost::system::error_code ec;
    address targetAddr =
    address::from_string(pfx, ec);
    if (ec || (rd_map.find(rdURI) == rd_map.end())) {
        return;
    }
    RoutingDomainState &rs = rd_map[rdURI];
    for(const auto& remoteRt : rs.remote_routes) {
        auto route_iter = remote_route_map.find(remoteRt);
        if(route_iter == remote_route_map.end()) {
            LOG(ERROR) << "No cached policy route for " << remoteRt;
            return;
        }
        shared_ptr<PolicyRoute> &route = route_iter->second;
        const boost::asio::ip::address& addr = route->getAddress();
        uint32_t prefixLen = route->getPrefixLen();
        if(addr.is_v4()  !=  targetAddr.is_v4()) {
            continue;
        }
        bool is_exact_match = false;
        if(network::prefix_match( targetAddr, pfxLen,
                                 addr, prefixLen, is_exact_match)) {
            optional<shared_ptr<LocalRoute>> localRoute
                = boost::make_optional<shared_ptr<LocalRoute> >(false, nullptr);
            optional<shared_ptr<LocalRouteToPrtRSrc>> lrtToPrt;
            optional<shared_ptr<LocalRouteToPsrtRSrc>> lrtToPsrt;
            localRoute = LocalRoute::resolve(framework,
                                             rdURI.toString(),
                                             addr.to_string(),
                                             prefixLen);
            lrtToPrt = localRoute.get()->resolveEpdrLocalRouteToPrtRSrc();
            lrtToPsrt = localRoute.get()->resolveEpdrLocalRouteToPsrtRSrc();
            if(lrtToPsrt && lrtToPrt) {
                if(lrtToPsrt.get()->getTargetURI().get() == extSubURI) {
                    Mutator mutator(framework, "policyelement");
                    if(newNet && newExtSub) {
                        localRoute.get()->
                            addEpdrLocalRouteToPsrtRSrc()->
                                setTargetExternalSubnet(
                                    newExtSub.get()->getURI());
                        localRoute.get()->
                            addEpdrLocalRouteToPrtRSrc()->
                                setTargetL3ExternalNetwork(
                                    newNet.get()->getURI());
                        LOG(DEBUG) << "Inheriting " <<
                            newNet.get()->getURI() << " for "
                            << rdURI << addr << "/" << prefixLen;
                    } else {
                        lrtToPrt.get()->remove();
                        lrtToPsrt.get()->remove();
                        LOG(DEBUG) << "Orphaning "
                            << rdURI << addr << "/" << prefixLen;
                    }
                    mutator.commit();
                    notifyLocalRoutes.insert(localRoute.get()->getURI());
                }
            } else {
                if(newNet && newExtSub) {
                    Mutator mutator(framework, "policyelement");
                    localRoute.get()->
                        addEpdrLocalRouteToPsrtRSrc()->
                            setTargetExternalSubnet(
                                newExtSub.get()->getURI());
                    localRoute.get()->
                        addEpdrLocalRouteToPrtRSrc()->
                            setTargetL3ExternalNetwork(
                                newNet.get()->getURI());
                    LOG(DEBUG) << "Inheriting " <<
                        newNet.get()->getURI() << " for "
                        << rdURI << addr << "/" << prefixLen;
                    mutator.commit();
                    notifyLocalRoutes.insert(localRoute.get()->getURI());
                }
            }
        }
    }
}

void PolicyManager::updateL3Nets(const opflex::modb::URI& rdURI,
                                 uri_set_t& contractsToNotify,
                                 uri_set_t& notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::epdr;
    optional<shared_ptr<LocalRouteDiscovered>> lD
            = LocalRouteDiscovered::resolve(framework);
    optional<shared_ptr<LocalRoute>> localRoute;
    optional<shared_ptr<LocalRouteToRrtRSrc>> lrtToRrt;
    optional<shared_ptr<LocalRouteToPrtRSrc>> lrtToPrt;
    RoutingDomainState& rds = rd_map[rdURI];
    optional<shared_ptr<RoutingDomain > > rd =
        RoutingDomain::resolve(framework, rdURI);
    LOG(DEBUG) << "updateL3Nets for" << rdURI;
    if (rd) {
        vector<shared_ptr<L3ExternalDomain> > extDoms;
        vector<shared_ptr<L3ExternalNetwork> > extNets;
        rd.get()->resolveGbpL3ExternalDomain(extDoms);
        for (shared_ptr<L3ExternalDomain>& extDom : extDoms) {
            extDom->resolveGbpL3ExternalNetwork(extNets);
        }

        unordered_set<URI> newNets;
        for (shared_ptr<L3ExternalNetwork> net : extNets) {
            newNets.insert(net->getURI());

            L3NetworkState& l3s = l3n_map[net->getURI()];
            l3s.extNet = net;
            if (l3s.routingDomain && l3s.natEpg) {
                auto it = nat_epg_l3_ext.find(l3s.natEpg.get());
                if (it != nat_epg_l3_ext.end()) {
                    it->second.erase(net->getURI());
                    if (it->second.empty())
                        nat_epg_l3_ext.erase(it);
                }
            }

            l3s.routingDomain = rd;

            optional<shared_ptr<L3ExternalNetworkToNatEPGroupRSrc> > natRef =
                net->resolveGbpL3ExternalNetworkToNatEPGroupRSrc();
            if (natRef) {
                optional<URI> natEpg = natRef.get()->getTargetURI();
                if (natEpg) {
                    l3s.natEpg = natEpg.get();
                    uri_set_t& s = nat_epg_l3_ext[l3s.natEpg.get()];
                    s.insert(net->getURI());
                }
            } else {
                l3s.natEpg = boost::none;
            }
            if(framework.getElementMode() ==
                    opflex::ofcore::OFConstants::TRANSPORT_MODE) {
                l3s.instContext = net->resolveGbpeInstContext();
                vector<shared_ptr<ExternalSubnet>> extSubs;
                net->resolveGbpExternalSubnet(extSubs);
                ext_subnet_map_t newExtSubs;
                for (shared_ptr<ExternalSubnet> &extsub : extSubs) {
                    if (!extsub->isAddressSet() || !extsub->isPrefixLenSet())
                        continue;
                    boost::system::error_code ec;
                    address::from_string(extsub->getAddress().get(), ec);
                    if (ec) continue;
                    newExtSubs[extsub->getURI()] = extsub;
                    if(l3s.subnet_map.find(extsub->getURI()) ==
                       l3s.subnet_map.end()) {
                        optional<shared_ptr<modelgbp::gbp::L3ExternalNetwork>>
                            oldNet;
                        optional<shared_ptr<modelgbp::gbp::ExternalSubnet>>
                            oldExtSub;
                        getBestPolicyPrefix(rd.get()->getURI(),
                                            extsub->getAddress().get(),
                                            extsub->getPrefixLen().get(),
                                            oldNet, oldExtSub);
                        Mutator mutator(framework, "policyelement");
                        //This is a new policy prefix, create a new localRoute
                        //with this info and fetch the next-hops for it
                        localRoute = lD.get()->addEpdrLocalRoute(
                                         rd.get()->getURI().toString(),
                                         extsub->getAddress().get(),
                                         extsub->getPrefixLen().get());
                        LOG(DEBUG) << "Added policy prefix " <<
                            rd.get()->getURI() << ", " <<
                            extsub->getAddress().get() << "/" <<
                            (uint32_t)extsub->getPrefixLen().get();
                        localRoute.get()->addEpdrLocalRouteToPrtRSrc()
                                            ->setTargetL3ExternalNetwork(
                                                net->getURI());
                        localRoute.get()->addEpdrLocalRouteToPsrtRSrc()
                                            ->setTargetExternalSubnet(
                                                extsub->getURI());
                        lrtToRrt = localRoute.get()->
                                       resolveEpdrLocalRouteToRrtRSrc();
                        if(!lrtToRrt) {
                            optional<URI> remoteRt;
                            getBestRemoteRoute(
                                rd.get()->getURI(),
                                extsub->getAddress().get(),
                                extsub->getPrefixLen().get(),
                                remoteRt);
                            if(remoteRt) {
                                LOG(DEBUG) << "Inheriting " <<
                                remoteRt.get() << " for ppfx " <<
                                rd.get()->getURI() <<
                                extsub->getAddress().get()<< "/" <<
                                (uint32_t)extsub->getPrefixLen().get();
                                localRoute.get()->addEpdrLocalRouteToRrtRSrc()
                                                    ->setTargetRemoteRoute(
                                                        remoteRt.get());
                            }
                        }
                        mutator.commit();
                        updateRemoteRouteChildrenForPolicyPrefix(
                            rd.get()->getURI(),
                            (oldNet? oldNet.get()->getURI():net->getURI()),
                            (oldExtSub?
                                oldExtSub.get()->getURI():extsub->getURI()),
                            extsub->getAddress().get(),
                            extsub->getPrefixLen().get(),
                            net,
                            extsub,
                            notifyLocalRoutes);
                        notifyLocalRoutes.insert(localRoute.get()->getURI());
                        l3s.subnet_map[extsub->getURI()] = extsub;
                    }
                }
                for (auto snet = l3s.subnet_map.begin();
                     snet != l3s.subnet_map.end();) {
                    optional<shared_ptr<L3ExternalNetwork>> newNet;
                    optional<shared_ptr<ExternalSubnet>> newExtSub;
                    if(newExtSubs.find(snet->first) == newExtSubs.end()) {
                        //This is a deleted policy prefix, update localRoutes
                        //being served by this policy prefix
                        opflex::modb::URI delURI = snet->second->getURI();
                        std::string delPPfx = snet->second->getAddress().get();
                        uint32_t pPfxLen = snet->second->getPrefixLen().get();
                        localRoute = LocalRoute::resolve(
                                         framework,
                                         rd.get()->getURI().toString(),
                                         delPPfx,
                                         pPfxLen);
                        notifyLocalRoutes.insert(localRoute.get()->getURI());
                        auto lrtToPrt = localRoute.get()->
                                            resolveEpdrLocalRouteToPrtRSrc();
                        auto lrtToPsrt = localRoute.get()->
                                            resolveEpdrLocalRouteToPsrtRSrc();
                        Mutator mutator(framework, "policyelement");
                        lrtToPrt.get()->remove();
                        lrtToPsrt.get()->remove();
                        mutator.commit();
                        if(isLocalRouteDeletable(localRoute.get())) {
                            localRoute.get()->remove();
                            mutator.commit();
                        }
                        snet = l3s.subnet_map.erase(snet);
                        getBestPolicyPrefix(
                            rd.get()->getURI(),
                            delPPfx,
                            pPfxLen,
                            newNet,
                            newExtSub);
                        updateRemoteRouteChildrenForPolicyPrefix(
                            rd.get()->getURI(),
                            net->getURI(),
                            delURI,
                            delPPfx,
                            pPfxLen,
                            std::move(newNet),
                            std::move(newExtSub),
                            notifyLocalRoutes);
                        continue;
                    }
                    snet++;
                }
            }
            updateGroupContracts(L3ExternalNetwork::CLASS_ID,
                                 net->getURI(), contractsToNotify);
        }

        for (const URI& net : rds.extNets) {
            if (newNets.find(net) == newNets.end()) {
                l3n_map_t::const_iterator lit = l3n_map.find(net);
                if (lit != l3n_map.end()) {
                    if (lit->second.natEpg) {
                        auto git = nat_epg_l3_ext.find(lit->second.natEpg.get());
                        if (git != nat_epg_l3_ext.end()) {
                            git->second.erase(net);
                            if (git->second.empty())
                                nat_epg_l3_ext.erase(git);
                        }
                    }
                }
                if(framework.getElementMode() !=
                    opflex::ofcore::OFConstants::TRANSPORT_MODE) {
                    l3n_map.erase(lit);
                }
                updateGroupContracts(L3ExternalNetwork::CLASS_ID,
                                     net, contractsToNotify);
            }
        }
        rds.extNets = std::move(newNets);
    } else {
        for (const URI& net : rds.extNets) {
            l3n_map.erase(net);
            updateGroupContracts(L3ExternalNetwork::CLASS_ID,
                                 net, contractsToNotify);
        }
        rd_map.erase(rdURI);
    }
}

bool PolicyManager::isLocalRouteDeletable(
         shared_ptr<modelgbp::epdr::LocalRoute> &localRoute)
{
    using namespace modelgbp::epdr;
    using namespace modelgbp::gbp;
    auto lrtToPrt = localRoute->
                        resolveEpdrLocalRouteToPrtRSrc();
    auto lrtToRrt = localRoute->
                        resolveEpdrLocalRouteToRrtRSrc();
    vector<shared_ptr<LocalRouteToSrtRSrc>> lrtToSrt;
    localRoute->resolveEpdrLocalRouteToSrtRSrc(lrtToSrt);
    if(!lrtToRrt && !lrtToPrt && (lrtToSrt.empty())) {
        return true;
    }
    if(!lrtToSrt.empty()) {
        return false;
    }
    if(lrtToRrt) {
        optional<shared_ptr<RemoteRoute>> rRt =
            RemoteRoute::resolve(framework,
                lrtToRrt.get()->getTargetURI().get());
        /* One of the owners is RemoteRoute which is still present*/
        if((rRt.get()->getAddress().get() == localRoute->getAddress().get())
           && (rRt.get()->getPrefixLen().get() ==
                   localRoute->getPrefixLen().get())) {
            return false;
        }
    }
    if(lrtToPrt) {
        auto lrtToPsrt = localRoute->
                             resolveEpdrLocalRouteToPsrtRSrc();
        /* Owner is PolicyPrefix which is still present*/
        if(lrtToPsrt) {
            optional<shared_ptr<ExternalSubnet>> extSub =
                ExternalSubnet::resolve(framework,
                    lrtToPsrt.get()->getTargetURI().get());
            if((extSub.get()->getAddress().get() ==
                    localRoute->getAddress().get())
               && (extSub.get()->getPrefixLen().get() ==
                       localRoute->getPrefixLen().get())) {
                return false;
            }
        }
    }
    return true;
}

void PolicyManager::getBestRemoteRoute(
        const opflex::modb::URI& rdURI,
        const std::string &pfx,
        const uint32_t pfxLen,
        optional<opflex::modb::URI> &newRemoteRt) {
    using namespace modelgbp::gbp;
    boost::system::error_code ec;
    address targetAddr =
    address::from_string(pfx, ec);
    if (ec || (rd_map.find(rdURI) == rd_map.end())) {
        return;
    }
    uint32_t bestLen=0;
    RoutingDomainState &rs = rd_map[rdURI];
    for(auto& remoteRt : rs.remote_routes) {
        auto route_iter = remote_route_map.find(remoteRt);
        if(route_iter == remote_route_map.end()) {
            LOG(ERROR) << "No cached policy route for " << remoteRt;
            return;
        }
        shared_ptr<PolicyRoute> &route = route_iter->second;
        const boost::asio::ip::address& addr = route->getAddress();
        uint32_t prefixLen = route->getPrefixLen();
        if(addr.is_v4()  !=  targetAddr.is_v4()) {
            continue;
        }
        bool is_exact_match = false;
        if(network::prefix_match(addr, prefixLen, targetAddr,
                                 pfxLen, is_exact_match) &&
           (prefixLen >= bestLen)) {
            newRemoteRt = remoteRt;
            bestLen = prefixLen;
            if(is_exact_match) {
                return;
            }
        }
    }
}

void PolicyManager::getBestPolicyPrefix(
                        const opflex::modb::URI& rdURI,
                        const std::string &pfx,
                        const uint32_t pfxLen,
                        optional<shared_ptr<
                            modelgbp::gbp::L3ExternalNetwork>> &newNet,
                        optional<shared_ptr<
                            modelgbp::gbp::ExternalSubnet>> &newExtSub) {
    using namespace modelgbp::gbp;
    boost::system::error_code ec;
    address targetAddr =
    address::from_string(pfx, ec);
    if (ec || (rd_map.find(rdURI) == rd_map.end())) {
        return;
    }
    uint32_t bestLen = 0;
    RoutingDomainState &rs = rd_map[rdURI];
    for (const auto& extNet : rs.extNets) {
        L3NetworkState &l3s = l3n_map[extNet];
        for (auto &extSubItr: l3s.subnet_map) {
            shared_ptr<modelgbp::gbp::ExternalSubnet> &extsub =
            extSubItr.second;
            if (!extsub->isAddressSet() || !extsub->isPrefixLenSet())
                continue;
            address addr =
            address::from_string(extsub->getAddress().get(), ec);
            if (ec) continue;
            uint32_t prefixLen = extsub->getPrefixLen().get();
            if(addr.is_v4()  !=  targetAddr.is_v4()) {
                continue;
            }
            bool is_exact_match = false;
            if(network::prefix_match(addr, prefixLen, targetAddr,
                                     pfxLen, is_exact_match) &&
               (prefixLen >= bestLen)) {
                newNet = l3s.extNet;
                newExtSub = extsub;
                bestLen = prefixLen;
                if(is_exact_match) {
                    return;
                }
            }
        }
    }
}

uint8_t PolicyManager::getEffectiveRoutingMode(const URI& egURI) {
    using namespace modelgbp::gbp;

    optional<shared_ptr<BridgeDomain> > bd = getBDForGroup(egURI);

    uint8_t routingMode = RoutingModeEnumT::CONST_ENABLED;
    if (bd)
        routingMode = bd.get()->getRoutingMode(routingMode);

    return routingMode;
}

boost::optional<address>
PolicyManager::getRouterIpForSubnet(modelgbp::gbp::Subnet& subnet) {
    optional<const string&> routerIpStr = subnet.getVirtualRouterIp();
    if (routerIpStr) {
        boost::system::error_code ec;
        address routerIp = address::from_string(routerIpStr.get(), ec);
        if (ec) {
            LOG(WARNING) << "Invalid router IP for subnet "
                         << subnet.getURI() << ": "
                         << routerIpStr.get() << ": " << ec.message();
        } else {
            return routerIp;
        }
    }
    return boost::none;
}

bool PolicyManager::updateExternalInterface(const URI& uri, bool &toRemove) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::gbpe;
    bool updated = false;

    optional<URI> extDomURI, extBDURI, extRDURI, pfxURI;
    optional<shared_ptr<RoutingDomain>> newRD =
        boost::make_optional<shared_ptr<RoutingDomain>>(false, nullptr);
    optional<shared_ptr<L3ExternalDomain>> newExtDom =
        boost::make_optional<shared_ptr<L3ExternalDomain>>(false, nullptr);
    optional<shared_ptr<ExternalL3BridgeDomain>> newExtBD =
        boost::make_optional<shared_ptr<ExternalL3BridgeDomain>>(false, nullptr);
    optional<shared_ptr<InstContext>> newRDContext, newBDContext;
    subnet_map_t newsmap;
    ExternalInterfaceState  &eis = ext_int_map[uri];

    optional<shared_ptr<ExternalInterface>> extIntf =
    ExternalInterface::resolve(framework, uri);
    if(!extIntf) {
        toRemove = true;
        return true;
    }
    toRemove = false;
    optional<shared_ptr<ExternalInterfaceToL3outRSrc> > refL3Out =
    extIntf.get()->resolveGbpExternalInterfaceToL3outRSrc();
    if (refL3Out) {
        extDomURI = refL3Out.get()->getTargetURI();
    }
    if(extDomURI) {
        newExtDom = L3ExternalDomain::resolve(framework, extDomURI.get());
    }
    optional<shared_ptr<ExternalInterfaceToExtl3bdRSrc> > refL3BD =
    extIntf.get()->resolveGbpExternalInterfaceToExtl3bdRSrc();
    if (refL3BD && refL3BD.get()->isTargetSet()) {
        extBDURI = refL3BD.get()->getTargetURI();
    }
    if(extBDURI) {
        newExtBD = ExternalL3BridgeDomain::resolve(framework, extBDURI.get());
        if(newExtBD) {
            newBDContext =
            newExtBD.get()->resolveGbpeInstContext();
            optional<shared_ptr<ExternalL3BridgeDomainToVrfRSrc>> refRD =
            newExtBD.get()->resolveGbpExternalL3BridgeDomainToVrfRSrc();
            if(refRD && refRD.get()->isTargetSet()) {
                extRDURI = refRD.get()->getTargetURI();
            }
        }
    }
    if(extRDURI) {
        newRD = RoutingDomain::resolve(framework, extRDURI.get());
        if(newRD) {
            newRDContext =
            newRD.get()->resolveGbpeInstContext();
        }
    }
    optional<shared_ptr<ExternalInterfaceToLocalPfxRSrc> > refPfx =
    extIntf.get()->resolveGbpExternalInterfaceToLocalPfxRSrc();
    if (refPfx && refPfx.get()->isTargetSet()) {
        pfxURI = refPfx.get()->getTargetURI();
        optional<shared_ptr<Subnets> > sns =
        Subnets::resolve(framework, pfxURI.get());
        if (sns) {
            vector<shared_ptr<Subnet> > csns;
            sns.get()->resolveGbpSubnet(csns);
            for (shared_ptr<Subnet>& csn : csns)
                newsmap[csn->getURI()] = csn;
        }
    }
    if(newExtDom != eis.extDomain ||
       newRD != eis.routingDomain ||
       newExtBD != eis.bridgeDomain ||
       newRDContext != eis.instRDContext ||
       newBDContext != eis.instContext ||
       newsmap != eis.subnet_map) {
        updated = true;
    }
    eis.extDomain = std::move(newExtDom);
    eis.routingDomain = std::move(newRD);
    eis.bridgeDomain = std::move(newExtBD);
    eis.instContext = std::move(newBDContext);
    eis.instRDContext = std::move(newRDContext);
    eis.subnet_map = std::move(newsmap);
    return updated;
}

void PolicyManager::updateDomain(class_id_t class_id, const URI& uri) {
    using namespace modelgbp::gbp;
    unique_lock<mutex> guard(state_mutex);
    uri_set_t notifyGroups;
    uri_set_t notifyRds;
    uri_set_t notifyExtIntfs;

    LOG(DEBUG) << "Updating cid:" << class_id << " uri:" << uri;
    if (class_id == modelgbp::gbp::EpGroup::CLASS_ID) {
        group_map[uri];
    }
    if (class_id == modelgbp::gbp::ExternalInterface::CLASS_ID) {
        ext_int_map[uri];
    }
    for (auto itr = group_map.begin(); itr != group_map.end(); ) {
        bool toRemove = false;
        if (updateEPGDomains(itr->first, toRemove)) {
            notifyGroups.insert(itr->first);
        }
        itr = (toRemove ? group_map.erase(itr) : ++itr);
    }
    // Determine routing-domains that may be affected by changes to NAT EPG
    for (const URI& u : notifyGroups) {
        uri_ref_map_t::const_iterator it = nat_epg_l3_ext.find(u);
        if (it != nat_epg_l3_ext.end()) {
            for (const URI& extNet : it->second) {
                l3n_map_t::const_iterator it2 = l3n_map.find(extNet);
                if (it2 != l3n_map.end()) {
                    notifyRds.insert(it2->second.routingDomain.get()->getURI());
                }
            }
        }
    }
    for (auto itr = ext_int_map.begin();
         itr != ext_int_map.end(); ) {
        bool toRemove = false;
        if (updateExternalInterface(itr->first, toRemove)) {
            notifyExtIntfs.insert(itr->first);
        }
        itr = (toRemove ? ext_int_map.erase(itr) : ++itr);
    }
    notifyRds.erase(uri);   // Avoid updating twice

    // Determine routing-domains that may be affected by changes to Subnet
    if (class_id == modelgbp::gbp::Subnets::CLASS_ID) {

        {
            lock_guard<mutex> rdGuard(subnets_rd_mutex);
            // Update routing domains that depend on this Subnets
            auto it1 = subnets_rd_map.find(uri);
            if (it1 != subnets_rd_map.end()) {
                uri_set_t &rdset = it1->second;

                for (const auto &it2: rdset) {
                    if (notifyRds.find(it2) != notifyRds.end())
                        continue;
                    notifyRds.insert(it2);
                }
            }
        }

        // Delete the Subnets from subnets_rd map
        optional<shared_ptr<Subnets> > subnets_obj =
            Subnets::resolve(framework, uri);
        if (!subnets_obj)
            deleteSubnets(uri);
    }

    guard.unlock();

    for (const URI& u : notifyGroups) {
        notifyEPGDomain(u);
    }
    for (const URI& u : notifyExtIntfs) {
        notifyExternalInterface(u);
    }
    if ((class_id != modelgbp::gbp::EpGroup::CLASS_ID) &&
        (class_id != modelgbp::gbp::ExternalInterface::CLASS_ID)) {
        notifyDomain(class_id, uri);
    }
    for (const URI& rd : notifyRds) {
        notifyDomain(RoutingDomain::CLASS_ID, rd);
    }
}

bool operator==(const PolicyRoute& lhs, const PolicyRoute& rhs)
{
    return ((lhs.rd->getURI() == rhs.rd->getURI()) &&
            (lhs.address == rhs.address) &&
            (lhs.prefix_len == rhs.prefix_len) &&
            (lhs.nextHops == rhs.nextHops));
}

bool operator!=(const PolicyRoute& lhs, const PolicyRoute& rhs)
{
    return !operator==(lhs, rhs);
}

PolicyRoute& PolicyRoute::operator=(const PolicyRoute& pRoute)
{
    this->rd = pRoute.rd;
    this->rdInst = pRoute.rdInst;
    this->address = pRoute.address;
    this->prefix_len = pRoute.prefix_len;
    this->nextHops = pRoute.nextHops;
    this->nd = pRoute.nd;
    return *this;
}

bool PolicyManager::getRoute(
         class_id_t route_type, const URI &uri,
         const boost::asio::ip::address &self_tep,
         shared_ptr<modelgbp::gbp::RoutingDomain> &rd_,
         shared_ptr<modelgbp::gbpe::InstContext> &rdInst_,
         boost::asio::ip::address &addr_, uint8_t &pfx_len,
         list<boost::asio::ip::address> &nhList,
         bool &are_nhs_remote,
         optional<uint32_t> &sclass)
{
    using namespace modelgbp::epdr;
    are_nhs_remote = true;
    lock_guard<mutex> guard(state_mutex);
    if(route_type == modelgbp::gbp::StaticRoute::CLASS_ID) {
        route_map_t::const_iterator iter = static_route_map.find(uri);
        if(iter == static_route_map.end()){
            return false;
        }
        iter->second->getRoute(rd_, rdInst_, addr_, pfx_len, nhList);
        return true;
    } else if(route_type == modelgbp::gbp::RemoteRoute::CLASS_ID) {
        route_map_t::const_iterator iter = remote_route_map.find(uri);
        if(iter == remote_route_map.end()){
            return false;
        }
        iter->second->getRoute(rd_, rdInst_, addr_, pfx_len, nhList);
        return true;
    } else if(route_type == modelgbp::epdr::LocalRoute::CLASS_ID) {
        auto localRoute = LocalRoute::resolve(framework,
                                              uri);
        if(!localRoute)
            return false;
        auto lrtToRrt = localRoute.get()->resolveEpdrLocalRouteToRrtRSrc();
        auto lrtToPrt = localRoute.get()->resolveEpdrLocalRouteToPrtRSrc();
        if(lrtToPrt) {
            const auto& extNetURI = lrtToPrt.get()->getTargetURI().get();
            l3n_map_t::const_iterator it = l3n_map.find(extNetURI);
            if(it != l3n_map.end() && it->second.instContext) {
                sclass = it->second.instContext.get()->getClassid();
            }
        }
        if(lrtToRrt) {
            const auto& remoteRtURI = lrtToRrt.get()->getTargetURI().get();
            route_map_t::const_iterator iter = remote_route_map.find(remoteRtURI);
            if(iter == remote_route_map.end()){
                return true;
            }
            iter->second->getRoute(rd_, rdInst_, addr_, pfx_len, nhList);
            for(auto const& nh : nhList) {
                if(nh == self_tep) {
                    are_nhs_remote = false;
                    break;
                }
            }
        }
        if(!are_nhs_remote) {
            localRoute = LocalRoute::resolve(framework,
                                             rd_->getURI().toString(),
                                             addr_.to_string(),
                                             pfx_len);
            vector<shared_ptr<LocalRouteToSrtRSrc>> lrtToSrt;
            if(localRoute)
                localRoute.get()->resolveEpdrLocalRouteToSrtRSrc(lrtToSrt);
            nhList.clear();
            list<boost::asio::ip::address> newNhList;
            for(auto const &stRoute: lrtToSrt) {
                const auto& stRouteURI = stRoute->getTargetURI().get();
                route_map_t::const_iterator iter = static_route_map.find(stRouteURI);
                if(iter == static_route_map.end()){
                    continue;
                }
                iter->second->getRoute(rd_, rdInst_, addr_, pfx_len, nhList);
                newNhList.merge(nhList);
            }
            nhList = std::move(newNhList);
        }
        return true;
    }
    return false;
}

void PolicyManager::updateExternalNode(const URI& uri,
                                       uri_set_t &notifyStaticRoutes,
                                       uri_set_t &notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::gbpe;
    using namespace modelgbp::epr;
    using namespace modelgbp::epdr;

    auto rd = boost::make_optional<shared_ptr<RoutingDomain> >(false, nullptr);
    auto rdInst = boost::make_optional<shared_ptr<InstContext> >(false, nullptr);
    ExternalNodeState &ens = ext_node_map[uri];
    vector<shared_ptr<StaticRoute>> staticRoutes;
    optional<shared_ptr<ExternalNode>> extNode =
        ExternalNode::resolve(framework, uri);
    if(!extNode) {
        return;
    }
    extNode.get()->resolveGbpStaticRoute(staticRoutes);
    for(shared_ptr<StaticRoute>& route: staticRoutes) {
        route_map_t::iterator routeIter;
        optional<shared_ptr<StaticRouteToVrfRSrc>> vrfRef =
        route->resolveGbpStaticRouteToVrfRSrc();
        if(vrfRef && vrfRef.get()->getTargetURI()) {
            rd = RoutingDomain::resolve(framework,
                                        vrfRef.get()->getTargetURI().get());
            if(rd)
                rdInst = rd.get()->resolveGbpeInstContext();
        }
        if(!rd || !route->getAddress() || !route->getPrefixLen()
           || !rdInst) {
            continue;
        }
        boost::system::error_code ec;
        boost::asio::ip::address addr =
        address::from_string(route->getAddress().get(), ec);
        if(ec) {
            continue;
        }
        vector<shared_ptr<StaticNextHop>> nhs;
        route->resolveGbpStaticNextHop(nhs);
        std::list<boost::asio::ip::address> lnhs;
        boost::asio::ip::address addr2;
        for(const auto &nh: nhs) {
            if(nh->getIp()) {
                addr2 = address::from_string(nh->getIp().get(), ec);
                if(!ec) {
                    lnhs.push_back(addr2);
                }
            }
        }
        lnhs.sort();
        shared_ptr<PolicyRoute> newRoute = make_shared<PolicyRoute>(
                                               rd.get(), rdInst.get(), addr,
                                               route->getPrefixLen().get(),
                                               lnhs, extNode.get());
        optional<shared_ptr<LocalRouteDiscovered>> lD;
        shared_ptr<LocalRoute> localRoute;
        Mutator mutator(framework, "policyelement");
        lD = LocalRouteDiscovered::resolve(framework);
        localRoute = lD.get()->addEpdrLocalRoute(
                         rd.get()->getURI().toString(),
                         route->getAddress().get(),
                         route->getPrefixLen().get());
        mutator.commit();
        auto rIter = ens.static_routes.find(route->getURI());
        if(rIter == ens.static_routes.end()) {
            ens.static_routes.insert(route->getURI());
            notifyStaticRoutes.insert(route->getURI());
            auto it = static_route_map.insert(std::make_pair(route->getURI(),
                                                             newRoute));
            it.first->second->setPresent(true);
            optional<shared_ptr<PeerRouteUniverse>> pU
                        = PeerRouteUniverse::resolve(framework);
            shared_ptr<ReportedRoute> repRoute;

            // Report this new route
            // In case of static and dynamic routes with the same prefix
            // report the lower cost, static route always overwrites the cost
            Mutator mutator(framework, "policyelement");

            localRoute->addEpdrLocalRouteToSrtRSrc(route->getURI().toString());
            repRoute = pU.get()->addEprReportedRoute(
                           rd.get()->getURI().toString(),
                           route->getAddress().get(),
                           route->getPrefixLen().get());
            repRoute->setCost(POLICYMANAGER_STATIC_ROUTE_COST);
            mutator.commit();
            notifyLocalRoutes.insert(localRoute->getURI());
            continue;
        }
        routeIter = static_route_map.find(route->getURI());
        if(routeIter == static_route_map.end()) {
            continue;
        }
        routeIter->second->setPresent(true);
        if(*(routeIter->second) != *newRoute) {
            routeIter->second = std::move(newRoute);
            routeIter->second->setPresent(true);
            notifyStaticRoutes.insert(route->getURI());
            notifyLocalRoutes.insert(localRoute->getURI());
        }
    }
    //Deleted static routes
    auto itr = ens.static_routes.begin();
    while(itr != ens.static_routes.end()) {
        route_map_t::iterator routeIter;
        routeIter = static_route_map.find(*itr);
        if(routeIter != static_route_map.end() &&
           !routeIter->second->isPresent()) {
            optional<shared_ptr<LocalRouteToSrtRSrc>> srtRef;
            optional<shared_ptr<ReportedRoute>> delRepRoute;
            optional<shared_ptr<LocalRoute>> delLocalRoute;
            shared_ptr<modelgbp::gbp::RoutingDomain> delRd;
            shared_ptr<modelgbp::gbpe::InstContext> delRdInst;
            boost::asio::ip::address addr;
            uint8_t pfxLen;
            std::list<boost::asio::ip::address> nhList;
            routeIter->second->getRoute(delRd,delRdInst, addr, pfxLen, nhList);
            Mutator mutator(framework, "policyelement");
            delLocalRoute = LocalRoute::resolve(framework,
                                                delRd->getURI().toString(),
                                                addr.to_string(),
                                                pfxLen);
            notifyLocalRoutes.insert(delLocalRoute.get()->getURI());
            delRepRoute = ReportedRoute::resolve(framework,
                                                 delRd->getURI().toString(),
                                                 addr.to_string(),
                                                 pfxLen);
            srtRef = delLocalRoute.get()->
            resolveEpdrLocalRouteToSrtRSrc(
                                           routeIter->first.toString());
            srtRef.get()->remove();

            mutator.commit();
            vector<shared_ptr<LocalRouteToSrtRSrc>> ecmpStaticRoutes;
            if(delLocalRoute) {
                delLocalRoute.get()->
                resolveEpdrLocalRouteToSrtRSrc(ecmpStaticRoutes);
                if(ecmpStaticRoutes.empty()) {
                    if(isLocalRouteDeletable(delLocalRoute.get())) {
                        delLocalRoute.get()->remove();
                    }
                    if(delRepRoute) {
                        delRepRoute.get()->remove();
                    }
                }
            }
            mutator.commit();
            notifyStaticRoutes.insert(*itr);
            itr = ens.static_routes.erase(itr);
            static_route_map.erase(routeIter);
            continue;
        }
        if(routeIter != static_route_map.end()) {
            routeIter->second->setPresent(false);
        }
        itr++;
    }
}

void PolicyManager::updateStaticRoutes(class_id_t class_id,
                                       const URI& uri,
                                       uri_set_t &notifyStaticRoutes,
                                       uri_set_t &notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::gbpe;
    using namespace modelgbp::epr;
    using namespace modelgbp::epdr;

    LOG(DEBUG) << "updateStaticRoutes for URI " << uri;
    if(class_id == ExternalNode::CLASS_ID) {
        optional<shared_ptr<ExternalNode>> extNode =
            ExternalNode::resolve(framework, uri);
        if(!extNode){
            auto extIter = ext_node_map.find(uri);
            if(extIter != ext_node_map.end()) {
                //Remove all static routes under external node
                for(const auto &iter: extIter->second.static_routes) {
                    notifyStaticRoutes.insert(iter);
                }
                ext_node_map.erase(extIter);
            }
            return;
        }
        updateExternalNode(uri,
                           notifyStaticRoutes,
                           notifyLocalRoutes);
    } else if(class_id == RoutingDomain::CLASS_ID) {
        for(const auto &extn: ext_node_map) {
            updateExternalNode(extn.first,
                               notifyStaticRoutes,
                               notifyLocalRoutes);
        }
    }
}

void PolicyManager::updateStaticRoute(class_id_t class_id, const URI& uri,
                                      uri_set_t &notifyStaticRoutes,
                                      uri_set_t &notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    if(class_id == StaticRoute::CLASS_ID) {
        route_map_t::const_iterator iter = static_route_map.find(uri);
        if(iter == static_route_map.end())
            return;
        boost::optional<opflex::modb::URI> extNodeURI;
        iter->second->getExtNodeURI(extNodeURI);
        if(extNodeURI)
            updateStaticRoutes(ExternalNode::CLASS_ID,
                               extNodeURI.get(),
                               notifyStaticRoutes,
                               notifyLocalRoutes);
    }
    if(class_id == StaticNextHop::CLASS_ID) {
        ext_node_map_t::iterator itr;
        for(itr = ext_node_map.begin(); itr != ext_node_map.end(); ++itr) {
            updateStaticRoutes(ExternalNode::CLASS_ID,
                               itr->first,
                               notifyStaticRoutes,
                               notifyLocalRoutes);
        }
    }
}

void PolicyManager::updatePolicyPrefixChildrenForRemoteRoute(
         const URI& rdURI,
         const optional<URI> &routeURI,
         const std::string &pfx,
         const uint32_t  pfxLen,
         const optional<URI> &parentRemoteRt,
         uri_set_t &notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::epdr;
    boost::system::error_code ec;
    address targetAddr =
    address::from_string(pfx, ec);
    if (ec || (rd_map.find(rdURI) == rd_map.end())) {
        return;
    }
    RoutingDomainState &rs = rd_map[rdURI];
    for (const auto& extNet : rs.extNets) {
        L3NetworkState &l3s = l3n_map[extNet];
        for (auto &extSubItr: l3s.subnet_map) {
            shared_ptr<modelgbp::gbp::ExternalSubnet> &extsub =
                extSubItr.second;
            if (!extsub->isAddressSet() || !extsub->isPrefixLenSet())
                continue;
            address addr =
            address::from_string(extsub->getAddress().get(), ec);
            if (ec) continue;
            uint32_t prefixLen = extsub->getPrefixLen().get();
            bool is_exact_match = false;
            if(network::prefix_match(targetAddr, pfxLen, addr,
                                     prefixLen, is_exact_match)) {
                optional<shared_ptr<LocalRoute>> localRoute =
                    LocalRoute::resolve(framework,
                                        rdURI.toString(),
                                        addr.to_string(),
                                        prefixLen);
                optional<shared_ptr<LocalRouteToRrtRSrc>> lrtToRrt =
                    localRoute.get()->resolveEpdrLocalRouteToRrtRSrc();
                optional<shared_ptr<LocalRouteToPrtRSrc>> lrtToPrt =
                    localRoute.get()->resolveEpdrLocalRouteToPrtRSrc();
                if(routeURI == parentRemoteRt) {
                    notifyLocalRoutes.insert(localRoute.get()->getURI());
                    continue;
                }
                if(lrtToRrt) {
                    if(lrtToRrt.get()->getTargetURI() == routeURI) {
                        Mutator mutator(framework, "policyelement");
                        if(parentRemoteRt) {
                            localRoute.get()->
                                addEpdrLocalRouteToRrtRSrc()
                                    ->setTargetRemoteRoute(
                                        parentRemoteRt.get());
                            LOG(DEBUG) << "Inheriting " <<
                                parentRemoteRt.get() << " for ppfx " <<
                                rdURI << addr << "/" << prefixLen;
                        }
                        else {
                            lrtToRrt.get()->remove();
                            LOG(DEBUG) << "Orphaning " << " for ppfx "
                                << rdURI << addr << "/" << prefixLen;
                        }
                        mutator.commit();
                        notifyLocalRoutes.insert(localRoute.get()->getURI());
                    }
                } else {
                    if(parentRemoteRt) {
                        Mutator mutator(framework, "policyelement");
                        localRoute.get()->
                            addEpdrLocalRouteToRrtRSrc()
                                ->setTargetRemoteRoute(
                                    parentRemoteRt.get());
                        LOG(DEBUG) << "Inheriting " <<
                             parentRemoteRt.get() << " for ppfx " <<
                             rdURI << addr << "/" << prefixLen;
                        mutator.commit();
                        notifyLocalRoutes.insert(localRoute.get()->getURI());
                        localRoute = LocalRoute::resolve(framework,
                                                         rdURI.toString(),
                                                         addr.to_string(),
                                                         prefixLen);
                        lrtToPrt = localRoute.get()->
                                       resolveEpdrLocalRouteToPrtRSrc();
                        LOG(DEBUG) << "ExtNet URI:" <<
                        lrtToPrt.get()->getTargetURI().get();
                    }
                }
            }
        }
    }
}

void PolicyManager::updateRemoteRoutes(const URI& uri,
                                       uri_set_t &notifyRemoteRoutes,
                                       uri_set_t &notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    using namespace modelgbp::epdr;
    LOG(DEBUG) << "updateRemoteRoutes for URI " << uri;
    optional<shared_ptr<RoutingDomain>> rd;
    vector<shared_ptr<RemoteRoute>> remoteRoutes;
    optional<shared_ptr<modelgbp::gbpe::InstContext>> rdInst;
    rd = RoutingDomain::resolve(framework,uri);
    if(!rd){
        auto rdIter = rd_map.find(uri);
        if(rdIter != rd_map.end()) {

            for(const auto &iter: rdIter->second.remote_routes) {
                notifyRemoteRoutes.insert(iter);
            }
            //RoutingDomain deletion will happen in domain context
            rdIter->second.remote_routes.clear();
        }
        return;
    }

    rdInst = rd.get()->resolveGbpeInstContext();
    //We will get called again when Routing Domain has forwarding data
    if(!rdInst){
        return;
    }
    RoutingDomainState &rs = rd_map[uri];
    rd.get()->resolveGbpRemoteRoute(remoteRoutes);
    for(shared_ptr<RemoteRoute>& route: remoteRoutes) {
        if(!route->getAddress() || !route->getPrefixLen()) {
            continue;
        }
        route_map_t::iterator routeIter;
        boost::system::error_code ec;
        boost::asio::ip::address addr;
        addr = address::from_string(route->getAddress().get(), ec);
        if(ec) {
            continue;
        }
        optional<URI> newRemoteRt = route->getURI();
        vector<shared_ptr<RemoteNextHop>> nhs;
        route->resolveGbpRemoteNextHop(nhs);
        list<boost::asio::ip::address> lnhs;
        boost::asio::ip::address addr2;
        for(const auto &nh: nhs) {
            if(nh->getIp()) {
                addr2 = address::from_string(nh->getIp().get(), ec);
                if(!ec) {
                    lnhs.push_back(addr2);
                }
            }
        }
        lnhs.sort();
        shared_ptr<PolicyRoute> newRoute = make_shared<PolicyRoute>(
                                               rd.get(), rdInst.get(), addr,
                                               route->getPrefixLen().get(),
                                               lnhs);

        auto it = rs.remote_routes.find(route->getURI());
        optional<shared_ptr<LocalRouteDiscovered>> lD;
        shared_ptr<LocalRoute> localRoute;
        optional<shared_ptr<L3ExternalNetwork>> extNet;
        optional<shared_ptr<ExternalSubnet>> extSub;
        if(it == rs.remote_routes.end()) {
            //New remote route
            optional<URI> parentRemoteRt;
            getBestRemoteRoute(rd.get()->getURI(),
                               route->getAddress().get(),
                               route->getPrefixLen().get(),
                               parentRemoteRt);
            Mutator mutator(framework, "policyelement");
            lD = LocalRouteDiscovered::resolve(framework);
            localRoute = lD.get()->addEpdrLocalRoute(
                             rd.get()->getURI().toString(),
                             route->getAddress().get(),
                             route->getPrefixLen().get());
            LOG(DEBUG) << "Added remote route " <<
                rd.get()->getURI() << ", " <<
                route->getAddress().get() << "/" <<
                (uint32_t)route->getPrefixLen().get();
            optional<shared_ptr<LocalRouteToPrtRSrc>> lrtToPrt;
            lrtToPrt = localRoute->resolveEpdrLocalRouteToPrtRSrc();
            if(!lrtToPrt) {
                //There is no exact/inherited match for a policy prefix, so do
                //an LPM search
                getBestPolicyPrefix(
                    rd.get()->getURI(),
                    route->getAddress().get(),
                    route->getPrefixLen().get(),
                    extNet, extSub);
                //Update Policy parent
                if(extNet && extSub) {
                    localRoute->addEpdrLocalRouteToPrtRSrc()
                                  ->setTargetL3ExternalNetwork(
                                      extNet.get()->getURI());
                    localRoute->addEpdrLocalRouteToPsrtRSrc()
                                  ->setTargetExternalSubnet(
                                      extSub.get()->getURI());
                    LOG(DEBUG) << "Inheriting " <<
                    extNet.get()->getURI() << " for " <<
                    route->getAddress().get() << "/" <<
                    (uint32_t)route->getPrefixLen().get();
                }
            }
            localRoute->addEpdrLocalRouteToRrtRSrc()
                          ->setTargetRemoteRoute(route->getURI());
            mutator.commit();
            updatePolicyPrefixChildrenForRemoteRoute(
                rd.get()->getURI(),
                parentRemoteRt,
                route->getAddress().get(),
                route->getPrefixLen().get(),
                newRemoteRt,
                notifyLocalRoutes);
            rs.remote_routes.insert(route->getURI());
            auto rIter = remote_route_map.insert(
                             std::make_pair(route->getURI(),newRoute));
            rIter.first->second->setPresent(true);
            notifyRemoteRoutes.insert(route->getURI());
            notifyLocalRoutes.insert(localRoute->getURI());
            continue;
        }
        routeIter = remote_route_map.find(route->getURI());
        if(routeIter == remote_route_map.end()) {
            continue;
        }
        routeIter->second->setPresent(true);
        if(*(routeIter->second) != *newRoute) {
            //Updated remote route
            routeIter->second = std::move(newRoute);
            routeIter->second->setPresent(true);
            notifyRemoteRoutes.insert(route->getURI());
            updatePolicyPrefixChildrenForRemoteRoute(rd.get()->getURI(),
                                               newRemoteRt,
                                               route->getAddress().get(),
                                               route->getPrefixLen().get(),
                                               newRemoteRt,
                                               notifyLocalRoutes);
            optional<shared_ptr<LocalRoute>> lRt =
                LocalRoute::resolve(framework,
                                    rd.get()->getURI().toString(),
                                    route->getAddress().get(),
                                    route->getPrefixLen().get());
            notifyLocalRoutes.insert(lRt.get()->getURI());
        }
    }
    //Deleted remote routes
    auto itr = rs.remote_routes.begin();
    while(itr != rs.remote_routes.end()) {
        route_map_t::iterator routeIter;
        routeIter = remote_route_map.find(*itr);
        optional<URI> parentRemoteRt;
        optional<shared_ptr<LocalRoute>> delLocalRoute;
        if((routeIter != remote_route_map.end()) &&
           !routeIter->second->isPresent()) {
            notifyRemoteRoutes.insert(*itr);
            optional<URI> rtURI = *itr;
            std::string delRemoteRt =
                routeIter->second->getAddress().to_string();
            uint32_t prefixLen = routeIter->second->getPrefixLen();
            remote_route_map.erase(routeIter);
            itr = rs.remote_routes.erase(itr);
            Mutator mutator(framework, "policyelement");
            delLocalRoute = LocalRoute::resolve(
                                framework,
                                rd.get()->getURI().toString(),
                                delRemoteRt,
                                prefixLen);
            notifyLocalRoutes.insert(delLocalRoute.get()->getURI());
            auto lrtToRrt = delLocalRoute.get()->
                                resolveEpdrLocalRouteToRrtRSrc();
            lrtToRrt.get()->remove();
            mutator.commit();
            if(isLocalRouteDeletable(delLocalRoute.get())) {
                delLocalRoute.get()->remove();
                mutator.commit();
            }
            getBestRemoteRoute(rd.get()->getURI(),
                               delRemoteRt,
                               prefixLen,
                               parentRemoteRt);
            updatePolicyPrefixChildrenForRemoteRoute(
                rd.get()->getURI(),
                rtURI,
                delRemoteRt,
                prefixLen,
                parentRemoteRt,
                notifyLocalRoutes);
            continue;
        }
        if(routeIter != remote_route_map.end()) {
            routeIter->second->setPresent(false);
        }
        itr++;
    }
}

void PolicyManager::updateRemoteRoute(class_id_t class_id, const URI& uri,
                                      uri_set_t &notifyRemoteRoutes,
                                      uri_set_t &notifyLocalRoutes) {
    using namespace modelgbp::gbp;
    if(class_id == RemoteRoute::CLASS_ID) {
        route_map_t::const_iterator iter = remote_route_map.find(uri);
        if(iter == remote_route_map.end()) {
            return;
        }
        opflex::modb::URI rdURI = iter->second->getRDURI();
        updateRemoteRoutes(rdURI, notifyRemoteRoutes,
                           notifyLocalRoutes);
    }
    if(class_id == RemoteNextHop::CLASS_ID) {
        /*TBD:This should be optimized*/
        rd_map_t::const_iterator iter = rd_map.begin();
        while(iter != rd_map.end()) {
            updateRemoteRoutes(iter->first, notifyRemoteRoutes,
                               notifyLocalRoutes);
            ++iter;
        }
    }
}

void PolicyManager::updateExternalNetworkPrefixes(
        const opflex::modb::URI& uri,
        uri_set_t &notifyRemoteRoutes,
        uri_set_t &notifyLocalRoutes) {

    if(framework.getElementMode() !=
            opflex::ofcore::OFConstants::TRANSPORT_MODE) {
        return;
    }
    using namespace modelgbp::gbp;
    using namespace modelgbp::epdr;
    optional<shared_ptr<LocalRoute>> localRoute;
    optional<shared_ptr<L3ExternalNetwork>> l3ext;
    LOG(DEBUG) << "updateExternalNetworkPrefixes for" << uri;
    auto l3n_iter = l3n_map.find(uri);
    if(l3n_iter == l3n_map.end()) {
        return;
    }
    L3NetworkState &l3s = l3n_iter->second;

    l3ext = L3ExternalNetwork::resolve(framework, uri);
    if(l3ext) {
        // Addition and update are handled by updateL3Nets
        return;
    }
    optional<shared_ptr<RoutingDomain > > rd =
        l3s.routingDomain;

    if (rd) {
        //Update policyprefix delete for each subnet
        auto snet = l3s.subnet_map.begin();
        while (snet != l3s.subnet_map.end())
        {
            optional<shared_ptr<L3ExternalNetwork>> newNet;
            optional<shared_ptr<ExternalSubnet>> newExtSub;
            opflex::modb::URI delURI = snet->second->getURI();
            std::string delPPfx = snet->second->getAddress().get();
            uint32_t pPfxLen = snet->second->getPrefixLen().get();
            //This is a deleted policy prefix, update localRoutes
            //being served by this policy prefix
            localRoute = LocalRoute::resolve(
                             framework,
                             rd.get()->getURI().toString(),
                             delPPfx,
                             pPfxLen);
            auto lrtToPrt = localRoute.get()->
                                resolveEpdrLocalRouteToPrtRSrc();
            notifyLocalRoutes.insert(localRoute.get()->getURI());
            Mutator mutator(framework, "policyelement");
            lrtToPrt.get()->remove();
            mutator.commit();
            snet = l3s.subnet_map.erase(snet);
            if(isLocalRouteDeletable(localRoute.get())) {
                localRoute.get()->remove();
                mutator.commit();
            }
            getBestPolicyPrefix(rd.get()->getURI(),
                                delPPfx,
                                pPfxLen,
                                newNet, newExtSub);
            updateRemoteRouteChildrenForPolicyPrefix(
                rd.get()->getURI(),
                uri,
                delURI,
                delPPfx,
                pPfxLen,
                std::move(newNet),
                std::move(newExtSub),
                notifyLocalRoutes);
        }
    } else {
        LOG(DEBUG) << "RD is not valid for uri: " << uri;
    }
    l3n_map.erase(l3n_iter);

}

PolicyManager::DomainListener::DomainListener(PolicyManager& pmanager_)
    : pmanager(pmanager_) {}
PolicyManager::DomainListener::~DomainListener() {}

void PolicyManager::DomainListener::objectUpdated(class_id_t class_id,
                                                  const URI& uri) {
    pmanager.taskQueue.dispatch("dl"+uri.toString(), [=]() {
            pmanager.updateDomain(class_id, uri);
        });
}

void PolicyManager::
executeAndNotifyContract(const std::function<void(uri_set_t&)>& func) {
    uri_set_t contractsToNotify;

    {
        unique_lock<mutex> guard(state_mutex);
        func(contractsToNotify);
    }

    for (const URI& u : contractsToNotify) {
        notifyContract(u);
    }
}

void PolicyManager::
executeAndNotifySecGroup(const std::function<void(uri_set_t&)>& func) {
    uri_set_t secGroupsToNotify;

    {
        unique_lock<mutex> guard(state_mutex);
        func(secGroupsToNotify);
    }

    for (const URI& u : secGroupsToNotify) {
        notifySecGroup(u);
    }
}

void PolicyManager::
        executeAndNotifyContractAndRoute(
            const std::function<void(uri_set_t&, uri_set_t&)>& func) {
    uri_set_t contractsToNotify;
    uri_set_t localRoutesToNotify;

    {
        unique_lock<mutex> guard(state_mutex);
        func(contractsToNotify, localRoutesToNotify);
    }

    for (const URI& u : contractsToNotify) {
        notifyContract(u);
    }
    for (const URI& u : localRoutesToNotify) {
        notifyLocalRoute(u);
    }
}

PolicyManager::ContractListener::ContractListener(PolicyManager& pmanager_)
    : pmanager(pmanager_) {}

PolicyManager::ContractListener::~ContractListener() {}

void PolicyManager::ContractListener::objectUpdated(class_id_t classId,
                                                    const URI& uri) {
    using namespace modelgbp::gbp;
    LOG(DEBUG) << "ContractListener update for URI " << uri;

    if (classId == EpGroup::CLASS_ID ||
        classId == L3ExternalNetwork::CLASS_ID) {
        pmanager.taskQueue.dispatch("cl"+uri.toString(), [=]() {
                pmanager.executeAndNotifyContract([&](uri_set_t& notif) {
                        pmanager.updateGroupContracts(classId, uri, notif);
                    });
            });
    } else if (classId == RoutingDomain::CLASS_ID) {
        pmanager.taskQueue.dispatch("cl"+uri.toString(), [=]() {
                pmanager.executeAndNotifyContractAndRoute([&](
                                                      uri_set_t& notif,
                                                      uri_set_t& notif2) {
                        pmanager.updateL3Nets(uri, notif, notif2);
                    });
            });
    } else if (classId == RedirectDestGroup::CLASS_ID) {
        pmanager.taskQueue.dispatch("cl"+uri.toString(), [=]() {
            pmanager.executeAndNotifyContract([&](uri_set_t& notif) {
                pmanager.updateRedirectDestGroup(uri, notif);
            });
        });
    } else if (classId == RedirectDest::CLASS_ID) {
        pmanager.taskQueue.dispatch("cl"+uri.toString(), [=]() {
            pmanager.executeAndNotifyContract([&](uri_set_t& notif) {
                pmanager.updateRedirectDestGroups(notif);
            });
        });
    } else {
        {
            unique_lock<mutex> guard(pmanager.state_mutex);
            if (classId == Contract::CLASS_ID) {
                pmanager.contractMap[uri];
            }
        }

        pmanager.taskQueue.dispatch("contract", [this]() {
                pmanager.updateContracts();
            });
    }
}

PolicyManager::SecGroupListener::SecGroupListener(PolicyManager& pmanager_)
    : pmanager(pmanager_) {}

PolicyManager::SecGroupListener::~SecGroupListener() {}

void PolicyManager::SecGroupListener::objectUpdated(class_id_t classId,
                                                    const URI& uri) {
    LOG(DEBUG) << "SecGroupListener update for URI " << uri;
    if (classId == modelgbp::epdr::DnsAnswer::CLASS_ID) {
        pmanager.taskQueue.dispatch("cl"+uri.toString(), [=]() {
            pmanager.executeAndNotifySecGroup([&](uri_set_t& notif) {
                pmanager.updateDnsPolicies(classId, uri, notif);
            });
        });
    } else {
        unique_lock<mutex> guard(pmanager.state_mutex);
        if (classId == modelgbp::gbp::SecGroup::CLASS_ID) {
            pmanager.secGrpMap[uri].isLocal = false;
        }

        pmanager.taskQueue.dispatch("secgroup", [this]() {
            pmanager.updateSecGrps(false);
        });
    }
}

PolicyManager::LocalSecGroupListener::LocalSecGroupListener(PolicyManager& pmanager_)
    : pmanager(pmanager_) {}

PolicyManager::LocalSecGroupListener::~LocalSecGroupListener() {}

void PolicyManager::LocalSecGroupListener::objectUpdated(class_id_t classId,
                                                         const URI& uri) {
    LOG(DEBUG) << "LocalSecGroupListener update for URI " << uri;
    unique_lock<mutex> guard(pmanager.state_mutex);

    if (classId == modelgbp::gbp::LocalSecGroup::CLASS_ID) {
        pmanager.secGrpMap[uri].isLocal = true;
    }

    pmanager.taskQueue.dispatch("localsecgroup", [this]() {
        pmanager.updateSecGrps(true);
    });
}

PolicyManager::ConfigListener::ConfigListener(PolicyManager& pmanager_)
    : pmanager(pmanager_) {}

PolicyManager::ConfigListener::~ConfigListener() {}

void PolicyManager::ConfigListener::objectUpdated(class_id_t, const URI& uri) {
    pmanager.notifyConfig(uri);
}

PolicyManager::RouteListener::RouteListener(PolicyManager& pmanager_)
    : pmanager(pmanager_) {}

PolicyManager::RouteListener::~RouteListener() {}

void PolicyManager::executeAndNotifyRoutes(bool static_source,
        const std::function<void(uri_set_t&, uri_set_t&)>& func) {
    uri_set_t notifyRoutes,notifyLocalRoutes;
    {
        unique_lock<mutex> guard(state_mutex);
        func(notifyRoutes, notifyLocalRoutes);
    }

    if(static_source){
        for (const URI& u : notifyRoutes) {
            notifyStaticRoute(u);
        }
    } else {
        for (const URI& u : notifyRoutes) {
            notifyRemoteRoute(u);
        }
    }
    for (const URI& u : notifyLocalRoutes) {
        notifyLocalRoute(u);
    }

}

void PolicyManager::RouteListener::objectUpdated(
        class_id_t classId, const URI& uri) {
    using namespace modelgbp::gbp;
    LOG(DEBUG) << "RouteListener update for URI " << uri;

    if(classId == ExternalNode::CLASS_ID) {
        pmanager.taskQueue.dispatch("rl"+uri.toString(),[=]() {
            pmanager.executeAndNotifyRoutes(true,
                    [&](uri_set_t &notifyStaticRoutes,
                        uri_set_t &notifyLocalRoutes) {
                pmanager.updateStaticRoutes(classId,
                                            uri, notifyStaticRoutes,
                                            notifyLocalRoutes);
            });});
    } else if(classId == RoutingDomain::CLASS_ID) {
        pmanager.taskQueue.dispatch("rlSR"+uri.toString(),[=]() {
            pmanager.executeAndNotifyRoutes(true,
                    [&](uri_set_t &notifyStaticRoutes,
                        uri_set_t &notifyLocalRoutes) {
                pmanager.updateStaticRoutes(classId,
                                            uri, notifyStaticRoutes,
                                            notifyLocalRoutes);
            });});
        pmanager.taskQueue.dispatch("rl"+uri.toString(),[=]() {
            pmanager.executeAndNotifyRoutes(false,
                    [&](uri_set_t &notifyRemoteRoutes,
                        uri_set_t &notifyLocalRoutes) {
                pmanager.updateRemoteRoutes(uri, notifyRemoteRoutes,
                                            notifyLocalRoutes);
            });});
    } else if(classId == L3ExternalNetwork::CLASS_ID) {
        pmanager.taskQueue.dispatch("rl"+uri.toString(),[=]() {
            pmanager.executeAndNotifyRoutes(false,
                   [&](uri_set_t &notifyRemoteRoutes,
                       uri_set_t &notifyLocalRoutes) {
                pmanager.updateExternalNetworkPrefixes(
                        uri, notifyRemoteRoutes,
                        notifyLocalRoutes);
           });});
    } else if((classId == StaticRoute::CLASS_ID)||
              (classId == StaticNextHop::CLASS_ID)) {
        pmanager.taskQueue.dispatch("rl"+uri.toString(),[=]() {
            pmanager.executeAndNotifyRoutes(true,
                    [&](uri_set_t &notifyStaticRoutes,
                        uri_set_t &notifyLocalRoutes) {
                pmanager.updateStaticRoute(classId, uri,
                                           notifyStaticRoutes,
                                           notifyLocalRoutes);
            });});
    } else if((classId == RemoteRoute::CLASS_ID) ||
              (classId == RemoteNextHop::CLASS_ID)) {
        pmanager.taskQueue.dispatch("rl"+uri.toString(),[=]() {
            pmanager.executeAndNotifyRoutes(false,
                    [&](uri_set_t &notifyRemoteRoutes,
                    uri_set_t &notifyLocalRoutes) {
                pmanager.updateRemoteRoute(classId, uri,
                                           notifyRemoteRoutes,
                                           notifyLocalRoutes);
            });});
    }

}

} /* namespace opflexagent */
