/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for QosManager class.
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <string>

#include <opflexagent/QosManager.h>
#include <opflexagent/logging.h>
#include <modelgbp/policy/Space.hpp>
#include <boost/optional.hpp>
#include <opflexagent/EndpointManager.h>
#include <opflexagent/Endpoint.h>
#include <opflexagent/Agent.h>

namespace opflexagent {

    using namespace std;
    using boost::optional;
    using opflex::modb::class_id_t;
    using opflex::modb::URI;
    using namespace modelgbp::gbp;

    recursive_mutex QosManager::qos_mutex;

    static const std::string EGRESS("Egress");
    static const std::string INGRESS("Ingress");
    static const std::string BOTH("Both");

    QosManager::QosManager(Agent& agent_,opflex::ofcore::OFFramework &framework_,
                             boost::asio::io_service& agent_io_) :
            qosUniverseListener(*this), agent(agent_), framework(framework_),
            taskQueue(agent_io_),stopping(false){
    }

    void QosManager::start() {
        LOG(DEBUG) << "starting qos manager";
        agent.getEndpointManager().registerListener(this);
        Requirement::registerListener(framework, &qosUniverseListener);
        BandwidthLimit::registerListener(framework, &qosUniverseListener);
        EpGroupToQosRSrc::registerListener(framework, &qosUniverseListener);
        DscpMarking::registerListener(framework, &qosUniverseListener);
    }

    void QosManager::stop() {
        stopping = true;
        LOG(DEBUG) << "stopping qos manager";
        agent.getEndpointManager().unregisterListener(this);
        Requirement::unregisterListener(framework, &qosUniverseListener);
        BandwidthLimit::unregisterListener(framework, &qosUniverseListener);
        EpGroupToQosRSrc::unregisterListener(framework, &qosUniverseListener);
        DscpMarking::unregisterListener(framework, &qosUniverseListener);
    }


    QosManager::QosUniverseListener::QosUniverseListener(QosManager& qosManager) :
        qosmanager(qosManager) {}

    QosManager::QosUniverseListener::~QosUniverseListener() {}

    void QosManager::QosUniverseListener::objectUpdated(class_id_t classId, const URI &uri) {
        LOG(DEBUG) << "update on QosUniverseListener URI " << uri;

        optional<URI> confUri = boost::none;
        if (classId == modelgbp::policy::Space::CLASS_ID) {
            optional <shared_ptr<modelgbp::policy::Space>> config_opt =
                modelgbp::policy::Space::resolve(qosmanager.framework, uri);
            if (config_opt) {
                vector <shared_ptr<modelgbp::qos::Requirement>> qosVec;
                config_opt.get()->resolveQosRequirement(qosVec);
                for (const shared_ptr <modelgbp::qos::Requirement>& qosReq : qosVec) {
                    LOG(DEBUG) << "creating qos config " << qosReq->getURI();
                    qosmanager.notifyUpdate.insert(qosReq->getURI());
                    qosmanager.taskQueue.dispatch(uri.toString(), [=]() {
                            processQosConfig(qosReq); });
                }
            }
        } else if (classId == modelgbp::qos::Requirement::CLASS_ID) {
            optional<shared_ptr<modelgbp::qos::Requirement>> qosReqOpt =
                modelgbp::qos::Requirement::resolve(qosmanager.framework, uri);
            if (qosReqOpt) {
                qosmanager.notifyUpdate.insert(uri);
                qosmanager.taskQueue.dispatch(uri.toString(), [=]() {
                        processQosConfig(qosReqOpt.get()); });
            }
        } else if (classId == modelgbp::qos::BandwidthLimit::CLASS_ID){
            optional<shared_ptr<modelgbp::qos::BandwidthLimit>> qosBandwidthOpt =
                modelgbp::qos::BandwidthLimit::resolve(qosmanager.framework, uri);
            if (qosBandwidthOpt){
                const shared_ptr<modelgbp::qos::BandwidthLimit> &qosBandwidth =
                    qosBandwidthOpt.get();
                LOG(INFO) << "Bandwidth receieved burst: " << qosBandwidth->getBurst()
                    << " rate: "<< qosBandwidth->getRate();
                qosmanager.notifyUpdate.insert(uri);
                qosmanager.taskQueue.dispatch(uri.toString(), [=]() {
                        processQosConfig(qosBandwidth); });
            }
        } else if (classId == modelgbp::qos::DscpMarking::CLASS_ID) {
            lock_guard<recursive_mutex> guard1(opflexagent::QosManager::qos_mutex);
            string dscpMarking("QosDscpMarking/");
            string dscpMarkingUri(uri.toString());
            dscpMarkingUri.erase(dscpMarkingUri.length()-dscpMarking.size());
            URI reqUri(dscpMarkingUri);
            LOG(INFO) << "Dscp-req: " << reqUri;

            qosmanager.notifyUpdate.insert(reqUri);
        } else if (classId == modelgbp::gbp::EpGroupToQosRSrc::CLASS_ID) {
            lock_guard<recursive_mutex> guard1(opflexagent::QosManager::qos_mutex);
            string rsQos("GbpEpGroupToQosRSrc/");
            string mEpgUri (uri.toString());
            mEpgUri.erase(mEpgUri.length()-rsQos.size());
            URI mUri(mEpgUri);
            LOG(INFO) << "qos update recieved on epg: "<< mUri;

            optional<shared_ptr<modelgbp::gbp::EpGroupToQosRSrc>> epgRs =
                modelgbp::gbp::EpGroupToQosRSrc::resolve(qosmanager.framework, uri);

            if (epgRs) {
                optional<URI> reqUriOpt = epgRs.get()->getTargetURI();
                if (reqUriOpt) {
                    qosmanager.notifyUpdate.insert(mUri);
                    LOG(INFO) << "EPG-QOS added: " << reqUriOpt.get().toString();
                    confUri = reqUriOpt.get();
                    qosmanager.updateEpgPolicyMap(mUri, reqUriOpt.get());
                }
            } else {
                qosmanager.clearEpgEntry(mUri);
                qosmanager.notifyDelete.insert(mUri);
            }
        }

        lock_guard<recursive_mutex> guard1(opflexagent::QosManager::qos_mutex);
        for (const URI& updatedUri : qosmanager.notifyUpdate) {
            processModbUpdate(updatedUri, INGRESS, qosmanager.ingressPolInterface);
            processModbUpdate(updatedUri, EGRESS, qosmanager.egressPolInterface);
            processModbUpdate(updatedUri, BOTH, qosmanager.reqToInterface);
            processModbUpdate(updatedUri, BOTH, qosmanager.epgToInterface, confUri);
            processModbUpdate(updatedUri, INGRESS, qosmanager.ingressPolEpg);
            processModbUpdate(updatedUri, EGRESS, qosmanager.egressPolEpg);
            processModbUpdate(updatedUri, BOTH, qosmanager.reqToEpg);
        }

        for(const URI& deletedUri : qosmanager.notifyDelete){
            processModbDelete(deletedUri, BOTH, qosmanager.epgToInterface);
        }
        qosmanager.notifyUpdate.clear();
        qosmanager.notifyDelete.clear();
    }

    void QosManager::endpointUpdated(const string& uuid){
        if (stopping) return;
        taskQueue.dispatch(uuid, [=]() { handleEndpointUpdate(uuid); });
    }

    void QosManager::handleEndpointUpdate(const string& uuid){
        lock_guard<recursive_mutex> guard(opflexagent::QosManager::qos_mutex);

        EndpointManager& epMgr  = agent.getEndpointManager();
        shared_ptr<const Endpoint> epWrapper = epMgr.getEndpoint(uuid);
        if (!epWrapper){
            return;
        }
        const Endpoint& endpoint = *epWrapper.get();
        const optional<URI>& epQosPol = endpoint.getQosPolicy();
        const optional<string>& ofPortName = endpoint.getAccessInterface();
        const optional<URI>& egUri = endpoint.getEgURI();

        if (ofPortName){
            optional<URI> qosUri = boost::none;
            const string &interface = ofPortName.get();
            LOG(DEBUG) << "Handle update for interface: " << interface;

            if (epQosPol) {
                const URI newReq = epQosPol.get();
                updateInterfacePolicyMap(interface, newReq);
                LOG(DEBUG) << "EpQosUri: " << epQosPol.get().toString();
                qosUri = newReq;
            } else {
                auto itr = interfaceToReq.find(interface);
                if (itr != interfaceToReq.end()) {
                    clearInterfaceEntry(interface);
                }
            }

            auto itr = interfaceToEpg.find(interface);
            if (itr != interfaceToEpg.end()) {
                optional<URI> oldEgUri = itr->second;
                interfaceToEpg.erase(itr);
                clearEntry(interface, oldEgUri.get(), epgToInterface);
            }

            if (egUri) {
                const URI epg = egUri.get();
                interfaceToEpg.insert(make_pair(interface, epg));
                addEntry(interface, epg, epgToInterface);
                LOG(DEBUG) << "epg found for interface: " << epg;
                if (!qosUri) {
                    auto it1 = epgToReq.find(epg);
                    if (it1 != epgToReq.end()){
                        qosUri = it1->second;
                    }
                }
            }
            notifyListeners(interface, BOTH, qosUri);
        }
    }

    void QosManager::registerListener(QosListener *listener) {
        LOG(DEBUG) << "registering qos listener";
        lock_guard<mutex> guard(listener_mutex);
        qosListeners.push_back(listener);
    }

    void QosManager::unregisterListener(QosListener* listener) {
        lock_guard <mutex> guard(listener_mutex);
        qosListeners.remove(listener);
    }

    optional<shared_ptr<QosConfigState>> QosManager::resolveEgressConfig (
            const optional<URI>& reqOpt) const {
        URI req("");
        if (reqOpt) {
            req = reqOpt.get();
        } else {
            return boost::none;
        }
        optional<shared_ptr<modelgbp::qos::Requirement>> qosReqOpt =
            modelgbp::qos::Requirement::resolve(framework, req);

        if (qosReqOpt){
            shared_ptr<modelgbp::qos::Requirement> qosReq = qosReqOpt.get();

            optional<shared_ptr<modelgbp::qos::RequirementToEgressRSrc> > rsEgress =
                qosReq->resolveQosRequirementToEgressRSrc();
            if (rsEgress){
                optional<URI> egressUri = rsEgress.get()->getTargetURI();
                if (egressUri){
                    const URI egUri = egressUri.get();
                    optional<shared_ptr<modelgbp::qos::BandwidthLimit>> bwOpt =
                        modelgbp::qos::BandwidthLimit::resolve(framework, egUri);
                    if (bwOpt) {
                        shared_ptr<modelgbp::qos::BandwidthLimit> bw = bwOpt.get();
                        shared_ptr<QosConfigState> qosConfig =
                            make_shared<QosConfigState>(bw->getURI(), bw->getName().get());
                        boost::optional<uint64_t> rate = bw->getRate();
                        if (rate) {
                            qosConfig->setRate(rate.get());
                        }
                        boost::optional<uint64_t> burst = bw->getBurst();
                        if (burst) {
                            qosConfig->setBurst(burst.get());
                        }
                        return qosConfig;
                    }
                }
            }
        }
        return boost::none;
    }

    uint8_t QosManager::resolveDscp(const optional<URI>& reqOpt) const {
        URI req("");
        if (reqOpt) {
            req = reqOpt.get();
        } else {
            return 0;
        }
        optional<shared_ptr<modelgbp::qos::Requirement>> qosReqOpt =
            modelgbp::qos::Requirement::resolve(framework, req);
        if (qosReqOpt){
            shared_ptr<modelgbp::qos::Requirement> qosReq = qosReqOpt.get();
            optional<shared_ptr<modelgbp::qos::DscpMarking> > dscpMarkingOpt =
                qosReq->resolveQosDscpMarking();
            if (dscpMarkingOpt){
                const shared_ptr<modelgbp::qos::DscpMarking> & dscpMarking =
                    dscpMarkingOpt.get();
                if (dscpMarking->isMarkSet()) {
                    uint8_t dscp = dscpMarking->getMark().get();
                    return dscp;
                }
            }
        }
        return 0;
    }

    optional<URI> QosManager::getEpQosPolicy (const string& interface) {
        optional<URI> req = boost::none;
        lock_guard<recursive_mutex> guard1(qos_mutex);
        auto it =  interfaceToReq.find(interface);
        if (it != interfaceToReq.end()){
            req = it->second;
        }
        return req;
    }

    optional<URI> QosManager::getEpgQosPolicy(const string& interface){
        optional<URI> req = boost::none;
        lock_guard<recursive_mutex> guard1(qos_mutex);
        auto it1  = interfaceToEpg.find(interface);
        if (it1 != interfaceToEpg.end()){
            const URI epg = it1->second;
            auto it2 = epgToReq.find(epg);
            if (it2 != epgToReq.end()){
                req = it2->second;
            }
        }
        return req;
    }

    optional<shared_ptr<QosConfigState>> QosManager::resolveIngressConfig(
        const optional<URI>& reqOpt) const {
        URI req("");
        if (reqOpt){
            req = reqOpt.get();
        } else {
            return boost::none;
        }

        optional<shared_ptr<modelgbp::qos::Requirement>> qosReqOpt =
            modelgbp::qos::Requirement::resolve(framework, req);

        if (qosReqOpt){
            shared_ptr<modelgbp::qos::Requirement> qosReq = qosReqOpt.get();

            optional<shared_ptr<modelgbp::qos::RequirementToIngressRSrc> > rsIngress =
                qosReq->resolveQosRequirementToIngressRSrc();
            if (rsIngress){
                optional<URI> ingressUri = rsIngress.get()->getTargetURI();
                if (ingressUri){
                    const URI ingUri = ingressUri.get();
                    optional<shared_ptr<modelgbp::qos::BandwidthLimit>> bwOpt =
                        modelgbp::qos::BandwidthLimit::resolve(framework, ingUri);
                    if (bwOpt) {
                        shared_ptr<modelgbp::qos::BandwidthLimit> bw = bwOpt.get();
                        shared_ptr<QosConfigState> qosConfig =
                            make_shared<QosConfigState>(bw->getURI(), bw->getName().get());
                        boost::optional<uint64_t> rate = bw->getRate();
                        if (rate) {
                            qosConfig->setRate(rate.get());
                        }
                        boost::optional<uint64_t> burst = bw->getBurst();
                        if (burst) {
                            qosConfig->setBurst(burst.get());
                        }
                        return qosConfig;
                    }
                }
            }
        }
        return boost::none;
    }


    void QosManager::notifyListeners(const string& interface, const string& direction,
            const optional<URI> conf) {

        lock_guard<mutex> guard1(listener_mutex);
        if (direction == BOTH) {
            uint8_t dscp = resolveDscp(conf);
            for (QosListener *listener : qosListeners) {
                listener->dscpQosUpdated(interface, dscp);
            }
        }

        if (direction == EGRESS || direction == BOTH){
            const optional<shared_ptr<QosConfigState>>& qosConfig = resolveEgressConfig(conf);
            for (QosListener *listener : qosListeners) {
                listener->egressQosUpdated(interface, qosConfig);
            }
        }

        if (direction == INGRESS || direction == BOTH){
            const optional<shared_ptr<QosConfigState>>& qosConfig = resolveIngressConfig(conf);
            for (QosListener *listener : qosListeners) {
                listener->ingressQosUpdated(interface, qosConfig);
            }
        }
    }


    void QosManager::notifyListeners(const unordered_set<string>& interfaces) {
        lock_guard<mutex> guard(listener_mutex);
        for (const string& interface : interfaces) {
            for (QosListener *listener : qosListeners) {
                listener->qosDeleted(interface);
            }
        }
    }

    void QosManager::updateQosConfigState(const shared_ptr<modelgbp::qos::BandwidthLimit>& qosconfig) {
        lock_guard<recursive_mutex> guard(opflexagent::QosManager::qos_mutex);
        LOG(INFO) << "BandwidthLimitUri: " << qosconfig->getURI().toString();

        shared_ptr<QosConfigState> qosConfig = make_shared<QosConfigState>(qosconfig->getURI(), qosconfig->getName().get());
        boost::optional<uint64_t> rate = qosconfig->getRate();
        if (rate) {
            qosConfig->setRate(rate.get());
        }
        boost::optional<uint64_t> burst = qosconfig->getBurst();
        if (burst) {
            qosConfig->setBurst(burst.get());
        }
    }

    void QosManager::updateQosConfigState(const shared_ptr<modelgbp::qos::Requirement>& qosconfig) {
        lock_guard<recursive_mutex> guard(opflexagent::QosManager::qos_mutex);
        LOG(INFO) << "Requirement URI: " << qosconfig->getURI().toString();

        optional<shared_ptr<modelgbp::qos::RequirementToEgressRSrc> > rsEgress =
            qosconfig->resolveQosRequirementToEgressRSrc();
        optional<URI> egressUri;
        const URI ReqUri = qosconfig->getURI();

        clearEntry(ReqUri);

        if (rsEgress){
            egressUri = rsEgress.get()->getTargetURI();
            if (egressUri){
                LOG(INFO) << "Egress URI: " << egressUri.get().toString();
                updateEntry(ReqUri, egressUri.get(), egressPolInterface);
                updateEntry(ReqUri, egressUri.get(), egressPolEpg);
            }
        }

        optional<shared_ptr<modelgbp::qos::RequirementToIngressRSrc> > rsIngress =
            qosconfig->resolveQosRequirementToIngressRSrc();
        optional<URI> ingressUri;

        if (rsIngress){
            ingressUri = rsIngress.get()->getTargetURI();
            if (ingressUri){
                LOG(INFO) << "Ingress URI: " << ingressUri.get().toString();
                updateEntry(ReqUri, ingressUri.get(), ingressPolInterface);
                updateEntry(ReqUri, ingressUri.get(), ingressPolEpg);
            }
        }

        reqToPol.insert(make_pair(qosconfig->getURI(), make_pair(egressUri,ingressUri)));
    }

    void QosManager::QosUniverseListener::processQosConfig(const shared_ptr<modelgbp::qos::Requirement>& qosconfig) {
        qosmanager.updateQosConfigState(qosconfig);
    }

    void QosManager::QosUniverseListener::processQosConfig(const shared_ptr<modelgbp::qos::BandwidthLimit>& qosconfig) {
        qosmanager.updateQosConfigState(qosconfig);
    }

    void QosManager::QosUniverseListener::updateInterfaces(const URI& updatedUri, const string &dir,
            const unordered_map<URI, unordered_set<string>>& policyMap, optional<URI> conf) {
        auto itr = policyMap.find(updatedUri);
        if (itr != policyMap.end()){
            const unordered_set<string> &interfaces = itr->second;
            for( const string& interface : interfaces){
                const optional<URI> epReq = qosmanager.getEpQosPolicy(interface);
                const optional<URI> epgReq = qosmanager.getEpgQosPolicy(interface);
                optional<URI> req;

                if (epReq) {
                    req = epReq;
                } else {
                    if (conf) {
                        req = conf; //cache may contain stale epg-qos policy.
                    } else {
                        req = epgReq; //conf is none, implies epg-qos policy is latest in cache.
                    }

                }
                string taskId = updatedUri.toString()+ interface + dir;
                qosmanager.taskQueue.dispatch(taskId, [=]() {
                        qosmanager.notifyListeners(interface, dir, std::move(req));
                        });
            }
        }
    }

    void QosManager::QosUniverseListener::processModbDelete(const URI& deletedUri, const string &dir,
            const unordered_map<URI, unordered_set<string>>& policyMap) {
        auto it1 = policyMap.find(deletedUri);
        if (it1 != policyMap.end()){
            const unordered_set<string> &interfaces = it1->second;
            for( const string& interface : interfaces){
                const optional<URI> epReq = qosmanager.getEpQosPolicy(interface);
                string taskId = deletedUri.toString()+ interface + dir;
                qosmanager.taskQueue.dispatch(taskId, [=]() {
                        qosmanager.notifyListeners(interface, dir, epReq);
                        });
            }
        }
    }

    void QosManager::QosUniverseListener::processModbUpdate(const URI& updatedUri, const string &dir,
            const unordered_map<URI, unordered_set<string>>& policyMap, optional<URI> conf){
        updateInterfaces(updatedUri, dir, policyMap, conf);
    }

    void QosManager::QosUniverseListener::processModbUpdate(const URI& updatedUri, const string& dir,
            const unordered_map<URI, unordered_set<URI>>& policyMap, optional<URI> conf){
        auto itr1 = policyMap.find(updatedUri);
        if (itr1 != policyMap.end()){
            const unordered_set<URI> &epgs = itr1->second;
            for( const URI& epg : epgs){
                updateInterfaces(epg, dir, qosmanager.epgToInterface, conf);
            }
        }
    }

    void QosManager::clearEntry(const string& interface, const URI& uri, unordered_map<URI, unordered_set<string>>& policyMap){
        auto itr = policyMap.find(uri);
        if (itr != policyMap.end()){
            itr->second.erase(interface);
        }
    }

    void QosManager::clearEntry(const URI& epg, const URI& uri, unordered_map<URI, unordered_set<URI>>& policyMap){
        auto itr = policyMap.find(uri);
        if (itr != policyMap.end()){
            itr->second.erase(epg);
        }
    }

    void QosManager::clearEntry(const URI& reqUri){
		optional<URI> egressUri;
        optional<URI> ingressUri;
        unordered_set<string> reqInterfaces;
        unordered_set<URI> reqEpgs;

        auto itr = reqToEpg.find(reqUri);
        if (itr != reqToEpg.end()){
            reqEpgs = itr->second;
        }

        auto itr1 = reqToInterface.find(reqUri);
        if (itr1 != reqToInterface.end()){
            reqInterfaces = itr1->second;
        }

        auto itr2 = reqToPol.find(reqUri);
        if (itr2 != reqToPol.end()){
            egressUri = itr2->second.first;
            ingressUri = itr2->second.second;
            reqToPol.erase(itr2);
        }

        if (egressUri){
            auto itr3 = egressPolInterface.find(egressUri.get());
            if (itr3 != egressPolInterface.end()){
                unordered_set<string> & updateInterfaces = itr3->second;
                for(const auto& intf : reqInterfaces){
                    updateInterfaces.erase(intf);
                }
            }

            auto itr4 = egressPolEpg.find(egressUri.get());
            if (itr4 != egressPolEpg.end()){
                unordered_set<URI> & updateEpgs = itr4->second;
                for(const auto& epg : reqEpgs){
                    updateEpgs.erase(epg);
                }
            }
        }

        if (ingressUri){
            auto itr3 = ingressPolInterface.find(ingressUri.get());
            if (itr3 != ingressPolInterface.end()){
                unordered_set<string> & updateInterfaces = itr3->second;
                for(const auto& intf : reqInterfaces){
                    updateInterfaces.erase(intf);
                }
            }

            auto itr4 = ingressPolEpg.find(ingressUri.get());
            if (itr4 != ingressPolEpg.end()){
                unordered_set<URI> & updateEpgs = itr4->second;
                for(const auto& epg : reqEpgs){
                    updateEpgs.erase(epg);
                }
            }
        }
    }

    void QosManager::updateEntry(const URI& reqUri, const URI& dirUri, unordered_map<URI, unordered_set<string>>& policyMap){
        auto itr1 = reqToInterface.find(reqUri);
        if (itr1 == reqToInterface.end()){
            return;
        }
        unordered_set<string> interfaces = itr1->second;
        auto itr2 = policyMap.find(dirUri);
        if (itr2 == policyMap.end()){
            policyMap.insert(make_pair(dirUri, interfaces));
            return;
        }
        unordered_set<string> &updateInterfaces = itr2->second;
        for(const auto& intf : interfaces){
            updateInterfaces.insert(intf);
        }
    }

    void QosManager::updateEntry(const URI& reqUri, const URI& dirUri, unordered_map<URI, unordered_set<URI>>& policyMap){
        auto itr1 = reqToEpg.find(reqUri);
        if (itr1 == reqToEpg.end()){
            return;
        }
        unordered_set<URI> epgs = itr1->second;
        auto itr2 = policyMap.find(dirUri);
        if (itr2 == policyMap.end()){
            policyMap.insert(make_pair(dirUri, epgs));
            return;
        }
        unordered_set<URI> &updateEpgs = itr2->second;
        for(const auto& epg : epgs){
            updateEpgs.insert(epg);
        }
    }

    void QosManager::addEntry(const string& interface, const URI& uri, unordered_map<URI, unordered_set<string>>& policyMap){
        auto itr = policyMap.find(uri);
        if (itr != policyMap.end()){
            itr->second.insert(interface);
        }else{
            unordered_set<string> interfaces;
            interfaces.insert(interface);
            policyMap.insert(make_pair(uri, interfaces));
        }
    }

    void QosManager::addEntry(const URI& epg, const URI& uri, unordered_map<URI, unordered_set<URI>>& policyMap){
        auto itr = policyMap.find(uri);
        if (itr != policyMap.end()){
            itr->second.insert(epg);
        }else{
            unordered_set<URI> epgs;
            epgs.insert(epg);
            policyMap.insert(make_pair(uri, epgs));
        }
    }

    void QosManager::clearInterfaceEntry(const string & interface){
        auto itr = interfaceToReq.find(interface);
        if (itr != interfaceToReq.end()){
            const URI oldReq = itr->second;
            interfaceToReq.erase(itr);

            auto itr2 = reqToPol.find(oldReq);
            if (itr2 != reqToPol.end()){
                const optional<URI> oldEgress = itr2->second.first;
                const optional<URI> oldIngress = itr2->second.second;
                if (oldEgress){
                    clearEntry(interface, oldEgress.get(), egressPolInterface);
                }

                if (oldIngress){
                    clearEntry(interface, oldIngress.get(), ingressPolInterface);
                }
            }
            clearEntry(interface, oldReq, reqToInterface);
        }
    }

    void QosManager::clearEpgEntry(const URI & epg){
        auto itr = epgToReq.find(epg);
        if (itr != epgToReq.end()){
            const URI oldReq = itr->second;
            epgToReq.erase(itr);

            auto itr2 = reqToPol.find(oldReq);
            if (itr2 != reqToPol.end()){
                const optional<URI> oldEgress = itr2->second.first;
                const optional<URI> oldIngress = itr2->second.second;
                if (oldEgress){
                    clearEntry(epg, oldEgress.get(), egressPolEpg);
                }

                if (oldIngress){
                    clearEntry(epg, oldIngress.get(), ingressPolEpg);
                }
            }
            clearEntry(epg, oldReq, reqToEpg);
        }
    }

    void QosManager::updateInterfacePolicyMap(const string& interface, const URI& newReq){
        clearInterfaceEntry(interface);
        interfaceToReq.insert(make_pair(interface, newReq));
        addEntry(interface, newReq, reqToInterface);

        auto itr3 = reqToPol.find(newReq);
        if (itr3 != reqToPol.end()){
            const optional<URI> newEgress = itr3->second.first;
            const optional<URI> newIngress = itr3->second.second;

            if (newEgress){
                addEntry(interface, newEgress.get(), egressPolInterface);
            }

            if (newIngress){
                addEntry(interface, newIngress.get(), ingressPolInterface);
            }
        }
    }

    void QosManager::updateEpgPolicyMap(const URI& epg, const URI& newReq){
        clearEpgEntry(epg);
        epgToReq.insert(make_pair(epg, newReq));
        addEntry(epg, newReq, reqToEpg);

        auto itr3 = reqToPol.find(newReq);
        if (itr3 != reqToPol.end()){
            const optional<URI> newEgress = itr3->second.first;
            const optional<URI> newIngress = itr3->second.second;

            if (newEgress){
                addEntry(epg, newEgress.get(), egressPolEpg);
            }

            if (newIngress){
                addEntry(epg, newIngress.get(), ingressPolEpg);
            }
        }
    }
}
