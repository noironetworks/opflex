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

    recursive_mutex QosManager::qos_mutex;

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
    }

    void QosManager::stop() {
        stopping = true;
        LOG(DEBUG) << "stopping qos manager";
        agent.getEndpointManager().unregisterListener(this);
        Requirement::unregisterListener(framework, &qosUniverseListener);
        BandwidthLimit::unregisterListener(framework, &qosUniverseListener);
    }


    QosManager::QosUniverseListener::QosUniverseListener(QosManager& qosManager) :
        qosmanager(qosManager) {}

    QosManager::QosUniverseListener::~QosUniverseListener() {}

    void QosManager::QosUniverseListener::objectUpdated(class_id_t classId, const URI &uri) {
        LOG(DEBUG) << "update on QosUniverseListener URI " << uri;

        lock_guard<recursive_mutex> guard1(opflexagent::QosManager::qos_mutex);

        //Updates may come on Bandwidth object, from there we derive requirement and update
        if (classId == modelgbp::policy::Space::CLASS_ID) {
            optional <shared_ptr<modelgbp::policy::Space>> config_opt =
                modelgbp::policy::Space::resolve(qosmanager.framework, uri);
            if (config_opt) {
                vector <shared_ptr<modelgbp::qos::Requirement>> qosVec;
                config_opt.get()->resolveQosRequirement(qosVec);
                for (const shared_ptr <modelgbp::qos::Requirement>& qosReq : qosVec) {
                    auto itr = qosmanager.reqToInterface.find(qosReq->getURI());
                    if (itr == qosmanager.reqToInterface.end()) {
                        LOG(DEBUG) << "creating qos config " << qosReq->getURI();
                        processQosConfig(qosReq);
                    }
                    qosmanager.notifyUpdate.insert(qosReq->getURI());
                }
            }
        } else if (classId == modelgbp::qos::Requirement::CLASS_ID) {
            optional<shared_ptr<modelgbp::qos::Requirement>> qosReqOpt =
                modelgbp::qos::Requirement::resolve(qosmanager.framework, uri);
            if (qosReqOpt) {
                processQosConfig(qosReqOpt.get());
                qosmanager.notifyUpdate.insert(uri);
            }

        } else if (classId == modelgbp::qos::BandwidthLimit::CLASS_ID){
            optional<shared_ptr<modelgbp::qos::BandwidthLimit>> qosBandwidthOpt =
                modelgbp::qos::BandwidthLimit::resolve(qosmanager.framework, uri);

            if (qosBandwidthOpt){
                const shared_ptr<modelgbp::qos::BandwidthLimit> &qosBandwidth =
                    qosBandwidthOpt.get();

                LOG(INFO) << "Bandwidth receieved burst: " << qosBandwidth->getBurst()
                    << " rate: "<< qosBandwidth->getRate();
                processQosConfig(qosBandwidth);
                qosmanager.notifyUpdate.insert(uri);
            }
        }

        for (const URI& updatedUri : qosmanager.notifyUpdate) {

            auto itr = qosmanager.ingressPolInterface.find(updatedUri);
            if (itr != qosmanager.ingressPolInterface.end()){
                unordered_set<string> &interfaces = itr->second;
                for( const string& interface : interfaces){
                    string taskId = updatedUri.toString()+ interface + string("Ingress");
                    qosmanager.taskQueue.dispatch(taskId, [=]() {
                            qosmanager.notifyListeners(interface, "Ingress");
                            });
                }
            }


            itr = qosmanager.egressPolInterface.find(updatedUri);
            if (itr != qosmanager.egressPolInterface.end()){
                unordered_set<string> &interfaces = itr->second;
                for( const string& interface : interfaces){
                    string taskId = updatedUri.toString() + interface + string("Egress");
                    qosmanager.taskQueue.dispatch(taskId, [=]() {
                            qosmanager.notifyListeners(interface, "Egress");
                            });
                }
            }

            itr = qosmanager.reqToInterface.find(updatedUri);
            if (itr != qosmanager.reqToInterface.end()){
                unordered_set<string> &interfaces = itr->second;
                for( const string& interface : interfaces){
                    string taskId = updatedUri.toString() + interface + string("Both");
                    qosmanager.taskQueue.dispatch(taskId, [=]() {
                            qosmanager.notifyListeners(interface, "Both");
                            });
                }
            }
        }
        qosmanager.notifyUpdate.clear();
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
        const optional<string>& ofPortName = endpoint.getInterfaceName();

        if (epQosPol && ofPortName){
            const string &interface = ofPortName.get();
            const URI newReq = epQosPol.get();
            updateInterfacePolicyMap(interface, newReq);

            LOG(DEBUG) << "Interface:  " << ofPortName.get() << ", RequirementUri: " << epQosPol.get().toString();
            notifyListeners(ofPortName.get(), "Both");
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

    void QosManager::notifyListeners(const string& interface, const string& direction) {
        lock_guard<mutex> guard1(listener_mutex);

        if (direction == "Egress" || direction == "Both"){
            for (QosListener *listener : qosListeners) {
                listener->egressQosUpdated(interface);
            }

        }

        if (direction == "Ingress" || direction == "Both"){
            for (QosListener *listener : qosListeners) {
                listener->ingressQosUpdated(interface);
            }
        }
    }


    void QosManager::notifyListeners(const unordered_set<string>& interfaces) {
        lock_guard<mutex> guard(listener_mutex);
        for (auto itr : interfaces){
            const string& interface = itr;
            for (QosListener *listener : qosListeners) {
                listener->qosDeleted(interface);
            }
        }
    }

    optional<shared_ptr<QosConfigState>>
        QosManager::getQosConfigState(const URI& uri) const {
            lock_guard<recursive_mutex> guard1(qos_mutex);
            auto itr = bwToConfig.find(uri);
            if (itr == bwToConfig.end()) {
                return boost::none;
            } else {
                return itr->second;
            }
        }

    optional<shared_ptr<QosConfigState>>
        QosManager::getEgressQosConfigState(const string& interface) const {
            lock_guard<recursive_mutex> guard1(qos_mutex);

            auto itr = interfaceToReq.find(interface);
            if (itr == interfaceToReq.end()) {
                return boost::none;
            } else {
                const URI& reqUri = itr->second;
                auto polIter = reqToPol.find(reqUri);
                if (polIter == reqToPol.end()) {
                    return boost::none;
                }

                pair<boost::optional<URI>, boost::optional<URI> > pols = polIter->second;
                if (pols.first) {
                    return getQosConfigState(pols.first.get());
                } else {
                    return boost::none;
                }
            }
        }

    optional<shared_ptr<QosConfigState>>
        QosManager::getIngressQosConfigState(const string& interface) const {
            lock_guard<recursive_mutex> guard1(qos_mutex);

            auto itr = interfaceToReq.find(interface);
            if (itr == interfaceToReq.end()) {
                return boost::none;
            } else {
                const URI& reqUri = itr->second;
                auto polIter = reqToPol.find(reqUri);
                if (polIter == reqToPol.end()) {
                    return boost::none;
                }

                pair<boost::optional<URI>, boost::optional<URI> > pols = polIter->second;
                if (pols.second) {
                    return getQosConfigState(pols.second.get());
                } else {
                    return boost::none;
                }
            }
        }


    void QosManager::updateQosConfigState(const shared_ptr<modelgbp::qos::BandwidthLimit>& qosconfig) {
        lock_guard<recursive_mutex> guard(opflexagent::QosManager::qos_mutex);
        LOG(INFO) << "BandwidthLimitUri: " << qosconfig->getURI().toString();

        auto itr = bwToConfig.find(qosconfig->getURI());
        if (itr != bwToConfig.end()){
            bwToConfig.erase(itr);
        }
        shared_ptr<QosConfigState> qosConfig = make_shared<QosConfigState>(qosconfig->getURI(), qosconfig->getName().get());
        boost::optional<uint64_t> rate =   qosconfig->getRate();
        if (rate) {
            qosConfig->setRate(rate.get());
        }
        boost::optional<uint64_t> burst = qosconfig->getBurst();
        if (burst) {
            qosConfig->setBurst(burst.get());
        }
        bwToConfig.insert(make_pair(qosconfig->getURI(), qosConfig));
    }


    void QosManager::updateQosConfigState(const shared_ptr<modelgbp::qos::Requirement>& qosconfig) {
        lock_guard<recursive_mutex> guard(opflexagent::QosManager::qos_mutex);
        LOG(INFO) << "Requirement URI: " << qosconfig->getURI().toString();

        optional<shared_ptr<modelgbp::qos::RequirementToEgressRSrc> > RsEgress =
            qosconfig->resolveQosRequirementToEgressRSrc();
        optional<URI> EgressUri;
        const URI ReqUri = qosconfig->getURI();

        clearEntry(ReqUri);

        if (RsEgress){
            EgressUri = RsEgress.get()->getTargetURI();
            if (EgressUri){
                LOG(INFO) << "Egress URI: " << EgressUri.get().toString();
                updateEntry(ReqUri, EgressUri.get(), egressPolInterface);
            }
        }

        optional<shared_ptr<modelgbp::qos::RequirementToIngressRSrc> > RsIngress =
            qosconfig->resolveQosRequirementToIngressRSrc();
        optional<URI> IngressUri;

        if (RsIngress){
            IngressUri = RsIngress.get()->getTargetURI();
            if (IngressUri){
                LOG(INFO) << "Ingress URI: " << IngressUri.get().toString();
                updateEntry(ReqUri, IngressUri.get(), ingressPolInterface);
            }
        }

        reqToPol.insert(make_pair(qosconfig->getURI(), make_pair(EgressUri,IngressUri)));
    }

    void QosManager::QosUniverseListener::processQosConfig(const shared_ptr<modelgbp::qos::Requirement>& qosconfig) {
        qosmanager.updateQosConfigState(qosconfig);
    }

    void QosManager::QosUniverseListener::processQosConfig(const shared_ptr<modelgbp::qos::BandwidthLimit>& qosconfig) {
        qosmanager.updateQosConfigState(qosconfig);
    }

    void QosManager::clearEntry(const string& interface, const URI& uri, unordered_map<URI, unordered_set<string>>& policyMap){
	    auto itr = policyMap.find(uri);
	    if (itr != policyMap.end()){
		    unordered_set<string> &interfaces = itr->second;
		    auto itr = interfaces.find(interface);
		    if (itr != interfaces.end()){
			    interfaces.erase(interface);
		    }
	    }
    }

    void QosManager::clearEntry(const URI& reqUri){
        optional<URI> egressUri;
        optional<URI> ingressUri;
        unordered_set<string> reqInterfaces;

        auto itr1 = reqToInterface.find(reqUri);
        if (itr1 == reqToInterface.end()){
            return;
        }
        reqInterfaces = itr1->second;

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
        }

        if (ingressUri){
            auto itr3 = ingressPolInterface.find(ingressUri.get());
            if (itr3 != ingressPolInterface.end()){
                unordered_set<string> & updateInterfaces = itr3->second;
                for(const auto& intf : reqInterfaces){
                    updateInterfaces.erase(intf);
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

    void QosManager::addEntry(const string& interface, const URI& uri, unordered_map<URI, unordered_set<string>>& policyMap){
        auto itr = policyMap.find(uri);
        if (itr != policyMap.end()){
            unordered_set<string> &interfaces = itr->second;
            interfaces.insert(interface);
        }else{
            unordered_set<string> interfaces;
            interfaces.insert(interface);
            policyMap.insert(make_pair(uri, interfaces));
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

}

