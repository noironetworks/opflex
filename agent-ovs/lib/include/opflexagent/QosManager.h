/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for QosManager
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_QOSMANAGER_H
#define OPFLEXAGENT_QOSMANAGER_H

#include <opflex/ofcore/OFFramework.h>
#include <opflex/modb/ObjectListener.h>
#include <opflexagent/QosListener.h>
#include <opflexagent/EndpointListener.h>
#include <modelgbp/qos/Requirement.hpp>
#include <modelgbp/qos/BandwidthLimit.hpp>
#include <modelgbp/qos/RequirementToEgressRSrc.hpp>
#include <modelgbp/qos/RequirementToIngressRSrc.hpp>
#include <opflexagent/TaskQueue.h>
#include <opflex/modb/URI.h>

#include <boost/asio.hpp>
#include <boost/optional.hpp>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <string>

using boost::asio::deadline_timer;
using namespace std;
using namespace opflex::modb;


namespace opflexagent {
	
namespace qos = modelgbp::qos;
using namespace qos;

class Agent;
/**
 * class to represent information on qos
 */
class QosManager: public EndpointListener {

public:


    /**
     * Instantiate a new QosManager
     */
    QosManager(Agent& agent_,opflex::ofcore::OFFramework& framework_,
            boost::asio::io_service& agent_io_);

    /**
     * Destroy the QosManager  and clean up all state
     */
    ~QosManager() {};

    /**
     * Start the QosManager
     */
    void start();

    /**
     * Stop the QosManager
     */
    void stop();

    /**
     * get shared ptr to QosConfigState using URI as the key.
     * @param[in] uri URI of the bandwidthLimit for QosConfigState.
     * @return shared ptr to QosConfigState.
     */
    boost::optional<shared_ptr<QosConfigState>> getQosConfigState(const URI& uri) const;

    /**
     * get shared ptr to ingress config for an interface.
     * @param[in] interface name of the interface.
     * @return shared ptr to QosConfigState or none.
     */
    boost::optional<shared_ptr<QosConfigState>> getIngressQosConfigState(const string& interface) const;

    /**
     * get shared ptr to egress config for an interface.
     * @param[in] interface name of the interface.
     * @return shared ptr to QosConfigState or none.
     */
    boost::optional<shared_ptr<QosConfigState>> getEgressQosConfigState(const string& interface) const;

    /**
     * update the egress and ingress policy uri in Requirement.
     * @param[in] requirement shared ptr to updated Requirement.
     */
    void updateQosConfigState(const shared_ptr<modelgbp::qos::Requirement>& requirement);

    /**
     * update qosConfigState for a bandwidthLimit object.
     * @param[in] requirement shared ptr to bandwidthLimit object.
     */
    void updateQosConfigState(const shared_ptr<modelgbp::qos::BandwidthLimit>& requirement);


    /**
     * update interfaces for a requirement to its ingress and egress policies.
     * @param[in] reqUri requirement uri.
     * @param[in] dirUri egress or ingress uri. 
     * @param[in] policyMap egress or ingress policy map mapping bandwidthLimit to interfaces.
     */
    void updateEntry(const URI& reqUri, const URI& dirUri, unordered_map<URI, unordered_set<string>>& policyMap);

    /**
     * remove interfaces of requirement from its ingress and egress policies.
     * @param[in] reqUri Uri of Requirement object
     */
    void clearEntry(const URI& reqUri);

    /**
     * update egress or ingress policy map by removing entry for input interface.
     * @param[in] interface name of the interface.
     * @param[in] uri Uri of ingress or egress policy.
     * @param[in] policyMap egress or ingress policy map.
     */
    void clearEntry(const string& interface, const URI& uri, unordered_map<URI, unordered_set<string>>& policyMap);

    /**
     * update egress or ingress policy map by adding entry for input interface.
     * @param[in] interface name of the interface.
     * @param[in] uri Uri of ingress or egress policy.
     * @param[in] policyMap egress or ingress policy map.
     */
    void addEntry(const string& interface, const URI& uri, unordered_map<URI, unordered_set<string>>& policyMap);

    /**
     * update all entries for interface in all maps to reflect its association to new requirement object.
     * @param[in] interface name of the interface.
     * @param[in] newReq Uri of requirement policy.
     */
    void updateInterfacePolicyMap(const string& interface, const URI& newReq);

    /**
     * Remove all entries for interface in all maps.
     * @param[in] interface name of the interface.
     */
    void clearInterfaceEntry(const string & interface);

    /**
     * Listen to endpointManager for new endpoints.
     * @param[in] uuid Uuid of a new endpoint.
     */
    virtual void endpointUpdated(const std::string& uuid);

    /**
     * Listen to endpointManager for new endpoints.
     * @param[in] uuid Uuid of a new endpoint.
     */
    virtual void remoteEndpointUpdated(const std::string& uuid);

    /**
     * Listen to endpointManager for new endpoints.
     * @param[in] uri.
     */
    virtual void localExternalDomainUpdated(const opflex::modb::URI& uri);
    
    /**
     * Handle endpoint update from endpointManager.
     * @param[in] uuid Uuid of a new endpoint.
     */
    void handleEndpointUpdate(const std::string& uuid);
    /**
     * Register a listener for Qos change events
     *
     * @param listener the listener functional object that should be
     * called when changes occur related to the class.  This memory is
     * owned by the caller and should be freed only after it has been
     * unregistered.
     * @see PolicyListener
     */
    void registerListener(QosListener* listener);

    /**
     * Unregister Listener for qos change events
     * @param listener the listener functional object that should be
     * called when changes occur related to the class.  This memory is
     * owned by the caller and should be freed only after it has been
     * unregistered.
     * @see PolicyListener
     */
    void unregisterListener(QosListener* listener);

    /**
     * Notify qos listeners about an update to the qos
     * configuration.
     * @param interface the interface whose qos is to be updated
     * @param direction egress/ingress/both direction of qos to be updated
     */
    void notifyListeners(const string& interface, const string& direction);

    /**
     * Notify qos listeners about clearing qos parameters 
     * @param interfaces set of interfaces on which qos is to be removed
     */
    void notifyListeners(const unordered_set<string>& interfaces);

    /**
     * Listener for changes related to qos
     */
    class QosUniverseListener : public opflex::modb::ObjectListener {
    public:
        /**
         * constructor for QosUniverseListener
         * @param[in] qosmanager reference to qos manager
         */
        QosUniverseListener(QosManager& qosmanager);
        virtual ~QosUniverseListener();

        /**
         * callback for handling updates to Qos universe
         * @param[in] class_id class id of updated object
         * @param[in] uri of updated object
         */
        virtual void objectUpdated(opflex::modb::class_id_t class_id,
                                   const URI& uri);

        /**
         * process requirement update
         * @param[in] requirementConfig shared pointer to a Requirement object
         */
         void processQosConfig(const shared_ptr<modelgbp::qos::Requirement>& requirementConfig);

	 /**
	  * process bandwidth update
	  * @param[in] requirementConfig shared pointer to a BandwidthLimit object
	  */
	 void processQosConfig(const shared_ptr<modelgbp::qos::BandwidthLimit>& requirementConfig);

    private:
        QosManager& qosmanager;

    };

    /**
     * instance of qos universe listener class.
     */
    QosUniverseListener qosUniverseListener;

private:
    
    Agent& agent;
    opflex::ofcore::OFFramework& framework;
    
    list<QosListener*> qosListeners;
    mutex listener_mutex;
    TaskQueue taskQueue;
    static recursive_mutex qos_config_mutex; 
    static recursive_mutex interface_mutex;
  
    std::atomic<bool> stopping;
   
    unordered_map<string, URI> InterfaceToReq;
    unordered_map<URI, unordered_set<string>> ReqToInterface;

    unordered_map<URI, pair<boost::optional<URI>, boost::optional<URI> > > ReqToPol;
    unordered_map<URI, unordered_set<string>> EgressPolInterface;
    unordered_map<URI, unordered_set<string>> IngressPolInterface;
    
    unordered_map<URI, shared_ptr<QosConfigState>> BwToConfig;

    unordered_set<URI> notifyUpdate;
    unordered_set<URI> notifyDelete;
};
}


#endif /* OPFLEXAGENT_QOSMANAGER_H */
