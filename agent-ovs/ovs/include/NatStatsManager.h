/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for stats manager
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#include "PolicyStatsManager.h"


#pragma once
#ifndef OPFLEXAGENT_NATSTATSMANAGER_H
#define OPFLEXAGENT_NATSTATSMANAGER_H


namespace opflexagent {

class Agent;
/**
 * Periodically query an OpenFlow switch for policy counters and stats
 * and distribute them as needed to other components for reporting.
 */

class NatStatsManager :public PolicyStatsManager {
public:

    /**
     * Instantiate a new stats manager that will use the provided io
     * service for scheduling asynchronous tasks
     *
     * @param agent the agent associated with the stats manager
     * @param intPortMapper the integration bridge port mapper
     * @param accessPortMapper the access bridge port mapper
     * @param intFlowManager the intFlowManager associated with the
        Policy Stats Manager
     * @param timer_interval the interval for the stats timer in
     * milliseconds
     */
    NatStatsManager(Agent* agent, IdGenerator& idGen, SwitchManager& switchManager, IntFlowManager& intFlowManager, long timer_interval_=30000);

    /**
     * Destroy the stats manager and clean up all state
     */
     virtual ~NatStatsManager() ;

     /**
     * Register the connections with the stats manager.  This
     * connection will be queried for counters.
     *
     * @param intConnection the connection to use for integration
     * bridge stats collection
     * @param accessConnection the connection to use for access bridge
     * stats collection
     */
//    void registerConnection(SwitchConnection* connection);

    /**
     * Set the interval between stats requests.
     *
     * @param timerInterval the interval in milliseconds
     */
 //   void setTimerInterval(long timerInterval) {
   //     timer_interval = timerInterval;
  //  }

    /**
     * Start the stats manager
     */
    void start();

    /**
     * Stop the stats manager
     */
    void stop();

    /**
     * Timer interval handler.  For unit tests only.
     */
    void on_timer(const boost::system::error_code& ec) override;
    
//    // see: MessageHandler
    void Handle(SwitchConnection *swConn,
                int type,
                ofpbuf *msg,
                struct ofputil_flow_removed* fentry=NULL) override;

    /** Interface: ObjectListener */
    void objectUpdated(opflex::modb::class_id_t class_id,
                       const opflex::modb::URI& uri) override;


   struct Nat_attr {

       std::string mappedIp;
       std::string floatingIp;
       std::string src_epg;
       std::string dst_epg;
       std::string uuid;
   };
//    
//    /**
//     * Send a flow stats request to the given table
//     */
//    void sendRequest(uint32_t table_id, uint64_t _cookie=0,
//                     uint64_t _cookie_mask=0);
//

private:


   /**
     * Type used as a key for Nat traffic counter maps
     */
    struct NatTrafficFlowMatchKey_t {
        /**
         * Trivial constructor for nat flowe match key
         */
        NatTrafficFlowMatchKey_t(uint32_t k1, string k2) {
            reg = k1;
            ip = k2;
        }

        /**
         * Flow cookie
         */
        uint32_t reg;
        string ip;

        /**
         * equality operator
         */
        bool operator==(const NatTrafficFlowMatchKey_t &other) const;
    };

    /**
     * Hasher for ServiceFlowMatchKey_t
     */
    struct NatFlowKeyHasher {
        /**
         * Hash for FlowMatch Key
         */
        size_t operator()(const NatTrafficFlowMatchKey_t& k) const noexcept;
    };

    /** map flow to Natted traffic info and counters */
    typedef std::unordered_map<NatTrafficFlowMatchKey_t,
                               FlowStats_t,
                               NatFlowKeyHasher> NatFlowCounterMap_t;

    /**
     * Get aggregated stats counters from for nat flows
     */
    void on_timer_base(const boost::system::error_code& ec,
                       flowCounterState_t& counterState,
                       NatFlowCounterMap_t& newClassCountersMap,
		       uint32_t table_id);

    bool check_if_match_exist(const FlowEntryMatchKey_t& flowkey, uint32_t& table_id,
			      uint32_t& reg, string& ip);
 //   bool check_if_match_exist(uint32_t reg0,
 //                             uint32_t reg2,
 //                             uint32_t reg7,
 //                             const struct flow& flow,
 //                             uint32_t& table_id);

    const std::string unit32_to_string(const uint32_t ipaddr);
//   Agent* agent;
  // SwitchManager& switchManager;
 //  long timer_interval;
   flowCounterState_t routeTableState;
   flowCounterState_t outTableState; 
   flowCounterState_t srcTableState;
   /**
     * The integration bridge flow manager
     */
    IntFlowManager& intFlowManager;
   
    /**
     * Generate/update the Nat stats objects for from the counter maps
     */
    void  updateNatStatsObjects(NatFlowCounterMap_t *counters, const string &direction); 
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_NATSTATSMANAGER_H */
