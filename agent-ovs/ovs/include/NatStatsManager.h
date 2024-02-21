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
     * Instantiate a new nat stats manager that will use the provided io
     * service for scheduling asynchronous tasks
     *
     * @param agent the agent associated with the stats manager
     * @param idGen the ID generator
     * @param switchManager the switchManager associated with the Policy Stats Manager
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
    
    // see: MessageHandler
    void Handle(SwitchConnection *swConn,
                int type,
                ofpbuf *msg,
                struct ofputil_flow_removed* fentry=NULL) override;

    /** Interface: ObjectListener */
    void objectUpdated(opflex::modb::class_id_t class_id,
                       const opflex::modb::URI& uri) override;


   /**Struct to store Ep mappings to export it to Nat Counter */
   struct Nat_attr {
       std::string mappedIp;
       std::string floatingIp;
       std::string src_epg;
       std::string dst_epg;
       std::string uuid;
   };

private:


   /**
     * Type used as a key for Nat traffic counter maps
     */
    struct NatTrafficFlowMatchKey_t {
        /**
         * Trivial constructor for nat flow match key
         */
        NatTrafficFlowMatchKey_t(uint32_t k1, uint32_t k2, string k3) {
            vnid = k1;
            rd = k2;
            ip = k3;
        }

        /**
         * Flow cookie
         */
        uint32_t vnid;
	uint32_t rd;
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

     /**
     * Flow Stats - used by Nat Flow egress and ingress.
     */
    struct NatFlowStats_t {
        /**
         * Counter in packets
         */
        boost::optional<uint64_t> packet_count;
        /**
         * Counter in bytes
         */
        boost::optional<uint64_t> byte_count;

        //Vm's ip address
        std::string vmIp;

        //External Floating Ip
        std::string fip;
  
        //Src epg
        std::string sepg;

        //dst epg
        std::string depg;

        //Ep Uuid
        std::string epUuid;
    };
    /** map for flow to Nat traffic counters */
    typedef std::unordered_map<NatTrafficFlowMatchKey_t,
                               NatFlowStats_t,
                               NatFlowKeyHasher> NatFlowCounterMap_t;

    /**
     * Get aggregated stats counters from for nat flows
     */
    void on_timer_base(const boost::system::error_code& ec,
                       flowCounterState_t& counterState,
                       NatFlowCounterMap_t& newClassCountersMap,
                       uint32_t table_id);


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
