/*
 * Include file for stats manager
 *
 * Copyright (c) 2023 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/logging.h>
#include "IntFlowManager.h"
#include <opflexagent/IdGenerator.h>
#include <opflexagent/Agent.h>
#include "TableState.h"
#include "NatStatsManager.h"
#include "FlowConstants.h"

#include "ovs-ofputil.h"
#include <lib/util.h>
extern "C" {
  #include <openvswitch/ofp-msgs.h>
}
#include <sstream>

namespace opflexagent {

using boost::make_optional;
using std::string;
using std::shared_ptr;
using boost::optional;
using boost::asio::placeholders::error;
using boost::posix_time::milliseconds;
using boost::system::error_code;
using std::bind;


NatStatsManager::NatStatsManager(Agent* agent_, IdGenerator& idGen_, SwitchManager& switchManager_, IntFlowManager& intFlowManager_, long timer_interval_)
     : PolicyStatsManager(agent_,idGen_,switchManager_,timer_interval_),intFlowManager(intFlowManager_) {

}
NatStatsManager::~NatStatsManager() {

}

void NatStatsManager::start() {

    LOG(INFO) << "Starting Nat stats manager ("
               << timer_interval << " ms)";
    PolicyStatsManager::start();
    
    {
        std::lock_guard<std::mutex> lock(timer_mutex);
        timer->async_wait(bind(&NatStatsManager::on_timer, this, error));
    } 
}

void NatStatsManager::stop() {
         LOG(DEBUG) << "Stopping Nat stats manager";
	PolicyStatsManager::stop();
}

void NatStatsManager::on_timer(const error_code& ec) {
   if (ec) {
	std::lock_guard<std::mutex> lock(timer_mutex);
	LOG(DEBUG) << "Resetting timer, error: " << ec.message();
	timer.reset();
	return;
    }
    {
    	TableState::cookie_callback_t cb_func;
    	cb_func = [this](uint64_t cookie, uint16_t priority,
                     const struct match& match) {
	const std::lock_guard<std::mutex> lock(pstatMtx);
    	updateFlowEntryMap(routeTableState, cookie, priority, match);
    	};  
        switchManager.forEachCookieMatch(IntFlowManager::ROUTE_TABLE_ID,cb_func);
        const std::lock_guard<std::mutex> lock(pstatMtx);
        // aggregate ingress CounterMap based on FlowCounterState
        NatFlowCounterMap_t ingCountersMap;
        on_timer_base(ec, routeTableState, ingCountersMap, IntFlowManager::ROUTE_TABLE_ID);
        
        // Update Nat stats objects. IntFlowManager would
        // have already created the objects. If its not resolved,
        // then new objects will get created
        const string& ingress="ingress";
        updateNatStatsObjects(&ingCountersMap, ingress);

    }
    {
	TableState::cookie_callback_t cb_func;
        cb_func = [this](uint64_t cookie, uint16_t priority,
                     const struct match& match) {
        const std::lock_guard<std::mutex> lock(pstatMtx);
        updateFlowEntryMap(outTableState, cookie, priority, match);
        };
        switchManager.forEachCookieMatch(IntFlowManager::OUT_TABLE_ID,cb_func);
        //const std::lock_guard<std::mutex> lock(pstatMtx);
        // aggregate eggress CounterMap based on FlowCounterState
        NatFlowCounterMap_t egCountersMap;
        on_timer_base(ec, outTableState, egCountersMap, IntFlowManager::OUT_TABLE_ID);
        const string& egress="egress";
        updateNatStatsObjects(&egCountersMap, egress);
     }


     {
        TableState::cookie_callback_t cb_func;
        cb_func = [this](uint64_t cookie, uint16_t priority,
                     const struct match& match) {
         const std::lock_guard<std::mutex> lock(pstatMtx);
        updateFlowEntryMap(srcTableState, cookie, priority, match);
        };
        switchManager.forEachCookieMatch(IntFlowManager::SRC_TABLE_ID,cb_func);
        //const std::lock_guard<std::mutex> lock(pstatMtx);
        // aggregate eggress CounterMap based on FlowCounterState
        NatFlowCounterMap_t srcCountersMap;
        on_timer_base(ec, srcTableState,srcCountersMap, IntFlowManager::SRC_TABLE_ID);
        const string& ingress="ingress";
        // we need to change this to incoming and outgoint packet
        updateNatStatsObjects(&srcCountersMap, ingress);
     }

        sendRequest(IntFlowManager::ROUTE_TABLE_ID, flow::cookie::NAT_FLOW,
                    flow::cookie::NAT_FLOW);
        sendRequest(IntFlowManager::OUT_TABLE_ID, flow::cookie::NAT_FLOW,
                    flow::cookie::NAT_FLOW);
        sendRequest(IntFlowManager::SRC_TABLE_ID, flow::cookie::NAT_FLOW,
                    flow::cookie::NAT_FLOW);
     if (!stopping) {
        std::lock_guard<std::mutex> lock(timer_mutex);
        if (timer) {
            timer->expires_from_now(milliseconds(timer_interval));
            timer->async_wait(bind(&NatStatsManager::on_timer, this, error));
        }
    }
}


// Generate/update Pod <--> Svc stats objects
void NatStatsManager::updateNatStatsObjects(NatFlowCounterMap_t *newCountersMap, const string& direction) {

    // walk through newCountersMap to update new set of MOs
    for (NatFlowCounterMap_t:: iterator itr = newCountersMap->begin();
         itr != newCountersMap->end();
         ++itr) {

        const NatTrafficFlowMatchKey_t& flowKey = itr->first;
        FlowStats_t&  newCounters = itr->second;
	LOG(INFO) << "update objects -- packet count "<<newCounters.packet_count.get();
	LOG(INFO) << "flowKey.reg "<< flowKey.reg;
	LOG(INFO) << "flowKey.ip "<< flowKey.ip;
        if (newCounters.packet_count.get() != 0) {
           intFlowManager.updateNatStatsCounters(direction,
                                                flowKey.reg,
       			                        flowKey.ip,
                                                newCounters.packet_count.get(),
                                                newCounters.byte_count.get());
       }
    }
}

  
  bool  NatStatsManager::check_if_match_exist(const FlowEntryMatchKey_t& flowkey, uint32_t& table_id, 
					      uint32_t& reg, string& ip){
     struct in_addr addr;
     if(table_id==IntFlowManager::ROUTE_TABLE_ID){
        addr = {flowkey.match->flow.nw_dst};
        reg = flowkey.match->flow.regs[0];
        ip = inet_ntoa(addr);
     } else if(table_id==IntFlowManager::OUT_TABLE_ID){
        addr = {flowkey.match->flow.nw_src};
        reg = flowkey.match->flow.regs[7];
        ip = inet_ntoa(addr);
     } else if(table_id==IntFlowManager::SRC_TABLE_ID){
        addr = {flowkey.match->flow.nw_dst};
        reg = flowkey.match->flow.regs[2];
        ip = inet_ntoa(addr);
     }
     return intFlowManager.checkFlowMap(reg, inet_ntoa(addr));
}

const string NatStatsManager::unit32_to_string(const uint32_t ipAddress){
    std::ostringstream ip_format;
    ip_format << ((ipAddress >> 24) && 0xFF) << '.'
              << ((ipAddress >> 16) && 0xFF) << '.'
              << ((ipAddress >> 8) && 0xFF) << '.'
              << (ipAddress && 0xFF) ;
    return ip_format.str();

}
// update nat statsCounterMap based on FlowCounterState
void NatStatsManager::on_timer_base(const error_code& ec,
              flowCounterState_t& counterState,
              NatFlowCounterMap_t& statsCountersMap,
	      uint32_t table_id) {

    // Walk through all the old map entries that have
    // been visited.
   
    for (auto& i : counterState.oldFlowCounterMap) {
        const FlowEntryMatchKey_t& flowEntryKey = i.first;
        FlowCounters_t& newFlowCounters = i.second;

        uint32_t  reg ;
        string ip;  
        bool flag = check_if_match_exist(flowEntryKey, table_id, reg, ip);
	if(flag) {
	    LOG(INFO) << "flag found ip address "<< ip;
            LOG(INFO) << "flag found reg "<< reg;  
	}
        NatTrafficFlowMatchKey_t flowMatchKey(reg,ip);

        FlowStats_t&  newStatsCounters = statsCountersMap[flowMatchKey];
        newStatsCounters.packet_count = 10; 
        newStatsCounters.byte_count = 100;
        newFlowCounters.diff_packet_count = make_optional(true, 0);
        newFlowCounters.diff_byte_count = make_optional(true, 0);
        newFlowCounters.age = 0;
        newFlowCounters.visited = false;
 //  } 
  //      bool flag = check_if_match_exist(flowEntryKey.match->flow.regs[0],
  //                                           flowEntryKey.match->flow.regs[2],
  //                                           flowEntryKey.match->flow.regs[7],
  //                                           flowEntryKey.match->flow,
  //                                           table_id);

      // Have we visited this flow entry yet
        if (!newFlowCounters.visited) {
            // increase age by polling interval
            newFlowCounters.age += 1;
            if (newFlowCounters.age >= MAX_AGE) {
                LOG(DEBUG) << "Unvisited entry for last " << MAX_AGE
                           << " polling intervals: "
                           << flowEntryKey.cookie << ", "
                           << *flowEntryKey.match;
            }
            continue;
        }
        // Have we collected non-zero diffs for this flow entry
        if (newFlowCounters.diff_packet_count &&
            newFlowCounters.diff_packet_count.get() != 0) {
	    bool flag = check_if_match_exist(flowEntryKey, table_id, reg, ip);
	    if (!flag) {
		return;
	    }
	    if(flag){
		LOG(INFO) << "flag found ip address "<< ip;
                LOG(INFO) << "flag found reg "<< reg;
	    }
            NatTrafficFlowMatchKey_t flowMatchKey(reg,ip);

            FlowStats_t&  newStatsCounters =
                                statsCountersMap[flowMatchKey];
            uint64_t packet_count = 0;
            uint64_t byte_count = 0;
            if (newStatsCounters.packet_count) {
                // get existing packet_count and byte_count
                packet_count = newStatsCounters.packet_count.get();
                byte_count = newStatsCounters.byte_count.get();
            }

            // Add counters for new flow entry to existing
            // packet_count and byte_count
            if (newFlowCounters.diff_packet_count) {
                newStatsCounters.packet_count =
                    make_optional(true,
                                  newFlowCounters.diff_packet_count.get() +
                                  packet_count);
        	LOG(INFO)<< "final packet count that we are storing "<<newStatsCounters.packet_count.get();
                newStatsCounters.byte_count =
                    make_optional(true,
                                  newFlowCounters.diff_byte_count.get() +
                                  byte_count);
            }

            // reset the per flow entry diff counters to zero.
            newFlowCounters.diff_packet_count = make_optional(true, 0);
            newFlowCounters.diff_byte_count = make_optional(true, 0);
            // set the age of this entry as zero as we have seen
            // its counter increment last polling cycle.
            newFlowCounters.age = 0;
        }
        // Set entry visited as false as we have consumed its diff
        // counters.  When we visit this entry when handling a
        // FLOW_STATS_REPLY corresponding to this entry, we mark this
        // entry as visited again.
        newFlowCounters.visited = false;
    }


  //      // Walk through all the removed flow map entries
       for (auto& i : counterState.removedFlowCounterMap) {
            LOG(INFO) << "Inside removed flow entry--------";
            const FlowEntryMatchKey_t& remFlowEntryKey = i.first;
            FlowCounters_t&  remFlowCounters = i.second;
            uint32_t  reg ;
            string ip;
  //      // Have we collected non-zero diffs for this removed flow entry
          if (remFlowCounters.diff_packet_count) {
		bool flag = check_if_match_exist(remFlowEntryKey, table_id, reg, ip);
           	if (!flag) {
               	    return;
           	}
           if(flag) {
                LOG(INFO) << "flag found ip address "<< ip;
                LOG(INFO) << "flag found reg "<< reg;
            }
            NatTrafficFlowMatchKey_t flowMatchKey(reg,ip);

            FlowStats_t& newStatsCounters =
                statsCountersMap[flowMatchKey];

            uint64_t packet_count = 0;
            uint64_t byte_count = 0;
            if (newStatsCounters.packet_count) {
                // get existing packet_count and byte_count
                packet_count = newStatsCounters.packet_count.get();
                byte_count = newStatsCounters.byte_count.get();
            }

            // Add counters for flow entry to be removed
            newStatsCounters.packet_count =
                make_optional(true,
                              (remFlowCounters.diff_packet_count)
                              ? remFlowCounters.diff_packet_count.get()
                              : 0 + packet_count);
            newStatsCounters.byte_count =
                make_optional(true,
                              (remFlowCounters.diff_byte_count)
                              ? remFlowCounters.diff_byte_count.get()
                              : 0 + byte_count);
        }
    }


  //  counterState.removedFlowCounterMap.clear();

    // Walk through all the old map entries and remove those entries
    // that have not been visited but age is equal to MAX_AGE times
    // polling interval.

    for (auto itr = counterState.oldFlowCounterMap.begin(); itr != counterState.oldFlowCounterMap.end();) {
        FlowCounters_t& flowCounters = itr->second;
        // Have we visited this flow entry yet
        if (!flowCounters.visited && (flowCounters.age >= MAX_AGE)) {
            itr = counterState.oldFlowCounterMap.erase(itr);
        } else
            itr++;
    }

    // Walk through all the new map entries and remove those entries
    // that have age equal to MAX_AGE times polling interval.
    for (auto itr = counterState.newFlowCounterMap.begin();
         itr != counterState.newFlowCounterMap.end();) {
        FlowCounters_t& flowCounters = itr->second;
        // Have we visited this flow entry yet
        if (flowCounters.age >= MAX_AGE) {
            itr = counterState.newFlowCounterMap.erase(itr);
        } else
            itr++;
    }
}

bool NatStatsManager::NatTrafficFlowMatchKey_t::
operator==(const NatTrafficFlowMatchKey_t &other) const {
    return (reg == other.reg
	    && ip == other.ip);
}

size_t NatStatsManager::NatFlowKeyHasher::
operator()(const NatStatsManager::NatTrafficFlowMatchKey_t& k) const noexcept {
    using boost::hash_value;
    using boost::hash_combine;

    std::size_t seed = 0;
    hash_combine(seed, hash_value(k.reg));
    hash_combine(seed, hash_value(k.ip));
    return (seed);
}

void NatStatsManager::objectUpdated(opflex::modb::class_id_t class_id,
                                         const URI& uri) {
    /* Don't need to register for any object updates. nat stats are
     * not related to specific objects
     */
}

void NatStatsManager::Handle(SwitchConnection* connection,
                                int msgType,
                                ofpbuf *msg,
                                struct ofputil_flow_removed* fentry) {
    LOG(DEBUG) << "Inside Nat Stats manager message handler";
    handleMessage(msgType, msg,
                  [this](uint32_t table_id) -> flowCounterState_t* {
                      switch (table_id) {
                      case IntFlowManager::ROUTE_TABLE_ID:
                          return &routeTableState;
                      case IntFlowManager::OUT_TABLE_ID:
                          return &outTableState;
		      case IntFlowManager::SRC_TABLE_ID:
			  return &srcTableState;
                      default:
                          return NULL;
                      }
                  }, fentry);
}

} /* namespace opflexagent */
