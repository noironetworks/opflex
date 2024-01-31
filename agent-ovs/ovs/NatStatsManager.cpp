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
   //By passing this to boost::bind,we would like to 
   //invoke the member-function, who's address is &NatStatsManager::on_timer,
   //on the current object (ie. this).
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
      NatFlowCounterMap_t routeCountersMap;
      on_timer_base(ec, routeTableState, routeCountersMap, IntFlowManager::ROUTE_TABLE_ID);
      // aggregate incoming traffic based on FlowCounterState  
      const string& exttoEp="ExtToEp";
      updateNatStatsObjects(&routeCountersMap, exttoEp);
   }
   {
      TableState::cookie_callback_t cb_func;
      cb_func = [this](uint64_t cookie, uint16_t priority,
                     const struct match& match) {
          const std::lock_guard<std::mutex> lock(pstatMtx);
          updateFlowEntryMap(outTableState, cookie, priority, match);
      };
      switchManager.forEachCookieMatch(IntFlowManager::OUT_TABLE_ID,cb_func);
      // aggregate outgoing traffic based on FlowCounterState
      NatFlowCounterMap_t outCountersMap;
      on_timer_base(ec, outTableState, outCountersMap, IntFlowManager::OUT_TABLE_ID);
      const string& epToExt="EpToExt";
      updateNatStatsObjects(&outCountersMap, epToExt);
     }
     {
        TableState::cookie_callback_t cb_func;
        cb_func = [this](uint64_t cookie, uint16_t priority,
                     const struct match& match) {
            const std::lock_guard<std::mutex> lock(pstatMtx);
            updateFlowEntryMap(srcTableState, cookie, priority, match);
        };
        switchManager.forEachCookieMatch(IntFlowManager::SRC_TABLE_ID,cb_func);
        // aggregate incoming traffic based on FlowCounterState
        NatFlowCounterMap_t srcCountersMap;
        on_timer_base(ec, srcTableState, srcCountersMap, IntFlowManager::SRC_TABLE_ID);
        const string& exttoEp="ExtToEp";
        updateNatStatsObjects(&srcCountersMap, exttoEp);
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


// Generate/update Vm <--> External network stats objects
void NatStatsManager::updateNatStatsObjects(NatFlowCounterMap_t *newCountersMap, const string& direction) {

    // walk through newCountersMap to update new set of MOs
    for (NatFlowCounterMap_t:: iterator itr = newCountersMap->begin();
         itr != newCountersMap->end();
         ++itr) {
        NatFlowStats_t&  newCounters = itr->second;
        if (newCounters.packet_count.get() != 0) {
           intFlowManager.updateNatStatsCounters(direction,
                                                newCounters.packet_count.get(),
                                                newCounters.byte_count.get(),
                                                newCounters.fip,
                                                newCounters.vmIp,
                                                newCounters.sepg,
                                                newCounters.depg,
                                                newCounters.epUuid);
       }
    }
}

// update nat statsCounterMap based on FlowCounterState
void NatStatsManager::on_timer_base( const error_code& ec,
                                     flowCounterState_t& counterState,
                                     NatFlowCounterMap_t& statsCountersMap, 
                                     uint32_t table_id) {

    // Walk through all the old map entries that have
    // been visited.
   
    for (auto& i : counterState.oldFlowCounterMap) {
        const FlowEntryMatchKey_t& flowEntryKey = i.first;
        FlowCounters_t& newFlowCounters = i.second;
        if ((flowEntryKey.cookie & 
            (uint32_t)ovs_ntohll(flow::cookie::NAT_FLOW)) ==0) 
             continue;
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
            struct in_addr addr;
            Nat_attr attr_map;
            uint32_t fepgvnid=0;
            uint32_t rdId=0;
            if (table_id==IntFlowManager::ROUTE_TABLE_ID) {
               //ExtToVm hashmap look up for 1:1 mapping flow stats
                addr = {flowEntryKey.match->flow.nw_dst};
                fepgvnid = flowEntryKey.match->flow.regs[0];
                if (!intFlowManager.updateEpAttributeMap( flowEntryKey.match->flow.regs[0],
                                                         int(0),	
                                                         inet_ntoa(addr),
                                                         &attr_map)) {
                    return;
                }
             } else if (table_id==IntFlowManager::OUT_TABLE_ID) {
                 //VmToExt hashmap look up for 1:1 mapping and SNAT flow stats 
                addr = {flowEntryKey.match->flow.nw_src};
                fepgvnid = flowEntryKey.match->flow.regs[7];
                rdId = flowEntryKey.match->flow.regs[6];
                if (!intFlowManager.updateEpAttributeMap( flowEntryKey.match->flow.regs[7],
                                                         flowEntryKey.match->flow.regs[6],
                                                         inet_ntoa(addr), 
                                                         &attr_map))
                    return;
             } else if (table_id==IntFlowManager::SRC_TABLE_ID ){
                 //ExtToVm hashmap look up for SNAT flow stats
                  addr = {flowEntryKey.match->flow.nw_dst};
                  if (!intFlowManager.updateEpAttributeMap( int(0),
                                                            int(0), 
                                                           inet_ntoa(addr), 
                                                           &attr_map)) {
                      return;
                   }
             }
             NatTrafficFlowMatchKey_t flowMatchKey(fepgvnid, rdId, inet_ntoa(addr));
             NatFlowStats_t&  newStatsCounters = statsCountersMap[flowMatchKey];
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
                 newStatsCounters.byte_count =
                     make_optional(true,
                                   newFlowCounters.diff_byte_count.get() +
                                   byte_count);
              }
              newStatsCounters.vmIp = attr_map.mappedIp;
              newStatsCounters.fip = attr_map.floatingIp;
              newStatsCounters.sepg = attr_map.src_epg;
              newStatsCounters.depg = attr_map.dst_epg;
              newStatsCounters.epUuid = attr_map.uuid;

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


       // Walk through all the removed flow map entries
    for (auto& i : counterState.removedFlowCounterMap) {
          const FlowEntryMatchKey_t& remFlowEntryKey = i.first;
          FlowCounters_t&  remFlowCounters = i.second;
          if ((remFlowEntryKey.cookie & 
              (uint32_t)ovs_ntohll(flow::cookie::NAT_FLOW)) == 0)
               continue; 
           
          // Have we collected non-zero diffs for this removed flow entry
          if (remFlowCounters.diff_packet_count &&
              remFlowCounters.diff_packet_count.get() != 0) {
              struct in_addr addr;
              Nat_attr attr_map;
              uint32_t fepgvnid=0;
              uint32_t rdId=0;
              if (table_id==IntFlowManager::ROUTE_TABLE_ID) {
                  //ExtToVm hashmap look up for 1:1 mapping flow stats
                  addr = {remFlowEntryKey.match->flow.nw_dst};
                  fepgvnid  = remFlowEntryKey.match->flow.regs[0];
                  if (!intFlowManager.updateEpAttributeMap( remFlowEntryKey.match->flow.regs[0],
                                                           int(0), 
                                                           inet_ntoa(addr),
                                                           &attr_map))
                       return;
               } else if (table_id==IntFlowManager::OUT_TABLE_ID) {
                   //VmToExt hashmap look up for 1:1 mapping and SNAT flow stats
                   addr = {remFlowEntryKey.match->flow.nw_src};
                   fepgvnid = remFlowEntryKey.match->flow.regs[7];
                   rdId = remFlowEntryKey.match->flow.regs[6];
                   if (!intFlowManager.updateEpAttributeMap( remFlowEntryKey.match->flow.regs[7],
                                                            remFlowEntryKey.match->flow.regs[6],
                                                            inet_ntoa(addr), 
                                                            &attr_map))
                        return;
                } else if (table_id==IntFlowManager::SRC_TABLE_ID ){
                     //ExtToVm hashmap look up for SNAT flow stats
                    addr = {remFlowEntryKey.match->flow.nw_dst};
                    if (!intFlowManager.updateEpAttributeMap( int(0),
                                                              int(0), 
                                                              inet_ntoa(addr),
                                                              &attr_map))
                        return;
                }
                NatTrafficFlowMatchKey_t flowMatchKey(fepgvnid, rdId, inet_ntoa(addr)); 
                NatFlowStats_t& newStatsCounters = statsCountersMap[flowMatchKey];
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
                                  : packet_count);
                newStatsCounters.byte_count =
                    make_optional(true,
                                  (remFlowCounters.diff_byte_count)
                                  ? remFlowCounters.diff_byte_count.get()
                                  : byte_count);
                newStatsCounters.vmIp = attr_map.mappedIp;
                newStatsCounters.fip = attr_map.floatingIp;
                newStatsCounters.sepg = attr_map.src_epg;
                newStatsCounters.depg = attr_map.dst_epg;
                newStatsCounters.epUuid = attr_map.uuid;
                }
        }

    counterState.removedFlowCounterMap.clear();

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
    return (vnid == other.vnid
            && rd == other.rd 
            && ip == other.ip);
}

size_t NatStatsManager::NatFlowKeyHasher::
operator()(const NatStatsManager::NatTrafficFlowMatchKey_t& k) const noexcept {
    using boost::hash_value;
    using boost::hash_combine;

    std::size_t seed = 0;
    hash_combine(seed, hash_value(k.vnid));
    hash_combine(seed, hash_value(k.rd));
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
