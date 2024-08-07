/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for BaseStatsManager class.
 *
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/logging.h>
#include <opflexagent/IdGenerator.h>
#include <opflexagent/Agent.h>
#include "FlowConstants.h"
#include "IntFlowManager.h"
#include "PolicyStatsManager.h"

#include "ovs-ofputil.h"

#include <openvswitch/lib/util.h>

extern "C" {
#include <openvswitch/ofp-msgs.h>
#include <openvswitch/ofp-monitor.h>
}

#include <opflex/modb/URI.h>
#include <opflex/modb/Mutator.h>

namespace opflexagent {

using std::string;
using boost::optional;
using boost::make_optional;
using std::shared_ptr;
using opflex::modb::URI;
using opflex::modb::Mutator;
using namespace modelgbp::gbp;
using namespace modelgbp::gbpe;
using boost::asio::deadline_timer;
using boost::posix_time::milliseconds;
using boost::system::error_code;

PolicyStatsManager::PolicyStatsManager(Agent* agent_, IdGenerator& idGen_,
                                       SwitchManager& switchManager_,
                                       long timer_interval_)
    : idGen(idGen_), agent(agent_),
      prometheusManager(agent->getPrometheusManager()),
      switchManager(switchManager_),
      connection(NULL),
      timer_interval(timer_interval_),
      stopping(false) {}

PolicyStatsManager::~PolicyStatsManager() {}

void PolicyStatsManager::registerConnection(SwitchConnection* connection) {
    this->connection = connection;
}

void PolicyStatsManager::start(bool register_listener,
                               optional<boost::asio::io_service&> io_service) {
    stopping = false;

    LOG(DEBUG) << "Starting policy stats manager " << this;
    if(connection) {
        connection->RegisterMessageHandler(OFPTYPE_FLOW_STATS_REPLY, this);
        connection->RegisterMessageHandler(OFPTYPE_FLOW_REMOVED, this);
        {
            std::lock_guard<std::mutex> lock(timer_mutex);
            if (io_service)
                timer.reset(new deadline_timer(io_service.get(),
                                               milliseconds(timer_interval)));
            else
                timer.reset(new deadline_timer(agent->getAgentIOService(),
                                               milliseconds(timer_interval)));
        }
    }
    if(register_listener) {
        L24Classifier::registerListener(agent->getFramework(),this);
        LocalL24Classifier::registerListener(agent->getFramework(),this);
    }
}

void PolicyStatsManager::stop(bool unregister_listener) {
    stopping = true;

    LOG(DEBUG) << "Stopping policy stats manager " << this;

    if (connection) {
        connection->UnregisterMessageHandler(OFPTYPE_FLOW_STATS_REPLY, this);
        connection->UnregisterMessageHandler(OFPTYPE_FLOW_REMOVED, this);
    }
    if(unregister_listener) {
        L24Classifier::unregisterListener(agent->getFramework(),this);
    }
    try {
        std::lock_guard<std::mutex> lock(timer_mutex);
        if (timer) {
            LOG(DEBUG) << "timer cancelled";
            timer->cancel();
        }
    } catch (const boost::system::system_error &e ) {
        LOG(DEBUG) << "Failed to cancel timer: " << e.what();
    }
}

void PolicyStatsManager::updateFlowEntryMap(flowCounterState_t& counterState,
                                            uint64_t cookie, uint16_t priority,
                                            const struct match& match) {
    FlowEntryMatchKey_t flowEntryKey(cookie, priority, match);

    /* check if Stats Manager has it in its oldFlowCounterMap */
    if (counterState.oldFlowCounterMap.find(flowEntryKey) !=
        counterState.oldFlowCounterMap.end())
        return;

    /* check if Stats Manager has it in its newFlowCounterMap */
    auto it = counterState.newFlowCounterMap.find(flowEntryKey);
    if (it != counterState.newFlowCounterMap.end()) {
        it->second.age += 1;
        return;
    }
    /* Add the flow entry to newmap */
    FlowCounters_t& flowCounters =
        counterState.newFlowCounterMap[flowEntryKey];
    flowCounters.visited = false;
    flowCounters.age = 0;
    flowCounters.last_packet_count = make_optional(false, 0);
    flowCounters.last_byte_count = make_optional(false, 0);
    flowCounters.diff_packet_count = make_optional(false, 0);
    flowCounters.diff_byte_count = make_optional(false, 0);
}

void PolicyStatsManager::
on_timer_base(const error_code& ec,
              flowCounterState_t& counterState,
              PolicyCounterMap_t& newClassCountersMap) {

    // Walk through all the old map entries that have
    // been visited.
    for (auto& i : counterState.oldFlowCounterMap) {
        const FlowEntryMatchKey_t& flowEntryKey = i.first;
        FlowCounters_t& newFlowCounters = i.second;
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

            PolicyFlowMatchKey_t flowMatchKey(flowEntryKey.cookie,
                                        flowEntryKey.match->flow.regs[0],
                                        flowEntryKey.match->flow.regs[2]);

            FlowStats_t&  newClassCounters =
                newClassCountersMap[flowMatchKey];

            // We get multiple flow stats entries for same
            // cookie, reg0 and reg2 ie for each classifier
            // multiple flow entries may get installed in OVS
            // The newCountersMap is used for the purpose of
            // additing counters of such flows that have same
            // classifier, reg0 and reg2.

            uint64_t packet_count = 0;
            uint64_t byte_count = 0;
            if (newClassCounters.packet_count) {
                // get existing packet_count and byte_count
                packet_count = newClassCounters.packet_count.get();
                byte_count = newClassCounters.byte_count.get();
            }

            // Add counters for new flow entry to existing
            // packet_count and byte_count
            if (newFlowCounters.diff_packet_count) {
                newClassCounters.packet_count =
                    make_optional(true,
                                  newFlowCounters.diff_packet_count.get() +
                                  packet_count);
                newClassCounters.byte_count =
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

    // Walk through all the removed flow map entries
    for (auto& i : counterState.removedFlowCounterMap) {
        const FlowEntryMatchKey_t& remFlowEntryKey = i.first;
        FlowCounters_t&  remFlowCounters = i.second;

        // Have we collected non-zero diffs for this removed flow entry
        if (remFlowCounters.diff_packet_count) {

            PolicyFlowMatchKey_t flowMatchKey(remFlowEntryKey.cookie,
                                        remFlowEntryKey.match->flow.regs[0],
                                        remFlowEntryKey.match->flow.regs[2]);

            FlowStats_t& newClassCounters =
                newClassCountersMap[flowMatchKey];

            uint64_t packet_count = 0;
            uint64_t byte_count = 0;
            if (newClassCounters.packet_count) {
                // get existing packet_count and byte_count
                packet_count = newClassCounters.packet_count.get();
                byte_count = newClassCounters.byte_count.get();
            }

            // Add counters for flow entry to be removed
            newClassCounters.packet_count =
                make_optional(true,
                              (remFlowCounters.diff_packet_count)
                              ? remFlowCounters.diff_packet_count.get()
                              : 0 + packet_count);
            newClassCounters.byte_count =
                make_optional(true,
                              (remFlowCounters.diff_byte_count)
                              ? remFlowCounters.diff_byte_count.get()
                              : 0 + byte_count);
        }
    }

    // Delete all the entries from removedFlowCountersMap
    // Since we have taken them into account in our calculations for
    // per classifier/epg pair counters.

    counterState.removedFlowCounterMap.clear();

    // Walk through all the old map entries and remove those entries
    // that have not been visited but age is equal to MAX_AGE times
    // polling interval.

    for (auto itr = counterState.oldFlowCounterMap.begin();
         itr != counterState.oldFlowCounterMap.end();) {
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

void PolicyStatsManager::updateNewFlowCounters(uint32_t cookie,
                                               uint16_t priority,
                                               struct match& match,
                                               uint64_t flow_packet_count,
                                               uint64_t flow_byte_count,
                                               flowCounterState_t& counterState,
                                               bool flowRemoved) {
    FlowEntryMatchKey_t flowEntryKey(cookie, priority, match);

    // look in existing oldFlowCounterMap
    auto it = counterState.oldFlowCounterMap.find(flowEntryKey);
    if (it != counterState.oldFlowCounterMap.end()) {
        FlowCounters_t& oldFlowCounters = it->second;
        /* compute diffs and mark the entry as visited */
        uint64_t packet_count = oldFlowCounters.last_packet_count.get();
        uint64_t byte_count = oldFlowCounters.last_byte_count.get();

        oldFlowCounters.visited = true;
        if ((flow_packet_count - packet_count) > 0) {
            oldFlowCounters.diff_packet_count =
                flow_packet_count - packet_count;
            oldFlowCounters.diff_byte_count =
                flow_byte_count - byte_count;
            oldFlowCounters.last_packet_count = flow_packet_count;
            oldFlowCounters.last_byte_count = flow_byte_count;
        }
        if (flowRemoved) {
            // Move the entry to removedFlowCounterMap
            FlowCounters_t & newFlowCounters =
                counterState.removedFlowCounterMap[flowEntryKey];
            newFlowCounters.diff_byte_count = oldFlowCounters.diff_byte_count;
            newFlowCounters.diff_packet_count =
                oldFlowCounters.diff_packet_count;
            // Delete the entry from oldFlowCounterMap
            counterState.oldFlowCounterMap.erase(flowEntryKey);
        }
    } else {
        // Check if we this entry exists in newFlowCounterMap;
        auto it = counterState.newFlowCounterMap.find(flowEntryKey);
        if (it != counterState.newFlowCounterMap.end()) {

            // the flow entry probably got removed even before Policy Stats
            // manager could process its FLOW_STATS_REPLY
            if (flowRemoved) {
                FlowCounters_t & remFlowCounters =
                    counterState.removedFlowCounterMap[flowEntryKey];
                remFlowCounters.diff_byte_count =
                    make_optional(true, flow_byte_count);
                remFlowCounters.diff_packet_count =
                    make_optional(true, flow_packet_count);
                // remove the entry from newFlowCounterMap->
                counterState.newFlowCounterMap.erase(flowEntryKey);
            } else {
                // Store the current counters as last counter value by
                // adding the entry to oldFlowCounterMap and expect
                // next FLOW_STATS_REPLY for it to compute delta and
                // mark the entry as visited. If PolicyStats
                // Manager(OVS agent) got restarted then we can't use
                // the counters reported as is until delta is computed
                // as entry may have existed long before it.

                if (flow_packet_count != 0) {
                    /* store the counters in oldFlowCounterMap for it and
                     * remove from newFlowCounterMap as it is no more new
                     */
                    FlowCounters_t & newFlowCounters =
                        counterState.oldFlowCounterMap[flowEntryKey];
                    newFlowCounters.last_packet_count =
                        make_optional(true, flow_packet_count);
                    newFlowCounters.last_byte_count =
                        make_optional(true, flow_byte_count);
                    newFlowCounters.visited = false;
                    newFlowCounters.age = 0;
                    // remove the entry from newFlowCounterMap
                    counterState.newFlowCounterMap.erase(flowEntryKey);
                }
            }
        }
    }
}

void PolicyStatsManager::handleMessage(int msgType,
                                       ofpbuf *msg,
                                       const table_map_t& tableMap,
                                       struct ofputil_flow_removed *fentry) {
    if (msg == (ofpbuf *)NULL) {
        LOG(ERROR) << "Unexpected null message";
        return;
    }
    if (msgType == OFPTYPE_FLOW_STATS_REPLY) {
        std::lock_guard<std::mutex> lock(pstatMtx);
        ofp_header *msgHdr = (ofp_header *)msg->data;
        ovs_be32 recvXid = msgHdr->xid;
        {
            std::lock_guard<mutex> lock(txnMtx);
            if (txns.find(recvXid) == txns.end()) {
                return;
            }
        }
        bool ret = handleFlowStats(msg, tableMap);
        {
            std::lock_guard<mutex> lock(txnMtx);
            if(ret) {
                txns.erase(recvXid);
            }
        }
    } else if (msgType == OFPTYPE_FLOW_REMOVED) {
        std::lock_guard<std::mutex> lock(pstatMtx);
        if(!fentry)
            return;
        flowCounterState_t* counterState = tableMap(fentry->table_id);
        if (!counterState)
            return;
        updateNewFlowCounters((uint32_t)ovs_ntohll(fentry->cookie),
                              fentry->priority,
                              (fentry->match),
                              fentry->packet_count,
                              fentry->byte_count,
                              *counterState, true);
    } else {
        LOG(ERROR) << "Unexpected message type: " << msgType;
    }
}

/**
 * Call this method holding the lock pstatMtx always. Lock has been
 * moved out of this method to avoid adding more specific locks in the
 * code path.
 */
bool PolicyStatsManager::handleFlowStats(ofpbuf *msg, const table_map_t& tableMap) {

    struct ofputil_flow_stats* fentry, fstat;
    fentry = &fstat;

    do {
        ofpbuf actsBuf;
        ofpbuf_init(&actsBuf, 64);
        bzero(fentry, sizeof(struct ofputil_flow_stats));

        int ret = ofputil_decode_flow_stats_reply(fentry, msg, false, &actsBuf);

        ofpbuf_uninit(&actsBuf);

        if (ret != 0) {
            if (ret != EOF) {
                LOG(ERROR) << "Failed to decode flow stats reply: "
                           << ovs_strerror(ret);
                return true;
            } else {
                return !ofpmp_more((ofp_header*)msg->header);
            }
        } else {

            /**
             * From OVS 2.11.2, when we are decoding flows received from ovs
             * using ofputil_decode_flow_stats_reply(), packet_type gets set
             * internally when OVS tries to generate "match" struct from "ofp11_match".
             * While we create flows using ofputil_encode_flow_mod(), packet_type
             * doesnt get set.
             *
             * packet_type is something internal which ovs sets up. From opflex-agent
             * point of view, we dont have to really worry about this packet_type,
             * since it wasnt used during creation of flows. Masking this field's
             * key and wildcard.
             *
             * Mentioning the call sequences for clarity.
             *
             * writeFlow()
             * --> FlowExecutor::DoExecuteNoBlock(const T& fe,
             * --> EncodeMod<typename T::Entry>(e, ofVersion)
             * --> ofputil_encode_flow_mod(&flowMod, proto)
             * --> ofputil_put_ofp11_match(msg, &match, protocol)
             * --> ofputil_match_to_ofp11_match(match, om)
             * --> packet_type is not set in the final match
             *
             * FlowReader::decodeReply()
             * --> ofputil_decode_flow_stats_reply(entry->entry, msg, false,
             * --> ofputil_pull_ofp11_match(msg, NULL, NULL, &fs->match,
             * --> ofputil_match_from_ofp11_match(om, match)
             * --> match_set_default_packet_type(match) <-- This is getting set for
             *                    dl_type, dl_src, dl_dst and some cases of dl_vlan
             */
            if (fentry) {
                fentry->match.flow.packet_type = 0;
                fentry->match.wc.masks.packet_type = 0;
            }

            flowCounterState_t* counterState = tableMap(fentry->table_id);
            if (!counterState)
                return true;

            if ((fentry->flags & OFPUTIL_FF_SEND_FLOW_REM) == 0) {
                // skip those flow entries that don't have flag set
                continue;
            }

            // Does flow stats entry qualify to be a drop entry?
            // if yes, then process it and continue with next flow
            // stats entry.
            if ((fentry->cookie & flow::cookie::RD_POL_DROP_FLOW) ==
                    flow::cookie::RD_POL_DROP_FLOW) {
                handleDropStats(fentry);
                handleTableDropStats(fentry);
            } else if ((fentry->cookie & flow::cookie::TABLE_DROP_FLOW) ==
                    flow::cookie::TABLE_DROP_FLOW) {
                handleTableDropStats(fentry);
            } else {
                // Handle flow stats entries for packets that are matched
                // and are forwarded
                updateNewFlowCounters((uint32_t)ovs_ntohll(fentry->cookie),
                                      fentry->priority,
                                      (fentry->match),
                                      fentry->packet_count,
                                      fentry->byte_count,
                                      *counterState, false);
            }
        }  
    } while (true);

}

void PolicyStatsManager::sendRequest(uint32_t table_id, uint64_t _cookie,
        uint64_t _cookie_mask) {

    if (!connection)
        return;

    // send port stats request again
    ofp_version ofVer = (ofp_version)connection->GetProtocolVersion();
    ofputil_protocol proto = ofputil_protocol_from_ofp_version(ofVer);

    ofputil_flow_stats_request fsr;
    bzero(&fsr, sizeof(ofputil_flow_stats_request));
    fsr.aggregate = false;
    match_init_catchall(&fsr.match);
    fsr.table_id = table_id;
    fsr.out_port = OFPP_ANY;
    fsr.out_group = OFPG_ANY;
    fsr.cookie = (uint64_t)_cookie;
    fsr.cookie_mask = (uint64_t) _cookie_mask;

    OfpBuf req(ofputil_encode_flow_stats_request(&fsr, proto));
    ofpmsg_update_length(req.get());
    ovs_be32 reqXid = ((ofp_header *)req->data)->xid;
    {
        std::lock_guard<mutex> lock(txnMtx);
        txns.insert(reqXid);
    }

    int err = connection->SendMessage(req);
    if (err != 0) {
        LOG(ERROR) << "Failed to send stats request"
                   << " swname: " << connection->getSwitchName()
                   << " tableid: " << table_id
                   << " err: " << ovs_strerror(err);
    }
}

static bool isExtNet(uint64_t reg) {
    return (reg & (1 << 31));
}

// Generate/update Policy table stats objects
void PolicyStatsManager::
generatePolicyStatsObjects(PolicyCounterMap_t *newCountersMap1,
                           PolicyCounterMap_t *newCountersMap2) {
    // walk through newCountersMap to create new set of MOs
    PolicyManager& polMgr = agent->getPolicyManager();

    for (PolicyCounterMap_t:: iterator itr = newCountersMap1->begin();
         itr != newCountersMap1->end();
         ++itr) {
        const PolicyFlowMatchKey_t& flowKey = itr->first;
        FlowStats_t&  newCounters1 = itr->second;
        FlowStats_t  newCounters2;
        optional<URI> srcEpgUri;
        optional<URI> dstEpgUri;
        if (newCountersMap2 != NULL) {
            auto it = newCountersMap2->find(flowKey);
            if (it != newCountersMap2->end()) {
                newCounters2 = it->second ;
            }
        } else {
            if (isExtNet(flowKey.reg0) || isExtNet(flowKey.reg2)) {
                // ignore contracts with external networks
                continue;
            }

            srcEpgUri = polMgr.getGroupForVnid(flowKey.reg0);
            dstEpgUri = polMgr.getGroupForVnid(flowKey.reg2);
            if (srcEpgUri == boost::none) {
                LOG(DEBUG) << "Reg0: " << flowKey.reg0
                           << " to EPG URI translation does not exist";
                continue;
            }
            if (dstEpgUri == boost::none) {
                LOG(DEBUG) << "Reg2: " << flowKey.reg2
                           << " to EPG URI translation does not exist";
                continue;
            }
        }
        optional<string> idStr =
            idGen.getStringForId(IntFlowManager::
                                 getIdNamespace(L24Classifier::CLASS_ID),
                                 flowKey.cookie);
        if (idStr == boost::none) {
            LOG(DEBUG) << "Cookie: " << flowKey.cookie
                       << " to Classifier URI translation does not exist";
            continue;
        }
        if (newCountersMap2 != NULL) {
            updatePolicyStatsCounters(idStr.get(),
                                      newCounters1,newCounters2);
        } else {
            if (newCounters1.packet_count.get() != 0) {
                updatePolicyStatsCounters(srcEpgUri.get().toString(),
                                          dstEpgUri.get().toString(),
                                          idStr.get(),
                                          newCounters1);
            }

        }
    }

    // handle SG OUT/Tx table alone is getting updated
    if (!newCountersMap1->size() && newCountersMap2) {
        for (PolicyCounterMap_t:: iterator itr = newCountersMap2->begin();
             itr != newCountersMap2->end();
             ++itr) {
            const PolicyFlowMatchKey_t& flowKey = itr->first;
            FlowStats_t&  outCounters = itr->second;
            FlowStats_t   inCounters;
            optional<string> idStr =
                idGen.getStringForId(IntFlowManager::
                                     getIdNamespace(L24Classifier::CLASS_ID),
                                     flowKey.cookie);
            if (idStr == boost::none) {
                LOG(DEBUG) << "Cookie: " << flowKey.cookie
                           << " to Classifier URI translation does not exist";
                continue;
            }
            updatePolicyStatsCounters(idStr.get(),
                                      inCounters,outCounters);
        }
    }
}

void PolicyStatsManager::removeAllCounterObjects(const string& key) {
    if (!genIdList_.count(key)) return;
    Mutator mutator(agent->getFramework(), "policyelement");
    for (size_t i = 0; i < genIdList_[key]->uidList.size(); i++)
        clearCounterObject(key, i);
    if (genIdList_.count(key)) genIdList_.erase(genIdList_.find(key));
    mutator.commit();
}

void PolicyStatsManager::clearOldCounters(const string& key,
                                          uint64_t nextId) {
    if (!genIdList_.count(key)) {
        genIdList_[key] =
            std::unique_ptr<CircularBuffer>(new CircularBuffer());
    }
    if (genIdList_[key]->count == MAX_COUNTER_LIMIT) {
        genIdList_[key]->count = 0;
    }
    if (genIdList_[key]->uidList.size() == MAX_COUNTER_LIMIT) {
        clearCounterObject(key,genIdList_[key]->count);
        genIdList_[key]->uidList[genIdList_[key]->count] = nextId;
    } else {
        genIdList_[key]->uidList.push_back(nextId);
    }
    genIdList_[key]->count++;
}

bool PolicyStatsManager::PolicyFlowMatchKey_t::
operator==(const PolicyFlowMatchKey_t &other) const {
    return (cookie == other.cookie
            && reg0 == other.reg0
            && reg2 == other.reg2);
}

PolicyStatsManager::FlowEntryMatchKey_t::
FlowEntryMatchKey_t(uint32_t k1, uint32_t k2, const struct match& k3) {
    cookie = k1;
    priority = k2;
    match = std::unique_ptr<struct match>(new struct match(k3));
}

PolicyStatsManager::FlowEntryMatchKey_t::
FlowEntryMatchKey_t(const FlowEntryMatchKey_t& o) {
    cookie = o.cookie;
    priority = o.priority;
    match = std::unique_ptr<struct match>(new struct match(*o.match));
}

bool PolicyStatsManager::FlowEntryMatchKey_t::
operator==(const FlowEntryMatchKey_t &other) const {
    return (cookie == other.cookie
            && priority == other.priority
            && match_equal(match.get(), other.match.get()));
}

size_t PolicyStatsManager::PolicyKeyHasher::
operator()(const PolicyStatsManager::PolicyFlowMatchKey_t& k) const noexcept {
    using boost::hash_value;
    using boost::hash_combine;

    std::size_t seed = 0;
    hash_combine(seed, hash_value(k.cookie));
    hash_combine(seed, hash_value(k.reg0));
    hash_combine(seed, hash_value(k.reg2));

    return (seed);
}

size_t PolicyStatsManager::FlowKeyHasher::
operator()(const PolicyStatsManager::FlowEntryMatchKey_t& k) const noexcept {
    using boost::hash_value;
    using boost::hash_combine;

    std::size_t hashv = match_hash(k.match.get(), 0);
    hash_combine(hashv, hash_value(k.cookie));
    hash_combine(hashv, hash_value(k.priority));

    return (hashv);
}

} /* namespace opflexagent */
