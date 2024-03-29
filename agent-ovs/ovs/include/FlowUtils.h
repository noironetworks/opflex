/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Utility functions for flow tables
 *
 * Copyright (c) 2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_FLOWUTILS_H
#define OPFLEXAGENT_FLOWUTILS_H

#include "TableState.h"
#include <opflexagent/Network.h>

#include <modelgbp/gbpe/L24Classifier.hpp>

#include <boost/optional.hpp>

#include <cstdint>

namespace opflexagent {

class FlowBuilder;
class ActionBuilder;

namespace flowutils {

/**
 * Add a match against routingDomain ID in REG6
 *
 * @param f the flow builder
 * @param rdId the routing domain ID or the VRF/context ID
 */
void match_rdId(FlowBuilder& f, uint32_t rdId);

/**
 * Add a match against source/destination group ID in REG0 and REG2
 *
 * @param f the flow builder
 * @param prio the priority
 * @param svnid the source group ID, or zero for any
 * @param dvnide the dest group ID, or zero for any
 */
void match_group(FlowBuilder& f, uint16_t prio, uint32_t svnid, uint32_t dvnid);

/**
 * Get a flow entry for the output table that will output to the port
 * in REG7
 *
 * @return the new flow entry
 */
FlowEntryPtr default_out_flow();

/**
 * Actions to take for classifier entries in add_classifier_entries
 */
enum ClassAction {
    /**
     * Drop the flow
     */
    CA_DENY,
    /**
     * Allow the flow by going to nextTable
     */
    CA_ALLOW,
    /**
     * Allow the flow by going to nextTable and committing a
     * connection tracking flow
     */
    CA_REFLEX_FWD,
    /**
     * Track an established forward flow
     */
    CA_REFLEX_FWD_EST,
    /**
     * Match against empty conntrack state and send to conntrack table,
     * recirculating the flow to nextTable
     */
    CA_REFLEX_FWD_TRACK,
    /**
     * same as above in reverse direction
     */
    CA_REFLEX_REV_TRACK,
    /**
     * Match against established conntrack state and go to nextTable
     */
    CA_REFLEX_REV_ALLOW,
    /**
     * Match against related flows in reverse direction
     */
    CA_REFLEX_REV_RELATED,
};

/**
 * Create flow entries for the classifier specified and append them
 * to the provided list.
 *
 * @param classifier Classifier object to get matching rules from
 * @param act an action to take for the flows
 * @param sourceSub A set of source networks to which the rule should apply
 * @param destSub A set of dest networks to which the rule should apply
 * @param destNamedSvcPorts A set of resolved domain names to which the rule should apply
 * @param nextTable the table to send to if the traffic is allowed
 * @param currentTable the table where this classifier is being programmed
 * @param dropTable the table to send to if the packet has to be logged
 * @param priority Priority of the entry created
 * @param cookie Cookie of the entry created
 * @param svnid VNID of the source endpoint group for the entry
 * @param dvnid VNID of the destination endpoint group for the entry
 * @param entries List to append entry to
 */
void add_classifier_entries(modelgbp::gbpe::L24Classifier& clsfr,
                            ClassAction act, bool log,
                            boost::optional<const network::subnets_t&> sourceSub,
                            boost::optional<const network::subnets_t&> destSub,
                            boost::optional<const network::service_ports_t&> destNamedSvcPorts,
                            uint8_t nextTable, uint8_t currentTable, uint8_t dropTable,
                            uint16_t priority,
                            uint32_t flags, uint64_t cookie,
                            uint32_t svnid, uint32_t dvnid,
                            bool isSystemRule,
                            /* out */ FlowEntryList& entries);

/**
 * Create L2 flow entries for the classifier specified and append them
 * to the provided list.
 *
 * @param classifier Classifier object to get matching rules from
 * @param act an action to take for the flows
 * @param nextTable the table to send to if the traffic is allowed
 * @param currentTable the table where this classifier is being programmed
 * @param dropTable the table to send to if the packet has to be logged
 * @param priority Priority of the entry created
 * @param flags the flow flags to use
 * @param cookie Cookie of the entry created
 * @param svnid VNID of the source endpoint group for the entry
 * @param dvnid VNID of the destination endpoint group for the entry
 * @param entries List to append entry to
 */
void add_l2classifier_entries(modelgbp::gbpe::L24Classifier& clsfr,
                              ClassAction act, bool log,
                              uint8_t nextTable, uint8_t currentTable, uint8_t dropTable,
                              uint16_t priority,
                              uint32_t flags, uint64_t cookie,
                              uint32_t svnid, uint32_t dvnid,
                              bool isSystemRule,
                              /* out */ FlowEntryList& entries);
/**
 * Add a match entry for the DHCP v4 and v6 request
 *
 * @param fb the flowbuilder
 * @param v4 whether its a v4 or v6
 *
 * @return the flowbuilder
 */
FlowBuilder& match_dhcp_req(FlowBuilder& fb, bool v4);

} // namespace flowutils
} // namespace opflexagent

#endif /* OPFLEXAGENT_FLOWUTILS_H */
