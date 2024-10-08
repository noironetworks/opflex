/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2014-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEXAGENT_INTFLOWMANAGER_H_
#define OPFLEXAGENT_INTFLOWMANAGER_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <opflexagent/Agent.h>
#include "SwitchManager.h"
#include <opflexagent/IdGenerator.h>
#include "ActionBuilder.h"
#include "AdvertManager.h"
#include <opflexagent/TunnelEpManager.h>
#include <opflexagent/RDConfig.h>
#include <opflexagent/TaskQueue.h>
#include <opflexagent/PrometheusManager.h>
#include "SwitchStateHandler.h"

#include <opflex/ofcore/PeerStatusListener.h>
#include <opflexagent/FaultManager.h>

#include <boost/asio/ip/address.hpp>
#include <boost/optional.hpp>
#include <boost/noncopyable.hpp>
#include <boost/asio/io_service.hpp>

#include <thread>
#include <utility>
#include <unordered_map>

#include "NatStatsManager.h"

namespace opflexagent {

class CtZoneManager;
class PacketInHandler;

/**
 * @brief Makes changes to OpenFlow tables to be in sync with state
 * of MOs.
 * Main function is to handling change notifications, generate a set
 * of flow modifications that represent the changes and apply these
 * modifications.
 */
class IntFlowManager : public SwitchStateHandler,
                       public EndpointListener,
                       public ServiceListener,
                       public ExtraConfigListener,
                       public LearningBridgeListener,
                       public PolicyListener,
                       public PortStatusListener,
                       public SnatListener,
                       public opflex::ofcore::PeerStatusListener,
                       private boost::noncopyable {
public:
    /**
     * Construct a new flow manager for the agent
     * @param agent the agent object
     * @param switchManager the switch manager
     * @param idGen the flow ID generator
     * @param ctZoneManager the conntrack zone manager
     * @param tnlEpManager tunnelEpManager instance
     */
    IntFlowManager(Agent& agent,
                   SwitchManager& switchManager,
                   IdGenerator& idGen,
                   CtZoneManager& ctZoneManager,
                   TunnelEpManager& tnlEpManager);
    ~IntFlowManager() {}

    /**
     * Module start
     * @param serviceStatsFlowDisabled toggle service stats flow creation based on agent config
     */
    void start(bool serviceStatsFlowDisabled=false, bool isNatStatsEnabled_=false);

    /**
     * Installs listeners for receiving updates to MODB state.
     */
    void registerModbListeners();

    /**
     * Module stop
     */
    void stop();

    /**
     * Encap types supported by the flow manager
     */
    enum EncapType {
        /**
         * No encapsulation; traffic can be forwarded only on the
         * local switch.
         */
        ENCAP_NONE,
        /**
         * Encapsulate using VLAN tags, with a (at least)
         * locally-significant VLAN for each endpoint group.
         */
        ENCAP_VLAN,
        /**
         * Encapsulate using a VXLAN tunnel, with a VNID for each
         * endpoint group.
         */
        ENCAP_VXLAN,
        /**
         * Encapsulate using an IVXLAN tunnel, with a VNID for each
         * endpoint group and additional metadata in the tunnel header
         */
        ENCAP_IVXLAN
    };

    /**
     * Set the encap type to use for packets sent over the network
     * @param encapType the encap type
     */
    void setEncapType(EncapType encapType);

    /**
     * Get the encap type to use for packets sent over the network
     * @return the encap type
     */
    EncapType getEncapType() { return encapType; }

    /**
     * Set the openflow interface name for encapsulated packets
     * @param encapIface the interface name
     */
    void setEncapIface(const std::string& encapIface);

    /**
     * Set the openflow interface name for uplink external tagged packets
     * @param uplinkIf the uplink interface names
     */
    void setUplinkIface(const std::string& uplinkIf);

    /**
     * Flooding scopes supported by the flow manager.
     */
    enum FloodScope {
        /**
         * Flood to all endpoints within a flood domain
         */
        FLOOD_DOMAIN,

        /**
         * Flood to endpoints only within an endpoint group
         */
        ENDPOINT_GROUP
    };

    /**
     * Set the flood scope
     * @param floodScope the flood scope
     */
    void setFloodScope(FloodScope floodScope);

    /**
     * Set the tunnel remote IP and port to use for tunnel traffic
     * @param tunnelRemoteIp the remote tunnel IP
     * @param tunnelRemotePort the remote tunnel port
     */
    void setTunnel(const std::string& tunnelRemoteIp,
                   uint16_t tunnelRemotePort);

    /**
     * Enable connection tracking support
     */
    void enableConnTrack();

    /**
     * Enable or disable the virtual routing
     *
     * @param virtualRouterEnabled true to enable the router
     * @param routerAdv true to enable IPv6 router advertisements
     * @param mac the MAC address to use as the router MAC formatted
     * as a colon-separated string of 6 hex-encoded bytes.
     */
    void setVirtualRouter(bool virtualRouterEnabled,
                          bool routerAdv,
                          const std::string& mac);

    /**
     * Enable or disable the virtual DHCP server
     *
     * @param dhcpEnabled true to enable the server
     * @param mac the MAC address to use as the dhcp MAC formatted as
     * a colon-separated string of 6 hex-encoded bytes.
     */
    void setVirtualDHCP(bool dhcpEnabled,
                        const std::string& mac);

    /**
     * Enable or disable endpoint advertisements and set the mode
     *
     * @param mode the endpoint advertisement mode
     * @param tunnelMode the tunnel endpoint advertisement mode
     * @param tunnelAdvIntvl the tunnel endpoint advertisement interval
     */
    void setEndpointAdv(AdvertManager::EndpointAdvMode mode,
            AdvertManager::EndpointAdvMode tunnelMode,
            uint64_t tunnelAdvIntvl=600);
    
    /**
     * Enable or disable tunnel endpoint advertisements and set the mode
     *
     * @param tunnelMode the tunnel endpoint advertisement mode
     * @param tunnelAdvIntvl the tunnel endpoint advertisement interval
     */
    void restartTunnelEndpointAdv(AdvertManager::EndpointAdvMode tunnelMode,
        uint64_t tunnelAdvIntvl);

    /**
     * Set the multicast group file
     * @param mcastGroupFile The file where multicast group
     * subscriptions will be written
     */
    void setMulticastGroupFile(const std::string& mcastGroupFile);

    /**
     * Set the drop log parameters
     * @param dropLogPort port name for the drop-log port
     * @param dropLogRemoteIp outer ip address for the drop-log geneve tunnel
     * @param dropLogRemotePort port number for geneve encap
     */
    void setDropLog(const string& dropLogPort, const string& dropLogRemoteIp,
            const uint16_t dropLogRemotePort);

    /**
     * Get the openflow port that maps to the configured tunnel
     * interface
     * @return the openflow port number
     */
    uint32_t getTunnelPort();

    /**
     * Get the openflow port that maps to the configured uplink
     * interface
     * @return the openflow port number
     */
    uint32_t getUplinkPort();

    /**
     * Get the configured tunnel destination as a parsed IP address
     * @return the tunnel destination
     */
    boost::asio::ip::address& getTunnelDst() { return tunnelDst; }

    /**
     * Set the flag serviceStatsFlowDisabled
     * @param disable set this to true to stop service stats flow creation.
     */
    void setServiceStatsFlowDisabled(bool disable) {
        serviceStatsFlowDisabled = disable;
    }

    /**
     * Get the flag serviceStatsFlowDisabled
     * @return flag to stop service stats flow creation: true or false
     */
    bool getServiceStatsFlowDisabled() {
        return serviceStatsFlowDisabled;
    }

    /**
     * Get the router MAC address as an array of 6 bytes
     * @return the router MAC
     */
    const uint8_t *getRouterMacAddr() { return routerMac; }

    /**
     * Get the DHCP MAC address as an array of 6 bytes
     * @return the DHCP MAC
     */
    const uint8_t *getDHCPMacAddr() { return dhcpMac; }

    /**
     * Get the name space string
     * @return the name space string
     */
    static const char * getIdNamespace(opflex::modb::class_id_t cid);

    /* Interface: SwitchStateHandler */
    virtual std::vector<FlowEdit>
    reconcileFlows(std::vector<TableState> flowTables,
                   std::vector<FlowEntryList>& recvFlows);
    virtual GroupEdit reconcileGroups(GroupMap& recvGroups);
    virtual void completeSync();

    /* Interface: EndpointListener */
    virtual void endpointUpdated(const std::string& uuid);
    virtual void remoteEndpointUpdated(const std::string& uuid);
    virtual void localExternalDomainUpdated(const opflex::modb::URI& uri);

    /* Interface: ServiceListener */
    virtual void serviceUpdated(const std::string& uuid);

    /* Interface: ExtraConfigListener */
    virtual void rdConfigUpdated(const opflex::modb::URI& rdURI);
    virtual void packetDropLogConfigUpdated(const opflex::modb::URI& dropLogCfgURI);
    virtual void packetDropFlowConfigUpdated(const opflex::modb::URI& dropFlowCfgURI);
    virtual void packetDropPruneConfigUpdated(const std::string& pruneFilter){
    /*Do nothing as of now*/
    }
    virtual void outOfBandConfigUpdated(std::shared_ptr<OutOfBandConfigSpec> &oobSptr) {
    /*Do nothing as of now*/
    }

    /* Interface: LearningBridgeListener */
    virtual void lbIfaceUpdated(const std::string& uuid);
    virtual void lbVlanUpdated(LearningBridgeIface::vlan_range_t vlan);

    /* Interface: PolicyListener */
    virtual void egDomainUpdated(const opflex::modb::URI& egURI);
    virtual void domainUpdated(opflex::modb::class_id_t cid,
                               const opflex::modb::URI& domURI);
    virtual void contractUpdated(const opflex::modb::URI& contractURI);
    virtual void configUpdated(const opflex::modb::URI& configURI);

    /* Interface: PortStatusListener */
    virtual void portStatusUpdate(const std::string& portName, uint32_t portNo,
                                  bool fromDesc);

    /* Interface: SnatListener */
    virtual void snatUpdated(const std::string& snatUuid);

    /**
     * Run periodic cleanup tasks
     */
    void cleanup();

    /**
     * Implementation for PeerStatusListener::peerStatusUpdated
     *
     * @param peerHostname the host name for the connection
     * @param peerPort the port number for the connection
     * @param peerStatus the new status for the connection
     */
    virtual void peerStatusUpdated(const std::string& peerHostname,
                                   int peerPort,
                                   PeerStatus peerStatus);

    /**
     * networks
     *
     * @param uris URIs of endpoint groups to search for
     * @param ids the corresponding set of vnids
     */
    void getGroupVnid(
        const std::unordered_set<opflex::modb::URI>& uris,
        /* out */std::unordered_set<uint32_t>& ids);

    /**
     * Get or generate a unique ID for a given object for use with flows.
     *
     * @param cid Class ID of the object
     * @param uri URI of the object
     * @return A unique ID for the object
     */
    uint32_t getId(opflex::modb::class_id_t cid, const opflex::modb::URI& uri);

    /**
     * Set fill in tunnel metadata in an action builder
     * @param ab the action builder
     * @param type the encap type
     * @param tunDst the tunnel destination, or boost::none to send to the
     * tunnel dst in reg7.
     */
    static void
    actionTunnelMetadata(ActionBuilder& ab, IntFlowManager::EncapType type,
                         const boost::optional<boost::asio::ip::address>&
                         tunDst = boost::none);

    /**
     * Convert ipv6 boost address to 4 longs
     * @param sAddr the source boost address
     * @param pAddr the pointer to first long addr
     * of an array of 4 longs.
     */
    static void
    in6AddrToLong(boost::asio::ip::address& sAddr, uint32_t *pAddr);

    /**
     * Get the tunnel destination to use for the given endpoint group.
     * @param epgURI the group URI
     * @return the tunnel destination IP
     */
    boost::asio::ip::address getEPGTunnelDst(const opflex::modb::URI& epgURI);

    /**
     * Indices of tables managed by the integration flow manager.
     */
    enum {
        /**
         * Handles drop log policy
         */
        DROP_LOG_TABLE_ID,
        /**
         * Handles port security/ingress policy
         */
        SEC_TABLE_ID,
        /**
         * Maps source addresses to endpoint groups and sets this
         * mapping into registers for use by later tables
         */
        SRC_TABLE_ID,
        /**
         * External World to SNAT IP
         * UN-SNAT traffic using connection tracking. Changes
         * network destination using state in connection
         * tracker and forwards traffic to the endpoint.
         */
        SNAT_REV_TABLE_ID,
        /**
         * For traffic returning from load-balanced service IP
         * addresses, restore the source address to the service
         * address
         */
        SERVICE_REV_TABLE_ID,
        /**
         * For flows that can be forwarded by bridging, maps the
         * destination L2 address to an endpoint group and next hop
         * interface and sets this mapping into registers for use by
         * later tables.  Also handles replies to protocols handled by
         * the agent or switch, such as ARP and NDP.
         */
        BRIDGE_TABLE_ID,
        /**
         * For load-balanced service IPs, map from a bucket ID to the
         * appropriate destination IP address.
         */
        SERVICE_NEXTHOP_TABLE_ID,
        /**
         * For flows that require routing, maps the destination L3
         * address to an endpoint group or external network and next
         * hop action and sets this information into registers for use
         * by later tables.
         */
        ROUTE_TABLE_ID,
        /**
         * Endpoint -> External World
         * Traffic that needs SNAT is determined after routing
         * local traffic. SNAT changes the source ip address and
         * source port based on configuration in the endpoint
         * file.
         */
        SNAT_TABLE_ID,
        /**
         * For flows destined for a NAT IP address, determine the
         * source external network for the mapped IP address and set
         * this in the source registers to allow applying policy to
         * NATed flows.
         */
        NAT_IN_TABLE_ID,
        /**
         * Source for flows installed by OVS learn action
         */
        LEARN_TABLE_ID,
        /**
         * Map traffic returning from a service interface to the
         * appropriate endpoint interface.
         */
        SERVICE_DST_TABLE_ID,
        /**
         * Allow policy for the flow based on the source and
         * destination groups and the contracts that are configured.
         */
        POL_TABLE_ID,
        /**
         * Flow stats computation
         */
        STATS_TABLE_ID,
        /**
         * Apply a destination action based on the action set in the
         * metadata field.
         */
        OUT_TABLE_ID,
        /*
         * Handle explicitly dropped packets here based on the
         * drop-log config
         */
        EXP_DROP_TABLE_ID,
        /**
         * The total number of flow tables
         */
        NUM_FLOW_TABLES
    };
    /**
     * Get registered Tunnel EpManager instance
     * @return Tunnel ep manager instance
     */
    TunnelEpManager &getTunnelEpManager(){
        return tunnelEpManager;
    }

    /**
     * Calls by PolicyStatsManager to update stats
     *
     * @param cookie flow.cookie formed by "svcstat" idgen. This
     *               uniquely identifies the pod<-->svc or *<-->svc-tgt combination.
     * @param pkts   aggregated packets per combination
     * @param bytes  aggregated bytes per combination
     */
    void updateSvcStatsCounters(const uint64_t &cookie,
                                const uint64_t &pkts,
                                const uint64_t &bytes);
    /**
     * Get the cookie used for PodSvc Flows.
     * @param uuid UUID of the Ep
     * @param ep_to_svc true if cookie for ep_to_svc,else svc_to_ep
     * @param cookie returned cookie
     * @return true if cookie was found, false otherwise
     */
    bool getPodSvcUuidCookie(const std::string & uuid,
                             bool ep_to_svc,
                             uint64_t &cookie) {
        const std::lock_guard<mutex> lock(svcStatMutex);
        if(podSvcUuidCkMap.find(uuid) == podSvcUuidCkMap.end()) {
            return false;
        }
        if(ep_to_svc) {
                cookie = podSvcUuidCkMap[uuid].first;
        } else {
                cookie = podSvcUuidCkMap[uuid].second;
        }
        return true;
    }
    /**
     * Populate TableDescriptionMap for this FlowManager
     * for use by drop counters.
     * @param fwdTblDescr returned TableDescriptionMap
     */
    static void populateTableDescriptionMap(
            SwitchManager::TableDescriptionMap &fwdTblDescr);
    /**
     * Get ASIO io_service used for svc stats processing
     */
    boost::asio::io_service& getSvcStatsIOService() {
        return svcStatsIOService;
    }

    //Update Nat Stat metrics to modb and prometheus counters
    void updateNatStatsCounters(const string &direction,
                                const uint64_t &pkts,
                                const uint64_t &bytes,
                                const string &fip,
                                const string &vmIp,
                                const string &sepg,
                                const string &depg,
                                const string &uuid);

    //This function call maintains an Hash Map between Nat Flow entry keys 
    //and ep attributes such as Vm's Ip, External network floating Ip,
    //src epg, dst epg, uudi of the Ep
    void  updateNatHashMapEntry(const std::string& fip, 
                                const std::string& mip, 
                                uint32_t fepgVnid,
                                uint32_t epgVnid, 
                                const string& mapping, 
                                const std::string& uuid,
                                uint32_t rdId);

    //This function call is called from NatStatsManager to update the Ep map if the hash key exists
    bool updateEpAttributeMap(uint32_t key1,
                              uint32_t key2, 
                              const std::string& key3, 
                              struct NatStatsManager::Nat_attr* att_map);

    //This function call clears the Modb and promethues Nat counters when the Ep get deleted
    void clearNatStatsCounters(const std::string& epUuid);
private:
    /**
     * Write flows that are fixed and not related to any policy or
     * managed objecs.
     */
    void createStaticFlows();

    /**
     * Compare and update flow/group tables due to changes in an remote
     * endpoint.
     *
     * @param uuid UUID of the changed remote endpoint
     */
    void handleRemoteEndpointUpdate(const std::string& uuid);

    /**
     * Compare and update flow/group tables due to changes in an endpoint.
     *
     * @param uuid UUID of the changed endpoint
     */
    void handleEndpointUpdate(const std::string& uuid);

    /**
     * Compare and update flow/group tables due to changes in an
     * service.
     *
     * @param uuid UUID of the changed service
     */
    void handleServiceUpdate(const std::string& uuid);

    /**
     * update Flow entry lists for services
     * @param uuid UUID of the service
     * @param serviceNextHopFlows flow list to service
     * @param serviceRevFlows flow list from service
     * @param loopback true if updating loopback flows
     */
    void updateServiceSnatDnatFlows(const string& uuid,
                                    FlowEntryList& serviceNextHopFlows,
                                    FlowEntryList& serviceRevFlows,
                                    bool loopback);
    /**
     * Compare and update snat & dnat flow tables due to changes in a
     * service.
     *
     * @param uuid UUID of the changed service
     */
    void programServiceSnatDnatFlows(const std::string& uuid);

    /**
     * Update service stats flows for metric collection
     *
     * @param uuid UUID of the changed service/ep
     * @param is_svc true if the uuid belongs to svc
     * @param is_add true if the svc/ep is added
     */
    void updateSvcStatsFlows(const std::string &uuid,
                             const bool &is_svc,
                             const bool &is_add);

    /**
     * Handle update of service stats flows for metric collection
     *
     * @param task_id made up of is_svc,is_add, & UUID of the changed service/ep
     */
    void handleUpdateSvcStatsFlows(const std::string& task_id);

    /**
     * Update ext<-->svc-tgt flows due to changes in a service/ep
     *
     * @param uuid UUID of the changed service/ep
     * @param is_svc true if the uuid belongs to svc
     * @param is_add true if the svc/ep is added
     */
    void updateSvcExtStatsFlows(const std::string &uuid,
                                const bool &is_svc,
                                const bool &is_add);

    /**
     * Update node<-->svc-tgt flows due to changes in a service/ep.
     *
     * @param uuid UUID of the changed service/ep
     * @param is_svc true if the uuid belongs to svc
     * @param is_add true if the svc/ep is added
     */
    void updateSvcNodeStatsFlows(const std::string &uuid,
                                 const bool &is_svc,
                                 const bool &is_add);

    /**
     * Update any<-->svc-tgt flows due to changes in a service/ep.
     *
     * @param uuid UUID of the changed service/ep
     * @param is_svc true if the uuid belongs to svc
     * @param is_add true if the svc/ep is added
     */
    void updateSvcTgtStatsFlows(const std::string &uuid,
                                const bool &is_svc,
                                const bool &is_add);

    /**
     * Update pod<-->svc flows due to changes in a service/ep.
     *
     * @param uuid UUID of the changed service/ep
     * @param is_svc true if the uuid belongs to svc
     * @param is_add true if the svc/ep is added
     */
    void updatePodSvcStatsFlows(const std::string &uuid,
                                const bool &is_svc,
                                const bool &is_add);

    typedef std::unordered_map<std::string, std::string> attr_map;
    /**
     * Clear svc counter and children stats
     *
     * @param uuid      The uuid of svc
     * @param attr_map  The attribute map of service
     * @param isExternal  is this update for external or cluster svc
     * @param isNodePort  Does this service have a nodePort configured
     */
    void clearSvcStatsCounters(const std::string& uuid,
                               const attr_map& attr_map,
                               bool isExternal,
                               bool isNodePort=false);

    /**
     * Clear svc-tgt counters
     *
     * @param uuid The uuid of svc
     * @param nhip The ip of svc-tgt
     * @param attr_map  The attribute map of service
     * @param isExternal  is this update for external or cluster tgt
     * @param isNodePort  Does this service have a nodePort configured
     */
    void clearSvcTgtStatsCounters(const std::string& uuid,
                                  const std::string& nhip,
                                  const attr_map& attr_map,
                                  bool isExternal,
                                  bool isNodePort=false);

    /**
     * Clear podsvc counter objects
     *
     * @param key The unique key to identify (pod,svc)
     */
    void clearPodSvcStatsCounters(const std::string& key);

    /*
     * Update svctgt counter objects
     */
    void updateSvcTgtStatsCounters(const uint64_t &cookie,
                                   const bool &isAnyToSvc,
                                   const string& idStr,
                                   const uint64_t &pkts,
                                   const uint64_t &bytes,
                                   const attr_map &svc_attr_map,
                                   const attr_map &ep_attr_map);

    /*
     * Update podsvc counter objects
     */
    void updatePodSvcStatsCounters(const uint64_t &cookie,
                                   const bool &isEpToSvc,
                                   const string& idStr,
                                   const uint64_t &pkts,
                                   const uint64_t &bytes);

    /*
     * Update svc counter objects
     */
    void updateSvcStatsCounters(const bool &isIngress,
                                const string& uuid,
                                const uint64_t &pkts,
                                const uint64_t &bytes,
                                const bool &add,
                                const bool &isNodePort=false);

    /*
     * Update podsvc counter attributes
     */
    template <class MO>
    void updatePodSvcStatsAttr(const std::shared_ptr<MO> &obj,
                               const attr_map &epAttr,
                               const attr_map &svcAttr);

    /**
     * Compare and update flow/group tables due to changes in a
     * learning bridge interface.
     *
     * @param uuid UUID of the changed learning bridge interface
     */
    void handleLearningBridgeIfaceUpdate(const std::string& uuid);

    /**
     * Compare and update flow/group tables due to changes in a
     * learning bridge VLAN
     *
     * @param vlan the VLAN whose membership has changed
     */
    void handleLearningBridgeVlanUpdate(LearningBridgeIface::vlan_range_t vlan);

    /**
     * Compare and update flow/group tables due to changes in an
     * endpoint group.
     *
     * @param egURI URI of the changed endpoint group
     */
    void handleEndpointGroupDomainUpdate(const opflex::modb::URI& egURI);

    /**
     * Update flows related to the given routing domain
     *
     * @param rdURI URI of the changed routing domain
     */
    void handleRoutingDomainUpdate(const opflex::modb::URI& rdURI);

    /**
     * Handle changes to a forwarding domain; only deals with
     * cleaning up flows etc when these objects are removed.
     *
     * @param cid Class of the forwarding domain
     * @param domURI URI of the changed forwarding domain
     */
    void handleDomainUpdate(opflex::modb::class_id_t cid,
                            const opflex::modb::URI& domURI);

    /**
     * Compare and update flow/group tables due to changes in a contract
     *
     * @param contractURI URI of the changed contract
     */
    void handleContractUpdate(const opflex::modb::URI& contractURI);

    /**
     * Compare and update flow/group tables due to changes in platform
     * config
     *
     * @param configURI URI of the changed contract
     */
    void handleConfigUpdate(const opflex::modb::URI& configURI);

    /**
     * Handle changes to port-status by recomputing flows for endpoints
     * and endpoint groups.
     *
     * @param portName Name of the port that changed
     * @param portNo Port number of the port that changed
     */
    void handlePortStatusUpdate(const std::string& portName, uint32_t portNo);

    /**
     * Create / Update SNAT flows due to SNAT update
     *
     * @param snatUuid the snat uuid for the snat object
     */
    void handleSnatUpdate(const std::string& snatUuid);

    /**
     * Create/Update/Delete local external domain
     *
     * @param uri URI of the local external domain
     */
    void handleLocalExternalDomainUpdated(const opflex::modb::URI &uri);

    /**
     * Get Forwarding Info for a given EpGroup
     *
     * @param snatIp the snat ip affected
     * @param snatUuid the snat uuid for the snat object
     */
    bool getGroupForwardingInfo(const opflex::modb::URI& egUri, uint32_t& vnid,
            boost::optional<opflex::modb::URI>& rdURI, uint32_t& rdId,
            boost::optional<opflex::modb::URI>& bdURI, uint32_t& bdId,
            boost::optional<opflex::modb::URI>& fdURI, uint32_t& fdId);

    void updateGroupSubnets(const opflex::modb::URI& egUri,
                            uint32_t bdId, uint32_t rdId);
    /**
     * Apply appropriate flood action on the EPG
     *
     * @param epgURI EPG URI
     * @param epgVnid encap id of the EPG
     * @param fgrpId flood group id
     * @param epgTunDst epg multicast IP to flood
     * @param isLocalExtDomain EPG refers to a local external domain
     */
    void updateEPGFlood(const opflex::modb::URI& epgURI,
                        uint32_t epgVnid, uint32_t fgrpId,
                        const boost::asio::ip::address& epgTunDst,
                        bool isLocalExtDomain=false);

    /**
     * Update all current group table entries
     */
    void updateGroupTable();

    /**
     * Update flow-tables to associate an endpoint with a flood-group.
     *
     * @param fgrpURI URI of flood-group (flood-domain or endpoint-group)
     * @param endpoint The endpoint to update
     * @param epPort Port number of endpoint
     * @param fd Flood-domain to which the endpoint belongs
     */
    void updateEndpointFloodGroup(const opflex::modb::URI& fgrpURI,
                                  const Endpoint& endPoint,
                                  uint32_t epPort,
                                  boost::optional<std::shared_ptr<
                                      modelgbp::gbp::FloodDomain> >& fd);

    /**
     * Update flow-tables to dis-associate an endpoint from any flood-group.
     *
     * @param epUUID UUID of endpoint
     */
    void removeEndpointFromFloodGroup(const std::string& epUUID);

    /*
     * Map of endpoint to the port it is using.
     */
    typedef std::unordered_map<std::string, uint32_t> Ep2PortMap;

    /**
     * Construct a group-table modification.
     *
     * @param type The modification type
     * @param groupId Identifier for the flow group to edit
     * @param ep2port Ports to be associated with this flow group
     * @return Group-table modification entry
     */
    GroupEdit::Entry createGroupMod(uint16_t type, uint32_t groupId,
                                    const Ep2PortMap& ep2port);

    void checkGroupEntry(GroupMap& recvGroups,
                         uint32_t groupId, const Ep2PortMap& epMap,
                         GroupEdit& ge);

    Agent& agent;
    SwitchManager& switchManager;
    IdGenerator& idGen;
    CtZoneManager& ctZoneManager;
    TunnelEpManager& tunnelEpManager;
    AgentPrometheusManager& prometheusManager;
    TaskQueue taskQueue;

    EncapType encapType;
    std::string encapIface, uplinkIface;
    FloodScope floodScope;
    boost::asio::ip::address tunnelDst;
    bool virtualRouterEnabled;
    uint8_t routerMac[6];
    bool routerAdv;
    bool virtualDHCPEnabled;
    bool conntrackEnabled;
    uint8_t dhcpMac[6];
    std::string mcastGroupFile;
    std::string dropLogIface;
    boost::asio::ip::address dropLogDst;
    uint16_t dropLogRemotePort;
    std::atomic<bool> serviceStatsFlowDisabled;
    //enabling/disabling flag for Nat Stats Managaer
    bool isNatStatsEnabled;

    /* Map containing ingress and egress cookie: Flows generated out
     * of same pod<-->svc uuid will use these cookies */
    unordered_map<std::string, pair<uint64_t, uint64_t>> podSvcUuidCkMap;

    /* Cookie cleanup of any<-->svc flows:
     * The key for every cookie is per NH svc-tgt.
     * svctoan:svc-tgt:svcuuid:nhip
     * and
     * antosvc:svc-tgt:svcuuid:nhip
     * If a service is removed, or if NH is deleted or if EP IP is removed
     * of if EP becomes external, then the flows get deleted.
     * The cookie will get freed up during cleanup timer of IntFlowManager as
     * part of idgen garbage collection. Since this timer kicks off once every
     * 180 seconds, caching the svc:nh-ip state to do faster cleanup.
     * This state is also used for cleanup of stats from observer MOs.
     */
    unordered_map<std::string, unordered_set<std::string>> svc_nh_map;

    // Lock to safe guard svcstat related state
    std::mutex svcStatMutex;

    /*
     * Map of flood-group URI to the endpoints associated with it.
     * The flood-group can either be a flood-domain or an endpoint-group
     */
    typedef std::unordered_map<opflex::modb::URI, Ep2PortMap> FloodGroupMap;
    FloodGroupMap floodGroupMap;

    uint32_t getExtNetVnid(const opflex::modb::URI& uri);

    AdvertManager advertManager;

    bool isSyncing;
    std::atomic<bool> stopping;

    void initPlatformConfig();

    /* Set of URIs of managed objects */
    typedef std::unordered_set<opflex::modb::URI> UriSet;
    /* Map of multi-cast IP addresses to associated managed objects */
    typedef std::unordered_map<std::string, UriSet> MulticastMap;
    MulticastMap mcastMap;
    /* Persistant multi-cast entries read during startup */
    std::vector<std::string> oldMcastEntries;
    // Lock to safe guard access to oldMcastEntries
    std::mutex oldMcastEntriesMutex;
    /* Set of external flood domain Ids*/
    std::unordered_set<uint32_t> localExternalFdSet;
    /**
     * Associate or disassociate a managed object with a multicast IP, and
     * update the multicast group subscription if necessary.
     * @param mcastIp The multicast IP to associate with; if unset disassociates
     * any previous association
     * @param uri URI of the managed object to associate to
     */
    void updateMulticastList(const boost::optional<std::string>& mcastIp,
                             const opflex::modb::URI& uri);

    /**
     * Remove all multicast IP associations for a managed object.
     * @param uri URI of the managed object to disassociate
     * @return true if an update should be queued
     */
    bool removeFromMulticastList(const opflex::modb::URI& uri);

    /**
     * Queue a write of the current multicast subscriptions
     */
    void multicastGroupsUpdated();

    /**
     * Write out the current multicast subscriptions
     */
    void writeMulticastGroups();

    /**
     * Read persistent multicast config from file
     */
    void readOldMulticastGroups();

    /**
     * Clear persistent in-memory groups previously read frm file
     */
    void clearOldMulticastGroups();
    /**
     *
     */
    void addContractRules(FlowEntryList& entryList,
                                 const uint32_t pvnid,
                                 const uint32_t cvnid,
                                 bool allowBidirectional,
                                 const PolicyManager::rule_list_t& rules);
    /**
     * Handle if the droplog port name is read later
     */
    void handleDropLogPortUpdate();
  
    std::unique_ptr<std::thread> svcStatsThread;
    boost::asio::io_service svcStatsIOService;
    std::unique_ptr<boost::asio::io_service::work> svcStatsIOWork;
    boost::asio::io_service multiCastIOService;
    std::unique_ptr<std::thread> multiCastIOThread;
    FaultManager& faultmanager;
    TaskQueue svcStatsTaskQueue;   
    // Lock to safe guard natstat related state
    std::mutex natStatMutex;

    struct  MatchLabels {
        std::string mappedIp;
        std::string floatingIp;
        std::string src_epg;
        std::string dst_epg;
        std::string uuid;
	uint32_t fvnid;
    };
    struct FlowKey {
        FlowKey(std::string k1, uint32_t k2, uint32_t k3) {
            ip=std::move(k1);
            reg=k2;
            rd = k3;
        }
        std::string ip;
        uint32_t reg;
        uint32_t rd;
        bool operator==(const FlowKey &other) const;
    };

    struct natFlowKeyHasher {
        size_t operator()(const FlowKey& k) const noexcept;
    };

    typedef std::unordered_map<FlowKey, MatchLabels, natFlowKeyHasher> natFlowMatchKey;
    
    natFlowMatchKey natEpMap;
};

} // namespace opflexagent

#endif // OPFLEXAGENT_INTFLOWMANAGER_H_
