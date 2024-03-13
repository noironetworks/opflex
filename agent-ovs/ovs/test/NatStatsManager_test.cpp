/*
 * Test suite for class NatStatsManager
 *
 * Copyright (c) 2014-2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
*/
#include <sstream>
#include <boost/test/unit_test.hpp>
#include <boost/format.hpp>
#include <opflexagent/Agent.h>
#include <opflexagent/test/ModbFixture.h>
#include "ovs-ofputil.h"
#include "IntFlowManager.h"
#include "NatStatsManager.h"
#include "PolicyStatsManagerFixture.h"
#include "ActionBuilder.h"
#include "FlowBuilder.h"
#include "FlowConstants.h"
#include <boost/chrono.hpp>
#include <boost/thread/thread.hpp>


using boost::optional;

namespace opflexagent {

static const uint32_t LAST_PACKET_COUNT = 350; // for removed flow entry

class MockNatStatsManager : public NatStatsManager {
public:
    MockNatStatsManager(Agent *agent_,
                        IdGenerator& idGen_,
                        SwitchManager& switchManager_,
                        IntFlowManager& intFlowManager_,
                        long timer_interval_)
        : NatStatsManager(agent_,
                          idGen_,
                          switchManager_,
                          intFlowManager_,
                          timer_interval_) {};
    void testInjectTxnId (uint32_t txn_id) {
        std::lock_guard<mutex> lock(txnMtx);
        txns.insert(txn_id);
    }
};

class NatStatsManagerFixture : public PolicyStatsManagerFixture {
 
    public:
    NatStatsManagerFixture() : PolicyStatsManagerFixture(),
                               intFlowManager(agent, switchManager, idGen,
                                              ctZoneManager, tunnelEpManager),
                               dnsManager(agent),
                               pktInHandler(agent, intFlowManager, dnsManager),
                               policyMgr(agent.getPolicyManager()),
                               natStatsManager(&agent, idGen,
                                               switchManager,
                                               intFlowManager, 300) {

    initialSetUp();
    }
    virtual ~NatStatsManagerFixture(){
       intFlowManager.stop();
       stop();
    }

    IntFlowManager  intFlowManager;
    DnsManager dnsManager;
    PacketInHandler pktInHandler;
    PolicyManager& policyMgr;
    MockNatStatsManager natStatsManager;
    string tunIf,uplinkIf;
    void createEps(void);
    void createNextHopEps(void);
    void testFlowStatsRoutetb(MockConnection& portConn,
                              PolicyStatsManager *statsManager);
    void testFlowStatsOutTb(MockConnection& portConn,
		            PolicyStatsManager *statsManager);
    void testFlowStatsSrcTb(MockConnection& portConn,
		            PolicyStatsManager *statsManager);
    void checkModbObjectCountersToEp(const std::string& epUuid,
                                         const std::string& dir,
                                         uint32_t packet_count,
                                         uint32_t byte_count);
    void checkMetrics(uint64_t pkts, uint64_t bytes, const string& dir);
    private:
        void initialSetUp(void);
        void writeNatFlowsRoutetb(FlowEntryList& entryList);
	void writeNatFlowsOuttb(FlowEntryList& entryList);
	void writeNatFlowsSrcTb(FlowEntryList& entryList);
};

void NatStatsManagerFixture::initialSetUp(){
     tunIf = "br0_vxlan0";
     uplinkIf = "uplink";
     intFlowManager.setEncapIface(tunIf);
     intFlowManager.setUplinkIface(uplinkIf);
     intFlowManager.setTunnel("10.11.12.13", 4789);
     intFlowManager.setVirtualRouter(true, true, "aa:bb:cc:dd:ee:ff");
     intFlowManager.setVirtualDHCP(true, "aa:bb:cc:dd:ee:ff");
     portmapper.setPort(uplinkIf, 1024);
     portmapper.setPort(tunIf, 2048);
     portmapper.setPort(2048, tunIf);
     portmapper.setPort(1024, uplinkIf);

     intFlowManager.enableConnTrack();
     pktInHandler.registerConnection(switchManager.getConnection(), NULL);
     pktInHandler.setPortMapper(&switchManager.getPortMapper(), NULL);
     pktInHandler.setFlowReader(&switchManager.getFlowReader());
     intFlowManager.setEndpointAdv(AdvertManager::EPADV_GRATUITOUS_BROADCAST, AdvertManager::EPADV_GARP_RARP_BROADCAST);
     createObjects();
     portmapper.setPort(ep0->getInterfaceName().get(), 80);
     portmapper.setPort(80, ep0->getInterfaceName().get()); 
     switchManager.setMaxFlowTables(IntFlowManager::NUM_FLOW_TABLES);
     intFlowManager.start(false,true);
     intFlowManager.setEncapType(IntFlowManager::ENCAP_VXLAN);
}
void NatStatsManagerFixture::createNextHopEps(){
    intFlowManager.egDomainUpdated(epg0->getURI());
     shared_ptr<modelgbp::policy::Space> common;
    shared_ptr<FloodDomain> fd_ext;
    shared_ptr<EpGroup> eg_nat;
    shared_ptr<RoutingDomain> rd_ext;
    shared_ptr<BridgeDomain> bd_ext;
    shared_ptr<Subnets> subnets_ext;
    shared_ptr<L3ExternalDomain> l3ext;
    shared_ptr<L3ExternalNetwork> l3ext_net;
    {
         Mutator mutator(framework, policyOwner);
        common = universe->addPolicySpace("common");
        bd_ext = common->addGbpBridgeDomain("bd_ext");
        rd_ext = common->addGbpRoutingDomain("rd_ext");
        fd_ext = common->addGbpFloodDomain("fd_ext");

        fd_ext->addGbpFloodDomainToNetworkRSrc()
            ->setTargetBridgeDomain(bd_ext->getURI());
        bd_ext->addGbpBridgeDomainToNetworkRSrc()
            ->setTargetRoutingDomain(rd_ext->getURI());

        subnets_ext = common->addGbpSubnets("subnets_ext");
        subnets_ext->addGbpSubnet("subnet_ext4")
            ->setAddress("5.5.5.0")
            .setPrefixLen(24);
        bd_ext->addGbpForwardingBehavioralGroupToSubnetsRSrc()
            ->setTargetSubnets(subnets_ext->getURI());
        rd_ext->addGbpRoutingDomainToIntSubnetsRSrc(subnets_ext->
                                                    getURI().toString());

        eg_nat = common->addGbpEpGroup("nat-epg");
        eg_nat->addGbpeInstContext()->setEncapId(0x4242);
        eg_nat->addGbpEpGroupToNetworkRSrc()
            ->setTargetFloodDomain(fd_ext->getURI());

        l3ext = rd0->addGbpL3ExternalDomain("ext");
        l3ext_net = l3ext->addGbpL3ExternalNetwork("outside");
        l3ext_net->addGbpExternalSubnet("outside")
            ->setAddress("5.5.0.0")
            .setPrefixLen(8);
        mutator.commit();
    }
    Endpoint::IPAddressMapping ipm4("91c5b217-d244-432c-922d-533c6c036ab3");
    ipm4.setMappedIP("10.20.44.2");
    ipm4.setFloatingIP("5.5.5.5");
    ipm4.setEgURI(eg_nat->getURI());
    WAIT_FOR(policyMgr.getBDForGroup(eg_nat->getURI()) != boost::none, 500);
    WAIT_FOR(policyMgr.getFDForGroup(eg_nat->getURI()) != boost::none, 500);
    WAIT_FOR(policyMgr.getRDForGroup(eg_nat->getURI()) != boost::none, 500);
    PolicyManager::subnet_vector_t sns;
    WAIT_FOR_DO(sns.size() == 1, 500, sns.clear();
                policyMgr.getSubnetsForGroup(eg_nat->getURI(), sns));

    intFlowManager.domainUpdated(RoutingDomain::CLASS_ID, rd0->getURI());
    intFlowManager.egDomainUpdated(epg0->getURI());
    intFlowManager.egDomainUpdated(eg_nat->getURI());
    intFlowManager.endpointUpdated(ep0->getUUID());
    WAIT_FOR_TABLES("create", 500);
    {
        Mutator mutator(framework, policyOwner);
        l3ext_net->addGbpL3ExternalNetworkToNatEPGroupRSrc()
            ->setTargetEpGroup(eg_nat->getURI());
        mutator.commit();
     }
     WAIT_FOR(policyMgr.getVnidForGroup(eg_nat->getURI())
              .get_value_or(0) == 0x4242, 500);
     intFlowManager.domainUpdated(RoutingDomain::CLASS_ID, rd0->getURI());
     portmapper.setPort("nexthop", 42);
     portmapper.setPort(42, "nexthop");
     ipm4.setNextHopIf("nexthop");
     ipm4.setNextHopMAC(MAC("42:00:42:42:42:42"));
     ep0->addIPAddressMapping(ipm4);
     epSrc.updateEndpoint(*ep0);
     unordered_set<string> eps;
     agent.getEndpointManager().getEndpointsByIpmNextHopIf("nexthop", eps);
     BOOST_CHECK_EQUAL(1, eps.size());
     intFlowManager.endpointUpdated(ep0->getUUID());
     WAIT_FOR_TABLES("natmapping", 500);
 }

void NatStatsManagerFixture::createEps(){
    intFlowManager.egDomainUpdated(epg0->getURI());
     shared_ptr<modelgbp::policy::Space> common;
    shared_ptr<FloodDomain> fd_ext;
    shared_ptr<EpGroup> eg_nat;
    shared_ptr<RoutingDomain> rd_ext;
    shared_ptr<BridgeDomain> bd_ext;
    shared_ptr<Subnets> subnets_ext;
    shared_ptr<L3ExternalDomain> l3ext;
    shared_ptr<L3ExternalNetwork> l3ext_net;
    {
        Mutator mutator(framework, policyOwner);
        common = universe->addPolicySpace("common");
        bd_ext = common->addGbpBridgeDomain("bd_ext");
        rd_ext = common->addGbpRoutingDomain("rd_ext");
        fd_ext = common->addGbpFloodDomain("fd_ext");

        fd_ext->addGbpFloodDomainToNetworkRSrc()
            ->setTargetBridgeDomain(bd_ext->getURI());
        bd_ext->addGbpBridgeDomainToNetworkRSrc()
            ->setTargetRoutingDomain(rd_ext->getURI());

        subnets_ext = common->addGbpSubnets("subnets_ext");
        subnets_ext->addGbpSubnet("subnet_ext4")
            ->setAddress("5.5.5.0")
            .setPrefixLen(24);
        bd_ext->addGbpForwardingBehavioralGroupToSubnetsRSrc()
            ->setTargetSubnets(subnets_ext->getURI());
        rd_ext->addGbpRoutingDomainToIntSubnetsRSrc(subnets_ext->
                                                    getURI().toString());

        eg_nat = common->addGbpEpGroup("nat-epg");
        eg_nat->addGbpeInstContext()->setEncapId(0x4242);
        eg_nat->addGbpEpGroupToNetworkRSrc()
            ->setTargetFloodDomain(fd_ext->getURI());

        l3ext = rd0->addGbpL3ExternalDomain("ext");
        l3ext_net = l3ext->addGbpL3ExternalNetwork("outside");
        l3ext_net->addGbpExternalSubnet("outside")
            ->setAddress("5.5.0.0")
            .setPrefixLen(8);
        mutator.commit();
    }
    Endpoint::IPAddressMapping ipm4("91c5b217-d244-432c-922d-533c6c036ab3");
    ipm4.setMappedIP("10.20.44.2");
    ipm4.setFloatingIP("5.5.5.5");
    ipm4.setEgURI(eg_nat->getURI());
    ep0->addIPAddressMapping(ipm4);
    epSrc.updateEndpoint(*ep0);
    WAIT_FOR(policyMgr.getBDForGroup(eg_nat->getURI()) != boost::none, 500);
    WAIT_FOR(policyMgr.getFDForGroup(eg_nat->getURI()) != boost::none, 500);
    WAIT_FOR(policyMgr.getRDForGroup(eg_nat->getURI()) != boost::none, 500);
    PolicyManager::subnet_vector_t sns;
    WAIT_FOR_DO(sns.size() == 1, 500, sns.clear();
                policyMgr.getSubnetsForGroup(eg_nat->getURI(), sns));

    intFlowManager.domainUpdated(RoutingDomain::CLASS_ID, rd0->getURI());
    intFlowManager.egDomainUpdated(epg0->getURI());
    intFlowManager.egDomainUpdated(eg_nat->getURI());
    intFlowManager.endpointUpdated(ep0->getUUID());
    WAIT_FOR_TABLES("create", 500);
              
}

void  NatStatsManagerFixture::checkModbObjectCountersToEp(const std::string& epUuid, const std::string& dir,
		                                          uint32_t packet_count, uint32_t byte_count){
     optional<shared_ptr<EpStatUniverse> > su =
                        EpStatUniverse::resolve(agent.getFramework());
     if(su){
        if (dir=="ExtToEp") {
                auto natStat = su.get()->resolveGbpeExtToEpStatsCounter
                                                         ("ExtToEp:"+epUuid);
		BOOST_CHECK(natStat);
		 if(natStat){
                        WAIT_FOR_DO_ONFAIL(
                            (natStat
                                 && (natStat.get()->getRxPackets(0) == packet_count)),
                            1000,
                            (natStat =  su.get()->resolveGbpeExtToEpStatsCounter("ExtToEp:"+epUuid)),
                             if(natStat) {
                                 BOOST_CHECK_EQUAL(natStat.get()->getRxPackets(0), packet_count);
                             });
			if(natStat.get()->getRxPackets(0) == packet_count)
                            checkMetrics(packet_count, byte_count, dir);
		}
	}else if (dir == "EpToExt"){
		 auto natStat = su.get()->resolveGbpeEpToExtStatsCounter
                                                          ("EpToExt:"+epUuid);
		 if(natStat){
	              WAIT_FOR_DO_ONFAIL(
                            (natStat
                                 && (natStat.get()->getTxPackets(0) == packet_count)),
                            1000,
                            (natStat =  su.get()->resolveGbpeEpToExtStatsCounter("EpToExt:"+epUuid)),
                             if(natStat) {
                                 BOOST_CHECK_EQUAL(natStat.get()->getTxPackets(0), packet_count);
                             });
		              if(natStat.get()->getTxPackets(0) == packet_count)
                                  checkMetrics(packet_count, byte_count, dir);
                }
        }
     }
}

void NatStatsManagerFixture::writeNatFlowsRoutetb(FlowEntryList& entryList){
    uint32_t port = portmapper.FindPort(ep0->getInterfaceName().get());
    string epmac(ep0->getMAC().get().toString());
    const uint8_t* rmac = intFlowManager.getRouterMacAddr();
    uint8_t macAddr[6];
    MAC(epmac).toUIntArray(macAddr);
    address ipAddr1 = address::from_string("5.5.5.5");
    address ipAddr2 = address::from_string("10.20.44.2");
    FlowBuilder().priority(452).reg(SEPG, 0x4242).reg(RD, 2)
         .ipDst(ipAddr1)
         .cookie(opflexagent::flow::cookie::NAT_FLOW)
         .flags(OFPUTIL_FF_SEND_FLOW_REM)
         .action().ethSrc(rmac).ethDst(macAddr)
         .ipDst(ipAddr2).decTtl()
         .reg(MFF_REG2, 0xa0a).reg(MFF_REG4, 1).reg(MFF_REG5, int(0))
         .reg(MFF_REG6, 1).reg(MFF_REG7, port)
         .metadata(opflexagent::flow::meta::ROUTED, opflexagent::flow::meta::ROUTED)
         .go(opflexagent::flow::meta::out::NAT).parent().build(entryList);
     return;
}

void NatStatsManagerFixture::writeNatFlowsOuttb(FlowEntryList& entryList){
    string epmac(ep0->getMAC().get().toString());
    const uint8_t* rmac = intFlowManager.getRouterMacAddr();
    uint8_t macAddr[6];
    MAC(epmac).toUIntArray(macAddr);
    address ipAddr1 = address::from_string("5.5.5.5");
    address ipAddr2 = address::from_string("10.20.44.2");
    FlowBuilder().priority(10)
             .reg(RD, 1).reg(OUTPORT, 0x4242)
             .metadata(opflexagent::flow::meta::out::NAT, flow::meta::out::MASK)
             .ipSrc(ipAddr2)
             .cookie(opflexagent::flow::cookie::NAT_FLOW)
             .flags(OFPUTIL_FF_SEND_FLOW_REM)
             .action().ethSrc(macAddr).ethDst(rmac)
             .ipSrc(ipAddr1).decTtl()
             .reg(MFF_REG0, 0x4242).reg(MFF_REG4, 2).reg(MFF_REG5, 1).reg(MFF_REG6, 2)
             .reg(MFF_REG7, int(0)).reg64(MFF_METADATA, opflexagent::flow::meta::ROUTED)
             .resubmit(OFPP_IN_PORT, IntFlowManager::BRIDGE_TABLE_ID).parent().build(entryList);
    return;
}

void NatStatsManagerFixture::writeNatFlowsSrcTb(FlowEntryList& entryList){
    const uint8_t* rmac = intFlowManager.getRouterMacAddr();
    string epmac(ep0->getMAC().get().toString());
    uint8_t epMac[6];
    MAC(epmac).toUIntArray(epMac);

    string nexthopmac("42:00:42:42:42:42");
    uint8_t nextHopMac[6];
    MAC(nexthopmac).toUIntArray(nextHopMac);

    address ipAddr1 = address::from_string("5.5.5.5");
    address ipAddr2 = address::from_string("10.20.44.2");
    FlowBuilder().priority(201).inPort(42)
                     .ethSrc(nextHopMac).ipDst(ipAddr1)
                     .cookie(opflexagent::flow::cookie::NAT_FLOW)
                     .flags(OFPUTIL_FF_SEND_FLOW_REM)
                     .action().ethSrc(rmac).ethDst(epMac).ipDst(ipAddr2).decTtl()
                     .reg(MFF_REG2, 0xa0a).reg(MFF_REG4, 1).reg(MFF_REG5, int(0)).reg(MFF_REG6, 1)
                     .reg(MFF_REG7, 0x50)
                     .metadata(opflexagent::flow::meta::ROUTED, opflexagent::flow::meta::ROUTED)
                     .go(IntFlowManager::NAT_IN_TABLE_ID).parent().build(entryList);
}

void NatStatsManagerFixture::testFlowStatsRoutetb(MockConnection& portConn,
                                                  PolicyStatsManager *statsManager){
    FlowEntryList entryList;
    writeNatFlowsRoutetb(entryList);
     auto ec = make_error_code(boost::system::errc::success);
    // Call update_state() function to setup flow stat state.
    natStatsManager.on_timer(ec);
    // create first flow reply message
    struct ofpbuf *res_msg = makeFlowStatReplyMessage_2(&portConn,
                                                        INITIAL_PACKET_COUNT,
                                                        IntFlowManager::ROUTE_TABLE_ID,
                                                        entryList);
    BOOST_REQUIRE(res_msg!=0);
    LOG(DEBUG) << "1 makeFlowStatsReplyMessage successful";
    ofp_header *msgHdr = (ofp_header *)res_msg->data;
    natStatsManager.testInjectTxnId(msgHdr->xid);
    // send first flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_STATS_REPLY,
                         res_msg);
    LOG(DEBUG) << "1 FlowStatsReplyMessage handling successful";
    ofpbuf_delete(res_msg);
    // Call update_state() function to process the stats collected
    // and update Genie objects for stats
    natStatsManager.on_timer(ec);
    // create second flow stats reply message
    res_msg = makeFlowStatReplyMessage_2(&portConn,
                                         FINAL_PACKET_COUNT,
                                         IntFlowManager::ROUTE_TABLE_ID,
                                         entryList);
    BOOST_REQUIRE(res_msg!=0);
    LOG(DEBUG) << "2 makeFlowStatReplyMessage successful";
    msgHdr = (ofp_header *)res_msg->data;
    natStatsManager.testInjectTxnId(msgHdr->xid);
    // send second flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_STATS_REPLY,
                         res_msg);
    LOG(DEBUG) << "2 FlowStatsReplyMessage handling successful";
    ofpbuf_delete(res_msg);
    natStatsManager.on_timer(ec);

    uint32_t expPkts = 0;
    uint32_t expBytes = 0;
    uint32_t numFlows = 1;
    auto epUuid = ep0->getUUID();
    expPkts = (FINAL_PACKET_COUNT - INITIAL_PACKET_COUNT) * numFlows;
    expBytes = expPkts * PACKET_SIZE;
    checkModbObjectCountersToEp(epUuid, "ExtToEp", expPkts, expBytes);

    res_msg =  makeFlowRemovedMessage_2(&portConn,  
		                          LAST_PACKET_COUNT,
                                          IntFlowManager::ROUTE_TABLE_ID,
                                          entryList);
    LOG(DEBUG) << "1 makeFlowRemovedMessage successful";
    struct ofputil_flow_removed fentry;
    SwitchConnection::DecodeFlowRemoved(res_msg, &fentry);
    
      // send first flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_REMOVED,
                         res_msg,
                         &fentry);
    LOG(DEBUG) << "1 FlowRemovedMessage handling successful";
    ofpbuf_delete(res_msg);
     // Call update_state() function to process the stats collected
    // and update Genie objects for stats
    natStatsManager.on_timer(ec);
        // calculate expected packet count and byte count
    // that we should have in Genie object
    uint32_t expPkts1 = 250;
    uint32_t expBytes1 = expPkts1 * PACKET_SIZE;
    checkModbObjectCountersToEp(epUuid, "ExtToEp", expPkts1, expBytes1);
}

void NatStatsManagerFixture::testFlowStatsOutTb(MockConnection& portConn,
                                                  PolicyStatsManager *statsManager){
    FlowEntryList entryList;
    writeNatFlowsOuttb(entryList);
     auto ec = make_error_code(boost::system::errc::success);
    // Call update_state() function to setup flow stat state.
    natStatsManager.on_timer(ec);
    // create first flow reply message
    struct ofpbuf *res_msg = makeFlowStatReplyMessage_2(&portConn,
                                                        INITIAL_PACKET_COUNT,
                                                        IntFlowManager::OUT_TABLE_ID,
                                                        entryList);
    BOOST_REQUIRE(res_msg!=0);
    LOG(DEBUG) << "1 makeFlowStatsReplyMessage successful";
    ofp_header *msgHdr = (ofp_header *)res_msg->data;
    natStatsManager.testInjectTxnId(msgHdr->xid);
    // send first flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_STATS_REPLY,
                         res_msg);
    LOG(DEBUG) << "1 FlowStatsReplyMessage handling successful";
    ofpbuf_delete(res_msg);
    // Call update_state() function to process the stats collected
    // and update Genie objects for stats
    natStatsManager.on_timer(ec);
    // create second flow stats reply message
    res_msg = makeFlowStatReplyMessage_2(&portConn,
                                         FINAL_PACKET_COUNT,
                                         IntFlowManager::OUT_TABLE_ID,
                                         entryList);
    BOOST_REQUIRE(res_msg!=0);
    LOG(DEBUG) << "2 makeFlowStatReplyMessage successful";
    msgHdr = (ofp_header *)res_msg->data;
    natStatsManager.testInjectTxnId(msgHdr->xid);
    // send second flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_STATS_REPLY,
                         res_msg);
    LOG(DEBUG) << "2 FlowStatsReplyMessage handling successful";
    ofpbuf_delete(res_msg);
    natStatsManager.on_timer(ec);

    uint32_t expPkts = 0;
    uint32_t expBytes = 0;
    uint32_t numFlows = 1;
    auto epUuid = ep0->getUUID();
    expPkts = (FINAL_PACKET_COUNT - INITIAL_PACKET_COUNT) * numFlows;
    expBytes = expPkts * PACKET_SIZE;
    checkModbObjectCountersToEp(epUuid, "EpToExt", expPkts, expBytes);

    res_msg =  makeFlowRemovedMessage_2(&portConn,
                                         LAST_PACKET_COUNT,
                                         IntFlowManager::OUT_TABLE_ID,
                                         entryList);
    LOG(DEBUG) << "1 makeFlowRemovedMessage successful";
    struct ofputil_flow_removed fentry;
    SwitchConnection::DecodeFlowRemoved(res_msg, &fentry);

      // send first flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_REMOVED,
                         res_msg,
                         &fentry);
    LOG(DEBUG) << "1 FlowRemovedMessage handling successful";
    ofpbuf_delete(res_msg);
     // Call update_state() function to process the stats collected
    // and update Genie objects for stats
    natStatsManager.on_timer(ec);
        // calculate expected packet count and byte count
    // that we should have in Genie object
    uint32_t expPkts1 = 250;
    uint32_t expBytes1 = expPkts1 * PACKET_SIZE;
    checkModbObjectCountersToEp(epUuid, "EpToExt", expPkts1, expBytes1);

}

void NatStatsManagerFixture::testFlowStatsSrcTb(MockConnection& portConn,
                                                  PolicyStatsManager *statsManager){
    FlowEntryList entryList;
    writeNatFlowsSrcTb(entryList);
     auto ec = make_error_code(boost::system::errc::success);
    // Call update_state() function to setup flow stat state.
    natStatsManager.on_timer(ec);
    // create first flow reply message
    struct ofpbuf *res_msg = makeFlowStatReplyMessage_2(&portConn,
                                                        INITIAL_PACKET_COUNT,
                                                        IntFlowManager::SRC_TABLE_ID,
                                                        entryList);
    BOOST_REQUIRE(res_msg!=0);
    LOG(DEBUG) << "1 makeFlowStatsReplyMessage successful";
    ofp_header *msgHdr = (ofp_header *)res_msg->data;
    natStatsManager.testInjectTxnId(msgHdr->xid);
    // send first flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_STATS_REPLY,
                         res_msg);
    LOG(DEBUG) << "1 FlowStatsReplyMessage handling successful";
    ofpbuf_delete(res_msg);
    // Call update_state() function to process the stats collected
    // and update Genie objects for stats
    natStatsManager.on_timer(ec);
    // create second flow stats reply message
    res_msg = makeFlowStatReplyMessage_2(&portConn,
                                         FINAL_PACKET_COUNT,
                                         IntFlowManager::SRC_TABLE_ID,
                                         entryList);
    BOOST_REQUIRE(res_msg!=0);
    LOG(DEBUG) << "2 makeFlowStatReplyMessage successful";
    msgHdr = (ofp_header *)res_msg->data;
    natStatsManager.testInjectTxnId(msgHdr->xid);
    // send second flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_STATS_REPLY,
                         res_msg);
    LOG(DEBUG) << "2 FlowStatsReplyMessage handling successful";
    ofpbuf_delete(res_msg);
    natStatsManager.on_timer(ec);

    uint32_t expPkts = 0;
    uint32_t expBytes = 0;
    uint32_t numFlows = 1;
    auto epUuid = ep0->getUUID();
    expPkts = (FINAL_PACKET_COUNT - INITIAL_PACKET_COUNT) * numFlows;
    expBytes = expPkts * PACKET_SIZE;
    checkModbObjectCountersToEp(epUuid, "ExtToVm", expPkts, expBytes);

    res_msg =  makeFlowRemovedMessage_2(&portConn,
                                         LAST_PACKET_COUNT,
                                         IntFlowManager::SRC_TABLE_ID,
                                         entryList);
    LOG(DEBUG) << "1 makeFlowRemovedMessage successful";
    struct ofputil_flow_removed fentry;
    SwitchConnection::DecodeFlowRemoved(res_msg, &fentry);

      // send first flow stats reply message
    statsManager->Handle(&portConn,
                         OFPTYPE_FLOW_REMOVED,
                         res_msg,
                         &fentry);
    LOG(DEBUG) << "1 FlowRemovedMessage handling successful";
    ofpbuf_delete(res_msg);
     // Call update_state() function to process the stats collected
    // and update Genie objects for stats
    natStatsManager.on_timer(ec);
        // calculate expected packet count and byte count
    // that we should have in Genie object
    uint32_t expPkts1 = 250;
    uint32_t expBytes1 = expPkts1 * PACKET_SIZE;
    checkModbObjectCountersToEp(epUuid, "ExtToVm", expPkts1, expBytes1);
}


// Check prom dyn gauge extnet-->vm metrics along with stats
void NatStatsManagerFixture::checkMetrics (uint64_t pkts,
                                           uint64_t bytes,
                                           const string& dir){

    const string& output = BaseFixture::getOutputFromCommand(cmd);
    if(dir == "ExtToEp"){
        const string& rx_bytes = "opflex_extnetwork_to_endpoint_bytes{depg=\"/PolicyUniverse/PolicySpace/tenant0/GbpEpGroup/epg0/\","\
                                 "ep_floating_ip=\"5.5.5.5\"," \
				 "ep_mapped_ip=\"10.20.44.2\",ep_uuid=\"ExtToEp:0-0-0-0\"," \
                                 "sepg=\"/PolicyUniverse/PolicySpace/common/GbpEpGroup/nat-epg/\"} " \
                                 + std::to_string(bytes);

        const string& rx_pkts = "opflex_extnetwork_to_endpoint_packets{depg=\"/PolicyUniverse/PolicySpace/tenant0/GbpEpGroup/epg0/\"," \
				 "ep_floating_ip=\"5.5.5.5\"," \
				 "ep_mapped_ip=\"10.20.44.2\",ep_uuid=\"ExtToEp:0-0-0-0\"," \
                                "sepg=\"/PolicyUniverse/PolicySpace/common/GbpEpGroup/nat-epg/\"} " \
                                + std::to_string(pkts);
    size_t pos = std::string::npos;
    pos = output.find(rx_pkts);
    BOOST_CHECK_NE(pos, std::string::npos);
    pos = output.find(rx_bytes);
    BOOST_CHECK_NE(pos, std::string::npos);
    }else if(dir == "EpToExt") {
         const string& rx_bytes = "opflex_endpoint_to_extnetwork_bytes{depg=\"/PolicyUniverse/PolicySpace/common/GbpEpGroup/nat-epg/\","\
                                  "ep_floating_ip=\"5.5.5.5\"," \
				  "ep_mapped_ip=\"10.20.44.2\",ep_uuid=\"EpToExt:0-0-0-0\"," \
                                  "sepg=\"/PolicyUniverse/PolicySpace/tenant0/GbpEpGroup/epg0/\"} " \
                                  + std::to_string(bytes);

         const string& rx_pkts = "opflex_endpoint_to_extnetwork_packets{depg=\"/PolicyUniverse/PolicySpace/common/GbpEpGroup/nat-epg/\"," \
                                 "ep_floating_ip=\"5.5.5.5\"," \
				 "ep_mapped_ip=\"10.20.44.2\",ep_uuid=\"EpToExt:0-0-0-0\"," \
                                 "sepg=\"/PolicyUniverse/PolicySpace/tenant0/GbpEpGroup/epg0/\"} " \
                                 + std::to_string(pkts);
	 LOG(DEBUG) << output;
         size_t pos = std::string::npos;
         pos = output.find(rx_pkts);
         BOOST_CHECK_NE(pos, std::string::npos);
         pos = output.find(rx_bytes);
         BOOST_CHECK_NE(pos, std::string::npos);
    }
}

BOOST_AUTO_TEST_SUITE(NatStatsManager_test)
    
BOOST_FIXTURE_TEST_CASE(testRouteTbStat, NatStatsManagerFixture) {
    LOG(DEBUG) << "Starting Nat Stat manager ";
    createEps();
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    natStatsManager.registerConnection(&integrationPortConn);
    natStatsManager.start();

    natStatsManager.Handle(NULL, OFPTYPE_FLOW_STATS_REPLY, NULL);
    natStatsManager.Handle(&integrationPortConn,
                                OFPTYPE_FLOW_STATS_REPLY, NULL);

    testFlowStatsRoutetb(integrationPortConn, &natStatsManager);
    intFlowManager.clearNatStatsCounters(ep0->getUUID());
    natStatsManager.stop();
 }


BOOST_FIXTURE_TEST_CASE(testOutTbStat, NatStatsManagerFixture) {
    LOG(DEBUG) << "Starting Nat Stat manager ";
    createEps();
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    natStatsManager.registerConnection(&integrationPortConn);
    natStatsManager.start();

    natStatsManager.Handle(NULL, OFPTYPE_FLOW_STATS_REPLY, NULL);
    natStatsManager.Handle(&integrationPortConn,
                                OFPTYPE_FLOW_STATS_REPLY, NULL);

    testFlowStatsOutTb(integrationPortConn, &natStatsManager);
    intFlowManager.clearNatStatsCounters(ep0->getUUID());
    natStatsManager.stop();
 }

BOOST_FIXTURE_TEST_CASE(testSrcTbStat, NatStatsManagerFixture) {
    LOG(DEBUG) << "Starting Nat Stat manager ";
    createNextHopEps();
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    natStatsManager.registerConnection(&integrationPortConn);
    natStatsManager.start();

    natStatsManager.Handle(NULL, OFPTYPE_FLOW_STATS_REPLY, NULL);
    natStatsManager.Handle(&integrationPortConn,
                                OFPTYPE_FLOW_STATS_REPLY, NULL);

    testFlowStatsSrcTb(integrationPortConn, &natStatsManager);
    intFlowManager.clearNatStatsCounters(ep0->getUUID());
    natStatsManager.stop();
}

BOOST_AUTO_TEST_SUITE_END()
}


