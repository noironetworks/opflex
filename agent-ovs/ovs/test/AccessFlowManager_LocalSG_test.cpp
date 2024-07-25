/*
 * Test suite for class AccessFlowManager
 *
 * Copyright (c) 2016 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/test/ModbFixture.h>
#include <opflexagent/test/BaseFixture.h>
#include <opflexagent/LearningBridgeSource.h>
#include "FlowManagerFixture.h"
#include "AccessFlowManager.h"
#include "CtZoneManager.h"
#include "FlowConstants.h"
#include "FlowUtils.h"

#include <opflex/modb/Mutator.h>
#include <modelgbp/gbp/LocalSecGroup.hpp>

#include <memory>
#include <vector>
#include <thread>

BOOST_AUTO_TEST_SUITE(AccessFlowManagerLocalSG_test)

using std::vector;
using std::string;
using std::shared_ptr;
using std::thread;
using boost::asio::io_service;
using opflex::modb::URI;
using namespace opflexagent;
using namespace modelgbp::gbp;
using modelgbp::gbpe::LocalL24Classifier;
using opflex::modb::Mutator;

class AccessFlowManagerLocalSGFixture : public FlowManagerFixture {
public:
    AccessFlowManagerLocalSGFixture()
        : accessFlowManager(agent, switchManager, idGen, ctZoneManager){
        bool enable = true;
        agent.getPolicyManager().configLocalNetpol(enable);
        expTables.resize(AccessFlowManager::NUM_FLOW_TABLES);
        switchManager.registerStateHandler(&accessFlowManager);
        idGen.initNamespace("l24classifierRule");
        start();
        accessFlowManager.enableConnTrack();
        accessFlowManager.start();
    }
    virtual ~AccessFlowManagerLocalSGFixture() {
        bool enable = false;
        agent.getPolicyManager().configLocalNetpol(enable);
        accessFlowManager.stop();
        stop();
    }

    /** Initialize static entries */
    void initExpStatic();

    /** Initialize endpoint-scoped flow entries */
    void initExpEp(shared_ptr<Endpoint>& ep);

    /** Initialize security group flow entries */
    uint16_t initExpSecGrp1(uint32_t setId, int remoteAddress);
    uint16_t initExpSecGrp2(uint32_t setId);
    void initExpSecGrpSet1();
    void initExpSecGrpSet12(bool second = true, int remoteAddress = 0);
    uint16_t initExpSecGrp3(int remoteAddress);
    void initExpSecGrp4(std::vector<std::pair<std::string,uint16_t>>& namedAddressSet);
    void initExpSecGrp6();

    /** Initialize system security group flow entries */
    void initExpSysSecGrpSet1();

    /** Initialize dscp flow entries */
    void addDscpFlows(shared_ptr<Endpoint>& ep);

    AccessFlowManager accessFlowManager;

    shared_ptr<LocalSecGroup> secGrp1;
    shared_ptr<LocalSecGroup> secGrp2;
    shared_ptr<LocalSecGroup> secGrp3;
    shared_ptr<LocalSecGroup> sysSecGrp1;

    shared_ptr<LocalL24Classifier> local_classifier100,local_classifier101;

    shared_ptr<modelgbp::policy::Space> pSpace;
    shared_ptr<modelgbp::qos::Requirement> reqCfg;
    shared_ptr<modelgbp::qos::DscpMarking> dscpCfg;

    /* Initialize dhcp flow entries */
    void initExpDhcpEp(shared_ptr<Endpoint>& ep);

    /* Initialize learning bridge entries */
    void initExpLearningBridge();
};

BOOST_FIXTURE_TEST_CASE(endpoint, AccessFlowManagerLocalSGFixture) {
    setConnected();

    ep0.reset(new Endpoint("0-0-0-0"));
    ep0->setAccessInterface("ep0-access");
    ep0->setAccessUplinkInterface("ep0-uplink");
    portmapper.setPort(ep0->getAccessInterface().get(), 42);
    portmapper.setPort(ep0->getAccessUplinkInterface().get(), 24);
    portmapper.setPort(42, ep0->getAccessInterface().get());
    portmapper.setPort(24, ep0->getAccessUplinkInterface().get());
    epSrc.updateEndpoint(*ep0);

    initExpStatic();
    initExpEp(ep0);
    WAIT_FOR_TABLES("create", 500);

    ep1.reset(new Endpoint("0-0-0-1"));
    ep1->setAccessInterface("ep1-access");
    portmapper.setPort(ep1->getAccessInterface().get(), 17);
    portmapper.setPort(17, ep1->getAccessInterface().get());
    epSrc.updateEndpoint(*ep1);
    epSrc.removeEndpoint(ep0->getUUID());

    clearExpFlowTables();
    initExpStatic();
    WAIT_FOR_TABLES("remove", 500);

    ep1->setAccessUplinkInterface("ep1-uplink");
    portmapper.setPort(ep1->getAccessUplinkInterface().get(), 18);
    portmapper.setPort(18, ep1->getAccessUplinkInterface().get());
    epSrc.updateEndpoint(*ep1);

    clearExpFlowTables();
    initExpStatic();
    initExpEp(ep1);
    WAIT_FOR_TABLES("uplink-added", 500);

    ep2.reset(new Endpoint("0-0-0-2"));
    ep2->setAccessInterface("ep2-access");
    ep2->setAccessUplinkInterface("ep2-uplink");
    epSrc.updateEndpoint(*ep2);
    epSrc.updateEndpoint(*ep0);
    epSrc.removeEndpoint(ep1->getUUID());

    clearExpFlowTables();
    initExpStatic();
    initExpEp(ep0);
    WAIT_FOR_TABLES("missing-portmap", 500);

    portmapper.setPort(ep1->getAccessInterface().get(), 91);
    portmapper.setPort(ep1->getAccessUplinkInterface().get(), 92);
    portmapper.setPort(91, ep1->getAccessInterface().get());
    portmapper.setPort(92, ep1->getAccessUplinkInterface().get());
    accessFlowManager.portStatusUpdate("ep2-access", 91, false);

    clearExpFlowTables();
    initExpStatic();
    initExpEp(ep0);
    initExpEp(ep2);
    WAIT_FOR_TABLES("portmap-added", 500);

    ep0->setAccessIfaceVlan(223);
    epSrc.updateEndpoint(*ep0);

    clearExpFlowTables();
    initExpStatic();
    initExpEp(ep0);
    initExpEp(ep2);
    WAIT_FOR_TABLES("access-vlan-added", 500);

    Endpoint::DHCPv4Config v4;
    Endpoint::DHCPv6Config v6;
    ep0->setAccessIfaceVlan(223);
    ep0->setDHCPv4Config(v4);
    ep0->setDHCPv6Config(v6);
    epSrc.updateEndpoint(*ep0);

    clearExpFlowTables();
    initExpStatic();
    initExpDhcpEp(ep0);
    WAIT_FOR_TABLES("dhcp-configured", 500);

}

BOOST_FIXTURE_TEST_CASE(epDscpTest, AccessFlowManagerLocalSGFixture) {
    setConnected();

    URI reqUri("/PolicyUniverse/PolicySpace/test/QosRequirement/req1/");
    ep0.reset(new Endpoint("0-0-0-0"));
    ep0->setAccessInterface("ep0-access");
    ep0->setAccessUplinkInterface("ep0-uplink");
    ep0->setQosPolicy(reqUri);
    portmapper.setPort(ep0->getAccessInterface().get(), 42);
    portmapper.setPort(ep0->getAccessUplinkInterface().get(), 24);
    portmapper.setPort(42, ep0->getAccessInterface().get());
    portmapper.setPort(24, ep0->getAccessUplinkInterface().get());
    epSrc.updateEndpoint(*ep0);

    {
        shared_ptr<modelgbp::policy::Universe> pUniverse =
                            modelgbp::policy::Universe::resolve(framework).get();
        Mutator mutator(framework, "policyreg");
        pSpace = pUniverse->addPolicySpace("test");
        reqCfg = pSpace->addQosRequirement("req1");
        mutator.commit();

        Mutator mutator2(framework, "framework");
        dscpCfg = reqCfg->addQosDscpMarking();
        dscpCfg->setMark(28);
        mutator2.commit();
    }

    initExpStatic();
    initExpEp(ep0);
    addDscpFlows(ep0);
    WAIT_FOR_TABLES("dscp-configured", 500);
}

BOOST_FIXTURE_TEST_CASE(learningBridge, AccessFlowManagerLocalSGFixture) {
    setConnected();

    ep0.reset(new Endpoint("0-0-0-0"));
    ep0->setInterfaceName("ep0-int");
    ep0->setAccessInterface("ep0-access");
    ep0->setAccessUplinkInterface("ep0-uplink");
    portmapper.setPort(ep0->getAccessInterface().get(), 42);
    portmapper.setPort(ep0->getAccessUplinkInterface().get(), 24);
    portmapper.setPort(42, ep0->getAccessInterface().get());
    portmapper.setPort(24, ep0->getAccessUplinkInterface().get());
    epSrc.updateEndpoint(*ep0);

    LearningBridgeSource lbSource(&agent.getLearningBridgeManager());
    LearningBridgeIface if1;
    if1.setUUID("1");
    if1.setInterfaceName(ep0->getInterfaceName().get());
    if1.setTrunkVlans({ {0x400,0x4ff} });
    lbSource.updateLBIface(if1);

    initExpStatic();
    initExpEp(ep0);
    initExpLearningBridge();
    WAIT_FOR_TABLES("create", 500);
}

#define ADDF(flow) addExpFlowEntry(expTables, flow)
enum TABLE {
    DROP_LOG=0, SVC_BYPASS = 1, GRP = 2, SYS_IN_POL = 3, IN_POL = 4, SYS_OUT_POL = 5, OUT_POL = 6, TAP=7, OUT = 8, EXP_DROP=9
};

enum CaptureReason {
        NO_MATCH=0,
        POLICY_DENY=1,
        POLICY_PERMIT=2
    };


BOOST_FIXTURE_TEST_CASE(secGrp, AccessFlowManagerLocalSGFixture) {
    LOG(DEBUG) << "AccessFlowManagerLocalSGFixture::secGrp";
    createObjects();
    createPolicyObjects();
    shared_ptr<modelgbp::gbp::LocalSubnets> rs;
    {
        Mutator mutator(framework, "policyelement");
        rs = space->addGbpLocalSubnets("subnets_rule0");

        rs->addGbpLocalSubnet("subnets_rule0_1")
            ->setAddress("0.0.0.0")
            .setPrefixLen(0);
        rs->addGbpLocalSubnet("subnets_rule0_2")
            ->setAddress("0::")
            .setPrefixLen(0);

        shared_ptr<modelgbp::gbp::LocalSecGroupRule> r1, r2, r3, r4, r5 ;
        secGrp1 = space->addGbpLocalSecGroup("secgrp1");

        r1 = secGrp1->addGbpLocalSecGroupSubject("1_subject1")
                ->addGbpLocalSecGroupRule("1_1_rule1");
        r1->setDirection(DirectionEnumT::CONST_IN).setOrder(100)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier1->getURI().toString());
        r1->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        r2 = secGrp1->addGbpLocalSecGroupSubject("1_subject1")
                ->addGbpLocalSecGroupRule("1_1_rule2");
        r2->setDirection(DirectionEnumT::CONST_IN).setOrder(150)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier8->getURI().toString());
        r2->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        r3 = secGrp1->addGbpLocalSecGroupSubject("1_subject1")
            ->addGbpLocalSecGroupRule("1_1_rule3");
        r3->setDirection(DirectionEnumT::CONST_OUT).setOrder(200)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier2->getURI().toString());

        r4 = secGrp1->addGbpLocalSecGroupSubject("1_subject1")
                ->addGbpLocalSecGroupRule("1_1_rule4");
        r4->setDirection(DirectionEnumT::CONST_IN).setOrder(300)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier6->getURI().toString());
        r4->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        r5 = secGrp1->addGbpLocalSecGroupSubject("1_subject1")
                 ->addGbpLocalSecGroupRule("1_1_rule5");
        r5->setDirection(DirectionEnumT::CONST_IN).setOrder(400)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier7->getURI().toString());
        r5->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());


        mutator.commit();
    }

    ep0.reset(new Endpoint("0-0-0-0"));
    epSrc.updateEndpoint(*ep0);

    initExpStatic();
    WAIT_FOR_TABLES("empty-secgrp", 500);

    ep0->addSecurityGroup(secGrp1->getURI());
    epSrc.updateEndpoint(*ep0);

    clearExpFlowTables();
    initExpStatic();
    initExpSecGrpSet1();
    WAIT_FOR_TABLES("one-secgrp", 500);

    ep0->addSecurityGroup(opflex::modb::URI("/PolicyUniverse/PolicySpace"
                                            "/tenant0/GbpLocalSecGroup/secgrp2/"));
    epSrc.updateEndpoint(*ep0);

    clearExpFlowTables();
    initExpStatic();
    initExpSecGrpSet12(false);
    WAIT_FOR_TABLES("two-secgrp-nocon", 500);

    {
        shared_ptr<modelgbp::gbp::LocalSecGroupRule> r1, r2, r3;

        Mutator mutator(framework, "policyelement");
        secGrp2 = space->addGbpLocalSecGroup("secgrp2");
        r1 = secGrp2->addGbpLocalSecGroupSubject("2_subject1")
                ->addGbpLocalSecGroupRule("2_1_rule1");
        r1->addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier0->getURI().toString());
        r1->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        r2 = secGrp2->addGbpLocalSecGroupSubject("2_subject1")
                ->addGbpLocalSecGroupRule("2_1_rule2");
        r2->setDirection(DirectionEnumT::CONST_BIDIRECTIONAL).setOrder(20)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier5->getURI().toString());

        r3 = secGrp2->addGbpLocalSecGroupSubject("2_subject1")
            ->addGbpLocalSecGroupRule("2_1_rule3");
        r3->setDirection(DirectionEnumT::CONST_OUT).setOrder(30)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier9->getURI().toString());
        r3->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());
        mutator.commit();
    }

    clearExpFlowTables();
    initExpStatic();
    initExpSecGrpSet12(true);
    WAIT_FOR_TABLES("two-secgrp", 500);

    {
        Mutator mutator(framework, "policyelement");
        rs = space->addGbpLocalSubnets("subnets_rule1");

        rs->addGbpLocalSubnet("subnets_rule1_1")
            ->setAddress("192.168.0.0")
            .setPrefixLen(16);
        rs->addGbpLocalSubnet("subnets_rule1_2")
            ->setAddress("fd80::")
            .setPrefixLen(32);

        secGrp1->addGbpLocalSecGroupSubject("1_subject1")
            ->addGbpLocalSecGroupRule("1_1_rule1")
            ->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        secGrp1->addGbpLocalSecGroupSubject("1_subject1")
            ->addGbpLocalSecGroupRule("1_1_rule2")
            ->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        secGrp1->addGbpLocalSecGroupSubject("1_subject1")
            ->addGbpLocalSecGroupRule("1_1_rule3")
            ->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        mutator.commit();
    }
    clearExpFlowTables();
    initExpStatic();
    initExpSecGrpSet12(true, 1);
    WAIT_FOR_TABLES("remote-secgrp", 500);

    {
        Mutator mutator(framework, "policyelement");

        rs->addGbpLocalSubnet("subnets_rule1_3")
            ->setAddress("10.0.0.0")
            .setPrefixLen(8);
        rs->addGbpLocalSubnet("subnets_rule1_4")
            ->setAddress("fd34:9c39:1374:358c::")
            .setPrefixLen(64);

        mutator.commit();
    }

    clearExpFlowTables();
    initExpStatic();
    initExpSecGrpSet12(true, 2);
    WAIT_FOR_TABLES("remote-addsubnets", 500);
}

BOOST_FIXTURE_TEST_CASE(syssecgrp, AccessFlowManagerLocalSGFixture) {
    createObjects();
    createPolicyObjects();
    shared_ptr<modelgbp::gbp::LocalSubnets> rs;
    {
        Mutator mutator(framework, "policyelement");
        rs = space->addGbpLocalSubnets("subnets_rule0");

        rs->addGbpLocalSubnet("subnets_rule0_1")
            ->setAddress("0.0.0.0")
            .setPrefixLen(0);
        rs->addGbpLocalSubnet("subnets_rule0_2")
            ->setAddress("0::")
            .setPrefixLen(0);

        shared_ptr<modelgbp::gbp::LocalSecGroupRule> r1, r2, r3, r4, r5 ;
        sysSecGrp1 = space->addGbpLocalSecGroup("ostack_SystemSecurityGroup");

        r1 = sysSecGrp1->addGbpLocalSecGroupSubject("2_subject1")
                ->addGbpLocalSecGroupRule("2_1_rule1");
        r1->addGbpLocalSecGroupRuleToClassifierRSrc(classifier0->getURI().toString());
        r1->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());

        r2 = sysSecGrp1->addGbpLocalSecGroupSubject("2_subject1")
                ->addGbpLocalSecGroupRule("2_1_rule2");
        r2->setDirection(DirectionEnumT::CONST_BIDIRECTIONAL).setOrder(20)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier5->getURI().toString());

        r3 = sysSecGrp1->addGbpLocalSecGroupSubject("2_subject1")
            ->addGbpLocalSecGroupRule("2_1_rule3");
        r3->setDirection(DirectionEnumT::CONST_OUT).setOrder(30)
            .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier9->getURI().toString());
        r3->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs->getURI().toString());
        mutator.commit();

    }

    ep0.reset(new Endpoint("0-0-0-0"));
    epSrc.updateEndpoint(*ep0);

    initExpStatic();
    WAIT_FOR_TABLES("empty-secgrp", 500);

    ep0->addSecurityGroup(sysSecGrp1->getURI());
    epSrc.updateEndpoint(*ep0);

    clearExpFlowTables();
    initExpStatic();
    initExpSysSecGrpSet1();
    WAIT_FOR_TABLES("syssecgrp", 500);
}

BOOST_FIXTURE_TEST_CASE(denyrule, AccessFlowManagerLocalSGFixture) {
    createObjects();
    createPolicyObjects();
    shared_ptr<modelgbp::gbp::LocalSubnets> rs1;
    {
       Mutator mutator(framework, "policyelement");
       rs1 = space->addGbpLocalSubnets("subnets_rule_1");
       rs1->addGbpLocalSubnet("subnets_rule1_1")
          ->setAddress("192.169.0.0")
          .setPrefixLen(16);

       shared_ptr<modelgbp::gbp::LocalSecGroupRule> r1, r2, r3, r4;
        //secgrp 3
       secGrp3 = space->addGbpLocalSecGroup("secgrp3");
        //action 1
       local_action1 = space->addGbpLocalAllowDenyAction("action1");
       local_action1->setAllow(0).setOrder(5);
       //action 2
       local_action2 =  space->addGbpLocalLogAction("action2");
       //security group rule
       r1 = secGrp3->addGbpLocalSecGroupSubject("1_subject1")
                   ->addGbpLocalSecGroupRule("1_1_rule1");
       r1->setDirection(DirectionEnumT::CONST_OUT).setOrder(100)
          .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier2->getURI().toString());
       r1->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs1->getURI().toString());
       r1->addGbpLocalSecGroupRuleToActionRSrcLocalAllowDenyAction(local_action1->getURI().toString())
         ->setTargetLocalAllowDenyAction(local_action1->getURI());
       r1->addGbpLocalSecGroupRuleToActionRSrcLocalLogAction(local_action2->getURI().toString())
         ->setTargetLocalLogAction(local_action2->getURI());
       r2 = secGrp3->addGbpLocalSecGroupSubject("1_subject1")
         ->addGbpLocalSecGroupRule("1_1_rule2");
       r2->setDirection(DirectionEnumT::CONST_IN).setOrder(150)
         .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier1->getURI().toString());
       r2->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs1->getURI().toString());
       r2->addGbpLocalSecGroupRuleToActionRSrcLocalAllowDenyAction(local_action1->getURI().toString())
         ->setTargetLocalAllowDenyAction(local_action1->getURI());
       r2->addGbpLocalSecGroupRuleToActionRSrcLocalLogAction(local_action2->getURI().toString())
         ->setTargetLocalLogAction(local_action2->getURI());
       r3 = secGrp3->addGbpLocalSecGroupSubject("1_subject1")
          ->addGbpLocalSecGroupRule("1_1_rule3");
       r3->setDirection(DirectionEnumT::CONST_BIDIRECTIONAL).setOrder(200)
           .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier5->getURI().toString());
       r3->addGbpLocalSecGroupRuleToRemoteAddressRSrc(rs1->getURI().toString());
       r3->addGbpLocalSecGroupRuleToActionRSrcLocalAllowDenyAction(local_action1->getURI().toString())
         ->setTargetLocalAllowDenyAction(local_action1->getURI());
       r3->addGbpLocalSecGroupRuleToActionRSrcLocalLogAction(local_action2->getURI().toString())
         ->setTargetLocalLogAction(local_action2->getURI());

       mutator.commit();
     }

    ep0.reset(new Endpoint("0-0-0-0"));
    epSrc.updateEndpoint(*ep0);

    initExpStatic();
    WAIT_FOR_TABLES("empty-secgrp", 500);

    ep0->addSecurityGroup(opflex::modb::URI("/PolicyUniverse/PolicySpace"
                                            "/tenant0/GbpLocalSecGroup/secgrp3/"));
    epSrc.updateEndpoint(*ep0);

    clearExpFlowTables();
    initExpStatic();

    initExpSecGrp3(1);
    WAIT_FOR_TABLES("deny-rule", 500);
}

BOOST_FIXTURE_TEST_CASE(permitLog, AccessFlowManagerLocalSGFixture) {
    createObjects();
    createPolicyObjects();
    shared_ptr<modelgbp::gbp::LocalSubnets> subnets1;
    {
       Mutator mutator(framework, "policyelement");
       subnets1 = space->addGbpLocalSubnets("subnets1");
       subnets1->addGbpLocalSubnet("subnets1")
          ->setAddress("10.0.0.0")
          .setPrefixLen(16);

        //secgrp 6
       auto secGrp6 = space->addGbpLocalSecGroup("secgrp6");
        //actions
       local_action1 = space->addGbpLocalAllowDenyAction("action1");
       local_action1->setAllow(1).setOrder(10);
       local_action2 =  space->addGbpLocalLogAction("action2");
       //security group rule
       auto r1 = secGrp6->addGbpLocalSecGroupSubject("1_subject1")
                   ->addGbpLocalSecGroupRule("1_rule1");
       r1->setDirection(DirectionEnumT::CONST_OUT).setOrder(100)
          .addGbpLocalSecGroupRuleToClassifierRSrc(local_classifier1->getURI().toString());
       r1->addGbpLocalSecGroupRuleToRemoteAddressRSrc(subnets1->getURI().toString());
       r1->addGbpLocalSecGroupRuleToActionRSrcLocalAllowDenyAction(local_action1->getURI().toString())
         ->setTargetLocalAllowDenyAction(local_action1->getURI());
       r1->addGbpLocalSecGroupRuleToActionRSrcLocalLogAction(local_action2->getURI().toString())
         ->setTargetLocalLogAction(local_action2->getURI());
       mutator.commit();
     }

    ep0.reset(new Endpoint("0-0-0-0"));
    epSrc.updateEndpoint(*ep0);

    initExpStatic();
    WAIT_FOR_TABLES("empty-secgrp", 500);

    ep0->addSecurityGroup(opflex::modb::URI("/PolicyUniverse/PolicySpace"
                                            "/tenant0/GbpLocalSecGroup/secgrp6/"));
    epSrc.updateEndpoint(*ep0);

    clearExpFlowTables();
    initExpStatic();

    initExpSecGrp6();
    WAIT_FOR_TABLES("permitLog", 500);
}

void AccessFlowManagerLocalSGFixture::addDscpFlows(shared_ptr<Endpoint>& ep) {
    uint32_t access = portmapper.FindPort(ep->getAccessInterface().get());
    if (access == OFPP_NONE) return;

    ADDF(Bldr().table(0).priority(65535).ipv6().in(access)
         .actions().setDscp(112).resubmit(access,1).done());

    ADDF(Bldr().table(0).priority(65535).ip().in(access)
         .actions().setDscp(112).resubmit(access,1).done());
}

void AccessFlowManagerLocalSGFixture::initExpStatic() {
    ADDF(Bldr().table(OUT).priority(1).isMdAct(0)
         .actions().out(OUTPORT).done());
    ADDF(Bldr().table(OUT).priority(1)
         .isMdAct(opflexagent::flow::meta::access_out::PUSH_VLAN,
                  opflexagent::flow::meta::out::MASK)
         .actions().pushVlan().move(FD12, VLAN).out(OUTPORT).done());
    ADDF(Bldr().table(OUT).priority(1)
         .isMdAct(opflexagent::flow::meta::access_out::UNTAGGED_AND_PUSH_VLAN,
                  opflexagent::flow::meta::out::MASK)
         .actions().out(OUTPORT).pushVlan()
         .move(FD12, VLAN).out(OUTPORT).done());
    ADDF(Bldr().table(OUT).priority(1)
         .isMdAct(opflexagent::flow::meta::access_out::POP_VLAN,
                  opflexagent::flow::meta::out::MASK)
         .isVlanTci("0x1000/0x1000")
         .actions().popVlan().out(OUTPORT).done());
    ADDF(Bldr().table(TAP).priority(2)
         .cookie(ovs_ntohll(opflexagent::flow::cookie::DNS_RESPONSE_V4))
         .tcp()
         .isMdAct(opflexagent::flow::meta::access_meta::INGRESS_DIR,
                  opflexagent::flow::meta::access_meta::MASK)
         .isTpSrc(53)
         .actions().controller(65535).go(OUT).done());
    ADDF(Bldr().table(TAP).priority(2)
         .cookie(ovs_ntohll(opflexagent::flow::cookie::DNS_RESPONSE_V6))
         .tcp6()
         .isMdAct(opflexagent::flow::meta::access_meta::INGRESS_DIR,
                  opflexagent::flow::meta::access_meta::MASK)
         .isTpSrc(53)
         .actions().controller(65535).go(OUT).done());
    ADDF(Bldr().table(TAP).priority(2)
         .cookie(ovs_ntohll(opflexagent::flow::cookie::DNS_RESPONSE_V4))
         .udp()
         .isMdAct(opflexagent::flow::meta::access_meta::INGRESS_DIR,
                  opflexagent::flow::meta::access_meta::MASK)
         .isTpSrc(53)
         .actions().controller(65535).go(OUT).done());
    ADDF(Bldr().table(TAP).priority(2)
         .cookie(ovs_ntohll(opflexagent::flow::cookie::DNS_RESPONSE_V6))
         .udp6()
         .isMdAct(opflexagent::flow::meta::access_meta::INGRESS_DIR,
                  opflexagent::flow::meta::access_meta::MASK)
         .isTpSrc(53)
         .actions().controller(65535).go(OUT).done());
    ADDF(Bldr().table(TAP).priority(1)
         .actions().go(OUT).done());
    ADDF(Bldr().table(OUT_POL).priority(PolicyManager::MAX_POLICY_RULE_PRIORITY)
         .reg(SEPG, 1).actions().go(TAP).done());
    ADDF(Bldr().table(IN_POL).priority(PolicyManager::MAX_POLICY_RULE_PRIORITY)
         .reg(SEPG, 1).actions().go(TAP).done());
    ADDF(Bldr().table(DROP_LOG).priority(0)
            .actions().go(SVC_BYPASS).done());
    ADDF(Bldr().table(SVC_BYPASS).priority(1)
            .actions().go(GRP).done());
    ADDF(Bldr().table(SYS_IN_POL).priority(1).actions().go(IN_POL).done());
    ADDF(Bldr().table(SYS_OUT_POL).priority(1).actions().go(OUT_POL).done());
    for(int i=SVC_BYPASS; i<=OUT; i++) {
        ADDF(Bldr().table(i).priority(0)
        .cookie(ovs_ntohll(opflexagent::flow::cookie::TABLE_DROP_FLOW))
        .flags(OFPUTIL_FF_SEND_FLOW_REM).priority(0)
        .actions().dropLog(i).go(EXP_DROP).done());
    }
}

void AccessFlowManagerLocalSGFixture::initExpDhcpEp(shared_ptr<Endpoint>& ep) {
    uint32_t access = portmapper.FindPort(ep->getAccessInterface().get());
    uint32_t uplink = portmapper.FindPort(ep->getAccessUplinkInterface().get());

    if (access == OFPP_NONE || uplink == OFPP_NONE) return;

    initExpEp(ep);
    if (ep->getDHCPv4Config()) {
        ADDF(Bldr()
             .table(GRP).priority(ep->getAccessIfaceVlan() ? 201 : 200).udp().in(access)
             .isVlan(ep->getAccessIfaceVlan().get())
             .isTpSrc(68).isTpDst(67)
             .actions()
             .load(OUTPORT, uplink)
             .meta((opflexagent::flow::meta::access_meta::EGRESS_DIR|
                    opflexagent::flow::meta::access_out::POP_VLAN),
                   opflexagent::flow::meta::ACCESS_MASK)
             .go(TAP).done());
        if (ep->isAccessAllowUntagged() && ep->getAccessIfaceVlan()) {
            ADDF(Bldr()
                 .table(GRP).priority(200).udp().in(access)
                 .isVlanTci("0x0000/0x1fff")
                 .isTpSrc(68).isTpDst(67)
                 .actions()
                 .load(OUTPORT, uplink)
                 .meta(opflexagent::flow::meta::access_meta::EGRESS_DIR,
                       opflexagent::flow::meta::ACCESS_MASK)
                 .go(TAP).done());
        }
    }
    if (ep->getDHCPv6Config()) {
        ADDF(Bldr()
             .table(GRP).priority(ep->getAccessIfaceVlan() ? 201 : 200).udp6().in(access)
             .isVlan(ep->getAccessIfaceVlan().get())
             .isTpSrc(546).isTpDst(547)
             .actions()
             .load(OUTPORT, uplink)
             .meta((opflexagent::flow::meta::access_meta::EGRESS_DIR|
                    opflexagent::flow::meta::access_out::POP_VLAN),
                   opflexagent::flow::meta::ACCESS_MASK)
             .go(TAP).done());
        if (ep->isAccessAllowUntagged() && ep->getAccessIfaceVlan()) {
            ADDF(Bldr()
                 .table(GRP).priority(200).udp6().in(access)
                 .isVlanTci("0x0000/0x1fff")
                 .isTpSrc(546).isTpDst(547)
                 .actions()
                 .load(OUTPORT, uplink)
                 .meta(opflexagent::flow::meta::access_meta::EGRESS_DIR,
                       opflexagent::flow::meta::ACCESS_MASK)
                 .go(TAP).done());
        }
    }
}

void AccessFlowManagerLocalSGFixture::initExpEp(shared_ptr<Endpoint>& ep) {
    uint32_t access = portmapper.FindPort(ep->getAccessInterface().get());
    uint32_t uplink = portmapper.FindPort(ep->getAccessUplinkInterface().get());
    uint32_t zoneId = idGen.getId("conntrack", ep->getUUID());

    if (access == OFPP_NONE || uplink == OFPP_NONE) return;

    if (ep->getAccessIfaceVlan()) {
        ADDF(Bldr().table(GRP).priority(100).in(access)
             .isVlan(ep->getAccessIfaceVlan().get())
             .actions()
             .load(RD, zoneId).load(SEPG, 1)
             .load(OUTPORT, uplink)
             .meta((opflexagent::flow::meta::access_out::POP_VLAN|
                    opflexagent::flow::meta::access_meta::EGRESS_DIR),
                   opflexagent::flow::meta::ACCESS_MASK)
             .go(SYS_OUT_POL).done());
        if (ep->isAccessAllowUntagged()) {
            ADDF(Bldr().table(GRP).priority(99).in(access)
                 .isVlanTci("0x0000/0x1fff")
                 .actions()
                 .load(RD, zoneId).load(SEPG, 1)
                 .load(OUTPORT, uplink)
                 .meta(opflexagent::flow::meta::access_meta::EGRESS_DIR,
                       opflexagent::flow::meta::access_meta::MASK)
                 .go(SYS_OUT_POL).done());
        }
        ADDF(Bldr().table(GRP).priority(100).in(uplink)
             .actions().load(RD, zoneId).load(SEPG, 1).load(OUTPORT, access)
             .load(FD, ep->getAccessIfaceVlan().get())
             .meta((opflexagent::flow::meta::access_out::PUSH_VLAN|
                    opflexagent::flow::meta::access_meta::INGRESS_DIR),
                   opflexagent::flow::meta::ACCESS_MASK)
             .go(SYS_IN_POL).done());
    } else {
        ADDF(Bldr().table(GRP).priority(100).in(access)
             .noVlan()
             .actions().load(RD, zoneId).load(SEPG, 1)
             .load(OUTPORT, uplink)
             .meta(opflexagent::flow::meta::access_meta::EGRESS_DIR,
                   opflexagent::flow::meta::access_meta::MASK)
             .go(SYS_OUT_POL).done());
        ADDF(Bldr().table(GRP).priority(100).in(uplink)
             .actions().load(RD, zoneId).load(SEPG, 1)
             .load(OUTPORT, access)
             .meta(opflexagent::flow::meta::access_meta::INGRESS_DIR,
                   opflexagent::flow::meta::access_meta::MASK)
             .go(SYS_IN_POL).done());
    }
}

void AccessFlowManagerLocalSGFixture::initExpLearningBridge() {
    ADDF(Bldr().table(GRP).priority(500).in(24)
         .isVlanTci("0x1400/0x1f00")
         .actions().outPort(42).done());
    ADDF(Bldr().table(GRP).priority(500).in(42)
         .isVlanTci("0x1400/0x1f00")
         .actions().outPort(24).done());
}

void AccessFlowManagerLocalSGFixture::initExpSecGrpSet1() {
    uint32_t setId = idGen.getId("secGroupSet", secGrp1->getURI().toString());
    initExpSecGrp1(setId, 0);
}

void AccessFlowManagerLocalSGFixture::initExpSecGrpSet12(bool second,
                                                  int remoteAddress) {
    uint32_t setId = idGen.getId("secGroupSet",
                                 secGrp1->getURI().toString() +
                                 ",/PolicyUniverse/PolicySpace/tenant0"
                                 "/GbpLocalSecGroup/secgrp2/");
    initExpSecGrp1(setId, remoteAddress);
    if (second)
        initExpSecGrp2(setId);
}

void AccessFlowManagerLocalSGFixture::initExpSysSecGrpSet1(){
    uint16_t prio = PolicyManager::MAX_POLICY_RULE_PRIORITY;
    PolicyManager::rule_list_t rules;
    agent.getPolicyManager().getSecGroupRules(sysSecGrp1->getURI(), rules);
    uint32_t ruleId;

    ADDF(Bldr().table(SYS_IN_POL).cookie(ovs_ntohll(opflexagent::flow::cookie::TABLE_DROP_FLOW))
        .flags(OFPUTIL_FF_SEND_FLOW_REM).priority(2)
        .actions().dropLog(SYS_IN_POL).go(EXP_DROP).done());

    ADDF(Bldr().table(SYS_OUT_POL).cookie(ovs_ntohll(opflexagent::flow::cookie::TABLE_DROP_FLOW))
        .flags(OFPUTIL_FF_SEND_FLOW_REM).priority(2)
        .actions().dropLog(SYS_OUT_POL).go(EXP_DROP).done());

    /* classifier 5 */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier5->getURI().toString());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_IN_POL).priority(prio).cookie(ruleId)
         .isEth(0x8906).actions().go(IN_POL).done());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_OUT_POL).priority(prio).cookie(ruleId)
         .isEth(0x8906).actions().go(OUT_POL).done());

    /* classifier 9 */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier9->getURI().toString());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_IN_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("-new+est-rel+rpl-inv+trk").tcp()
         .actions().go(IN_POL).done());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_IN_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("-new+rel-inv+trk").ip()
         .actions().go(IN_POL).done());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_IN_POL).priority(prio - 128)
         .isCtState("-trk").tcp()
         .actions().ct("table=2,zone=NXM_NX_REG6[0..15]").done());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_OUT_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("-trk")
         .tcp().isTpDst(22)
         .actions().ct("table=2,zone=NXM_NX_REG6[0..15]").done());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_OUT_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("+est+trk")
         .tcp().isTpDst(22)
         .actions()
         .go(OUT_POL).done());
    ADDF(Bldr(SEND_FLOW_REM).table(SYS_OUT_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("+new+trk")
         .tcp().isTpDst(22)
         .actions()
         .go(OUT_POL).done());

}

uint16_t AccessFlowManagerLocalSGFixture::initExpSecGrp1(uint32_t setId,
                                                  int remoteAddress) {
    uint16_t prio = PolicyManager::MAX_POLICY_RULE_PRIORITY;
    PolicyManager::rule_list_t rules;
    agent.getPolicyManager().getSecGroupRules(secGrp1->getURI(), rules);
    uint32_t ruleId;

    /* classifer 1  */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier1->getURI().toString());
    if (remoteAddress) {
        ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio).cookie(ruleId)
             .tcp().reg(SEPG, setId).isIpSrc("192.168.0.0/16").isTpDst(80)
             .actions().go(TAP).done());
        if (remoteAddress > 1)
            ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio).cookie(ruleId)
                 .tcp().reg(SEPG, setId).isIpSrc("10.0.0.0/8").isTpDst(80)
                 .actions().go(TAP).done());
    }
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio).cookie(ruleId)
         .tcp().reg(SEPG, setId).isTpDst(80).actions().go(TAP).done());
    /* classifer 8  */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier8->getURI().toString());
    if (remoteAddress) {
        ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-128).cookie(ruleId)
             .tcp6().reg(SEPG, setId).isIpv6Src("fd80::/32").isTpDst(80)
             .actions().go(TAP).done());
        if (remoteAddress > 1)
            ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-128).cookie(ruleId)
                 .tcp6().reg(SEPG, setId)
                 .isIpv6Src("fd34:9c39:1374:358c::/64")
                 .isTpDst(80).actions().go(TAP).done());
    }
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-128).cookie(ruleId)
        .tcp6().reg(SEPG, setId).isTpDst(80)
        .actions().go(TAP).done());
    /* classifier 2  */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier2->getURI().toString());
    if (remoteAddress) {
        ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio-256).cookie(ruleId)
              .arp().reg(SEPG, setId).isTpa("192.168.0.0/16")
              .actions().go(TAP).done());
        if (remoteAddress > 1)
           ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio-256).cookie(ruleId)
                 .arp().reg(SEPG, setId).isTpa("10.0.0.0/8")
                 .actions().go(TAP).done());
    } else {
        ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio-256).cookie(ruleId)
             .arp().reg(SEPG, setId).actions().go(TAP).done());
    }
    /* classifier 6 */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier6->getURI().toString());
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-384).cookie(ruleId)
         .tcp().reg(SEPG, setId).isTpSrc(22)
         .isTcpFlags("+syn+ack").actions().go(TAP).done());
    /* classifier 7 */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier7->getURI().toString());
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-512).cookie(ruleId)
         .tcp().reg(SEPG, setId).isTpSrc(21)
         .isTcpFlags("+ack").actions().go(TAP).done());
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-512).cookie(ruleId)
         .tcp().reg(SEPG, setId).isTpSrc(21)
         .isTcpFlags("+rst").actions().go(TAP).done());

    return 512;
}


uint16_t AccessFlowManagerLocalSGFixture::initExpSecGrp2(uint32_t setId) {
    uint16_t prio = PolicyManager::MAX_POLICY_RULE_PRIORITY;
    PolicyManager::rule_list_t rules;
    agent.getPolicyManager().getSecGroupRules(secGrp2->getURI(), rules);
    uint32_t ruleId;

    /* classifier 5 */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier5->getURI().toString());
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio).cookie(ruleId)
         .reg(SEPG, setId).isEth(0x8906).actions().go(TAP).done());
    ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio).cookie(ruleId)
         .reg(SEPG, setId).isEth(0x8906).actions().go(TAP).done());

    /* classifier 9 */
    ruleId = idGen.getId("l24classifierRule",
                         local_classifier9->getURI().toString());
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("-new+est-rel+rpl-inv+trk").tcp().reg(SEPG, setId)
         .actions().go(TAP).done());
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("-new+rel-inv+trk").ip().reg(SEPG, setId)
         .actions().go(TAP).done());
    ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio - 128)
         .isCtState("-trk").tcp().reg(SEPG, setId)
         .actions().ct("table=2,zone=NXM_NX_REG6[0..15]").done());
    ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("-trk")
         .tcp().reg(SEPG, setId).isTpDst(22)
         .actions().ct("table=2,zone=NXM_NX_REG6[0..15]").done());
    ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("+est+trk")
         .tcp().reg(SEPG, setId).isTpDst(22)
         .actions()
         .go(TAP).done());
    ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio - 128).cookie(ruleId)
         .isCtState("+new+trk")
         .tcp().reg(SEPG, setId).isTpDst(22)
         .actions().ct("commit,zone=NXM_NX_REG6[0..15]")
         .go(TAP).done());

    return 1;
}

uint16_t AccessFlowManagerLocalSGFixture::initExpSecGrp3(int remoteAddress) {

    uint32_t setId = 2;
    uint16_t prio = PolicyManager::MAX_POLICY_RULE_PRIORITY;
    PolicyManager::rule_list_t rules;
    agent.getPolicyManager().getSecGroupRules(secGrp3->getURI(), rules);
    uint64_t ruleId;

     /* classifer 2  */
    ruleId = idGen.getId("l24classifierRule", local_classifier2->getURI().toString());
    if (remoteAddress) {
         ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio).cookie(ruleId)
             .arp().reg(SEPG, setId).actions()
             .dropLog(OUT_POL, POLICY_DENY, ruleId).go(EXP_DROP).done());
    }

    /* classifer 1  */
    ruleId = idGen.getId("l24classifierRule", local_classifier1->getURI().toString());
    if (remoteAddress) {
        ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-128).cookie(ruleId)
        .tcp().reg(SEPG, setId).actions()
        .dropLog(IN_POL, POLICY_DENY, ruleId).go(EXP_DROP).done());

    }

    /* classifer 5  */
    ruleId = idGen.getId("l24classifierRule", local_classifier5->getURI().toString());
    if (remoteAddress) {
        ADDF(Bldr(SEND_FLOW_REM).table(IN_POL).priority(prio-256).cookie(ruleId)
             .reg(SEPG, setId).isEth(0x8906).actions()
             .dropLog(IN_POL, POLICY_DENY, ruleId).go(EXP_DROP).done());
        ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio-256).cookie(ruleId)
             .reg(SEPG, setId).isEth(0x8906).actions()
             .dropLog(OUT_POL, POLICY_DENY, ruleId).go(EXP_DROP).done());

    }
    return 512;
}

void AccessFlowManagerLocalSGFixture::initExpSecGrp4(std::vector<std::pair<std::string,uint16_t>>& namedAddressSet) {
    using boost::asio::ip::address;
    uint32_t setId = 2;
    uint16_t prio = PolicyManager::MAX_POLICY_RULE_PRIORITY;
    uint64_t ruleId = idGen.getId("l24classifierRule", local_classifier100->getURI().toString());
    uint64_t rule6Id = idGen.getId("l24classifierRule", local_classifier101->getURI().toString());
    for( auto& pr : namedAddressSet) {
        auto destAddr = address::from_string(pr.first);
        if(destAddr.is_v4()) {
            ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio).cookie(ruleId)
             .ip().reg(SEPG, setId).isIpDst(pr.first).actions()
             .go(TAP).done());
        } else {
            ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio-128).cookie(rule6Id)
             .ipv6().reg(SEPG, setId).isIpv6Dst(pr.first).actions()
             .go(TAP).done());
        }
    }
}

void AccessFlowManagerLocalSGFixture::initExpSecGrp6() {
    uint32_t setId = 2;
    uint16_t prio = PolicyManager::MAX_POLICY_RULE_PRIORITY;
    uint64_t ruleId = idGen.getId("l24classifierRule", local_classifier1->getURI().toString());
    ADDF(Bldr(SEND_FLOW_REM).table(OUT_POL).priority(prio).cookie(ruleId)
             .tcp().reg(SEPG, setId).isIpDst("10.0.0.0/16").isTpDst(80).actions()
             .permitLog(OUT_POL,EXP_DROP,ruleId).go(TAP).done());
}
BOOST_AUTO_TEST_SUITE_END()
