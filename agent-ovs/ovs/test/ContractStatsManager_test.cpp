/*
 * Test suite for class ContractStatsManager.
 *
 * Copyright (c) 2017 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <sstream>
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <opflexagent/logging.h>
#include <opflexagent/test/ModbFixture.h>
#include "ovs-ofputil.h"
#include <lib/util.h>
#include "IntFlowManager.h"
#include "ContractStatsManager.h"
#include "TableState.h"
#include "ActionBuilder.h"
#include "RangeMask.h"
#include "FlowConstants.h"
#include "PolicyStatsManagerFixture.h"
#include <opflex/modb/Mutator.h>
#include <modelgbp/gbp/Contract.hpp>
#include "ovs-ofputil.h"
#include <modelgbp/gbpe/L24ClassifierCounter.hpp>

extern "C" {
#include <openvswitch/ofp-parse.h>
#include <openvswitch/ofp-print.h>
}

using namespace boost::assign;
using boost::optional;
using std::shared_ptr;
using std::string;
using namespace modelgbp::gbp;
using namespace modelgbp::gbpe;
using modelgbp::observer::PolicyStatUniverse;
using opflex::modb::class_id_t;
using opflex::modb::Mutator;

namespace opflexagent {

static const uint32_t LAST_PACKET_COUNT = 379; // for removed flow entry

class MockContractStatsManager : public ContractStatsManager {
public:
    MockContractStatsManager(Agent *agent_,
                             IdGenerator& idGen_,
                             SwitchManager& switchManager_,
                             long timer_interval_)
        : ContractStatsManager(agent_, idGen_, switchManager_, timer_interval_) {};

    void testInjectTxnId (uint32_t txn_id) {
        std::lock_guard<mutex> lock(txnMtx);
        txns.insert(txn_id);
    }
};

class ContractStatsManagerFixture : public PolicyStatsManagerFixture {

public:
    ContractStatsManagerFixture() : PolicyStatsManagerFixture(),
                                    intFlowManager(agent, switchManager, idGen,
                                                   ctZoneManager, tunnelEpManager),
                                    contractStatsManager(&agent, idGen,
                                                         switchManager, 300),
                                    policyManager(agent.getPolicyManager()) {
        switchManager.setMaxFlowTables(IntFlowManager::NUM_FLOW_TABLES);
        intFlowManager.start();
        createObjects();
        createPolicyObjects();
        idGen.initNamespace("l24classifierRule");
        idGen.initNamespace("routingDomain");
        switchManager.setMaxFlowTables(IntFlowManager::NUM_FLOW_TABLES);
    }
    virtual ~ContractStatsManagerFixture() {
        intFlowManager.stop();
        stop();
    }
    void verifyRoutingDomainDropStats(shared_ptr<RoutingDomain> rd,
                                      uint32_t packet_count,
                                      uint32_t byte_count);
    void waitForRdDropEntry(void);
#ifdef HAVE_PROMETHEUS_SUPPORT
    virtual void verifyPromMetrics(shared_ptr<L24Classifier> classifier,
                            uint32_t pkts,
                            uint32_t bytes,
                            bool isTx=false) override;
    void verifyRdDropPromMetrics(uint32_t pkts, uint32_t bytes);
    void updateOFPeerStats(std::shared_ptr<OFAgentStats> opflexStats);
    void verifyOFPeerMetrics(const std::string& peer, uint32_t count, bool del);
#endif
    IntFlowManager  intFlowManager;
    MockContractStatsManager contractStatsManager;
    PolicyManager& policyManager;
private:
    bool checkNewFlowMapSize(size_t pol_table_size);
};

#ifdef HAVE_PROMETHEUS_SUPPORT
void ContractStatsManagerFixture::
updateOFPeerStats (std::shared_ptr<OFAgentStats> opflexStats)
{
    opflexStats->incrIdentReqs();
    opflexStats->incrIdentResps();
    opflexStats->incrPolResolves();
    opflexStats->incrPolResolveResps();
    opflexStats->incrPolUnresolves();
    opflexStats->incrPolUnresolveResps();
    opflexStats->incrPolUpdates();
    opflexStats->incrEpDeclares();
    opflexStats->incrEpDeclareResps();
    opflexStats->incrEpUndeclares();
    opflexStats->incrEpUndeclareResps();
    opflexStats->incrStateReports();
    opflexStats->incrStateReportResps();
    opflexStats->incrPolUnresolvedCount();
}

void ContractStatsManagerFixture::
verifyOFPeerMetrics (const std::string& peer, uint32_t count, bool del)
{
    const std::string& output = BaseFixture::getOutputFromCommand(cmd);
    size_t pos = std::string::npos;
    const auto& val1 = std::to_string(count) + ".000000";
    const auto& val2 = "0.000000";

    const std::string& ident_req = "opflex_peer_identity_req_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(ident_req);
    BaseFixture::expPosition(!del, pos);
    const std::string ident_resp = "opflex_peer_identity_resp_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(ident_resp);
    BaseFixture::expPosition(!del, pos);
    const std::string ident_err = "opflex_peer_identity_err_count{peer=\""
                                   + peer + "\"} " + val2;
    pos = output.find(ident_err);
    BaseFixture::expPosition(!del, pos);

    const std::string& res_req = "opflex_peer_policy_resolve_req_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(res_req);
    BaseFixture::expPosition(!del, pos);
    const std::string& res_resp = "opflex_peer_policy_resolve_resp_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(res_resp);
    BaseFixture::expPosition(!del, pos);
    const std::string& res_err = "opflex_peer_policy_resolve_err_count{peer=\""
                                   + peer + "\"} " + val2;
    pos = output.find(res_err);
    BaseFixture::expPosition(!del, pos);

    const std::string& unres_req = "opflex_peer_policy_unresolve_req_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(unres_req);
    BaseFixture::expPosition(!del, pos);
    const std::string& unres_resp = "opflex_peer_policy_unresolve_resp_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(unres_resp);
    BaseFixture::expPosition(!del, pos);
    const std::string& unres_err = "opflex_peer_policy_unresolve_err_count{peer=\""
                                   + peer + "\"} " + val2;
    pos = output.find(unres_err);
    BaseFixture::expPosition(!del, pos);

    const std::string& pol_upd = "opflex_peer_policy_update_receive_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(pol_upd);
    BaseFixture::expPosition(!del, pos);

    const std::string& epd_req = "opflex_peer_ep_declare_req_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(epd_req);
    BaseFixture::expPosition(!del, pos);
    const std::string& epd_resp = "opflex_peer_ep_declare_resp_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(epd_resp);
    BaseFixture::expPosition(!del, pos);
    const std::string& epd_err = "opflex_peer_ep_declare_err_count{peer=\""
                                   + peer + "\"} " + val2;
    pos = output.find(epd_err);
    BaseFixture::expPosition(!del, pos);

    const std::string& epud_req = "opflex_peer_ep_undeclare_req_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(epud_req);
    BaseFixture::expPosition(!del, pos);
    const std::string& epud_resp = "opflex_peer_ep_undeclare_resp_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(epud_resp);
    BaseFixture::expPosition(!del, pos);
    const std::string& epud_err = "opflex_peer_ep_undeclare_err_count{peer=\""
                                   + peer + "\"} " + val2;
    pos = output.find(epud_err);
    BaseFixture::expPosition(!del, pos);

    const std::string& rep_req = "opflex_peer_state_report_req_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(rep_req);
    BaseFixture::expPosition(!del, pos);
    const std::string& rep_resp = "opflex_peer_state_report_resp_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(rep_resp);
    BaseFixture::expPosition(!del, pos);
    const std::string& rep_err = "opflex_peer_state_report_err_count{peer=\""
                                   + peer + "\"} " + val2;
    pos = output.find(rep_err);
    BaseFixture::expPosition(!del, pos);
 
    const std::string& unres_count = "opflex_peer_unresolved_policy_count{peer=\""
                                   + peer + "\"} " + val1;
    pos = output.find(unres_count);
    BaseFixture::expPosition(!del, pos);
}

void ContractStatsManagerFixture::
verifyPromMetrics (shared_ptr<L24Classifier> classifier,
                   uint32_t pkts,
                   uint32_t bytes,
                   bool isTx)
{
    const std::string& s_pkts = "opflex_contract_packets{classifier=\"tenant:tenant0,"\
                                "policy:classifier3,[etype:2048,proto:6,dport:80-85,]\""\
                                ",dst_epg=\"tenant:tenant0,policy:epg2\",src_epg=\""\
                                "tenant:tenant0,policy:epg1\"} "\
                                + std::to_string(pkts) + ".000000";
    const std::string& s_bytes = "opflex_contract_bytes{classifier=\"tenant:tenant0,"\
                                 "policy:classifier3,[etype:2048,proto:6,dport:80-85,]\""\
                                 ",dst_epg=\"tenant:tenant0,policy:epg2\",src_epg=\""\
                                 "tenant:tenant0,policy:epg1\"} "\
                                 + std::to_string(bytes) + ".000000";

    const std::string& output = BaseFixture::getOutputFromCommand(cmd);
    size_t pos = std::string::npos;
    pos = output.find(s_pkts);
    BOOST_CHECK_NE(pos, std::string::npos);
    pos = output.find(s_bytes);
    BOOST_CHECK_NE(pos, std::string::npos);
}

void ContractStatsManagerFixture::
verifyRdDropPromMetrics (uint32_t pkts,
                         uint32_t bytes)
{
    const std::string& s_pkts = "opflex_policy_drop_packets{routing_domain=\"tenant0:rd0\"} "\
                                + std::to_string(pkts) + ".000000";
    const std::string& s_bytes = "opflex_policy_drop_bytes{routing_domain=\"tenant0:rd0\"} "\
                                 + std::to_string(bytes) + ".000000";

    const std::string& output = BaseFixture::getOutputFromCommand(cmd);
    size_t pos = std::string::npos;
    pos = output.find(s_pkts);
    BOOST_CHECK_NE(pos, std::string::npos);
    pos = output.find(s_bytes);
    BOOST_CHECK_NE(pos, std::string::npos);
}
#endif

void ContractStatsManagerFixture::
verifyRoutingDomainDropStats(shared_ptr<RoutingDomain> rd,
                             uint32_t packet_count,
                             uint32_t byte_count) {

    optional<shared_ptr<PolicyStatUniverse> > su =
        PolicyStatUniverse::resolve(agent.getFramework());

    auto uuid = contractStatsManager.getAgentUUID();
    WAIT_FOR_DO_ONFAIL(su.get()->resolveGbpeRoutingDomainDropCounter(uuid,
                                    contractStatsManager.getCurrDropGenId(),
                                    rd->getURI().toString()),
                                    500,, LOG(ERROR) << "Obj not resolved";);
    optional<shared_ptr<RoutingDomainDropCounter> > myCounter =
        su.get()->resolveGbpeRoutingDomainDropCounter(uuid,
                                                      contractStatsManager
                                                      .getCurrDropGenId(),
                                                      rd->getURI().toString());
    BOOST_CHECK(myCounter);
    BOOST_CHECK_EQUAL(myCounter.get()->getPackets().get(), packet_count);
    BOOST_CHECK_EQUAL(myCounter.get()->getBytes().get(), byte_count);

#ifdef HAVE_PROMETHEUS_SUPPORT
    verifyRdDropPromMetrics(packet_count, byte_count);
#endif
}

struct ofpbuf *makeFlowStatReplyMessage(uint32_t priority, uint64_t cookie,
                                        uint32_t packet_count,
                                        uint32_t byte_count,
                                        uint32_t reg0, uint32_t reg2,
                                        uint32_t reg6) {

    struct ofputil_flow_stats_request fsr;
    bzero(&fsr, sizeof(struct ofputil_flow_stats_request));
    fsr.table_id = IntFlowManager::POL_TABLE_ID;
    fsr.out_port = OFPP_ANY;
    fsr.out_group = OFPG_ANY;
    fsr.cookie = fsr.cookie_mask = (uint64_t)0;
    enum ofputil_protocol proto =
        ofputil_protocol_from_ofp_version((ofp_version)OFP13_VERSION);
    struct ofpbuf *req_msg = ofputil_encode_flow_stats_request(&fsr, proto);

    struct ofp_header *req_hdr = (ofp_header *)req_msg->data;

    ovs_list ovs_replies;
    struct ofpbuf *reply = 0;

    ofpmp_init(&ovs_replies, req_hdr);
    ofpbuf_delete(req_msg);
    {
        struct ofputil_flow_stats *fs, fstat;

        fs = &fstat;
        bzero(fs, sizeof(struct ofputil_flow_stats));
        fs->table_id = IntFlowManager::POL_TABLE_ID;
        fs->priority = priority;
        fs->cookie = cookie;
        fs->packet_count = packet_count;
        fs->byte_count = byte_count;
        fs->flags = OFPUTIL_FF_SEND_FLOW_REM;
        // set match registers reg0, reg2
        match_set_reg(&(fs->match), 0 /* REG0 */, reg0);
        match_set_reg(&(fs->match), 2 /* REG2 */, reg2);
        match_set_reg(&(fs->match), 6 /* REG6 */, reg6);

        ofputil_append_flow_stats_reply(fs, &ovs_replies, NULL);
        reply = ofpbuf_from_list(ovs_list_back(&ovs_replies));
        ofpmsg_update_length(reply);
        // set it to be OFPRAW_ type of openflow message by setting
        // header to be null.
        reply->header = NULL;
        return reply;
    }

}

bool ContractStatsManagerFixture::checkNewFlowMapSize (size_t pol_table_size)
{
    //on_timer will kick in via agent_io thread. That will update
    //stats state to indicate all necessary flows have been initialized
    std::lock_guard<std::mutex> lock(contractStatsManager.pstatMtx);
    if (contractStatsManager.contractState.newFlowCounterMap.size() == pol_table_size)
        return true;

    return false;
}

// Wait for IntFlowManager to create rddrop flow and stats tables to get initialized
void ContractStatsManagerFixture::waitForRdDropEntry (void)
{
    // 1 table-drop static entry in POL table with stats enabled
    WAIT_FOR_DO_ONFAIL(checkNewFlowMapSize(1),
                       500,,
                       LOG(ERROR) << "##### flow state not fully setup ####";);

    intFlowManager.domainUpdated(RoutingDomain::CLASS_ID, rd0->getURI());

    // 1 entry is installed in policy table per VRF for collecting rddrop stats
    WAIT_FOR_DO_ONFAIL(checkNewFlowMapSize(2),
                       500,,
                       LOG(ERROR) << "##### flow state not fully setup ####";);

    // rdid for this rd should have been allocated
    WAIT_FOR_DO_ONFAIL(
            (idGen.getIdNoAlloc(IntFlowManager::getIdNamespace(RoutingDomain::CLASS_ID),
                           rd0->getURI().toString()) != (uint32_t)-1),
                        500,,
                        LOG(ERROR) << "rdId not yet alloc'd for rd0");
}

BOOST_AUTO_TEST_SUITE(ContractStatsManager_test)

BOOST_FIXTURE_TEST_CASE(testFlowMatchStats, ContractStatsManagerFixture) {
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    contractStatsManager.registerConnection(&integrationPortConn);
    contractStatsManager.start();
    LOG(DEBUG) << "### Contract flow stats start";

    contractStatsManager.Handle(NULL, OFPTYPE_FLOW_STATS_REPLY, NULL);
    contractStatsManager.Handle(&integrationPortConn,
                                OFPTYPE_FLOW_STATS_REPLY, NULL);

    testOneFlow<MockContractStatsManager>(integrationPortConn,classifier3,
                IntFlowManager::POL_TABLE_ID,
                1,
                false,
                &contractStatsManager,
                &policyManager,
                epg1,
                epg2);

    LOG(DEBUG) << "### Contract flow stats end";
    contractStatsManager.stop();
}

BOOST_FIXTURE_TEST_CASE(testRdDropStats, ContractStatsManagerFixture) {
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    contractStatsManager.registerConnection(&integrationPortConn);
    contractStatsManager.start();
    LOG(DEBUG) << "### rddrop stats start";
    waitForRdDropEntry();

    // get rdId
    uint32_t rdId =
        idGen.getIdNoAlloc(IntFlowManager::getIdNamespace(RoutingDomain::CLASS_ID),
                           rd0->getURI().toString());
    uint32_t priority = 1;
    uint32_t packet_count = 39;
    uint32_t byte_count = 6994;

    /* create  per RD flow drop stats  */
    struct ofpbuf *res_msg = makeFlowStatReplyMessage(priority,
                                                      flow::cookie::RD_POL_DROP_FLOW,
                                                      packet_count, byte_count,
                                                      0, 0, rdId);
    BOOST_REQUIRE(res_msg!=0);
    ofp_header *msgHdr = (ofp_header *)res_msg->data;
    contractStatsManager.testInjectTxnId(msgHdr->xid);

    contractStatsManager.Handle(&integrationPortConn,
                                OFPTYPE_FLOW_STATS_REPLY, res_msg);
    ofpbuf_delete(res_msg);
    LOG(DEBUG) << "testRd:FlowStatsReplyMessage handling successful";

    verifyRoutingDomainDropStats(rd0, packet_count, byte_count);
    LOG(DEBUG) << "testRd:FlowStatsReplyMessage verification successful";
    LOG(DEBUG) << "### rddrop stats end";
    contractStatsManager.stop();
}

BOOST_FIXTURE_TEST_CASE(testFlowRemoved, ContractStatsManagerFixture) {
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    contractStatsManager.registerConnection(&integrationPortConn);
    contractStatsManager.start();
    LOG(DEBUG) << "### Contract flow removed start";

    // Add flows in switchManager
    FlowEntryList entryList;
    writeClassifierFlows(entryList,
                         IntFlowManager::POL_TABLE_ID,
                         1,
                         classifier3,
                         epg1,
                         epg2,
                         &policyManager);

    boost::system::error_code ec;
    ec = make_error_code(boost::system::errc::success);
    // Call on_timer function to process the flow entries received from
    // switchManager.
    contractStatsManager.on_timer(ec);

    struct ofpbuf *res_msg =
        makeFlowRemovedMessage_2(&integrationPortConn,
                                 LAST_PACKET_COUNT,
                                 IntFlowManager::POL_TABLE_ID,
                                 entryList);
    LOG(DEBUG) << "1 makeFlowRemovedMessage_2 created";
    BOOST_REQUIRE(res_msg!=0);
    struct ofputil_flow_removed fentry;
    SwitchConnection::DecodeFlowRemoved(res_msg, &fentry);

    contractStatsManager.Handle(&integrationPortConn,
                                OFPTYPE_FLOW_REMOVED, res_msg,
                                &fentry);
    LOG(DEBUG) << "1 makeFlowRemovedMessage_2 handled";
    ofpbuf_delete(res_msg);

    // Call on_timer function to process the stats collected
    // and generate Genie objects for stats

    contractStatsManager.on_timer(ec);
    LOG(DEBUG) << "1 on_timer called";

    // calculate expected packet count and byte count
    // that we should have in Genie object

    verifyFlowStats(classifier3,
                    LAST_PACKET_COUNT,
                    LAST_PACKET_COUNT * PACKET_SIZE,
                    false,
                    IntFlowManager::POL_TABLE_ID,
                    &contractStatsManager,
                    epg1,epg2);
    LOG(DEBUG) << "1 verifyflowstats successful";
    LOG(DEBUG) << "### Contract flow removed stop";
    contractStatsManager.stop();
}

BOOST_FIXTURE_TEST_CASE(testCircularBuffer, ContractStatsManagerFixture) {
    MockConnection intPortConn(TEST_CONN_TYPE_INT);
    contractStatsManager.registerConnection(&intPortConn);
    contractStatsManager.start();
    LOG(DEBUG) << "### Contract circbuffer Start";
    // Add flows in switchManager
    testCircBuffer<MockContractStatsManager>(intPortConn,classifier3,
                   IntFlowManager::POL_TABLE_ID,2,&contractStatsManager,
                   epg1,epg2,&policyManager);
    LOG(DEBUG) << "### Contract circbuffer End";
    contractStatsManager.stop();

}

BOOST_FIXTURE_TEST_CASE(testContractDelete, ContractStatsManagerFixture) {
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    contractStatsManager.registerConnection(&integrationPortConn);
    contractStatsManager.start();
    LOG(DEBUG) << "### Contract classifier Delete Start";

    contractStatsManager.Handle(&integrationPortConn,
                                OFPTYPE_FLOW_STATS_REPLY, NULL);

    testOneFlow<MockContractStatsManager>(integrationPortConn,
                classifier3,
                IntFlowManager::POL_TABLE_ID,
                1,
                false,
                &contractStatsManager,
                &policyManager,
                epg1,
                epg2);
    Mutator mutator(agent.getFramework(), "policyreg");
    // Note: In UTs, deleting the sg doesnt trigger classifier delete
    //modelgbp::gbp::Contract::remove(agent.getFramework(),"tenant0","contract3");
    modelgbp::gbpe::L24Classifier::remove(agent.getFramework(),"tenant0","classifier3");
    mutator.commit();
    optional<shared_ptr<PolicyStatUniverse> > su =
        PolicyStatUniverse::resolve(agent.getFramework());
    auto uuid = contractStatsManager.getAgentUUID();
    optional<shared_ptr<L24ClassifierCounter> > myCounter;
    WAIT_FOR_DO_ONFAIL(!(su.get()->resolveGbpeL24ClassifierCounter(uuid,
                        contractStatsManager.getCurrClsfrGenId(),
                        epg1->getURI().toString(),
                        epg2->getURI().toString(),
                        classifier3->getURI().toString()))
                        ,500
                        ,
                        ,LOG(ERROR) << "Obj still present";);
    LOG(DEBUG) << "### Contract classifier Delete End";
    contractStatsManager.stop();
}

BOOST_FIXTURE_TEST_CASE(testSEpgDelete, ContractStatsManagerFixture) {
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    contractStatsManager.registerConnection(&integrationPortConn);
    contractStatsManager.start();
    LOG(DEBUG) << "### Contract SEPG Delete Start";

    testOneFlow<MockContractStatsManager>(integrationPortConn,
                classifier3,
                IntFlowManager::POL_TABLE_ID,
                1,
                false,
                &contractStatsManager,
                &policyManager,
                epg1,
                epg2);
    Mutator mutator(agent.getFramework(), "policyreg");
    modelgbp::gbp::EpGroup::remove(agent.getFramework(),"tenant0","epg1");
    mutator.commit();
    optional<shared_ptr<PolicyStatUniverse> > su =
        PolicyStatUniverse::resolve(agent.getFramework());
    auto uuid = contractStatsManager.getAgentUUID();
    optional<shared_ptr<L24ClassifierCounter> > myCounter;
    WAIT_FOR_DO_ONFAIL(!(su.get()->resolveGbpeL24ClassifierCounter(uuid,
                        contractStatsManager.getCurrClsfrGenId(),
                        epg1->getURI().toString(),
                        epg2->getURI().toString(),
                        classifier3->getURI().toString()))
                        ,500
                        ,
                        ,LOG(ERROR) << "Obj still present";);
    LOG(DEBUG) << "### Contract SEPG Delete End";
    contractStatsManager.stop();
}

BOOST_FIXTURE_TEST_CASE(testrDSEpgDelete, ContractStatsManagerFixture) {
    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
    contractStatsManager.registerConnection(&integrationPortConn);
    contractStatsManager.start();
    LOG(DEBUG) << "### Contract DSEPG Delete Start";

    testOneFlow<MockContractStatsManager>(integrationPortConn,
                classifier3,
                IntFlowManager::POL_TABLE_ID,
                1,
                false,
                &contractStatsManager,
                &policyManager,
                epg1,
                epg2);
    Mutator mutator(agent.getFramework(), "policyreg");
    modelgbp::gbp::EpGroup::remove(agent.getFramework(),"tenant0","epg2");
    mutator.commit();
    optional<shared_ptr<PolicyStatUniverse> > su =
        PolicyStatUniverse::resolve(agent.getFramework());
    auto uuid = contractStatsManager.getAgentUUID();
    optional<shared_ptr<L24ClassifierCounter> > myCounter;
    WAIT_FOR_DO_ONFAIL(!(su.get()->resolveGbpeL24ClassifierCounter(uuid,
                        contractStatsManager.getCurrClsfrGenId(),
                        epg1->getURI().toString(),
                        epg2->getURI().toString(),
                        classifier3->getURI().toString()))
                        ,500
                        ,
                        ,LOG(ERROR) << "Obj still present";);
    LOG(DEBUG) << "### Contract DEPG Delete End";
    contractStatsManager.stop();
}

#ifdef HAVE_PROMETHEUS_SUPPORT
// Note: OFPeer stats are currently updated as part of PolicyStatsManager.cpp
// there is a plan to move this code outside PolicyStatsManager.cpp. While thats
// done, the below test also will be moved out from this file.
BOOST_FIXTURE_TEST_CASE(testOFPeer, ContractStatsManagerFixture) {

    LOG(DEBUG) << "### OfPeer start";
    std::shared_ptr<OFAgentStats> opflexStats = std::make_shared<OFAgentStats>();
    const std::string peer = "127.0.0.1:8009";

    updateOFPeerStats(opflexStats);
    agent.getPrometheusManager().addNUpdateOFPeerStats(peer,
                                                       opflexStats);
    verifyOFPeerMetrics(peer, 1, false);

    updateOFPeerStats(opflexStats);
    agent.getPrometheusManager().addNUpdateOFPeerStats(peer,
                                                       opflexStats);
    verifyOFPeerMetrics(peer, 2, false);

    agent.getPrometheusManager().removeOFPeerStats(peer);
    verifyOFPeerMetrics(peer, 0, true);
    LOG(DEBUG) << "### OFPeer end";
}
#endif

BOOST_AUTO_TEST_SUITE_END()

}
