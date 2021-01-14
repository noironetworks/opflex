/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for SysStatManager
 *
 * Copyright (c) 2021 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>
#include <opflexagent/test/ModbFixture.h>
#include <opflexagent/test/BaseFixture.h>
#include <opflexagent/logging.h>
#include <modelgbp/observer/SysStatUniverse.hpp>
#include <opflexagent/SysStatsManager.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_PROMETHEUS_SUPPORT
#include <opflexagent/PrometheusManager.h>
#endif

namespace opflexagent {

using boost::optional;
using std::size_t;
using namespace modelgbp::gbp;
using namespace modelgbp::gbpe;
using namespace opflex::modb;
using modelgbp::observer::SysStatUniverse;

class SysStatsManagerFixture : public ModbFixture {
    typedef opflex::ofcore::OFConstants::OpflexElementMode opflex_elem_t;
public:
    SysStatsManagerFixture(opflex_elem_t mode = opflex_elem_t::INVALID_MODE)
        : ModbFixture(mode) {
    }

    virtual ~SysStatsManagerFixture() {
    }

#ifdef HAVE_PROMETHEUS_SUPPORT
    void updateOFPeerStats(std::shared_ptr<OFAgentStats> opflexStats);
    void verifyOFPeerMetrics(const std::string& peer, uint32_t count, bool del);
    void updateMoDBCounts(std::shared_ptr<ModbCounts> pCounts, int count);
    void verifyMoDBCounts(uint32_t count, bool del);
    const string cmd = "curl --proxy \"\" --compressed --silent http://127.0.0.1:9612/metrics 2>&1;";
#endif
};

#ifdef HAVE_PROMETHEUS_SUPPORT
void SysStatsManagerFixture::
updateMoDBCounts (std::shared_ptr<ModbCounts> pCounts, int count)
{
    pCounts->setLocalEP(count++);
    pCounts->setRemoteEP(count++);
    pCounts->setExtEP(count++);
    pCounts->setEpg(count++);
    pCounts->setExtIntfs(count++);
    pCounts->setRd(count++);
    pCounts->setService(count++);
    pCounts->setContract(count++);
    pCounts->setSg(count);
}

void SysStatsManagerFixture::
verifyMoDBCounts (uint32_t count, bool del)
{
    const std::string& output = BaseFixture::getOutputFromCommand(cmd);
    size_t pos = std::string::npos;

    const std::string& local_ep = "opflex_total_ep_local " + std::to_string(count++) + ".000000";
    pos = output.find(local_ep);
    BaseFixture::expPosition(!del, pos);

    const std::string& remote_ep = "opflex_total_ep_remote " + std::to_string(count++) + ".000000";
    pos = output.find(remote_ep);
    BaseFixture::expPosition(!del, pos);

    const std::string& ext_ep = "opflex_total_ep_ext " + std::to_string(count++) + ".000000";
    pos = output.find(ext_ep);
    BaseFixture::expPosition(!del, pos);

    const std::string& epg = "opflex_total_epg " + std::to_string(count++) + ".000000";
    pos = output.find(epg);
    BaseFixture::expPosition(!del, pos);

    const std::string& ext_intf = "opflex_total_ext_intf " + std::to_string(count++) + ".000000";
    pos = output.find(ext_intf);
    BaseFixture::expPosition(!del, pos);

    const std::string& rd = "opflex_total_rd " + std::to_string(count++) + ".000000";
    pos = output.find(rd);
    BaseFixture::expPosition(!del, pos);

    const std::string& service = "opflex_total_service " + std::to_string(count++) + ".000000";
    pos = output.find(service);
    BaseFixture::expPosition(!del, pos);

    const std::string& contract = "opflex_total_contract " + std::to_string(count++) + ".000000";
    pos = output.find(contract);
    BaseFixture::expPosition(!del, pos);

    const std::string& sg = "opflex_total_sg " + std::to_string(count) + ".000000";
    pos = output.find(sg);
    BaseFixture::expPosition(!del, pos);
}

void SysStatsManagerFixture::
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

void SysStatsManagerFixture::
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
#endif

BOOST_AUTO_TEST_SUITE(SysStatsManager_test)

#ifdef HAVE_PROMETHEUS_SUPPORT
BOOST_FIXTURE_TEST_CASE(testOFPeer, SysStatsManagerFixture) {

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

BOOST_FIXTURE_TEST_CASE(testMoDBCounts, SysStatsManagerFixture) {

    LOG(DEBUG) << "### MoDBCounts start";
    Mutator mutator(agent.getFramework(), "policyelement");
    optional<std::shared_ptr<SysStatUniverse> > ssu =
                SysStatUniverse::resolve(agent.getFramework());
    BOOST_CHECK(ssu);

    auto pCounts = ssu.get()->addObserverModbCounts();
    BOOST_CHECK(pCounts);

    updateMoDBCounts(pCounts, 1);
    agent.getPrometheusManager().addNUpdateMoDBCounts(pCounts);
    verifyMoDBCounts(1, false);

    updateMoDBCounts(pCounts, 10);
    agent.getPrometheusManager().addNUpdateMoDBCounts(pCounts);
    verifyMoDBCounts(10, false);

    pCounts->remove();
    mutator.commit();
    agent.getPrometheusManager().removeMoDBCounts();
    verifyMoDBCounts(0, true);
    LOG(DEBUG) << "### MoDBCounts end";
}
#endif

BOOST_AUTO_TEST_SUITE_END()
}
