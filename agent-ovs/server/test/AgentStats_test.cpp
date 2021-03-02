/*
 * Test suite for class OFServerStats.
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <sstream>
#include <boost/test/unit_test.hpp>

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <opflexagent/logging.h>
#include <opflexagent/test/BaseFixture.h>
#include <lib/util.h>
#include <opflexagent/PrometheusManager.h>
#include <opflex/ofcore/OFServerStats.h>

using std::shared_ptr;
using std::string;
using namespace modelgbp::gbp;
using namespace modelgbp::gbpe;
using modelgbp::observer::PolicyStatUniverse;
using opflex::modb::class_id_t;

namespace opflexagent {

class AgentStatsFixture : public BaseFixture {
    typedef opflex::ofcore::OFConstants::OpflexElementMode opflex_elem_t;
public:
    AgentStatsFixture(opflex_elem_t mode = opflex_elem_t::INVALID_MODE) : BaseFixture(mode)
    {
        prometheusManager.start(true);
    }

    virtual ~AgentStatsFixture()
    {
        prometheusManager.stop();
    }

    void updateOFAgentStats(shared_ptr<OFServerStats> opflexStats);
    void verifyOFAgentMetrics(const string& agent, uint32_t count, bool del);
    const string cmd = "curl --proxy \"\" --compressed --silent http://127.0.0.1:9632/metrics 2>&1;";
    ServerPrometheusManager prometheusManager;
};

void AgentStatsFixture::
updateOFAgentStats (shared_ptr<OFServerStats> opflexStats)
{
    opflexStats->incrIdentReqs();
    opflexStats->incrPolUpdates();
    opflexStats->incrPolUnavailableResolves();
    opflexStats->incrPolResolves();
    opflexStats->incrPolResolveErrs();
    opflexStats->incrPolUnresolves();
    opflexStats->incrPolUnresolveErrs();
    opflexStats->incrEpDeclares();
    opflexStats->incrEpDeclareErrs();
    opflexStats->incrEpUndeclares();
    opflexStats->incrEpUndeclareErrs();
    opflexStats->incrEpResolves();
    opflexStats->incrEpResolveErrs();
    opflexStats->incrEpUnresolves();
    opflexStats->incrEpUnresolveErrs();
    opflexStats->incrStateReports();
    opflexStats->incrStateReportErrs();
}

void AgentStatsFixture::
verifyOFAgentMetrics (const string& agent, uint32_t count, bool del)
{
    const string& output = BaseFixture::getOutputFromCommand(cmd);
    const auto& val = std::to_string(count);

    const string& ident_req = "opflex_agent_identity_req_count{agent=\""
                                   + agent + "\"} " + val;
    size_t pos = output.find(ident_req);
    BaseFixture::expPosition(!del, pos);

    const string& pol_upd = "opflex_agent_policy_update_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(pol_upd);
    BaseFixture::expPosition(!del, pos);

    const string& res_un = "opflex_agent_policy_unavailable_resolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(res_un);
    BaseFixture::expPosition(!del, pos);

    const string& res_req = "opflex_agent_policy_resolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(res_req);
    BaseFixture::expPosition(!del, pos);
    const string& res_err = "opflex_agent_policy_resolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(res_err);
    BaseFixture::expPosition(!del, pos);

    const string& unres_req = "opflex_agent_policy_unresolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(unres_req);
    BaseFixture::expPosition(!del, pos);
    const string& unres_err = "opflex_agent_policy_unresolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(unres_err);
    BaseFixture::expPosition(!del, pos);

    const string& epd_req = "opflex_agent_ep_declare_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epd_req);
    BaseFixture::expPosition(!del, pos);
    const string& epd_err = "opflex_agent_ep_declare_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epd_err);
    BaseFixture::expPosition(!del, pos);

    const string& epud_req = "opflex_agent_ep_undeclare_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epud_req);
    BaseFixture::expPosition(!del, pos);
    const string& epud_err = "opflex_agent_ep_undeclare_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epud_err);
    BaseFixture::expPosition(!del, pos);

    const string& epr_req = "opflex_agent_ep_resolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epr_req);
    BaseFixture::expPosition(!del, pos);
    const string& epr_err = "opflex_agent_ep_resolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epr_err);
    BaseFixture::expPosition(!del, pos);

    const string& epur_req = "opflex_agent_ep_unresolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epur_req);
    BaseFixture::expPosition(!del, pos);
    const string& epur_err = "opflex_agent_ep_unresolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epur_err);
    BaseFixture::expPosition(!del, pos);

    const string& rep_req = "opflex_agent_state_report_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(rep_req);
    BaseFixture::expPosition(!del, pos);
    const string& rep_err = "opflex_agent_state_report_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(rep_err);
    BaseFixture::expPosition(!del, pos);
}

BOOST_AUTO_TEST_SUITE(AgentStats_test)

BOOST_FIXTURE_TEST_CASE(testOFAgent, AgentStatsFixture) {

    LOG(DEBUG) << "### OfAgent start";
    shared_ptr<OFServerStats> opflexStats = std::make_shared<OFServerStats>();
    const string& agent = "127.0.0.1:9999";

    updateOFAgentStats(opflexStats);
    prometheusManager.addNUpdateOFAgentStats(agent,
                                             opflexStats);
    verifyOFAgentMetrics(agent, 1, false);

    updateOFAgentStats(opflexStats);
    prometheusManager.addNUpdateOFAgentStats(agent,
                                             opflexStats);
    verifyOFAgentMetrics(agent, 2, false);

    prometheusManager.removeOFAgentStats(agent);
    verifyOFAgentMetrics(agent, 0, true);
    LOG(DEBUG) << "### OFAgent end";
}

BOOST_AUTO_TEST_SUITE_END()

}
