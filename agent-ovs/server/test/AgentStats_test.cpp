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
#include <boost/assign/list_of.hpp>

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <opflexagent/logging.h>
#include <opflexagent/test/BaseFixture.h>
#include <lib/util.h>
#include <opflex/modb/Mutator.h>
#ifdef HAVE_PROMETHEUS_SUPPORT
#include <opflexagent/PrometheusManager.h>
#endif
#include <opflex/ofcore/OFServerStats.h>

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

    void updateOFAgentStats(std::shared_ptr<OFServerStats> opflexStats);
#ifdef HAVE_PROMETHEUS_SUPPORT
    void verifyOFAgentMetrics(const std::string& agent, uint32_t count);
    const string cmd = "curl --proxy \"\" --compressed --silent http://127.0.0.1:9632/metrics 2>&1;";
    ServerPrometheusManager prometheusManager;
#endif
};

void AgentStatsFixture::
updateOFAgentStats (std::shared_ptr<OFServerStats> opflexStats)
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

#ifdef HAVE_PROMETHEUS_SUPPORT
void AgentStatsFixture::
verifyOFAgentMetrics (const std::string& agent, uint32_t count)
{
    const std::string& output = BaseFixture::getOutputFromCommand(cmd);
    size_t pos = std::string::npos;
    const auto& val = std::to_string(count) + ".000000";

    const std::string& ident_req = "opflex_agent_identity_req_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(ident_req);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& pol_upd = "opflex_agent_policy_update_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(pol_upd);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& res_un = "opflex_agent_policy_unavailable_resolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(res_un);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& res_req = "opflex_agent_policy_resolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(res_req);
    BOOST_CHECK_NE(pos, std::string::npos);
    const std::string& res_err = "opflex_agent_policy_resolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(res_err);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& unres_req = "opflex_agent_policy_unresolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(unres_req);
    BOOST_CHECK_NE(pos, std::string::npos);
    const std::string& unres_err = "opflex_agent_policy_unresolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(unres_err);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& epd_req = "opflex_agent_ep_declare_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epd_req);
    BOOST_CHECK_NE(pos, std::string::npos);
    const std::string& epd_err = "opflex_agent_ep_declare_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epd_err);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& epud_req = "opflex_agent_ep_undeclare_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epud_req);
    BOOST_CHECK_NE(pos, std::string::npos);
    const std::string& epud_err = "opflex_agent_ep_undeclare_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epud_err);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& epr_req = "opflex_agent_ep_resolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epr_req);
    BOOST_CHECK_NE(pos, std::string::npos);
    const std::string& epr_err = "opflex_agent_ep_resolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epr_err);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& epur_req = "opflex_agent_ep_unresolve_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epur_req);
    BOOST_CHECK_NE(pos, std::string::npos);
    const std::string& epur_err = "opflex_agent_ep_unresolve_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(epur_err);
    BOOST_CHECK_NE(pos, std::string::npos);

    const std::string& rep_req = "opflex_agent_state_report_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(rep_req);
    BOOST_CHECK_NE(pos, std::string::npos);
    const std::string& rep_err = "opflex_agent_state_report_err_count{agent=\""
                                   + agent + "\"} " + val;
    pos = output.find(rep_err);
    BOOST_CHECK_NE(pos, std::string::npos);
}
#endif

BOOST_AUTO_TEST_SUITE(AgentStats_test)

BOOST_FIXTURE_TEST_CASE(testOFAgent, AgentStatsFixture) {

    LOG(DEBUG) << "### OfAgent start";
    std::shared_ptr<OFServerStats> opflexStats = std::make_shared<OFServerStats>();
    const std::string agent = "127.0.0.1:9999";

    updateOFAgentStats(opflexStats);
#ifdef HAVE_PROMETHEUS_SUPPORT
    prometheusManager.addNUpdateOFAgentStats("127.0.0.1:9999",
                                             opflexStats);
    verifyOFAgentMetrics(agent, 1);
#endif

    updateOFAgentStats(opflexStats);
#ifdef HAVE_PROMETHEUS_SUPPORT
    prometheusManager.addNUpdateOFAgentStats("127.0.0.1:9999",
                                             opflexStats);
    verifyOFAgentMetrics(agent, 2);
#endif
    LOG(DEBUG) << "### OFAgent end";
}

BOOST_AUTO_TEST_SUITE_END()

}
