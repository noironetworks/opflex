/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for qos manager
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>
#include <modelgbp/dmtree/Root.hpp>

#include <opflexagent/logging.h>
#include <opflexagent/test/BaseFixture.h>
#include "Policies.h"

namespace opflexagent {

using std::shared_ptr;
using namespace modelgbp;

class QosFixture : public BaseFixture {

public:
    QosFixture() : BaseFixture() {
        shared_ptr<policy::Universe> pUniverse =
            policy::Universe::resolve(framework).get();

        Mutator mutator(framework, "policyreg");
        pSpace = pUniverse->addPolicySpace("test");
        qosCfg = pSpace->addQosBandwidthLimit("testQos");
        qosCfg->setRate(3000);
        qosCfg->setBurst(300);
        mutator.commit();
    }

    virtual ~QosFixture() {}

    shared_ptr<policy::Space> pSpace;
    shared_ptr<qos::BandwidthLimit> qosCfg;
};
BOOST_AUTO_TEST_SUITE(QosManager_test)

static bool checkQos(boost::optional<shared_ptr<QosConfigState>> pQos,
                                const URI& qosUri) {
    if (!pQos)
        return false;
    LOG(DEBUG) << "checkBandwidthLimit " << pQos.get()->getUri();
    return qosUri == pQos.get()->getUri();
}

static bool checkQosRate(boost::optional<shared_ptr<QosConfigState>> pQos,
                                shared_ptr<qos::BandwidthLimit>& pQosCfg) {
    if (!pQos)
        return false;
    LOG(DEBUG) << "checkQosRate " << pQos.get()->getRate();
    return pQos.get()->getRate() == pQosCfg->getRate();
}
static bool checkQosBurst(boost::optional<shared_ptr<QosConfigState>> pQos,
                                   shared_ptr<qos::BandwidthLimit>& pQosCfg) {
    if (!pQos)
        return false;
    LOG(DEBUG) << "checkQosBurst " << pQos.get()->getBurst();
    return pQos.get()->getBurst() == pQosCfg->getBurst();
}
BOOST_FIXTURE_TEST_CASE( verify_artifacts, QosFixture ) {
    WAIT_FOR(checkQos(agent.getQosManager().getQosConfigState(qosCfg->getURI()),
                          qosCfg->getURI()), 500);
    WAIT_FOR(checkQosRate(agent.getQosManager().getQosConfigState(qosCfg->getURI()), qosCfg), 500);
    WAIT_FOR(checkQosBurst(agent.getQosManager().getQosConfigState(qosCfg->getURI()), qosCfg), 500);

    // remove qosCfg
    const URI& qosUri = qosCfg->getURI();
    Mutator mutator(framework, "policyreg");
    qosCfg->remove();
    mutator.commit();

//  WAIT_FOR(!span::Session::resolve(framework, sessionUri), 500);
    WAIT_FOR(!qos::BandwidthLimit::resolve(framework, qosUri), 500);
}

BOOST_AUTO_TEST_SUITE_END()
}
