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
#include <boost/filesystem/fstream.hpp>
#include <opflexagent/FSEndpointSource.h>

namespace opflexagent {

namespace fs = boost::filesystem;
using std::shared_ptr;
using namespace modelgbp;
using namespace std;

class QosFixture : public BaseFixture {
    public:
        QosFixture() : BaseFixture(),
        temp(fs::temp_directory_path() / fs::unique_path()) {
            shared_ptr<policy::Universe> pUniverse =
                policy::Universe::resolve(framework).get();

            Mutator mutator(framework, "policyreg");
            pSpace = pUniverse->addPolicySpace("test");
            qosCfg = pSpace->addQosBandwidthLimit("testQos");
            qosCfg->setRate(3000);
            qosCfg->setBurst(300);

            reqCfg = pSpace->addQosRequirement("req1");
            epg = pSpace->addGbpEpGroup("epg");

            mutator.commit();

            Mutator mutator2(framework, "framework");
            egressRs = reqCfg->addQosRequirementToEgressRSrc();
            egressRs->setTargetBandwidthLimit("test", "testQos");

            mutator2.commit();

            Mutator mutator3(framework, "policyreg");
            reqRs = epg->addGbpEpGroupToQosRSrc();
            reqRs->setTargetRequirement("test","req1");

            mutator3.commit();
            fs::create_directory(temp);
        }

        virtual ~QosFixture() {
            fs::remove_all(temp);
        }

        shared_ptr<policy::Space> pSpace;
        shared_ptr<qos::BandwidthLimit> qosCfg;
        shared_ptr<qos::Requirement> reqCfg;
        shared_ptr<qos::RequirementToEgressRSrc> egressRs;
        shared_ptr<gbp::EpGroup> epg;
        shared_ptr<gbp::EpGroupToQosRSrc> reqRs;
        fs::path temp;
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


static bool checkInterfaceCache(QosManager &qosmanager) {
    std::lock_guard<std::recursive_mutex> guard1(opflexagent::QosManager::qos_mutex);

    URI egressUri("/PolicyUniverse/PolicySpace/test/QosBandwidthLimit/testQos/");
    URI reqUri("/PolicyUniverse/PolicySpace/test/QosRequirement/req1/");
    string interface("veth0-acc");

    LOG(DEBUG) << "checkInterfaceCache";

    auto itr1 = qosmanager.getReqToInterface().find(reqUri);
    if (itr1 != qosmanager.getReqToInterface().end()) {
        unordered_set<string> interfaces = itr1->second;
        if (interfaces.find(interface) == interfaces.end()) {
            return false;
        }
    } else {
        return false;
    }

    LOG(DEBUG) << "ReqToInterface passed";

    auto itr2 = qosmanager.getInterfaceToReq().find(interface);
    if (itr2 != qosmanager.getInterfaceToReq().end()) {
        URI reqUriCached = itr2->second;
        if (reqUri != reqUriCached) {
            return false;
        }
    } else {
        return false;
    }

    LOG(DEBUG) << "interfaceToReq passed";

    auto itr3 = qosmanager.getEgressPolInterface().find(egressUri);
    if (itr3 != qosmanager.getEgressPolInterface().end()) {
        const unordered_set<string> &interfaces = itr3->second;
        if (interfaces.find(interface) == interfaces.end()) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

static bool checkEpgCache(QosManager &qosmanager) {
    std::lock_guard<std::recursive_mutex> guard1(opflexagent::QosManager::qos_mutex);

	URI egressUri("/PolicyUniverse/PolicySpace/test/QosBandwidthLimit/testQos/");
	URI reqUri("/PolicyUniverse/PolicySpace/test/QosRequirement/req1/");
	URI epg("/PolicyUniverse/PolicySpace/test/GbpEpGroup/epg/");

	LOG(DEBUG) << "checkEpgCache";

	auto itr1 = qosmanager.getReqToEpg().find(reqUri);
	if (itr1 != qosmanager.getReqToEpg().end()) {
		unordered_set<URI> epgs = itr1->second;
		if (epgs.find(epg) == epgs.end()) {
			return false;
		}
	} else {
		return false;
	}

	LOG(DEBUG) << "ReqToEpg passed";

	auto itr2 = qosmanager.getEpgToReq().find(epg);
	if (itr2 != qosmanager.getEpgToReq().end()) {
		URI reqUriCached = itr2->second;
		if (reqUri != reqUriCached) {
			return false;
		}
	} else {
		return false;
	}

	LOG(DEBUG) << "epgToReq passed";

	auto itr3 = qosmanager.getEgressPolEpg().find(egressUri);
	if (itr3 != qosmanager.getEgressPolEpg().end()) {
		const unordered_set<URI> &epgs = itr3->second;
		if (epgs.find(epg) == epgs.end()) {
			return false;
		}
	} else {
		return false;
	}

	return true;
}


BOOST_FIXTURE_TEST_CASE( verify_artifacts, QosFixture ) {
    const std::string& uuid1 = "83f18f0b-80f7-46e2-b06c-4d9487b0c754";
    fs::path path1(temp / "83f18f0b-80f7-46e2-b06c-4d9487b0c754.ep");
    fs::ofstream os(path1);
    os << "{"
        << "\"uuid\":\"" << uuid1 << "\","
        << "\"mac\":\"10:ff:00:a3:01:00\","
        << "\"ip\":[\"10.0.0.1\",\"10.0.0.2\",\"10.0.0.3\"],"
        << "\"interface-name\":\"veth0\","
        << "\"access-interface\":\"veth0-acc\","
        << "\"endpoint-group\":\"/PolicyUniverse/PolicySpace/test/GbpEpGroup/epg/\","
        << "\"security-group\":["
        << "{\"policy-space\":\"sg1-space1\",\"name\":\"sg1\"},"
        << "{\"policy-space\":\"sg2-space2\",\"name\":\"sg2\"}"
        << "],"
        << "\"attributes\":{"
        << "\"attr1\":\"value1\",\"attr2\":\"value2\""
        << "},"
        <<"\"qos-policy\":["
        <<"{\"policy-space\":\"test\",\"name\":\"req1\"}"
        <<"]"
        << "}" << std::endl;
    os.close();

    FSWatcher watcher;
    FSEndpointSource source(&agent.getEndpointManager(), watcher,
            temp.string());
    watcher.start();

    WAIT_FOR(checkQos(agent.getQosManager().getQosConfigState(qosCfg->getURI()),
                qosCfg->getURI()), 500);
    WAIT_FOR(checkQosRate(agent.getQosManager().getQosConfigState(qosCfg->getURI()), qosCfg), 500);
    WAIT_FOR(checkQosBurst(agent.getQosManager().getQosConfigState(qosCfg->getURI()), qosCfg), 500);
    WAIT_FOR(checkInterfaceCache(agent.getQosManager()), 500);

    fs::ofstream os2(path1);
    os2 << "{"
        << "\"uuid\":\"" << uuid1 << "\","
        << "\"mac\":\"10:ff:00:a3:01:00\","
        << "\"ip\":[\"10.0.0.1\",\"10.0.0.2\"],"
        << "\"interface-name\":\"veth0\","
        << "\"access-interface\":\"veth1-acc\","
        << "\"policy-space-name\":\"test\","
        << "\"endpoint-group-name\":\"epg\","
        << "\"security-group\":["
        << "{\"policy-space\":\"sg1-space1\",\"name\":\"sg1\"}"
        << "],"
        << "\"attributes\":{"
        << "\"vm-name\":\"acc-veth0\""
        << "}"
        << "}" << std::endl;
    os2.close();

    WAIT_FOR(checkEpgCache(agent.getQosManager()), 500);

    const URI& qosUri = qosCfg->getURI();
    Mutator mutator(framework, "policyreg");
    qosCfg->remove();
    mutator.commit();

    WAIT_FOR(!qos::BandwidthLimit::resolve(framework, qosUri), 500);
    watcher.stop();
}

BOOST_AUTO_TEST_SUITE_END()
}
