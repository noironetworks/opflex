#include <boost/test/unit_test.hpp>
#include "ovs-ofputil.h"
#include <opflexagent/Agent.h>
#include "IntFlowManager.h"
#include "NatStatsManager.h"
#include "PolicyStatsManagerFixture.h"

namespace opflexagent {

class MockNatStatsManager : public NatStatsManager {
public:
   MockNatStatsManager(Agent *agent_, IdGenerator& idGen_, SwitchManager& switchManager_, IntFlowManager& intFlowManager_, long timer_interval_)
         :  NatStatsManager(agent_,idGen_,switchManager_,intFlowManager_, timer_interval_){
	}
};
//
//class MockNatStatsManagerFixture: public PolicyStatsManagerFixture {
//public:
//    MockNatStatsManagerFixture() : PolicyStatsManagerFixture(), serviceStatsManager(&agent, idGen, switchManager, 300) {		
//    
//          createObjects();
////          createPolicyObjects();
////          idGen.initNamespace("l24classifierRule");
//// 	  idGen.initNamespace("routingDomain");
////          switchManager.setMaxFlowTables(IntFlowManager::NUM_FLOW_TABLES);
////   }
////   //Destructor
//   virtual ~MockNatStatsManagerFixture() {
//          stop();
//   }
////   //member varible
//    MockNatStatsManager serviceStatsManager;
//};
//
//
//
//
//BOOST_AUTO_TEST_SUITE(NatStatsManager_test)
//
//
//BOOST_FIXTURE_TEST_CASE(Fabricconnection, MockNatStatsManagerFixture) {
//
//    MockConnection integrationPortConn(TEST_CONN_TYPE_INT);
//    //serviceStatsManager.registerConnection(&integrationPortConn);
//    serviceStatsManager.start();
//    //serviceStatsManager.Handle(&integrationPortConn,
//                                //OFPTYPE_FLOW_STATS_REPLY, NULL);
//
//    LOG(DEBUG) << "############# NAT STATS MANAGER ############";
//    serviceStatsManager.stop();
//    
//}
//
//BOOST_AUTO_TEST_SUITE_END()

}




