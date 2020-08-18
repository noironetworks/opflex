#include <opflexagent/FaultManager.h>
#include <opflexagent/FSWatcher.h>
#include <opflexagent/FSFaultSource.h>
#include <opflexagent/test/BaseFixture.h>
#include <opflexagent/logging.h>
#include <opflexagent/Agent.h>
#include <modelgbp/fault/Universe.hpp>
#include <boost/filesystem.hpp>
#include <opflexagent/FSEndpointSource.h>
#include <opflexagent/test/MockEndpointSource.h>
#include <opflexagent/SpanManager.h>
#include <mutex>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

namespace opflexagent {

using std::string;
using std::vector;
using opflex::modb::URI;
using opflex::ofcore::OFFramework;
using std::shared_ptr;
using namespace modelgbp;
using namespace modelgbp::gbp;

namespace fs = boost::filesystem;

class FSFaultFixture : public BaseFixture {
public:
    FSFaultFixture()
       : BaseFixture(), 
         epSource(&agent.getEndpointManager()),
         bduri("/PolicyUniverse/PolicySpace/test/GbpBridgeDomain/bd/"),
         temp(fs::temp_directory_path() / fs::unique_path()) {
               fs::create_directory(temp);
          }

    ~FSFaultFixture() {
        fs::remove_all(temp);
    }



    MockEndpointSource epSource;
    URI bduri;
    shared_ptr<policy::Space> space;
    shared_ptr<policy::Space> common;
    shared_ptr<EpGroup> eg1;
    shared_ptr<BridgeDomain> bd;
    shared_ptr<L2Ep> l2E1;
    std::mutex lock_modb_mutex;
    fs::path temp;

};

BOOST_AUTO_TEST_SUITE(FaultManager_test)

BOOST_FIXTURE_TEST_CASE( faultmodb, FSFaultFixture ) {
//check for modb update
   const std::string& uuid1 = "83f18f0b-80f7-46e2-b06c-4d9487b0c754-1";
   fs::path path1(temp / (uuid1+".fs" ));
   fs::ofstream os(path1);
   os << "{"
      << "\"fault_uuid\":\"" << uuid1 << "\","
      << "\"faultCode\":\"1\","
      << "\"description\":\"Broken bridge domain\","
      << "\"severity\":\"critical\""
      << "}" << std::endl;
   os.close();
 
   FSWatcher watcher;
   FSFaultSource source(&agent.getFaultManager(), watcher, temp.string(), agent);
   watcher.start();
   auto fu_instance = modelgbp::fault::Universe::resolve(agent.getFramework());
   WAIT_FOR((fu_instance.get()->resolveFaultInstance(uuid1)), 500);
   auto fu = fu_instance.get()->resolveFaultInstance(uuid1);
   uint8_t severity = 5;
   uint32_t faultcode = 1;
   string  description = "Broken bridge domain";
   string opflex_domain = agent.getPolicyManager().getOpflexDomain();
   opflex::modb::URI compute_node_uri = opflex::modb::URIBuilder()
                                              .addElement("PolicyUniverse")
                                              .addElement("PlatformConfig")
                                              .addElement(opflex_domain).build();
   string  affected_obj = compute_node_uri.toString();
   BOOST_CHECK_EQUAL(description, fu.get()->getDescription("default"));
   BOOST_CHECK_EQUAL(affected_obj, fu.get()->getAffectedObject("default"));
   BOOST_CHECK_EQUAL(faultcode, fu.get()->getFaultCode(100));
   BOOST_CHECK_EQUAL(severity, fu.get()->getSeverity(100));

   fs::remove_all(temp / (uuid1+".fs" ));
   source.deleted(temp.string()+"/"+uuid1+".fs");
   WAIT_FOR((!fu_instance.get()->resolveFaultInstance(uuid1)), 500);   
   watcher.stop();

}

static bool hasFault(const string& pathstr, FSFaultSource& faultsource, string uuid){
   string ret_uuid = "";
   faultsource.getFaultUUID(ret_uuid, pathstr);
   if(ret_uuid == uuid) {
     return true;
   }
   return false;
}
   
BOOST_FIXTURE_TEST_CASE( faultsource, FSFaultFixture ) {

 //check for the updates from already existing file
  const std::string& uuid2 = "83f18f0b-80f7-46e2-b06c-4d9487b0c754-2";
  fs::path path1(temp / (uuid2+".fs" ));
  fs::ofstream os(path1);
   os << "{"
      << "\"fault_uuid\":\"" << uuid2 << "\","
      << "\"faultCode\":\"1\","
      << "\"description\":\"Broken bridge domain\","
      << "\"severity\":\"critical\","
      << "\"mac\":\"00:00:00:00:00:01\""
      << "}" << std::endl;
  os.close();
  FSWatcher watcher;
  FSFaultSource fu_source(&agent.getFaultManager(), watcher, temp.string(), agent);
  watcher.start();
 
  WAIT_FOR((hasFault(temp.string()+"/"+uuid2+".fs", fu_source, uuid2)),500);
  bool has_fault = hasFault(temp.string()+"/"+uuid2+".fs", fu_source, uuid2);
  BOOST_CHECK_EQUAL(true, has_fault);  
 
//update the file by giving different values to severiity, description and faultCode

   fs::path path2(temp / (uuid2+".fs" ));
   fs::ofstream os2(path2);
   os2 << "{"
      << "\"fault_uuid\":\"" << uuid2 << "\","
      << "\"faultCode\":\"2\","
      << "\"description\":\"Broken routing domain\","
      << "\"severity\":\"major\","
      << "\"mac\":\"00:00:00:00:00:02\""
      << "}" << std::endl;
   os2.close();

   WAIT_FOR((hasFault(temp.string()+"/"+uuid2+".fs", fu_source, uuid2)),500);
   bool has_fault_2 = hasFault(temp.string()+"/"+uuid2+".fs", fu_source, uuid2);
   BOOST_CHECK_EQUAL(true, has_fault_2);  
   watcher.stop();
}

static bool hasPendingFault(FaultManager& manager, string uuid){
  return (manager.getPendingFault(uuid));
}

template<typename T>
bool hasEPREntry(OFFramework& framework, const URI& uri,
                 const boost::optional<std::string>& uuid = boost::none) {
    boost::optional<std::shared_ptr<T> > entry =
                                   T::resolve(framework, uri);
    if (!entry) return false;
    if (uuid) return (entry.get()->getUuid("") == uuid);
    return true;
}

BOOST_FIXTURE_TEST_CASE( epfault, FSFaultFixture ) {

    shared_ptr<policy::Universe> pUniverse = policy::Universe::resolve(framework).get();
    Mutator mutator(framework, "policyreg");
    space = pUniverse->addPolicySpace("test");
    common = pUniverse->addPolicySpace("common");
    bd = space->addGbpBridgeDomain("bd");
    eg1 = space->addGbpEpGroup("group1");
    eg1->addGbpEpGroupToNetworkRSrc()
         ->setTargetBridgeDomain(bd->getURI());
    mutator.commit();

    Endpoint ep1("e82e883b-851d-4cc6-bedb-fb5e27530043");
    ep1.setMAC(MAC("00:00:00:00:00:01"));
    ep1.addIP("10.1.1.2");
    ep1.addIP("10.1.1.3");
    ep1.setInterfaceName("veth1");
    ep1.setEgURI(eg1->getURI());
    epSource.updateEndpoint(ep1);
    Mutator mutatorElem(framework, "policyelement");
    shared_ptr<L2Universe> l2u = L2Universe::resolve(framework).get();
    l2E1 = l2u->addEprL2Ep(bd->getURI().toString(),
                ep1.getMAC().get());
    l2E1->setUuid(ep1.getUUID());
    l2E1->setGroup(eg1->getURI().toString());
    l2E1->setInterfaceName(ep1.getInterfaceName().get());
    mutatorElem.commit();

    URI l2epr1 = URIBuilder()
                     .addElement("EprL2Universe")
                     .addElement("EprL2Ep")
                     .addElement(bd->getURI().toString())
                     .addElement(MAC("00:00:00:00:00:01")).build();
    WAIT_FOR(hasEPREntry<L2Ep>(framework, l2epr1), 500);

    const std::string& uuid3 = "83f18f0b-80f7-46e2-b06c-4d9487b0c754-3";
    fs::path path3(temp / (uuid3+".fs" ));
    fs::ofstream os(path3);
    os << "{"
       << "\"fault_uuid\":\"" << uuid3 << "\","
       << "\"faultCode\":\"2\","
       << "\"description\":\"Vlan encap mismatch\","
       << "\"severity\":\"critical\","
       << "\"mac\":\"00:00:00:00:00:01\","
       << "\"ep_uuid\":\"e82e883b-851d-4cc6-bedb-fb5e27530043\","
       << "\"policy-space-name\":\"test\","
       << "\"endpoint-group-name\":\"group1\""
       << "}" << std::endl;
    os.close();
    FSWatcher watcher;
    FSFaultSource fu_source(&agent.getFaultManager(), watcher, temp.string(), agent);
    watcher.start();
    auto fu_instance = modelgbp::fault::Universe::resolve(agent.getFramework());
    WAIT_FOR((fu_instance.get()->resolveFaultInstance(uuid3)), 2000);
    auto fu = fu_instance.get()->resolveFaultInstance(uuid3);
    uint8_t severity = 5;
    uint32_t faultcode = 2;
    string  description = "Vlan encap mismatch";
    opflex::modb::URI ep_uri = opflex::modb::URIBuilder()
                                           .addElement("EprL2Universe")
                                           .addElement("EprL2Ep")
                                           .addElement(bduri.toString())
                                           .addElement(MAC("00:00:00:00:00:01")).build();
    string  affected_obj = ep_uri.toString();
    BOOST_CHECK_EQUAL(description, fu.get()->getDescription("default"));
    BOOST_CHECK_EQUAL(affected_obj, fu.get()->getAffectedObject("default"));
    BOOST_CHECK_EQUAL(faultcode, fu.get()->getFaultCode(100));
    BOOST_CHECK_EQUAL(severity, fu.get()->getSeverity(100));
    watcher.stop();

}

BOOST_FIXTURE_TEST_CASE( epPendingFaultCheck, FSFaultFixture ) {


   const std::string& uuid4 = "83f18f0b-80f7-46e2-b06c-4d9487b0c754-4";
   fs::path path3(temp / (uuid4+".fs" ));
   fs::ofstream os(path3);
   os << "{"
       << "\"fault_uuid\":\"" << uuid4 << "\","
       << "\"faultCode\":\"2\","
       << "\"description\":\"Vlan encap mismatch\","
       << "\"severity\":\"critical\","
       << "\"mac\":\"00:00:00:00:00:02\","
       << "\"ep_uuid\":\"e82e883b-851d-4cc6-bedb-fb5e27530043-1\","
       << "\"policy-space-name\":\"test\","
       << "\"endpoint-group-name\":\"group2\""
       << "}" << std::endl;
   os.close();
   FSWatcher watcher;
   FSFaultSource fu_source(&agent.getFaultManager(), watcher, temp.string(), agent);
   watcher.start();
   WAIT_FOR((hasPendingFault(agent.getFaultManager(), uuid4)),500); 
   bool has_fault = hasPendingFault(agent.getFaultManager(), uuid4);
   BOOST_CHECK_EQUAL(true, has_fault);
   watcher.stop();
}
BOOST_AUTO_TEST_SUITE_END()


 
} /* namespace opflexagent */ 
 


