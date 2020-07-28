
#include <opflexagent/FaultManager.h>
#include <opflexagent/FSWatcher.h>
#include <opflexagent/FSFaultSource.h>
#include <opflexagent/test/BaseFixture.h>
#include <opflexagent/logging.h>
#include <opflexagent/Agent.h>
#include <modelgbp/fault/Instance.hpp>
#include <modelgbp/fault/Universe.hpp>
#include <assert.h> 
#include <boost/filesystem.hpp>
#include <unordered_map> 

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

namespace opflexagent {

using std::string;
using std::vector;

namespace fs = boost::filesystem;

class FSFaultFixture : public BaseFixture {
public:
    FSFaultFixture()
       : BaseFixture(),
          temp(fs::temp_directory_path() / fs::unique_path()) {
        LOG(INFO) << "temp path " << fs::temp_directory_path() << "unique path " <<  fs::unique_path();
        fs::create_directory(temp);
    }

    ~FSFaultFixture() {
        fs::remove_all(temp);
    }

    fs::path temp;
};

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
 assert(description == fu.get()->getDescription("default"));
 assert(affected_obj == fu.get()->getAffectedObject("default"));
 assert(faultcode == fu.get()->getFaultCode(100));
 assert(severity == fu.get()->getSeverity(100));

//check for delete fucntion. Not sure how to go ahead with this. I have commented this for now. 

 //source.deleted(temp.string()+"/"+uuid1+".fs");
 //WAIT_FOR((fu_instance.get()->resolveFaultInstance(uuid1)), 500);
// auto fu_2 = fu_instance.get()->resolveFaultInstance(uuid1);
// assert(fu_2.get()->getDescription("default") == "default");
// assert(fu_2.get()->getAffectedObject("default") == "default");
// assert(fu_2.get()->getFaultCode(100)== 100);
// assert(fu_2.get()->getSeverity(100) ==100 );
   
   watcher.stop();

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
 
 WAIT_FOR((fu_source.getFaultUUID(temp.string()+"/"+uuid2+".fs")!= "null"),500);
 string ret_uuid = fu_source.getFaultUUID(temp.string()+"/"+uuid2+".fs");
 assert(ret_uuid == uuid2);
 
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

  //Get the uuid from the map by passing pathstr as the key 
   WAIT_FOR((fu_source.getFaultUUID(temp.string()+"/"+uuid2+".fs")!= "null"),500);
   WAIT_FOR((fu_source.getFaultUUID(temp.string()+"/"+uuid2+".fs")!= "null"),500);
   string ret_uuid2 = fu_source.getFaultUUID(temp.string()+"/"+uuid2+".fs");
   assert(ret_uuid2 == uuid2);
   watcher.stop();
}
 
} /* namespace opflexagent */ 
 


