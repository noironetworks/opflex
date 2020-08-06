#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <opflexagent/FaultManager.h>
#include <opflexagent/Agent.h>
#include <opflexagent/logging.h>
#include <opflexagent/Faults.h>
#include <opflexagent/logging.h>
#include <opflex/modb/Mutator.h>
#include <modelgbp/fault/SeverityEnumT.hpp>
#include <opflexagent/EndpointManager.h>
#include <opflexagent/Endpoint.h>

#include <string>
#include <iostream>

namespace opflexagent {

using opflex::modb::URI;
using opflex::modb::Mutator;
using namespace modelgbp;
using opflex::modb::MAC;

FaultManager::FaultManager(Agent& agent_, 
                           opflex::ofcore::OFFramework& framework_)
                           :agent(agent_), framework(framework_){
                           agent.getEndpointManager().registerListener(this) ;}

FaultManager::~FaultManager() { agent.getEndpointManager().unregisterListener(this); }

void FaultManager::createPlatformFault(Agent& agent, const Fault& fs){

   string opflex_domain = agent.getPolicyManager().getOpflexDomain();
   URI compute_node_uri = URIBuilder()
                                .addElement("PolicyUniverse")
                                .addElement("PlatformConfig")
                                .addElement(opflex_domain).build(); 
   std::unique_lock<std::mutex> lock(lock_modb_mutex);
   Mutator mutator_policyelem(agent.getFramework(), "policyelement");
   auto fu = modelgbp::fault::Universe::resolve(agent.getFramework());
   auto fi = fu.get()->addFaultInstance(fs.getFSUUID());
   fi->setSeverity(fs.getSeverity());
   fi->setDescription(fs.getDescription());
   fi->setFaultCode(fs.getFaultcode());
   fi->setAffectedObject(compute_node_uri.toString());
   mutator_policyelem.commit();
}

void FaultManager::removeFault(const std::string& uuid){
   std::unique_lock<std::mutex> lock(lock_modb_mutex);
   Mutator mutator_policyelem(agent.getFramework(), "policyelement");
   auto fu = modelgbp::fault::Instance::resolve(agent.getFramework(),uuid);
   fu.get()->remove(agent.getFramework(), uuid);
   mutator_policyelem.commit();
}


void FaultManager::endpointUpdated(const std::string& uuid) {
   std::unique_lock<std::mutex> lock(lock_modb_mutex);
   for (auto it=pendingFaults.begin(); it != pendingFaults.end(); it++){
      auto faultuuid = it->first;
      //if ep uuid is present in the map, then call updateEpFault
      if (pendingFaults[faultuuid]["epuuid"] == uuid) {
         updateEpFault(agent,faultuuid);
   }
   }       
}



void FaultManager::createEpFault(Agent& agent, const Fault& fs) {

  //I am building the uri of the EP based on bd and the platform domain   
   string domain = agent.getPolicyManager().getOpflexDomain();
   URI l2epr = URIBuilder()
                 .addElement("EprL2Universe")
                 .addElement("EprL2Ep")
                 .addElement("/PolicyUniverse/PolicySpace/"+domain+"/GbpBridgeDomain/bd/")
                 .addElement(MAC(fs.getMAC())).build();


   //If i add a lock to modb, the response was very late due to which the controller gets stuck. and Ep is yet not updated in the modb. Hence I removed the lock. 
   auto l2Ep = L2Ep::resolve(agent.getFramework(), l2epr);
   if (l2Ep) {
   
      //Here the affected object is egURI;
      const URI& egURI = l2Ep.get()->getURI();
      std::unique_lock<std::mutex> lock(lock_modb_mutex);
      Mutator mutator_policyelem(agent.getFramework(), "policyelement");
      auto fu = modelgbp::fault::Universe::resolve(agent.getFramework());
      auto fi = fu.get()->addFaultInstance(fs.getFSUUID());
      fi->setSeverity(fs.getSeverity());
      fi->setDescription(fs.getDescription());
      fi->setFaultCode(fs.getFaultcode());
      fi->setAffectedObject(egURI.toString());
      mutator_policyelem.commit();
   }
   else {
        // If the fault file gets updated before the EP file, add the faults to database. I am using map here 
        addPendingFaults(fs);
   } 
     
}

void FaultManager::addPendingFaults(const Fault& fs) {
  
    //storing all the fault objects in map 
    std::unique_lock<std::mutex> lock(lock_modb_mutex);
    pendingFaults[fs.getFSUUID()].insert(make_pair("severity",std::to_string(fs.getSeverity()))) ;
    pendingFaults[fs.getFSUUID()].insert(make_pair("epuuid", fs.getEPUUID()));
    pendingFaults[fs.getFSUUID()].insert(make_pair("description", fs.getDescription()));
    pendingFaults[fs.getFSUUID()].insert(make_pair("faultcode", std::to_string(fs.getFaultcode())));
    pendingFaults[fs.getFSUUID()].insert(make_pair("mac", fs.getMAC()));
}

void FaultManager::clearPendingFaults(const std::string& faultUUID) {

   std::unique_lock<std::mutex> lock(lock_modb_mutex);
   if (pendingFaults.find(faultUUID) != pendingFaults.end()) {
       pendingFaults[faultUUID].clear();
   }
}


void FaultManager::updateEpFault(Agent& agent, const std::string& uuid) {

    string domain = agent.getPolicyManager().getOpflexDomain();
 
    //while adding the faultcode and severity into the map, its typecasted to string. While retrieving I am typecasting back to uint64_t and uint8_t
    uint64_t faultCode = atoi(pendingFaults[uuid]["faultcode"].c_str ());
    uint8_t severity = atoi(pendingFaults[uuid]["severity"].c_str ());
    
    URI l2epr = URIBuilder()
                  .addElement("EprL2Universe")
                  .addElement("EprL2Ep")
                  .addElement("/PolicyUniverse/PolicySpace/"+domain+"/GbpBridgeDomain/bd/")
                  .addElement(MAC(pendingFaults[uuid]["mac"])).build();

    auto l2Ep = L2Ep::resolve(agent.getFramework(), l2epr);
    if (l2Ep) {
        const URI& egURI = l2Ep.get()->getURI();

        std::unique_lock<std::mutex> lock(lock_modb_mutex);
        Mutator mutator_policyelem(agent.getFramework(), "policyelement");
        auto fu = modelgbp::fault::Universe::resolve(agent.getFramework());
        auto fi = fu.get()->addFaultInstance(uuid);
        fi->setSeverity(severity);
        fi->setDescription(pendingFaults[uuid]["description"]);
        fi->setFaultCode(faultCode);
        fi->setAffectedObject(egURI.toString());
        mutator_policyelem.commit();

        //After the pending faults gets updated in the db, I will call clear() 
        pendingFaults[uuid].clear();
    }
}

} /* namespace opflexagent */
