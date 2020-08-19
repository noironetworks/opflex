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

FaultManager::~FaultManager() { agent.getEndpointManager().unregisterListener(this);}

void FaultManager::endpointUpdated(const std::string& uuid) {
         
     lock_guard<recursive_mutex> lock(map_mutex);
     for (auto it=pendingFaults.begin(); it != pendingFaults.end(); it++) {
         if (it->second.getEPUUID() == uuid) {
             createEpFault(agent,it->second);
          } 
      }
}

void FaultManager::createPlatformFault(Agent& agent, const Fault& fs){

     const string& opflex_domain = agent.getPolicyManager().getOpflexDomain();
     URI compute_node_uri = URIBuilder()
                                .addElement("PolicyUniverse")
                                .addElement("PlatformConfig")
                                .addElement(opflex_domain).build(); 
     Mutator mutator_policyelem(agent.getFramework(), "policyelement");
     auto fu = modelgbp::fault::Universe::resolve(agent.getFramework());
     auto fi = fu.get()->addFaultInstance(fs.getFSUUID());
     fi->setSeverity(fs.getSeverity());
     fi->setDescription(fs.getDescription());
     fi->setFaultCode(fs.getFaultcode());
     fi->setAffectedObject(compute_node_uri.toString());
     mutator_policyelem.commit();
}

void FaultManager::createEpFault(Agent& agent, const Fault& fs) {
     const boost::optional<opflex::modb::URI>& epURI = fs.getEgURI();
     optional<shared_ptr<modelgbp::gbp::BridgeDomain> > bd;
     bd = agent.getPolicyManager().getBDForGroup(epURI.get());
     shared_ptr<const Endpoint> ep = agent.getEndpointManager().getEndpoint(fs.getEPUUID());     
     if ((bd) && (ep)){
       const string& bd_uri = bd.get()->getURI().toString();
       URI l2epr = URIBuilder()
                  .addElement("EprL2Universe")
                  .addElement("EprL2Ep")
                  .addElement(bd_uri)
                  .addElement(fs.getMAC().get()).build();

       auto l2Ep = L2Ep::resolve(agent.getFramework(), l2epr);
       if (l2Ep) {
           const URI& epURI = l2Ep.get()->getURI();
           Mutator mutator_policyelem(agent.getFramework(), "policyelement");
           auto fu = modelgbp::fault::Universe::resolve(agent.getFramework());
           auto fi = fu.get()->addFaultInstance(fs.getFSUUID());
           fi->setSeverity(fs.getSeverity());
           fi->setDescription(fs.getDescription());
           fi->setFaultCode(fs.getFaultcode());
           fi->setAffectedObject(epURI.toString());
           mutator_policyelem.commit();
           std::unique_lock<std::mutex> lock(lock_modb_mutex);
           pendingFaults.erase(fs.getFSUUID()); 
       } else {
            LOG(INFO) << "Not able to create a Fault : l2EP was not resolved "
                      << "MAC " << fs.getMAC();
            lock_guard<recursive_mutex> lock(map_mutex);
            pendingFaults.insert(pair <std::string, Fault> (fs.getFSUUID(), fs));
       }
   } else {
           if (!bd) LOG(INFO) << "Not able to create a Fault : BD not found " 
                              << "FaultUUID = " << fs.getFSUUID() << "EPUUID = " << fs.getEPUUID();
           if (!ep) LOG(INFO) << "Not able to create a Fault : Endpoint not found " 
			      << "FaultUUID = " << fs.getFSUUID() << "EPUUID = " << fs.getEPUUID();	
           lock_guard<recursive_mutex> lock(map_mutex);
           pendingFaults.insert(pair <std::string, Fault> (fs.getFSUUID(), fs));
       }
}


void FaultManager::clearPendingFaults(const std::string& faultUUID) {
     std::unique_lock<std::mutex> lock(lock_modb_mutex);
     pendingFaults.erase(faultUUID);     
}

void FaultManager::removeFault(const std::string& uuid){
    Mutator mutator_policyelem(agent.getFramework(), "policyelement");
    auto fu = modelgbp::fault::Instance::resolve(agent.getFramework(),uuid);
    if (fu){
       fu.get()->remove(agent.getFramework(), uuid);
       mutator_policyelem.commit();
    }
}

bool FaultManager::hasPendingFault(const std::string& faultUUID) {
     lock_guard<recursive_mutex> lock(map_mutex);
     if (pendingFaults.find(faultUUID) != pendingFaults.end()) {
         return true;
     }
     return false;
}

} /* namespace opflexagent */
