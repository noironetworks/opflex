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

void FaultManager::endpointUpdated(const std::string& uuid) {
     std::unique_lock<std::mutex> lock(lock_modb_mutex);
     for (auto it=pendingFaults.begin(); it != pendingFaults.end(); it++){
         auto faultuuid = it->first;
         if (it->second.getEPUUID() == uuid) {
           createPendingFault(agent,it->second);
         }
    }
}

void FaultManager::createPlatformFault(Agent& agent, const Fault& fs){

    string opflex_domain = agent.getPolicyManager().getOpflexDomain();
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
     if (bd){
       string bd_uri = bd.get()->getURI().toString();
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
       }
   } else {
           std::unique_lock<std::mutex> lock(lock_modb_mutex);
           pendingFaults[fs.getFSUUID()] = fs;
   }
}

void FaultManager::createPendingFault(Agent& agent, const Fault& fs) {
     const boost::optional<opflex::modb::URI>& epURI = fs.getEgURI();
     optional<shared_ptr<modelgbp::gbp::BridgeDomain> > bd;
     bd = agent.getPolicyManager().getBDForGroup(epURI.get());
     if (bd){
       string bd_uri = bd.get()->getURI().toString();
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
       }
     }
}

void FaultManager::clearPendingFaults(const std::string& faultUUID) {
     std::unique_lock<std::mutex> lock(lock_modb_mutex);
     if (pendingFaults.find(faultUUID) != pendingFaults.end()) {
       pendingFaults.erase(faultUUID);
     }
}

void FaultManager::removeFault(const std::string& uuid){
    std::unique_lock<std::mutex> lock(lock_modb_mutex);
    Mutator mutator_policyelem(agent.getFramework(), "policyelement");
    auto fu = modelgbp::fault::Instance::resolve(agent.getFramework(),uuid);
    fu.get()->remove(agent.getFramework(), uuid);
    mutator_policyelem.commit();
}

void FaultManager::getPendingFault(const std::string& faultUUID, bool& ret_val) {
     std::unique_lock<std::mutex> lock(lock_modb_mutex);
     if (pendingFaults.find(faultUUID) != pendingFaults.end()) {
         ret_val = true;
     }
     else ret_val = false;
}

} /* namespace opflexagent */
