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

#include <string>
#include <iostream>

namespace opflexagent {

using opflex::modb::URI;
using opflex::modb::Mutator;
using namespace modelgbp;

FaultManager::FaultManager(Agent& agent_, 
                           opflex::ofcore::OFFramework& framework_)
                           :agent(agent_), framework(framework_){}

FaultManager::~FaultManager() {}

void FaultManager::createFault(Agent& agent, const Fault& fs){

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

} /* namespace opflexagent */
