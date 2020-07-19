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
#include <thread>

namespace opflexagent {

using opflex::modb::URI;

FaultManager::FaultManager(Agent& agent_, 
                           opflex::ofcore::OFFramework& framework_)
                           :agent(agent_), framework(framework_){}

FaultManager::~FaultManager() {}

void FaultManager::createFault(Agent& agent, const Fault& fs){
   using opflex::modb::Mutator; 
   using namespace modelgbp;

   std::unique_lock<std::mutex> guard(mutex);
   opflex::modb::Mutator mutator_policyreg(agent.getFramework(), "policyreg");
   auto universe = modelgbp::policy::Universe::resolve(agent.getFramework()).get();
   auto config = universe->addPlatformConfig(agent.getPolicyManager().getOpflexDomain());
   mutator_policyreg.commit();

   opflex::modb::Mutator mutator_policyelem(agent.getFramework(), "policyelement");
   auto fu = modelgbp::fault::Universe::resolve(agent.getFramework());
   auto fi = fu.get()->addFaultInstance(fs.getFSUUID());
   fi->setSeverity(fs.getSeverity());
   fi->setDescription(fs.getDescription());
   fi->setFaultCode(fs.getFaultcode());
   auto affectedObj = URI(config->getURI()); 
   fi->setAffectedObject(affectedObj.toString());
   mutator_policyelem.commit();
}
} /* namespace opflexagent */
