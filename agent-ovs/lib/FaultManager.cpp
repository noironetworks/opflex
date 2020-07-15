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

FaultManager::FaultManager(Agent& agent_, 
                           opflex::ofcore::OFFramework& framework_)
                           :agent(agent_), framework(framework_){}

FaultManager::~FaultManager() {}

void FaultManager::createFault(Agent& agent, const Fault& fs){
   using opflex::modb::Mutator; 
   using namespace modelgbp;
   LOG(INFO) << "inside fault manager";
   auto fu = modelgbp::fault::Universe::resolve(agent.getFramework());
   std::unique_lock<std::mutex> guard(mutex);
   opflex::modb::Mutator mutator(agent.getFramework(), "policyelement");
   auto fi = fu.get()->addFaultInstance(fs.getFSUUID());
   fi->setSeverity(modelgbp::fault::SeverityEnumT::CONST_CRITICAL);
   fi->setDescription(fs.getFSdescribe());
   fi->setFaultCode(opflexagent::FaultCodes::SAMPLE_FAULT);

   //std::shared_ptr<modelgbp::policy::Universe> universe;
   //std::shared_ptr<modelgbp::platform::Config> config;
   //universe = modelgbp::policy::Universe::resolve(framework).get();
   //config = universe->addPlatformConfig(agent.getPolicyManager().getOpflexDomain());

   fi->setAffectedObject("/PolicyUniverse/PlatformConfig/default/");
   mutator.commit();

}
} /* namespace opflexagent */
