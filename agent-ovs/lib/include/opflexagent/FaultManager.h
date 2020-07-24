#pragma once
#ifndef OPFLEXAGENT_FAULTMANAGER_H
#define OPFLEXAGENT_FAULTMANAGER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <opflex/ofcore/OFFramework.h>
#include <opflexagent/Fault.h> 
#include <mutex>

namespace opflexagent {

class Agent;

class FaultManager {
public:

  FaultManager(Agent& agent,
                    opflex::ofcore::OFFramework& framework);


  virtual ~FaultManager();

   /**
    * Create the fault with the specified params from the fault
    * manager
    *
    */
   void createFault(Agent& agent, const Fault& fs);
 
   /**
    * Remove the fault with the specified UUID from the fault
    * manager.
    *
    * @param uuid the UUID of the fault that no longer exists
    */
   void removeFault(const std::string& uuid);


  Agent& agent;
  opflex::ofcore::OFFramework& framework;

private:
  std::mutex lock_modb_mutex;
};

} /* namespace opflexagent */
#endif 
