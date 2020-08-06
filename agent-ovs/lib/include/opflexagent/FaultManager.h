#pragma once
#ifndef OPFLEXAGENT_FAULTMANAGER_H
#define OPFLEXAGENT_FAULTMANAGER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <opflex/ofcore/OFFramework.h>
#include <opflexagent/Fault.h> 
#include <opflexagent/EndpointListener.h>
#include <mutex>
//#include <opflexagent/Agent.h>

namespace opflexagent {

class Agent;

class FaultManager: public EndpointListener{
public:

  FaultManager(Agent& agent,
                    opflex::ofcore::OFFramework& framework);


  virtual ~FaultManager();

   /**
    * Create the fault with the specified params from the fault
    * manager
    *
    */
   void createPlatformFault(Agent& agent, const Fault& fs);
 
   /**
    * Remove the fault with the specified UUID from the fault
    * manager.
    *
    * @param uuid the UUID of the fault that no longer exists
    */
   void removeFault(const std::string& uuid);

   void createEpFault(Agent& agent, const Fault& fs);
  
    /* Interface: EndpointListener */
   virtual void endpointUpdated(const std::string& uuid);

  Agent& agent;
  opflex::ofcore::OFFramework& framework;

  std::map<std::string, std::map<std::string, std::string>> pendingFaults;

  void addPendingFaults(const Fault& fs);

  void clearPendingFaults(const std::string& faultUUID);  

  void updateEpFault(Agent& agent, const std::string& uuid);


private:
  std::mutex lock_modb_mutex;
};

} /* namespace opflexagent */
#endif 
