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

namespace opflexagent {

class Agent;

class FaultManager: public EndpointListener{
public:

  FaultManager(Agent& agent,
                    opflex::ofcore::OFFramework& framework);


  virtual ~FaultManager();

   /**
    * Create the fault against platform with the specified params from the fault
    * manager
    */
   void createPlatformFault(const Fault& fs);
 
   /**
    * Remove the fault with the specified UUID from the fault
    * manager.
    *
    * @param uuid the UUID of the fault that no longer exists
    */
   void removeFault(const std::string& uuid);
   
   /**
    * Create the fault against endpoint with the specified params from the fault  
    * manager 
    */
   void createEpFault(const Fault& fs);

   /* Interface: EndpointListener */
   virtual void endpointUpdated(const std::string& uuid);

   /*
    * check if the faults which are not 
    * processed gets added to the map 
    */
    bool hasPendingFault(const std::string& faultUUID);

   /* Clear the pending faults */
    void clearPendingFaults(const std::string& faultUUID);

   /* handle endpoint object */
    void handleEndpointUpdate(const std::string& uuid);

    Agent& agent;
    opflex::ofcore::OFFramework& framework;
    std::map<std::string, Fault> pendingFaults;

private:
   std::recursive_mutex map_mutex;
};

} /* namespace opflexagent */
#endif 
