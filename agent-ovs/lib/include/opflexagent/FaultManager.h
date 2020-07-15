#pragma once
#ifndef OPFLEXAGENT_FAULTMANAGER_H
#define OPFLEXAGENT_FAULTMANAGER_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <opflex/ofcore/OFFramework.h>
#include <opflexagent/Fault.h> 

namespace opflexagent {

class Agent;

class FaultManager {
public:

  FaultManager(Agent& agent,
                    opflex::ofcore::OFFramework& framework);


  virtual ~FaultManager();

  void createFault(Agent& agent, const Fault& fs);

  Agent& agent;
  opflex::ofcore::OFFramework& framework;

};

} /* namespace opflexagent */
#endif 
