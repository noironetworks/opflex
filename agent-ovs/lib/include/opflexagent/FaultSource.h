#pragma once
#ifndef OPFLEXAGENT_FAULTSOURCE_H
#define OPFLEXAGENT_FAULTSOURCE_H

namespace opflexagent {
class FaultManager;

/**
 * An abstract base class for the source of fault.  A component
 * that discovers faults on the system can implement this interface
 * to inform the fault manager when faults are created or
 * modified.
 */

class FaultSource {
public:
  /**
    * Instantiate a new fault source using the fault manager
    * specified
    */
  FaultSource(FaultManager* manager);

 /**
   * Destroy the fault source and clean up all state
   */
  virtual ~FaultSource();


protected:
    /**
     * The fault manager that will be updated
     */
    FaultManager* manager;
};

}

#endif
