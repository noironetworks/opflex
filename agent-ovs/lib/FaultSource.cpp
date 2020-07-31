#include <opflexagent/FaultSource.h>
#include <opflexagent/FaultManager.h>

namespace opflexagent {

FaultSource::FaultSource(FaultManager* manager_)
    : manager(manager_) {}

FaultSource::~FaultSource() {}

} /* namespace opflexagent */

