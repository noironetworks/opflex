#include <opflexagent/Fault.h>

namespace opflexagent {


   std::ostream & operator<<(std::ostream &os, const Fault& fs){
        os << "Fault["
        << "Fault UUID=" << fs.getFSUUID()
        << ",FaultCode=" << fs.getFaultcode()
        << ",Severity=" << fs.getSeverity()
        << ",Description=" << fs.getDescription() << "]"; 
        return os;  

   }
}   /* namespace opflexagent */ 
