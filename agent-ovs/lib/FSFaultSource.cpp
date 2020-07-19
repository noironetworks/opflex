#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if defined(HAVE_SYS_INOTIFY_H) && defined(HAVE_SYS_EVENTFD_H)
#define USE_INOTIFY
#endif

#include <config.h>
#include <stdexcept>
#include <sstream>
#include <opflexagent/FSFaultSource.h>
#include <opflexagent/FaultManager.h>
#include <opflexagent/Agent.h>
#include <opflexagent/logging.h>
#include <opflex/modb/URIBuilder.h>
#include <opflexagent/Fault.h>
#include <cstdlib>

#include <modelgbp/fault/Instance.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <modelgbp/fault/SeverityEnumT.hpp>
#include <opflex/modb/Mutator.h>

namespace opflexagent {

using boost::optional;
namespace fs = boost::filesystem;
using std::string;
using std::runtime_error;
using std::make_pair;
using opflex::modb::URI;
using opflex::modb::MAC;

FSFaultSource::FSFaultSource(FaultManager* manager_,
                             FSWatcher& listener,
                             const std::string& faultSourceDir, Agent& agent_): FaultSource(manager_),agent(agent_),faultManager(manager_){
    LOG(INFO) << "Watching " << faultSourceDir << " for fault objects";
    listener.addWatch(faultSourceDir, *this);
}

static bool isfault(fs::path filePath) {
    string fstr = filePath.filename().string();
    LOG(INFO) << "FILE NAME " << fstr;
    return (boost::algorithm::ends_with(fstr, ".fs") &&
            !boost::algorithm::starts_with(fstr, "."));
}

void FSFaultSource::updated(const fs::path& filePath) {
    if (!isfault(filePath)) return;
    static const std::string EP_UUID("ep_uuid");
    static const std::string FS_UUID("fault_uuid");
    static const std::string EP_MAC("mac");
    static const std::string EP_GROUP("endpoint-group-name");
    static const std::string POLICY_SPACE_NAME("policy-space-name");
    static const std::string EG_POLICY_SPACE("eg-policy-space");
    static const std::string EP_GROUP_NAME("endpoint-group-name");
    static const std::string FS_SEVERITY("severity");
    static const std::string FS_DESCRIPTION("description");
    static const std::string FS_CODE("faultCode");
 
    try {
        using boost::property_tree::ptree;
        ptree properties;
        Fault newfs;
        typedef modelgbp::fault::SeverityEnumT SevEnum;

        string pathstr = filePath.string();
        read_json(pathstr, properties);
        string fault_uuid = properties.get<string>(FS_UUID, "not_avaialable");
        if (fault_uuid == "not_avaialable"){
           LOG(ERROR) << "Fault UUID Unknown";
           return;
        } else { newfs.setFSUUID(fault_uuid); }
 
        optional<string> ep_uuid = properties.get_optional<string>(EP_UUID);
        if(ep_uuid){
           newfs.setEPUUID(ep_uuid.get());
        }
         
        static const string severity = properties.get<string>(FS_SEVERITY, "not_available");
        if(severity == "critical"){
           newfs.setSeverity(SevEnum::CONST_CRITICAL);
        }else if(severity == "major"){
           newfs.setSeverity(SevEnum::CONST_MAJOR);
        }else if(severity == "minor"){  
           newfs.setSeverity(SevEnum::CONST_MINOR);
        }else if(severity == "info"){
          newfs.setSeverity(SevEnum::CONST_INFO);
        }else if(severity == "warning"){
          newfs.setSeverity(SevEnum::CONST_WARNING);
        }else if(severity == "cleared"){
          newfs.setSeverity(SevEnum::CONST_CLEARED);
        }else if(severity == "not_available"){
          LOG(ERROR) << "Fault Severity unknown";
          return;
        }
        
        string description = properties.get<string>(FS_DESCRIPTION, "not_available");
        if (description == "not_available") return;
        else newfs.setDescription(description);

        uint64_t faultCode = properties.get<uint64_t>(FS_CODE,0);
        if (faultCode == 0) return;
        else{
          newfs.setFaultcode(faultCode);
        }

        optional<string> mac = properties.get_optional<string>(EP_MAC);
        if (mac) {
            newfs.setMAC(MAC(mac.get()));
        }

        optional<string> eg_name = properties.get_optional<string>(EP_GROUP_NAME);
        optional<string> ps_name = properties.get_optional<string>(EG_POLICY_SPACE);
        if (!ps_name)
          ps_name = properties.get_optional<string>(POLICY_SPACE_NAME);
        if (eg_name && ps_name) {
          newfs.setEgURI(opflex::modb::URIBuilder()
                         .addElement("PolicyUniverse")
                         .addElement("PolicySpace")
                         .addElement(ps_name.get())
                         .addElement("GbpEpGroup")
                         .addElement(eg_name.get()).build());
        }
        faultManager->createFault(agent,newfs);
                      
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not load faults from: "
                   << filePath << ": "
                   << ex.what();
      } 
}
void FSFaultSource::deleted(const fs::path& filePath){ 
}

}/* namespace opflexagent */
