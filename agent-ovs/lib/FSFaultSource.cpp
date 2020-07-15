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

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/predicate.hpp>

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

static bool isep(fs::path filePath) {
    string fstr = filePath.filename().string();
    LOG(INFO) << "FILE NAME " << fstr;
    return (boost::algorithm::ends_with(fstr, ".fs") &&
            !boost::algorithm::starts_with(fstr, "."));
}

void FSFaultSource::updated(const fs::path& filePath) {
    if (!isep(filePath)) return;
    static const std::string EP_UUID("ep_uuid");
    static const std::string FS_UUID("fs_uuid");
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

        string pathstr = filePath.string();
        read_json(pathstr, properties);
        newfs.setEPUUID(properties.get<string>(EP_UUID));
        newfs.setFSUUID(properties.get<string>(FS_UUID));
        newfs.setSeverity(properties.get<string>(FS_SEVERITY));
        newfs.setFSdescribe(properties.get<string>(FS_DESCRIPTION));
        newfs.setFaultcode(properties.get<string>(FS_CODE));
         
        optional<string> mac = properties.get_optional<string>(EP_MAC);
        if (mac) {
            newfs.setMAC(MAC(mac.get()));
        }

        optional<string> eg = properties.get_optional<string>(EP_GROUP);
        if (eg) {
            newfs.setEgURI(URI(eg.get()));
        }
        else {
            optional<string> eg_name =
                properties.get_optional<string>(EP_GROUP_NAME);
            optional<string> ps_name =
                properties.get_optional<string>(EG_POLICY_SPACE);
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
        }        
                      
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not load fault source from: "
                   << filePath << ": "
                   << ex.what();
      } 
}
void FSFaultSource::deleted(const fs::path& filePath) { 
      string pathstr = filePath.string();      
}

}/* namespace opflexagent */
