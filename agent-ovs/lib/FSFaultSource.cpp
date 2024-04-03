/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for FSFaultSource class.
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if defined(HAVE_SYS_INOTIFY_H) && defined(HAVE_SYS_EVENTFD_H)
#define USE_INOTIFY
#endif

#include <stdexcept>
#include <sstream>
#include <opflexagent/FSFaultSource.h>
#include <opflexagent/FaultManager.h>
#include <opflexagent/Agent.h>
#include <opflexagent/logging.h>
#include <opflex/modb/URIBuilder.h>
#include <opflexagent/Fault.h>

#include <modelgbp/fault/Instance.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <modelgbp/fault/SeverityEnumT.hpp>

namespace opflexagent {

using boost::optional;
namespace fs = boost::filesystem;
using std::string;
using opflex::modb::URI;
using opflex::modb::MAC;

FSFaultSource::FSFaultSource(FaultManager* manager_,
                             FSWatcher& listener,
                             const std::string& faultSourceDir, Agent& agent_): FaultSource(manager_),agent(agent_),faultManager(manager_){
    LOG(INFO) << "Watching " << faultSourceDir << " for fault objects";
    listener.addWatch(faultSourceDir, *this);
}

static bool isfault(const fs::path& filePath) {
    string fstr = filePath.filename().string();
    return (boost::algorithm::ends_with(fstr, ".fs") &&
            !boost::algorithm::starts_with(fstr, "."));
}

void FSFaultSource::updated(const fs::path& filePath) {
    if (!isfault(filePath)) return;
    
    static const std::string EP_UUID("ep_uuid");
    static const std::string FS_UUID("fault_uuid");
    static const std::string EP_MAC("mac");
    static const std::string POLICY_SPACE_NAME("policy-space-name");
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

        newfs.setFSUUID(properties.get<string>(FS_UUID));

        string severity = properties.get<string>(FS_SEVERITY);
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
        }else {
          LOG(ERROR) << "Could not load faults from: "
                     << filePath << " Fault Severity Unknown";
                     return;
        }
       
        newfs.setDescription(properties.get<string>(FS_DESCRIPTION));
        newfs.setFaultcode(properties.get<uint64_t>(FS_CODE));
   
        optional<string> ep_uuid = properties.get_optional<string>(EP_UUID); 
        if (ep_uuid){
            newfs.setEPUUID(ep_uuid.get());
            string eg_name = properties.get<string>(EP_GROUP_NAME);
            string ps_name = properties.get<string>(POLICY_SPACE_NAME);
            newfs.setMAC(MAC(properties.get<string>(EP_MAC)));
            newfs.setEgURI(opflex::modb::URIBuilder()
                                 .addElement("PolicyUniverse")
                                 .addElement("PolicySpace")
                                 .addElement(ps_name)
                                 .addElement("GbpEpGroup")
                                 .addElement(eg_name).build());
            faultManager->createEpFault(newfs);

        } else {
             faultManager->createPlatformFault(newfs);
          }
        std::unique_lock<std::mutex> lock(lock_map_mutex);
        fault_map_t::const_iterator it =  knownFaults.find(pathstr);
        if (it != knownFaults.end()) {
            if (newfs.getFSUUID() != it->second) {
                deleted(filePath);
                faultManager->clearPendingFaults(it->second); 
            }
        }
 
        knownFaults[pathstr] = newfs.getFSUUID();
        LOG(INFO) << "Updated Faults " << newfs << " from " << filePath;
    } catch (const std::exception& ex) {
          LOG(ERROR) << "Could not load Faults from: "
                     << filePath << ": "
                     << ex.what();
      } 
}

void FSFaultSource::deleted(const fs::path& filePath){
    try {
        string pathstr = filePath.string(); 
        if (!fs::exists(filePath)){ 
            std::unique_lock<std::mutex> lock(lock_map_mutex);
            fault_map_t::const_iterator it =  knownFaults.find(pathstr);
            if (it != knownFaults.end()) {
                LOG(INFO) << "Removed Fault "
                          << it->second
                          << " at " << filePath;
                faultManager->removeFault(it->second);
                knownFaults.erase(it);
           }
        }
    } catch (const std::exception& ex) {
          LOG(ERROR) << "Could not delete Fault for "
                     << filePath << ": "
                     << ex.what();
    } catch (...) {
          LOG(ERROR) << "Unknown error while deleting Fault information for "
                     << filePath;
    }
}

void FSFaultSource::getFaultUUID (string& uuid, const string& pathstr){
    std::unique_lock<std::mutex> lock(lock_map_mutex);
    fault_map_t::const_iterator it = knownFaults.find(pathstr);
    if (it != knownFaults.end()) {
        uuid = it->second;
    }
}

}/* namespace opflexagent */
