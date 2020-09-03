/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for FSIpamConfigSource class.
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <config.h>
#if defined(HAVE_SYS_INOTIFY_H) && defined(HAVE_SYS_EVENTFD_H)
#define USE_INOTIFY
#endif

#include <stdexcept>
#include <sstream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <opflexagent/FSIpamConfigSource.h>
#include <opflexagent/ExtraConfigManager.h>
#include <opflexagent/IpamConfig.h>
#include <opflexagent/logging.h>

namespace opflexagent {

using boost::optional;
namespace fs = boost::filesystem;
using std::string;
using std::make_pair;
using std::runtime_error;
using opflex::modb::URI;

FSIpamConfigSource::FSIpamConfigSource(ExtraConfigManager* manager_,
                                   FSWatcher& listener,
                                   const std::string& ipamConfigDir)
    : manager(manager_) {
    listener.addWatch(ipamConfigDir, *this);
}

static bool isIpamConfig(const fs::path& filePath) {
    string fstr = filePath.filename().string();
    return (boost::algorithm::ends_with(fstr, ".ipamconfig") &&
            !boost::algorithm::starts_with(fstr, "."));
}

void FSIpamConfigSource::updated(const fs::path& filePath) {
    if (!isIpamConfig(filePath)) return;

    static const std::string IPAM_UUID("uuid");
    static const std::string IPAM_MAP("map");
    static const std::string IPAM_NETWORK("network");
    static const std::string IPAM_VTEP("vtep");


    try {
        using boost::property_tree::ptree;
        ptree properties;

        string pathstr = filePath.string();

        read_json(pathstr, properties);

        IpamConfig newIpam(properties.get<string>(IPAM_UUID));

        optional<ptree&> map =
            properties.get_child_optional(IPAM_MAP);
        if (map) {
            for (const ptree::value_type &v :map.get()) {
                 optional<string> network =
                    v.second.get_optional<string>(IPAM_NETWORK);
                optional<string> vtep =
                    v.second.get_optional<string>(IPAM_VTEP);

                if (network && vtep) {
                    newIpam.addToMap(network.get(), vtep.get());
                }
            }
        }

        ipamconfig_map_t::const_iterator it = knownIpamConfigs.find(pathstr);
        if (it != knownIpamConfigs.end()) {
            if (newIpam.getUUID() != it->second)
                deleted(filePath);
        }
        knownIpamConfigs[pathstr] = newIpam.getUUID();
        manager->updateIpamConfig(newIpam);

        LOG(INFO) << "Updated ipam config " << newIpam
                  << " from " << filePath;

    } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not load ipam config from: "
                   << filePath << ": "
                   << ex.what();
    } catch (...) {
        LOG(ERROR) << "Unknown error while loading ipam config "
                   << "information from "
                   << filePath;
    }
}

void FSIpamConfigSource::deleted(const fs::path& filePath) {
    try {
        const string& pathstr = filePath.string();
        auto it = knownIpamConfigs.find(pathstr);
        if (it != knownIpamConfigs.end()) {
            LOG(INFO) << "Removed ipam config "
                      << it->second
                      << " at " << filePath;
            manager->removeIpamConfig(it->second);
            knownIpamConfigs.erase(it);
        }
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not delete ipam config for "
                   << filePath << ": "
                   << ex.what();
    } catch (...) {
        LOG(ERROR) << "Unknown error while deleting ipam config for "
                   << filePath;
    }
}

} /* namespace opflexagent */
