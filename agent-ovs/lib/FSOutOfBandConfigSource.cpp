/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for FSOutOfBandConfigSource class.
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

#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string.hpp>
#include <opflex/modb/URIBuilder.h>
#include <boost/algorithm/string/predicate.hpp>
#include <opflexagent/FSOutOfBandConfigSource.h>
#include <modelgbp/observer/DropLogModeEnumT.hpp>
#include <opflexagent/ExtraConfigManager.h>
#include <opflexagent/logging.h>

namespace opflexagent {

using boost::optional;
namespace fs = boost::filesystem;
using std::string;
using std::make_pair;
using std::runtime_error;
using opflex::modb::URI;
using boost::asio::ip::address;
using modelgbp::observer::DropLogModeEnumT;

FSOutOfBandConfigSource::FSOutOfBandConfigSource(ExtraConfigManager* manager_,
                                   FSWatcher& listener,
                                   const std::string& serviceDir,
                                   const opflex::modb::URI &uri)
    : manager(manager_) {
    listener.addWatch(serviceDir, *this);
}

static bool isOutOfBandConfig(const fs::path& filePath) {
    string fstr = filePath.filename().string();
    return (fstr == "aci-containers-system.oob");
}

void FSOutOfBandConfigSource::updated(const fs::path& filePath) {
    using boost::property_tree::ptree;
    ptree properties;
     try {
        if (isOutOfBandConfig(filePath)) {
            const string& pathStr = filePath.string();
            read_json(pathStr, properties);
            const std::string TUNNEL_ADV_INTVL("tunnel-ep-advertisement-interval");
            OutOfBandConfigSpec oobSpec(properties.get<long>(TUNNEL_ADV_INTVL, 300));
            manager->outOfBandConfigUpdated(oobSpec);
        }
         } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not update out of band config for "
                   << filePath << ": "
                   << ex.what();
    }

}

void FSOutOfBandConfigSource::deleted(const fs::path& filePath) {
    try {
        string pathStr = filePath.string();
        if (isOutOfBandConfig(filePath)) {          
            manager->outOfBandConfigDeleted();
        }  
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not delete out of band config for "
                   << filePath << ": "
                   << ex.what();
    }
}

} /* namespace opflexagent */
