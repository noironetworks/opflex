/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for FSNetpolSource class.
 *
 * Copyright (c) 2024 Cisco Systems, Inc. and others.  All rights reserved.
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
#include <boost/algorithm/string/predicate.hpp>

#include <opflexagent/FSNetpolSource.h>
#include <opflexagent/logging.h>

namespace opflexagent {

using boost::optional;
namespace fs = boost::filesystem;
using std::string;
using std::runtime_error;

FSNetpolSource::FSNetpolSource(opflex::ofcore::OFFramework& framework_,
                               FSWatcher& listener,
                               const std::string& netpolDir)
    : framework(framework_) {
    LOG(INFO) << "Watching " << netpolDir << " for netpol data";
    listener.addWatch(netpolDir, *this);
}

static bool isnetpol(fs::path filePath) {
    string fstr = filePath.filename().string();
    return (boost::algorithm::ends_with(fstr, ".netpol") &&
            !boost::algorithm::starts_with(fstr, "."));
}

void FSNetpolSource::updated(const fs::path& filePath) {
    if (!isnetpol(filePath)) return;

    try {
        string pathstr = filePath.string();
        netpol_map_t::const_iterator it = knownNetpols.find(pathstr);
        if (it != knownNetpols.end()) {
            deleted(filePath);
        }
        opflex::modb::mointernal::StoreClient::notif_t notifs;
        size_t n =
            framework.updateMOs(pathstr, opflex::gbp::PolicyUpdateOp::REPLACE, &notifs);
        knownNetpols[pathstr] = notifs;

        LOG(INFO) << "Updated Netpol " << filePath.stem()
                  << " from " << filePath
                  << " ( " << n << " Objects )";
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not load netpol from: "
                   << filePath << ": "
                   << ex.what();
    } catch (...) {
        LOG(ERROR) << "Unknown error while loading netpol "
                   << "information from "
                   << filePath;
   }
}

void FSNetpolSource::deleted(const fs::path& filePath) {
    try {
        string pathstr = filePath.string();
        netpol_map_t::iterator it = knownNetpols.find(pathstr);
        if (it != knownNetpols.end()) {

            framework.deleteMOs(it->second);
            LOG(INFO) << "Removed netpol-uuid "
                      << filePath.stem()
                      << " at " << filePath
                      << " ( " << it->second.size() << " Objects )";
            knownNetpols.erase(it);
        }
    } catch (const std::exception& ex) {
        LOG(ERROR) << "Could not delete netpol for "
                   << filePath << ": "
                   << ex.what();
    } catch (...) {
        LOG(ERROR) << "Unknown error while deleting netpol information for "
                   << filePath;
    }
}

} /* namespace opflexagent */
