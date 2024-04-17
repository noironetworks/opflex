/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OvsdbState.h
 * @brief Local state of OVSDB
 */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_OVSDBSTATE_H
#define OPFLEX_OVSDBSTATE_H

#include <set>
#include <unordered_map>
#include <boost/optional.hpp>
#include "OvsdbMessage.h"
#include <opflexagent/SpanSessionState.h>
#include <opflexagent/logging.h>

namespace opflexagent {

using std::mutex;
using std::set;
using std::string;
using std::unique_lock;
using std::unordered_map;

/** Contents of a row in an OVSDB table */
typedef unordered_map<string, OvsdbValue> OvsdbRowDetails;
/** Contents of an OVSDB table */
typedef unordered_map<string, OvsdbRowDetails> OvsdbTableDetails;

/**
  * struct for managing mirror data
  */
typedef struct mirror_ {
    /**
      * UUID of the mirror
      */
    string uuid;
    /**
     * set of source port UUIDs
     */
    set<string> src_ports;
    /**
     * set of destination port UUIDs
     */
    set<string> dst_ports;
    /**
      * set of erspan ports
      */
    string out_port;
} mirror;

/**
 * Local representation of the OVSDB state
 */
class OvsdbState {
public:
    /** Constructor */
    OvsdbState() = default;

    /** Destructor */
    virtual ~OvsdbState() = default;

    /**
     * Replace the local view of a table in OVSDB
     * @param table affected table
     * @param fields fields in table
     */
    void fullUpdate(OvsdbTable table, const OvsdbTableDetails& fields) {
        unique_lock<mutex> lock(stateMutex);
        ovsdbState[table] = fields;
    }

    /**
     * Update row in cache
     */
    void updateRow(OvsdbTable table, const string& key, const OvsdbRowDetails& row) {
        unique_lock<mutex> lock(stateMutex);
        ovsdbState[table][key] = row;
    }

    /**
     * Delete row in cache
     */
    void deleteRow(OvsdbTable table, const string& key) {
        unique_lock<mutex> lock(stateMutex);
        ovsdbState[table].erase(key);
    }

    /** Clear the state */
    void clear() {
        unique_lock<mutex> lock(stateMutex);
        ovsdbState.clear();
    }

    /**
     * Get the bridge UUID
     * @param bridgeName bridge name
     * @param uuid bridge UUID
     */
    void getBridgeUuid(const string& bridgeName, string& uuid) {
        unique_lock<mutex> lock(stateMutex);
        auto& bridgeRows = ovsdbState[OvsdbTable::BRIDGE];
        if (bridgeRows.find(bridgeName) != bridgeRows.end()) {
            auto bridgeParams = bridgeRows[bridgeName];
            if (bridgeParams.find("uuid") != bridgeParams.end()) {
                uuid = bridgeParams["uuid"].getStringValue();
            }
        }
    }

    /**
     * Get the UUID for port with the specified name
     *
     * @param table table to pull UUID from
     * @param name name of port
     * @param uuid Corresponding UUID
     */
    void getUuidForName(OvsdbTable table, const string& name, string& uuid) {
        unique_lock<mutex> lock(stateMutex);
        auto& portRows = ovsdbState[table];
        for (auto& row : portRows) {
            if (row.second.find("name") != row.second.end()) {
                if (row.second["name"].getStringValue() == name) {
                    LOG(DEBUG) << "Found mapping from " << name << " to " << row.second["uuid"].getStringValue();
                    uuid = row.second["uuid"].getStringValue();
                }
            }
        }
    }

    void getQosUuidForPort(const string& name, string& uuid) {
        unique_lock<mutex> lock(stateMutex);
        auto& portRows = ovsdbState[OvsdbTable::PORT];
        for (auto& row : portRows) {
            if (row.second.find("name") != row.second.end() &&
                row.second.find("qos") != row.second.end() &&
                row.second["name"].getStringValue() == name) {
                const auto& col = row.second["qos"].getCollectionValue();
                for(auto it = col.begin(); it!=col.end();it++){
                    uuid = it->first;
                }
            }
        }
    }

    void getQueueUuidForQos(const string& qos, string &uuid) {
        unique_lock<mutex> lock(stateMutex);
        auto& qosRows = ovsdbState[OvsdbTable::QOS];
        for (auto& row : qosRows) {
             if (row.second.find("uuid") != row.second.end() &&
                 row.second["uuid"].getStringValue() == qos &&
                 row.second.find("queues") != row.second.end())  {
                 const auto& col = row.second["queues"].getCollectionValue();
                 for(auto it = col.begin(); it != col.end(); it++) {
                     LOG(DEBUG) << "queue: " << it->first << "=" << it->second;
                     uuid = it->second;
                 }
             }
        }
    }

    /**
     * Get the mirror state
     * @param name mirror name
     * @param mir Mirror struct to fill with details of mirror
     * @return True is mirror is present
     */
    bool getMirrorState(const string& name, mirror& mir) {
        bool found = false;
        unique_lock<mutex> lock(stateMutex);
        auto mirrorRows = ovsdbState[OvsdbTable::MIRROR];
        for (auto& row : mirrorRows) {
            if (row.second.find("name") != row.second.end()) {
                if (row.second["name"].getStringValue() == name) {
                    LOG(DEBUG) << "Found mirror with name " << name;
                    if (row.second.find("uuid") != row.second.end()) {
                        mir.uuid = row.second["uuid"].getStringValue();
                        found = true;
                    } else {
                        LOG(WARNING) << "Unable to find UUID for mirror named " << name;
                    }
                    mir.src_ports.clear();
                    if (row.second.find("select_src_port") != row.second.end()) {
                        if (row.second["select_src_port"].getType() == Dtype::SET) {
                            auto ports = row.second["select_src_port"].getCollectionValue();
                            for (auto& port : ports) {
                                mir.src_ports.emplace(port.first);
                                LOG(DEBUG) << "add src port " << port.first;
                            }
                        } else if (row.second["select_src_port"].getType() == Dtype::STRING) {
                            auto& port = row.second["select_src_port"].getStringValue();
                            mir.src_ports.emplace(port);
                            LOG(DEBUG) << "add src port " << port;
                        }
                    }
                    mir.dst_ports.clear();
                    if (row.second.find("select_dst_port") != row.second.end()) {
                        if (row.second["select_dst_port"].getType() == Dtype::SET) {
                            auto ports = row.second["select_dst_port"].getCollectionValue();
                            for (auto& port : ports) {
                                mir.dst_ports.emplace(port.first);
                                LOG(DEBUG) << "add dest port " << port.first;
                            }
                        } else if (row.second["select_dst_port"].getType() == Dtype::STRING) {
                            auto& port = row.second["select_dst_port"].getStringValue();
                            mir.dst_ports.emplace(port);
                            LOG(DEBUG) << "add dest port " << port;
                        }
                    }
                    if (row.second.find("out_port") != row.second.end()) {
                        auto& port = row.second["out_port"].getStringValue();
                        mir.out_port = port;
                        LOG(DEBUG) << "add out port " << port;
                    }
                }
            }
        }
        return found;
    }

    /**
     * Get ERSPAN interface params
     */
    bool getErspanParams(const string& interfaceName, ErspanParams& params) {
        unique_lock<mutex> lock(stateMutex);
        auto interfaceRows = ovsdbState[OvsdbTable::INTERFACE];
        for (auto& row : interfaceRows) {
            if (row.second.find("name") != row.second.end()) {
                if (row.second["name"].getStringValue() == interfaceName) {
                    LOG(DEBUG) << "found erspan params for interface " << interfaceName;
                    params.setPortName(interfaceName);
                    if (row.second.find("options") != row.second.end()) {
                        auto options = row.second["options"].getCollectionValue();
                        if (options.find("erspan_ver") != options.end()) {
                            LOG(DEBUG) << "setting version to " << options["erspan_ver"];
                            params.setVersion(stoul(options["erspan_ver"]));
                        }
                        if (options.find("remote_ip") != options.end()) {
                            LOG(DEBUG) << "Setting remote IP to " << options["remote_ip"];
                            params.setRemoteIp(options["remote_ip"]);
                        }
                        if (options.find("key") != options.end()) {
                            LOG(DEBUG) << "Setting session ID to " << options["key"];
                            params.setSessionId(stoul(options["key"]));
                        }
                    }
                    return true;
                }
            }
        }
        return false;
    }

private:
    unordered_map<OvsdbTable, OvsdbTableDetails> ovsdbState;
    mutex stateMutex;
};

}
#endif //OPFLEX_OVSDBSTATE_H
