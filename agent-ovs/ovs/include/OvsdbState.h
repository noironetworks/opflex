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

#include <unordered_map>
#include <boost/optional.hpp>
#include "OvsdbMessage.h"

namespace opflexagent {

using std::mutex;
using std::string;
using std::unique_lock;
using std::unordered_map;

/** Contents of a row in an OVSDB table */
typedef unordered_map<string, TupleData> OvsdbRowDetails;
/** Contents of an OVSDB table */
typedef unordered_map<string, OvsdbRowDetails> OvsdbTableDetails;

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
        auto bridgeRows = ovsdbState[OvsdbTable::BRIDGE];
        if (bridgeRows.find(bridgeName) != bridgeRows.end()) {
            auto bridgeParams = bridgeRows[bridgeName];
            if (bridgeParams.find("uuid") != bridgeParams.end()) {
                uuid = bridgeParams["uuid"].getStringValue();
            }
        }
    }

private:
    unordered_map<OvsdbTable, OvsdbTableDetails> ovsdbState;
    mutex stateMutex;
};

}
#endif //OPFLEX_OVSDBSTATE_H
