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

// row key to prop map
typedef unordered_map<string, TupleData> OvsdbRowDetails;
typedef unordered_map<string, OvsdbRowDetails> OvsdbTableDetails;

/**
 * Local representation of the OVSDB state
 */
class OvsdbState {
public:
    OvsdbState() {}

    /**
     * Destructor
     */
    virtual ~OvsdbState() {};

    void fullUpdate(OvsdbTable table, const OvsdbTableDetails& fields) {
        unique_lock<mutex> lock(stateMutex);
        ovsdbState[table] = fields;
    }

    void clear() {
        unique_lock<mutex> lock(stateMutex);
        ovsdbState.clear();
    }

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
