/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OvsdbTransactMessage.h
 * @brief Interface definition for JSON-RPC transact messages used by the
 * engine
 */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_OVSDBTRANSACTMESSAGE_H
#define OPFLEX_OVSDBTRANSACTMESSAGE_H

#include <rapidjson/document.h>
#include "OvsdbMessage.h"
#include <list>
#include <set>
#include <unordered_map>

namespace opflexagent {

using namespace std;
using namespace rapidjson;

/**
 * Transact message
 */
class OvsdbTransactMessage : public OvsdbMessage {
public:
    /**
     * Construct a transact request
     */
    OvsdbTransactMessage(OvsdbOperation operation_, OvsdbTable table_) : OvsdbMessage("transact", REQUEST),
                                                                         operation(operation_), table(table_) {}

    /**
     * Copy constructor
     */
     OvsdbTransactMessage(const OvsdbTransactMessage& copy) : OvsdbMessage("transact", REQUEST),
         conditions(copy.conditions), columns(copy.columns), rowData(copy.rowData), mutateRowData(copy.mutateRowData),
         externalKey(copy.externalKey), operation(copy.getOperation()), table(copy.getTable()) {}

    /**
     * Assignment operator
     */
    OvsdbTransactMessage& operator=(OvsdbTransactMessage& rhs) = default;

    /**
     * Destructor
     */
    virtual ~OvsdbTransactMessage() {};

    /**
     * Operator to serialize a payload to a writer
     * @param writer the writer to serialize to
     */
    virtual bool operator()(yajr::rpc::SendHandler& writer) const;

    /**
     * operation type, E.g select, insert.
     */
    OvsdbOperation getOperation() const {
        return operation;
    }

    /**
     * table name
     */
    OvsdbTable getTable() const {
        return table;
    }

    /**
     * set of tuple of data to be mapped to rows
     */
    set<tuple<string, OvsdbFunction, string>> conditions;

    /**
     * set of columns in table
     */
    set<string> columns;
    /**
     * map of row data
     */
    unordered_map<string, OvsdbValues> rowData;
    /**
     * mutate row data
     */
    unordered_map<string, std::pair<OvsdbOperation, OvsdbValues>> mutateRowData;
    /**
     * generated key name to value
     */
    pair<string, string> externalKey;

private:
    OvsdbOperation operation;
    OvsdbTable table;
};

/**
 * JSON/RPC transaction message
 */
class TransactReq : public OvsdbMessage {
public:
    /**
     * Construct a TransactReq instance
     * @param tl transaction data
     * @param reqId request ID
     */
    TransactReq(const list<OvsdbTransactMessage>& tl, uint64_t reqId)
        : OvsdbMessage("transact", REQUEST, reqId) , transList(tl) {
    }

    /**
     * Destructor
     */
    virtual ~TransactReq() {}

    /**
     * Operator to serialize OVSDB transaction
     * @tparam T Type
     * @param writer writer
     * @return
     */
    virtual bool operator()(yajr::rpc::SendHandler& writer) const {
        writer.StartArray();
        writer.String("Open_vSwitch");
        for (auto& tr : transList) {
            writer.StartObject();
            tr.serializePayload(writer);
            writer.EndObject();
        }
        writer.EndArray();
        return true;
    }

private:
    list<OvsdbTransactMessage> transList;
};

}

#endif //OPFLEX_OVSDBTRANSACTMESSAGE_H
