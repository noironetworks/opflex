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
#include <unordered_map>

namespace opflexagent {

using namespace std;
using namespace rapidjson;

/**
 * enum for data types to be sent over JSON/RPC
 */
enum class Dtype {STRING, INTEGER, BOOL};

/**
 * Class to represent JSON/RPC tuple data.
 */
class TupleData {
public:
    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    TupleData(const string& key_, const string& val) : key(key_), type(Dtype::STRING), sVal(val), iVal(-1), bVal(false) {}

    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    TupleData(const string& key_, bool val) : key(key_), type(Dtype::BOOL), iVal(-1), bVal(val) {}
    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    TupleData(const string& key_, int val) : key(key_), type(Dtype::INTEGER), iVal(val), bVal(false) {}

    /**
     * Copy constructor
     *
     * @param copy Object to copy from
     */
    TupleData(const TupleData& copy) : key(copy.key), type(copy.type), sVal(copy.sVal), iVal(copy.iVal), bVal(copy.bVal) {}

    /**
     * Assignment operator
     */
    TupleData& operator=(const TupleData& rhs) = default;

    /**
     * Destructor
     */
    virtual ~TupleData() {}

    /** Get key */
    const string& getKey() const {
        return key;
    }

    /**
     * get the data type
     * @return enum Dtype
     */
     Dtype getType() const {
        return type;
    }

    /**
     * Get the value when set to string type
     */
    const string& getStringValue() const {
         return sVal;
     }

    /**
     * Get the value when set to bool type
     */
     bool getBoolValue() const {
         return bVal;
     }

    /**
     * Get the value when set to int type
     */
     int getIntValue() const {
         return iVal;
     }

private:
    string key;
    Dtype type;
    string sVal;
    int iVal;
    bool bVal;
};

/**
 * class for representing JSON/RPC tuple data set
 */
class TupleDataSet {
public:
    /**
     * Default constructor
     */
    TupleDataSet() {}
    /**
     * Copy constructor
     */
    TupleDataSet(const TupleDataSet& s) : label(s.label), tuples(s.tuples) {}

    /**
     * constructor that takes a tuple
     */
    TupleDataSet(const vector<TupleData>& m, string l = "") : label(l), tuples(m) {}

    /**
     * Assignment operator
     */
    TupleDataSet& operator=(TupleDataSet& rhs) = default;

    virtual ~TupleDataSet() {}

    /**
     * label for collection type, viz. map, set
     */
    string label;
    /**
     * tuple data
     */
    vector<TupleData> tuples;
};

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
         conditions(copy.conditions), columns(copy.columns), rowData(copy.rowData), mutateRowData(copy.mutateRowData), kvPairs(copy.kvPairs),
         operation(copy.getOperation()), table(copy.getTable()) {}

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
    unordered_map<string, TupleDataSet> rowData;
    /**
     * mutate row data
     */
    unordered_map<string, std::pair<OvsdbOperation, TupleDataSet>> mutateRowData;
    /**
     * key value pairs
     */
    vector<TupleData> kvPairs;

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
        for (auto tr : transList) {
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
