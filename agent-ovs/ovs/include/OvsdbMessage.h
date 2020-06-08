/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OvsdbMessage.h
 * @brief Interface definition for JSON-RPC monitor messages used by the
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
#ifndef OPFLEX_OVSDBMESSAGE_H
#define OPFLEX_OVSDBMESSAGE_H

#include <opflex/rpc/JsonRpcMessage.h>

namespace opflexagent {

using namespace opflex::jsonrpc;

/**
 * OVSDB operations
 */
enum class OvsdbOperation {SELECT, INSERT, UPDATE, MUTATE, DELETE};

/**
 * OVSDB tables
 */
enum class OvsdbTable {PORT, INTERFACE, BRIDGE, IPFIX, NETFLOW, MIRROR};

/**
 * OVSDB functions
 */
enum class OvsdbFunction {EQ};

/**
 * Abstract OVSDB message
 */
class OvsdbMessage : public JsonRpcMessage {
public:

    /**
     * Construct an OVSDB message
     *
     * @param method the method for the message
     * @param type the type of message
     * @param reqId_ request ID
     */
    OvsdbMessage(const std::string& method, MessageType type, uint64_t reqId_ = 0) :
        JsonRpcMessage(method, type), reqId(reqId_) {
    }

    /**
     * Destructor
     */
    virtual ~OvsdbMessage() {};

    /**
     * Get request ID
     * @return request ID
     */
    uint64_t getReqId() const {
        return reqId;
    }

    /**
     * Serialize payload
     * @param writer writer
     */
    virtual void serializePayload(yajr::rpc::SendHandler& writer) const;

    /**
     * Operator to serialize a payload to a writer
     * @param writer the writer to serialize to
     */
    virtual bool operator()(yajr::rpc::SendHandler& writer) const = 0;

    /**
     * Convert table to string
     * @param table OVSDB table
     * @return table as string
     */
    static const char* toString(OvsdbTable table);

protected:
    /**
     * Convert operation to string
     * @param operation OVSDB operation
     * @return operation as string
     */
    static const char* toString(OvsdbOperation operation);

    /**
     * Convert function to string
     * @param function OVSDB function
     * @return function as string
     */
    static const char* toString(OvsdbFunction function);

private:
    uint64_t reqId;
};

/**
 * enum for data types to be sent over JSON/RPC
 */
enum class Dtype {STRING, INTEGER, BOOL};

/**
 * Class to represent JSON/RPC tuple data.
 */
class TupleData {
public:
    TupleData() : type(Dtype::STRING), iVal(-1), bVal(false) {}
    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    TupleData(const std::string& key_, const std::string& val) : key(key_), type(Dtype::STRING), sVal(val), iVal(-1), bVal(false) {}

    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    TupleData(const std::string& key_, bool val) : key(key_), type(Dtype::BOOL), iVal(-1), bVal(val) {}
    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    TupleData(const std::string& key_, int val) : key(key_), type(Dtype::INTEGER), iVal(val), bVal(false) {}

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
     * Move operator
     */
    TupleData& operator=(TupleData&&) = default;

    /**
     * Destructor
     */
    virtual ~TupleData() {}

    /** Get key */
    const std::string& getKey() const {
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
    const std::string& getStringValue() const {
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
    std::string key;
    Dtype type;
    std::string sVal;
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
    TupleDataSet(const std::vector<TupleData>& m, std::string l = "") : label(l), tuples(m) {}

    /**
     * Assignment operator
     */
    TupleDataSet& operator=(TupleDataSet& rhs) = default;

    virtual ~TupleDataSet() {}

    /**
     * label for collection type, viz. map, set
     */
    std::string label;
    /**
     * tuple data
     */
    std::vector<TupleData> tuples;
};

}
#endif //OPFLEX_OVSDBMESSAGE_H
