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
enum class Dtype {STRING, INTEGER, BOOL, SET, MAP};

/**
 * Class to represent an OVSDB value
 */
class OvsdbValue {
public:
    /** Default constructor */
    OvsdbValue() : type(Dtype::STRING), iVal(-1), bVal(false) {}

    /**
     * constructor
     * @param val value
     */
    OvsdbValue(const std::string& val) : type(Dtype::STRING), sVal(val), iVal(-1), bVal(false) {}

    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    OvsdbValue(const std::string& key_, const std::string& val) : key(key_), type(Dtype::STRING), sVal(val), iVal(-1), bVal(false) {}

    /**
     * constructor
     * @param val value
     */
    OvsdbValue(bool val) : type(Dtype::BOOL), iVal(-1), bVal(val) {}

    /**
     * constructor
     * @param val value
     */
    OvsdbValue(int val) : type(Dtype::INTEGER), iVal(val), bVal(false) {}

    /**
     * constructor
     * @param type_ type of collection
     * @param key_ the key string
     * @param val value
     */
    OvsdbValue(Dtype type_, const std::string& key_, const std::map<std::string, std::string>& val) : key(key_), type(type_), iVal(-1), bVal(false), collection(val) {}

    /**
     * Copy constructor
     *
     * @param copy Object to copy from
     */
    OvsdbValue(const OvsdbValue& copy) : key(copy.key), type(copy.type), sVal(copy.sVal), iVal(copy.iVal), bVal(copy.bVal), collection(copy.collection) {}

    /**
     * Assignment operator
     */
    OvsdbValue& operator=(const OvsdbValue& rhs) = default;

    /**
     * Move operator
     */
    OvsdbValue& operator=(OvsdbValue&&) = default;

    /**
     * Destructor
     */
    virtual ~OvsdbValue() {}

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

     /**
      * Get the value when set to a collection type
      * @return collection by value
      */
     std::map<std::string, std::string> getCollectionValue() const {
         return collection;
     }

private:
    std::string key;
    Dtype type;
    std::string sVal;
    int iVal;
    bool bVal;
    std::map<std::string, std::string> collection;
};

/**
 * class for representing OVSDB values
 */
class OvsdbValues {
public:
    /**
     * Default constructor
     */
    OvsdbValues() {}
    /**
     * Copy constructor
     */
    OvsdbValues(const OvsdbValues& s) : label(s.label), values(s.values) {}

    /**
     * constructor that takes a label and set of values
     */
    OvsdbValues(const std::string& l, const std::vector<OvsdbValue>& m) : label(l), values(m) {}

    /**
     * constructor that takes a set of values
     */
    OvsdbValues(const std::vector<OvsdbValue>& m) : values(m) {}

    /**
     * Assignment operator
     */
    OvsdbValues& operator=(OvsdbValues& rhs) = default;

    virtual ~OvsdbValues() {}

    /**
     * label if this is a collection type
     */
    std::string label;
    /**
     * tuple data
     */
    std::vector<OvsdbValue> values;
};

}
#endif //OPFLEX_OVSDBMESSAGE_H
