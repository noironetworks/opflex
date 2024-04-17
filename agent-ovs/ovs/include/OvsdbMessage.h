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

#include <map>
#include <utility>

namespace opflexagent {

using namespace opflex::jsonrpc;

/**
 * OVSDB operations
 */
enum class OvsdbOperation {SELECT, INSERT, UPDATE, MUTATE, DELETE};

/**
 * OVSDB tables
 */
enum class OvsdbTable {PORT, INTERFACE, BRIDGE, IPFIX, NETFLOW, MIRROR, QOS, QUEUE};

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
    virtual ~OvsdbMessage() = default;

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
    explicit OvsdbValue(std::string val) : type(Dtype::STRING), sVal(std::move(val)), iVal(-1), bVal(false) {}

    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    OvsdbValue(std::string key_, std::string val) : key(std::move(key_)), type(Dtype::STRING), sVal(std::move(val)), iVal(-1), bVal(false) {}

    /**
     * constructor
     * @param val value
     */
    explicit OvsdbValue(bool val) : type(Dtype::BOOL), iVal(-1), bVal(val) {}

    /**
     * constructor
     * @param val value
     */
    explicit OvsdbValue(int val) : type(Dtype::INTEGER), iVal(val), bVal(false) {}


    /**
     * constructor
     * @param val value
     */
    OvsdbValue(uint64_t val) : type(Dtype::INTEGER), iVal(val), bVal(false) {}


    /**
     * constructor
     * @param type_ type of collection
     * @param key_ the key string
     * @param val value
     */
    OvsdbValue(Dtype type_, std::string key_, std::map<std::string, std::string> val) : key(std::move(key_)), type(type_), iVal(-1), bVal(false), collection(std::move(val)) {}


    /**
     * constructor
     * @param key_ the key string
     * @param val value
     */
    OvsdbValue(const std::string& key_, int val) : key(key_), type(Dtype::INTEGER), iVal(val),  bVal(false) {}


    /**
     * Copy constructor
     *
     * @param copy Object to copy from
     */
    OvsdbValue(const OvsdbValue& copy) = default;

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
    virtual ~OvsdbValue() = default;

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
    OvsdbValues() = default;
    /**
     * Copy constructor
     */
    OvsdbValues(const OvsdbValues& s) = default;

    /**
     * constructor that takes a label and set of values
     */
    OvsdbValues(std::string l, std::vector<OvsdbValue> m) : label(std::move(l)), values(std::move(m)) {}

    /**
     * constructor that takes a set of values
     */
    explicit OvsdbValues(std::vector<OvsdbValue> m) : values(std::move(m)) {}

    /**
     * Assignment operator
     */
    OvsdbValues& operator=(const OvsdbValues& rhs) = default;

    virtual ~OvsdbValues() = default;

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
