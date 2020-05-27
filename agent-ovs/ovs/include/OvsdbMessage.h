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

protected:
    /**
     * Convert operation to string
     * @param operation OVSDB operation
     * @return operation as string
     */
    static const char* toString(OvsdbOperation operation);

    /**
     * Convert table to string
     * @param table OVSDB table
     * @return table as string
     */
    static const char* toString(OvsdbTable table);

    /**
     * Convert function to string
     * @param function OVSDB function
     * @return function as string
     */
    static const char* toString(OvsdbFunction function);

private:
    uint64_t reqId;
};

}
#endif //OPFLEX_OVSDBMESSAGE_H
