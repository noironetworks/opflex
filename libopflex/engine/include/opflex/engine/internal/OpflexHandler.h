/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OpflexHandler.h
 * @brief Interface definition file for OpFlex message handlers
 */
/*
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <string>

#include <rapidjson/document.h>

#include "opflex/ofcore/OFConstants.h"
#include "opflex/rpc/JsonRpcHandler.h"

#pragma once
#ifndef OPFLEX_ENGINE_OPFLEXHANDLER_H
#define OPFLEX_ENGINE_OPFLEXHANDLER_H

namespace opflex {
namespace engine {
namespace internal {

class OpflexConnection;

/**
 * Abstract base class for implementing the Opflex protocol
 */
class OpflexHandler : public opflex::jsonrpc::JsonRpcHandler {
public:
    /**
     * Construct a new handler associated with the given Opflex
     * connection
     *
     * @param conn the opflex connection
     */
    OpflexHandler(OpflexConnection* conn) : opflex::jsonrpc::JsonRpcHandler((opflex::jsonrpc::RpcConnection*)conn) {}

    /**
     * Destroy the handler
     */
    virtual ~OpflexHandler() {}

    // *************************
    // Protocol Message Handlers
    // *************************

    /**
     * Handle an Opflex send identity request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleSendIdentityReq(const rapidjson::Value& id,
                                       const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Send Identity Request");
    }

    /**
     * Handle an Opflex send identity response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleSendIdentityRes(uint64_t reqId,
                                       const rapidjson::Value& payload) {
        handleUnexpected("Send Identity Response");
    }

    /**
     * Handle an Opflex send identity error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleSendIdentityErr(uint64_t reqId,
                                       const rapidjson::Value& payload) {
        handleError(reqId, payload, "Send Identity");
    }

    /**
     * Handle an Opflex policy resolve request
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handlePolicyResolveReq(const rapidjson::Value& id,
                                        const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Policy Resolve Request");
    }

    /**
     * Handle an Opflex policy resolve response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handlePolicyResolveRes(uint64_t reqId,
                                        const rapidjson::Value& payload) {
        handleUnexpected("Policy Resolve Response");
    }

    /**
     * Handle an Opflex policy resolve error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handlePolicyResolveErr(uint64_t reqId,
                                        const rapidjson::Value& payload) {
        handleError(reqId, payload, "Policy Resolve");
    }

    /**
     * Handle an Opflex policy unresolve request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handlePolicyUnresolveReq(const rapidjson::Value& id,
                                          const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Policy Unresolve Request");
    }

    /**
     * Handle an Opflex policy unresolve response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handlePolicyUnresolveRes(uint64_t reqId,
                                          const rapidjson::Value& payload) {
        handleUnexpected("Policy Unresolve Response");
    }

    /**
     * Handle an Opflex policy unresolve error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handlePolicyUnresolveErr(uint64_t reqId,
                                          const rapidjson::Value& payload) {
        handleError(reqId, payload, "Policy Unresolve");
    }

    /**
     * Handle an Opflex policy update  request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handlePolicyUpdateReq(const rapidjson::Value& id,
                                       const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Policy Update Request");
    }

    /**
     * Handle an Opflex policy update response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handlePolicyUpdateRes(uint64_t reqId,
                                       const rapidjson::Value& payload) {
        handleUnexpected("Policy Update Response");
    }

    /**
     * Handle an Opflex policy update error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handlePolicyUpdateErr(uint64_t reqId,
                                       const rapidjson::Value& payload) {
        handleError(reqId, payload, "Policy Update");
    }

    /**
     * Handle an Opflex endpoint declare request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleEPDeclareReq(const rapidjson::Value& id,
                                    const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Endpoint Declare Request");
    }

    /**
     * Handle an Opflex endpoint declare response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPDeclareRes(uint64_t reqId,
                                    const rapidjson::Value& payload) {
        handleUnexpected("Endpoint Declare Response");
    }

    /**
     * Handle an Opflex endpoint declare error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPDeclareErr(uint64_t reqId,
                                    const rapidjson::Value& payload) {
        handleError(reqId, payload, "Endpoint Declare");
    }

    /**
     * Handle an Opflex endpoint undeclare request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleEPUndeclareReq(const rapidjson::Value& id,
                                      const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Endpoint Undeclare Request");
    }

    /**
     * Handle an Opflex endpoint undeclare response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPUndeclareRes(uint64_t reqId,
                                      const rapidjson::Value& payload) {
        handleUnexpected("Endpoint Undeclare Response");
    }

    /**
     * Handle an Opflex endpoint undeclare error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPUndeclareErr(uint64_t reqId,
                                      const rapidjson::Value& payload) {
        handleError(reqId, payload, "Endpoint Undeclare");
    }

    /**
     * Handle an Opflex endpoint resolve request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleEPResolveReq(const rapidjson::Value& id,
                                    const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Endpoint Resolve Request");
    }

    /**
     * Handle an Opflex endpoint resolve response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPResolveRes(uint64_t reqId,
                                    const rapidjson::Value& payload) {
        handleUnexpected("Endpoint Resolve Response");
    }

    /**
     * Handle an Opflex endpoint resolve error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPResolveErr(uint64_t reqId,
                                    const rapidjson::Value& payload) {
        handleError(reqId, payload, "Endpoint Resolve");
    }

    /**
     * Handle an Opflex endpoint unresolve request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleEPUnresolveReq(const rapidjson::Value& id,
                                      const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Endpoint Unresolve Request");
    }

    /**
     * Handle an Opflex endpoint unresolve response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPUnresolveRes(uint64_t reqId,
                                      const rapidjson::Value& payload) {
        handleUnexpected("Endpoint Unresolve Response");
    }

    /**
     * Handle an Opflex endpoint unresolve error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPUnresolveErr(uint64_t reqId,
                                      const rapidjson::Value& payload) {
        handleError(reqId, payload, "Endpoint Unresolve");
    }

    /**
     * Handle an Opflex endpoint update request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleEPUpdateReq(const rapidjson::Value& id,
                                   const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Endpoint Update Request");
    }

    /**
     * Handle an Opflex endpoint update response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPUpdateRes(uint64_t reqId,
                                   const rapidjson::Value& payload) {
        handleUnexpected("Endpoint Update Response");
    }

    /**
     * Handle an Opflex endpoint update error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleEPUpdateErr(uint64_t reqId,
                                   const rapidjson::Value& payload) {
        handleError(reqId, payload, "Endpoint Update");
    }

    /**
     * Handle an Opflex state report request.
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleStateReportReq(const rapidjson::Value& id,
                                      const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "State Report Request");
    }

    /**
     * Handle an Opflex state report response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleStateReportRes(uint64_t reqId,
                                      const rapidjson::Value& payload) {
        handleUnexpected("State Report Response");
    }

    /**
     * Handle an Opflex state report error response.
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleStateReportErr(uint64_t reqId,
                                      const rapidjson::Value& payload) {
        handleError(reqId, payload, "State Report");
    }

    /**
     * Handle an Opflex "custom" request for vendor extensions
     *
     * @param id the ID of the remote message
     * @param payload the payload of the message
     */
    virtual void handleCustomReq(const rapidjson::Value& id,
                                 const rapidjson::Value& payload) {
        handleUnsupportedReq(id, "Custom Request");
    }

    /**
     * Handle an Opflex "custom" response for vendor extensions
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleCustomRes(uint64_t reqId,
                                 const rapidjson::Value& payload) {
        handleUnexpected("Custom Response");
    }

    /**
     * Handle an Opflex "custom" error response for vendor extensions
     *
     * @param reqId the request ID from the response
     * @param payload the payload of the message
     */
    virtual void handleCustomErr(uint64_t reqId,
                                 const rapidjson::Value& payload) {
        handleError(reqId, payload, "Custom");
    }

    // ***************
    // Utility methods
    // ***************

    /**
     * Generically handle an error by logging the message
     *
     * @param reqId the request ID associated with the error
     * @param payload the error payload
     * @param type the type of message
     */
    virtual void handleError(uint64_t reqId,
                             const rapidjson::Value& payload,
                             const std::string& type);

    /**
     * Handle an unexpected message by logging an error, and then
     * disconnecting the connection.
     *
     * @param type the type of message
     */
    virtual void handleUnexpected(const std::string& type);

    /**
     * Handle an unsupported request by responding with an error with
     * a response code of EUNSUPPORTED
     *
     * @param id the ID of the remote message
     * @param type the type of message
     */
    virtual void handleUnsupportedReq(const rapidjson::Value& id,
                                      const std::string& type);

    /**
     * Send an error response with the given information in response
     * to the message with the given ID.  This will also log the error.
     *
     * @param id the ID of the remote message
     * @param code the Opflex error code
     * @param message the error message to send
     */
    virtual void sendErrorRes(const rapidjson::Value& id,
                              const std::string& code,
                              const std::string& message);

    /**
     * Check that the connection is in ready state before handling the
     * specified request.  If the connection is not ready, send an
     * error response, disconnect the connection, and return false.
     *
     * @param id the ID for the request
     * @param method the name of the request method
     */
    virtual bool requireReadyReq(const rapidjson::Value& id,
                                 const std::string& method);

    /**
     * Check that the connection is in ready state before handling the
     * specified response.  If the connection is not ready, disconnect
     * the connection and return false.
     *
     * @param reqId the ID for the request
     * @param method the name of the request method
     */
    virtual bool requireReadyRes(uint64_t reqId,
                                 const std::string& method);

};


} /* namespace internal */
} /* namespace engine */
} /* namespace opflex */

#endif /* OPFLEX_ENGINE_OPFLEXHANDLER_H */
