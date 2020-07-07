/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of JSON-RPC connection
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

/* This must be included before anything else */
#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "opflex/logging/internal/logging.hpp"
#include "opflex/rpc/JsonRpcConnection.h"

namespace opflex {
namespace jsonrpc {

RpcConnection::RpcConnection() : requestId(1), connGeneration(0) {
}

RpcConnection::~RpcConnection() {
}

void RpcConnection::cleanup() {
    const std::lock_guard<std::mutex> lock(queue_mutex);
    connGeneration += 1;
    while (!write_queue.empty()) {
        delete write_queue.front().first;
        write_queue.pop_front();
    }
}

void RpcConnection::sendMessage(JsonRpcMessage* message, bool sync) {
    if (sync) {
        std::unique_ptr<JsonRpcMessage> messagep(message);
        doWrite(message);
    } else {
        const std::lock_guard<std::mutex> lock(queue_mutex);
        write_queue.push_back(std::make_pair(message, connGeneration));
    }
    messagesReady();
}


void RpcConnection::processWriteQueue() {
    const std::lock_guard<std::mutex> lock(queue_mutex);
    while (!write_queue.empty()) {
        const write_queue_item_t& qi = write_queue.front();
        // Avoid writing messages from a previous reconnect attempt
        if (qi.second < connGeneration) {
            LOG(DEBUG) << "Ignoring " << qi.first->getMethod()
                       << " of type " << qi.first->getType();
            continue;
        }
        std::unique_ptr<JsonRpcMessage> message(qi.first);
        write_queue.pop_front();
        doWrite(message.get());
    }
}

void RpcConnection::doWrite(JsonRpcMessage* message) {
    if (getPeer() == NULL) return;

    jsonrpc::PayloadWrapper wrapper(message);
    switch (message->getType()) {
    case jsonrpc::JsonRpcMessage::REQUEST:
        {
            yajr::rpc::MethodName method(message->getMethod().c_str());
            uint64_t xid = message->getReqXid();
            if (xid == 0) xid = requestId++;
            yajr::rpc::OutboundRequest outm(wrapper, &method, xid, getPeer());
            outm.send();
        }
        break;
    case jsonrpc::JsonRpcMessage::RESPONSE:
        {
            yajr::rpc::OutboundResult outm(*getPeer(), wrapper, message->getId());
            outm.send();
        }
        break;
    case jsonrpc::JsonRpcMessage::ERROR_RESPONSE:
        {
            yajr::rpc::OutboundError outm(*getPeer(), wrapper, message->getId());
            outm.send();
        }
        break;
    }
}
}
}
