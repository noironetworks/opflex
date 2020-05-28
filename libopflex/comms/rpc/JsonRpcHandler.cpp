/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of JSON-RPC handler
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

#include "opflex/rpc/JsonRpcHandler.h"

namespace opflex {
namespace jsonrpc {

bool JsonRpcHandler::isReady() {
    boost::unique_lock<boost::mutex> guard(stateMutex);
    return state == READY;
}

void JsonRpcHandler::setState(ConnectionState state_) {
    boost::unique_lock<boost::mutex> guard(stateMutex);
    state = state_;
    if (state == READY) {
        guard.unlock();
        conn->notifyReady();
    } else if (state == FAILED) {
        guard.unlock();
        conn->notifyFailed();
    }
}

}
}