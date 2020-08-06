/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of abstract OVSDB messages
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "OvsdbMessage.h"
#include <opflexagent/logging.h>

namespace opflexagent {

void OvsdbMessage::serializePayload(yajr::rpc::SendHandler& writer) const {
    if (getReqId() != 0) {
        LOG(DEBUG) << "serializePayload send handler - reqId " << std::to_string(getReqId());
    }
    (*this)(writer);
}

static const char* OvsdbOperationStrings[] = {"select", "insert", "update", "mutate", "delete"};

const char* OvsdbMessage::toString(OvsdbOperation operation) {
    return OvsdbOperationStrings[static_cast<uint32_t>(operation)];
}

static const char* OvsdbTableStrings[] = {"Port", "Interface", "Bridge", "IPFIX", "NetFlow", "Mirror", "QoS", "Queue"};

const char* OvsdbMessage::toString(OvsdbTable table) {
    return OvsdbTableStrings[static_cast<uint32_t>(table)];
}

static const char* OvsdbFunctionStrings[] = {"=="};

const char* OvsdbMessage::toString(OvsdbFunction function) {
    return OvsdbFunctionStrings[static_cast<uint32_t>(function)];
}
}
