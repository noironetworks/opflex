/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifndef OPFLEX_MOCKRPCCONNECTION_H
#define OPFLEX_MOCKRPCCONNECTION_H

#include "OvsdbConnection.h"

namespace opflexagent {

/**
 * class for a mockup of an RpcConnection object
 */
class MockRpcConnection : public opflexagent::OvsdbConnection {
public:
    /**
     * constructor that takes a Transaction object reference
     */
    MockRpcConnection() : OvsdbConnection(false) {}

    /**
     * establish mock connection
     */
    virtual void connect() {
        setConnected(true);
        setSyncComplete(true);
    }

    /**
     * disconnect mock connection
     */
    virtual void disconnect() { setConnected(false);}

    /**
     * New messages are ready to be written to the socket.
     * No-op with mock connection
     */
    virtual void messagesReady() {};

    /**
     * destructor
     */
    virtual ~MockRpcConnection() {}
};

}

#endif //OPFLEX_MOCKRPCCONNECTION_H
