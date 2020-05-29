/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for OpflexConnection
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

/* This must be included before anything else */
#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include "opflex/engine/internal/OpflexConnection.h"
#include "opflex/engine/internal/OpflexHandler.h"

#include "yajr/transport/ZeroCopyOpenSSL.hpp"

static uv_once_t ssl_once = UV_ONCE_INIT;

namespace opflex {
namespace engine {
namespace internal {

using rapidjson::Value;
using std::string;
using yajr::rpc::OutboundRequest;
using yajr::rpc::OutboundResult;
using yajr::rpc::OutboundError;
using yajr::transport::ZeroCopyOpenSSL;

OpflexConnection::OpflexConnection(HandlerFactory& handlerFactory)
    : RpcConnection(), handler(handlerFactory.newHandler(this))
{
    connect();
}

OpflexConnection::~OpflexConnection() {
    cleanup();
    if (handler)
        delete handler;
}

static void init_ssl() {
    ZeroCopyOpenSSL::initOpenSSL(true);
}

void OpflexConnection::initSSL() {
    uv_once(&ssl_once, init_ssl);
}

void OpflexConnection::connect() {}

void OpflexConnection::disconnect() {
    cleanup();
}

void OpflexConnection::close() {
    disconnect();
}

bool OpflexConnection::isReady() {
    return handler->isReady();
}

void OpflexConnection::notifyReady() {

}

} /* namespace internal */
} /* namespace engine */
} /* namespace opflex */
