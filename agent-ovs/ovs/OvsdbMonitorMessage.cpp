/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of OVSDB monitor messages
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "OvsdbMonitorMessage.h"

namespace opflexagent {

bool OvsdbMonitorMessage::operator()(yajr::rpc::SendHandler& writer) const {
    writer.StartArray();
    writer.String("Open_vSwitch");
    writer.String(toString(table));
    writer.StartObject();
    writer.String(toString(table));
    writer.StartArray();
    writer.StartObject();
    writer.String("columns");
    writer.StartArray();
    for (const std::string& column : columns) {
        writer.String(column.c_str());
    }
    writer.EndArray();
    writer.EndObject();
    writer.EndArray();
    writer.EndObject();
    writer.EndArray();
    return true;
}

}