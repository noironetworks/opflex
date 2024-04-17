/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*!
 * @file OvsdbMonitorMessage.h
 * @brief Interface definition for OVSDB monitor messages
 */
/*
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_OVSDBMONITORMESSAGE_H
#define OPFLEX_OVSDBMONITORMESSAGE_H

#include "OvsdbMessage.h"
#include <list>

namespace opflexagent {

/**
 * Represents an OVSDB monitor message
 *
 * Represents a single monitor message for an OVSDB table
 * and columns of that table that we are interested in
 */
class OvsdbMonitorMessage : public OvsdbMessage {
public:
    /**
     * Constructor
     * @param table_ Table to be monitored
     * @param columns_ Columns to monitor (all columns if empty)
     * @param reqId Req ID for the message
     */
    OvsdbMonitorMessage(OvsdbTable table_, const std::list<std::string>& columns_, uint64_t reqId) : OvsdbMessage("monitor", REQUEST, reqId), table(table_), columns(columns_) {}

    /**
     * Destructor
     */
    virtual ~OvsdbMonitorMessage() {};

    /**
     * Operator to serialize a payload to a writer
     * @param writer the writer to serialize to
     */
    virtual bool operator()(yajr::rpc::SendHandler& writer) const;

private:
    OvsdbTable table;
    std::list<std::string> columns;
};

}

#endif //OPFLEX_OVSDBMONITORMESSAGE_H
