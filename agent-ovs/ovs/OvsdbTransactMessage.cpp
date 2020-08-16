/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of JSON-RPC transact messages
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

#include <opflexagent/logging.h>
#include "OvsdbTransactMessage.h"

namespace opflexagent {

void writeValue(yajr::rpc::SendHandler& writer, const OvsdbValue& value) {
    if (value.getType() == Dtype::INTEGER) {
        writer.Int(value.getIntValue());
    } else if (value.getType() == Dtype::STRING) {
        if (!value.getKey().empty()) {
            writer.StartArray();
            writer.String(value.getKey().c_str());
        }
        writer.String(value.getStringValue().c_str());
        if (!value.getKey().empty()) {
            writer.EndArray();
        }
    } else if (value.getType() == Dtype::BOOL) {
        writer.Bool(value.getBoolValue());
    } else if (value.getType() == Dtype::MAP){
        std::map<std::string, std::string> valueMap = value.getCollectionValue();
        writer.StartArray();
        const string& qId = value.getKey();
        std::istringstream ss(qId);
        int intQId;
        ss >> intQId;
        writer.Int(intQId);

        for(auto it : valueMap){
            writer.StartArray();
            writer.String(it.first.c_str());
            writer.String(it.second.c_str());
            writer.EndArray();
        }
        writer.EndArray();
    }
}

bool OvsdbTransactMessage::operator()(yajr::rpc::SendHandler& writer) const {
    if (!externalKey.first.empty()) {
        writer.String(externalKey.first.c_str());
        writer.String(externalKey.second.c_str());
    }
    if (getOperation() != OvsdbOperation::INSERT) {
        writer.String("where");
        writer.StartArray();
        if (!conditions.empty()) {
            for (auto elem : conditions) {
                writer.StartArray();
                const string& lhs = get<0>(elem);
                writer.String(lhs.c_str());
                writer.String(toString(get<1>(elem)));
                const string& rhs = get<2>(elem);
                if (lhs == "_uuid") {
                    writer.StartArray();
                    writer.String("uuid");
                    writer.String(rhs.c_str());
                    writer.EndArray();
                } else {
                    writer.String(rhs.c_str());
                }
                writer.EndArray();
            }
        }
        writer.EndArray();
    }
    writer.String("table");
    writer.String(toString(getTable()));
    writer.String("op");
    writer.String(toString(getOperation()));
    if (!columns.empty()) {
        writer.String("columns");
        writer.StartArray();
        for (auto& tmp : columns) {
            writer.String(tmp.c_str());
        }
        writer.EndArray();
    }

    if (!rowData.empty()) {
        writer.String("row");
        writer.StartObject();
        for (auto& rowEntry : rowData) {
            const string& col = rowEntry.first;
            writer.String(col.c_str());
            const OvsdbValues& tdsPtr = rowEntry.second;
            if (!tdsPtr.label.empty()) {
                writer.StartArray();
                writer.String(tdsPtr.label.c_str());
                writer.StartArray();
                for (auto& val : tdsPtr.values) {
                    writeValue(writer, val);
                }
                writer.EndArray();
                writer.EndArray();
            } else {
                writeValue(writer, *(tdsPtr.values.begin()));
            }
        }
        writer.EndObject();
    }
    if (getOperation() == OvsdbOperation::MUTATE && !mutateRowData.empty()) {
        writer.String("mutations");
        writer.StartArray();
        for (auto& rowEntry : mutateRowData) {
            const string& col = rowEntry.first;
            writer.StartArray();
            writer.String(col.c_str());
            const string& mutateRowOperation = toString(rowEntry.second.first);
            writer.String(mutateRowOperation.c_str());
            const OvsdbValues &tdsPtr = rowEntry.second.second;
            writeValue(writer, *(tdsPtr.values.begin()));
            writer.EndArray();
        }
        writer.EndArray();
    }
    return true;
}

}
