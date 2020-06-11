/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of ovsdb messages for engine
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

/* This must be included before anything else */
#if HAVE_CONFIG_H
#  include <config.h>
#endif

extern "C" {
#include <lib/dirs.h>
}

#include "ovs/include/OvsdbConnection.h"
#include "OvsdbMonitorMessage.h"
#include <opflexagent/logging.h>

namespace opflexagent {

mutex OvsdbConnection::ovsdbMtx;

void OvsdbConnection::on_writeq_async(uv_async_t* handle) {
    auto* conn = (OvsdbConnection*)handle->data;
    conn->processWriteQueue();
}

void OvsdbConnection::start() {
    LOG(DEBUG) << "Starting .....";
    unique_lock<mutex> lock(OvsdbConnection::ovsdbMtx);
    client_loop = threadManager.initTask("OvsdbConnection");
    yajr::initLoop(client_loop);
    uv_async_init(client_loop,&connect_async, connect_cb);
    writeq_async.data = this;
    uv_async_init(client_loop, &writeq_async, on_writeq_async);

    threadManager.startTask("OvsdbConnection");
}

void OvsdbConnection::connect_cb(uv_async_t* handle) {
    unique_lock<mutex> lock(OvsdbConnection::ovsdbMtx);
    auto* ocp = (OvsdbConnection*)handle->data;
    if (ocp->ovsdbUseLocalTcpPort) {
        ocp->peer = yajr::Peer::create("127.0.0.1",
                                       "6640",
                                       on_state_change,
                                       ocp, loop_selector, false);
        ocp->remote_peer = "127.0.0.1:6640";
    } else {
        std::string swPath;
        swPath.append(ovs_rundir()).append("/db.sock");
        ocp->peer = yajr::Peer::create(swPath, on_state_change,
                                       ocp, loop_selector, false);
        ocp->remote_peer = swPath;
    }
    assert(ocp->peer);
}

void OvsdbConnection::stop() {
    uv_close((uv_handle_t*)&connect_async, nullptr);
    uv_close((uv_handle_t*)&writeq_async, nullptr);
    if (peer) {
        peer->destroy();
    }
    yajr::finiLoop(client_loop);
    threadManager.stopTask("OvsdbConnection");
}

 void OvsdbConnection::on_state_change(yajr::Peer * p, void * data,
                     yajr::StateChange::To stateChange,
                     int error) {
    auto* conn = (OvsdbConnection*)data;
    switch (stateChange) {
        case yajr::StateChange::CONNECT: {
            conn->setConnected(true);
            p->startKeepAlive(0, 5000, 60000);
            // OVSDB monitor call
            conn->syncMsgsRemaining = 6;
            list<string> bridgeColumns = {"name", "ports", "netflow", "ipfix", "mirrors"};
            auto message = new OvsdbMonitorMessage(OvsdbTable::BRIDGE, bridgeColumns, conn->getNextId());
            conn->sendMessage(message, false);
            list<string> portColumns = {"name", "interfaces"};
            message = new OvsdbMonitorMessage(OvsdbTable::PORT, portColumns, conn->getNextId());
            conn->sendMessage(message, false);
            list<string> interfaceColumns = {"name", "type", "options"};
            message = new OvsdbMonitorMessage(OvsdbTable::INTERFACE, interfaceColumns, conn->getNextId());
            conn->sendMessage(message, false);
            list<string> mirrorColumns = {"name", "select_src_port", "select_dst_port", "output_port"};
            message = new OvsdbMonitorMessage(OvsdbTable::MIRROR, mirrorColumns, conn->getNextId());
            conn->sendMessage(message, false);
            list<string> netflowColumns = {"targets", "active_timeout", "add_id_to_interface"};
            message = new OvsdbMonitorMessage(OvsdbTable::NETFLOW, netflowColumns, conn->getNextId());
            conn->sendMessage(message, false);
            list<string> ipfixColumns = {"targets", "sampling", "other_config"};
            message = new OvsdbMonitorMessage(OvsdbTable::IPFIX, ipfixColumns, conn->getNextId());
            conn->sendMessage(message, false);
        }
            break;
        case yajr::StateChange::DISCONNECT:
            conn->setConnected(false);
            LOG(INFO) << "Disconnected";
            break;
        case yajr::StateChange::TRANSPORT_FAILURE:
            conn->setConnected(false);
            LOG(ERROR) << "SSL Connection error";
            break;
        case yajr::StateChange::FAILURE:
            conn->setConnected(false);
            LOG(ERROR) << "Connection error: " << uv_strerror(error);
            break;
        case yajr::StateChange::DELETE:
            conn->setConnected(false);
            LOG(INFO) << "Connection closed";
            break;
    }
}

uv_loop_t* OvsdbConnection::loop_selector(void* data) {
    auto* conn = (OvsdbConnection*)data;
    return conn->client_loop;
}

void OvsdbConnection::connect() {
    unique_lock<mutex> lock(OvsdbConnection::ovsdbMtx);
    if (!connected) {
        connect_async.data = this;
        uv_async_send(&connect_async);
    }
}

void OvsdbConnection::disconnect() {
    // TODO
}

void OvsdbConnection::handleTransaction(uint64_t reqId, const Document& payload) {
    LOG(DEBUG) << "Received response for transaction with reqId " << reqId;
}

void OvsdbConnection::handleTransactionError(uint64_t reqId, const Document& payload) {
    if (payload.HasMember("error")) {
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        payload.Accept(writer);
        LOG(WARNING) << "Received error response for reqId " << reqId << " - " << buffer.GetString();
    } else {
        LOG(WARNING) << "Received error response with no error element";
    }
}

void populateValues(const Value& value, string& type, map<string, string>& values) {
    assert(value.IsArray());
    if (value.GetArray().Size() == 2) {
        if (value[0].IsString()) {
            std::string arrayType = value[0].GetString();
            if (arrayType == "uuid" && value[1].IsString()) {
                const string strVal = value[1].GetString();
                values[strVal];
            } else if (arrayType == "set" && value[1].IsArray()) {
                type = arrayType;
                for (Value::ConstValueIterator memberItr = value[1].GetArray().Begin();
                     memberItr != value[1].GetArray().End(); ++memberItr) {
                    if (memberItr->IsArray()) {
                        if (memberItr->GetArray().Size() == 2) {
                            if (memberItr->GetArray()[1].IsString()) {
                                values[memberItr->GetArray()[1].GetString()];
                            } else {
                                LOG(WARNING) << "member type = " << memberItr->GetArray()[1].GetType();
                            }
                        }
                    }
                }
            } else if (arrayType == "map") {
                type = arrayType;
                for (Value::ConstValueIterator memberItr = value[1].GetArray().Begin();
                     memberItr != value[1].GetArray().End(); ++memberItr) {
                    if (memberItr->IsArray()) {
                        for (Value::ConstValueIterator mapMemberItr = value[1].GetArray().Begin();
                             mapMemberItr != value[1].GetArray().End(); ++mapMemberItr) {
                            if (mapMemberItr->GetArray().Size() == 2) {
                                if (mapMemberItr->GetArray()[0].IsString() &&
                                    mapMemberItr->GetArray()[1].IsString()) {
                                    values[memberItr->GetArray()[0].GetString()] = memberItr->GetArray()[1].GetString();
                                } else {
                                    LOG(WARNING) << "map key type = " << mapMemberItr->GetArray()[0].GetType();
                                    LOG(WARNING) << "map value type = " << mapMemberItr->GetArray()[0].GetType();
                                }
                            }
                        }
                    }
                }
            } else {
                LOG(WARNING) << "Unexpected array type of " << arrayType;
            }
        }
    }
}

/**
 * Process an OVSDB row update
 * @param value rapidjson value
 * @param rowDetails details of the row
 * @return Is this an existing row
 */
bool processRowUpdate(const Value& value, OvsdbRowDetails& rowDetails) {
    bool result = false;
    for (Value::ConstMemberIterator itr = value.MemberBegin();
         itr != value.MemberEnd(); ++itr) {
        if (itr->name.IsString() && itr->value.IsObject()) {
            string state = itr->name.GetString();
            if ("new" == state) {
                result = true;
            } else if ("old" != state) {
                LOG(WARNING) << "Unexpected state " << state;
            }
            for (Value::ConstMemberIterator propItr = itr->value.MemberBegin();
                 propItr != itr->value.MemberEnd(); ++propItr) {
                if (propItr->name.IsString()) {
                    const std::string propName = propItr->name.GetString();
                    if (propItr->value.IsString()) {
                        std::string stringValue = propItr->value.GetString();
                        rowDetails[propName] = OvsdbValue(stringValue);
                    } else if (propItr->value.IsArray()) {
                        map<string, string> items;
                        string type;
                        populateValues(propItr->value, type, items);
                        opflexagent::Dtype dataType = type.empty() ? opflexagent::Dtype::STRING : (type == "map" ? Dtype::MAP : Dtype::SET);
                        rowDetails[propName] = OvsdbValue(dataType, type, items);
                    } else if (propItr->value.IsInt()) {
                        int intValue = propItr->value.GetInt();
                        rowDetails[propName] = OvsdbValue(intValue);
                    } else if (propItr->value.IsBool()) {
                        bool boolValue = propItr->value.GetBool();
                        rowDetails[propName] = OvsdbValue(boolValue);
                    }
                }
            }
        }
    }
    return result;
}

void OvsdbConnection::handleMonitor(uint64_t reqId, const Document& payload) {
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    payload.Accept(writer);
    if (payload.IsObject()) {
        OvsdbTableDetails tableState;
        if (payload.HasMember(OvsdbMessage::toString(OvsdbTable::BRIDGE))) {
            const Value& bridgeValue = payload[OvsdbMessage::toString(OvsdbTable::BRIDGE)];
            if (bridgeValue.IsObject()) {
                for (Value::ConstMemberIterator itr = bridgeValue.MemberBegin();
                     itr != bridgeValue.MemberEnd(); ++itr) {
                    if (itr->name.IsString() && itr->value.IsObject()) {
                        OvsdbRowDetails rowDetails;
                        std::string uuid = itr->name.GetString();
                        rowDetails["uuid"] = OvsdbValue(uuid);
                        std::string bridgeName;
                        processRowUpdate(itr->value, rowDetails);
                        if (rowDetails.find("name") != rowDetails.end()) {
                            bridgeName = rowDetails["name"].getStringValue();
                            // use bridge name as key as that's the most common lookup
                            tableState[bridgeName] = rowDetails;
                        } else {
                            LOG(WARNING) << "Dropping bridge with no name";
                        }
                    }
                }
                ovsdbState.fullUpdate(OvsdbTable::BRIDGE, tableState);
            }
        } else if (payload.HasMember(OvsdbMessage::toString(OvsdbTable::IPFIX))) {
            const Value& ipfixValue = payload[OvsdbMessage::toString(OvsdbTable::IPFIX)];
            if (ipfixValue.IsObject()) {
                for (Value::ConstMemberIterator itr = ipfixValue.MemberBegin();
                     itr != ipfixValue.MemberEnd(); ++itr) {
                    if (itr->name.IsString() && itr->value.IsObject()) {
                        std::string uuid = itr->name.GetString();
                        OvsdbRowDetails rowDetails;
                        rowDetails["uuid"] = OvsdbValue(uuid);
                        processRowUpdate(itr->value, rowDetails);
                        tableState[uuid] = rowDetails;
                    }
                }
                ovsdbState.fullUpdate(OvsdbTable::IPFIX, tableState);
            }
        } else if (payload.HasMember(OvsdbMessage::toString(OvsdbTable::NETFLOW))) {
            const Value& netflowValue = payload[OvsdbMessage::toString(OvsdbTable::NETFLOW)];
            if (netflowValue.IsObject()) {
                for (Value::ConstMemberIterator itr = netflowValue.MemberBegin();
                     itr != netflowValue.MemberEnd(); ++itr) {
                    if (itr->name.IsString() && itr->value.IsObject()) {
                        std::string uuid = itr->name.GetString();
                        OvsdbRowDetails rowDetails;
                        rowDetails["uuid"] = OvsdbValue(uuid);
                        processRowUpdate(itr->value, rowDetails);
                        tableState[uuid] = rowDetails;
                    }
                }
                ovsdbState.fullUpdate(OvsdbTable::NETFLOW, tableState);
            }
        } else if (payload.HasMember(OvsdbMessage::toString(OvsdbTable::MIRROR))) {
            const Value& mirrorValue = payload[OvsdbMessage::toString(OvsdbTable::MIRROR)];
            if (mirrorValue.IsObject()) {
                for (Value::ConstMemberIterator itr = mirrorValue.MemberBegin();
                     itr != mirrorValue.MemberEnd(); ++itr) {
                    if (itr->name.IsString() && itr->value.IsObject()) {
                        std::string uuid = itr->name.GetString();
                        OvsdbRowDetails rowDetails;
                        rowDetails["uuid"] = OvsdbValue(uuid);
                        processRowUpdate(itr->value, rowDetails);
                        tableState[uuid] = rowDetails;
                    }
                }
                ovsdbState.fullUpdate(OvsdbTable::MIRROR, tableState);
            }
        } else if (payload.HasMember(OvsdbMessage::toString(OvsdbTable::PORT))) {
            const Value& portValue = payload[OvsdbMessage::toString(OvsdbTable::PORT)];
            if (portValue.IsObject()) {
                for (Value::ConstMemberIterator itr = portValue.MemberBegin();
                     itr != portValue.MemberEnd(); ++itr) {
                    if (itr->name.IsString() && itr->value.IsObject()) {
                        OvsdbRowDetails rowDetails;
                        std::string uuid = itr->name.GetString();
                        rowDetails["uuid"] = OvsdbValue(uuid);
                        processRowUpdate(itr->value, rowDetails);
                        tableState[uuid] = rowDetails;
                    }
                }
                ovsdbState.fullUpdate(OvsdbTable::PORT, tableState);
            }
        } else if (payload.HasMember(OvsdbMessage::toString(OvsdbTable::INTERFACE))) {
            const Value& interfaceValue = payload[OvsdbMessage::toString(OvsdbTable::INTERFACE)];
            if (interfaceValue.IsObject()) {
                for (Value::ConstMemberIterator itr = interfaceValue.MemberBegin();
                     itr != interfaceValue.MemberEnd(); ++itr) {
                    if (itr->name.IsString() && itr->value.IsObject()) {
                        OvsdbRowDetails rowDetails;
                        std::string uuid = itr->name.GetString();
                        rowDetails["uuid"] = OvsdbValue(uuid);
                        processRowUpdate(itr->value, rowDetails);
                        tableState[uuid] = rowDetails;
                    }
                }
                ovsdbState.fullUpdate(OvsdbTable::INTERFACE, tableState);
            }
        } else if (!payload.ObjectEmpty()) {
            LOG(WARNING) << "Unhandled monitor";
        }
    }
    decrSyncMsgsRemaining();
}

void OvsdbConnection::handleMonitorError(uint64_t reqId, const Document& payload) {
    if (payload.HasMember("error")) {
        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        payload.Accept(writer);
        LOG(WARNING) << "Received error response for reqId " << reqId << " - " << buffer.GetString();
    } else {
        LOG(WARNING) << "Received error response with no error element";
    }
}

void OvsdbConnection::handleUpdate(const Document& payload) {
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    payload.Accept(writer);
    if (payload.IsArray()) {
        if (payload[0].IsString()) {
            if (payload[1].IsObject()) {
                if (payload[1].HasMember(OvsdbMessage::toString(OvsdbTable::BRIDGE))) {
                    LOG(DEBUG) << "OVSDB update for bridge table";
                    const Value& value = payload[1][OvsdbMessage::toString(OvsdbTable::BRIDGE)];
                    if (value.IsObject()) {
                        for (Value::ConstMemberIterator itr = value.MemberBegin();
                             itr != value.MemberEnd(); ++itr) {
                            string rowUuid = itr->name.GetString();
                            LOG(DEBUG) << "bridge uuid " << rowUuid;
                            OvsdbRowDetails rowDetails;
                            rowDetails["uuid"] = OvsdbValue(rowUuid);
                            bool addRow = processRowUpdate(itr->value, rowDetails);
                            if (addRow) {
                                LOG(DEBUG) << "received updated row for bridge " << rowUuid;
                                getOvsdbState().updateRow(OvsdbTable::BRIDGE, rowUuid, rowDetails);
                            } else {
                                LOG(DEBUG) << "received deleted row for bridge " << rowUuid;
                                getOvsdbState().deleteRow(OvsdbTable::BRIDGE, rowUuid);
                            }
                        }
                    }
                } else if (payload[1].HasMember(OvsdbMessage::toString(OvsdbTable::MIRROR))) {
                    LOG(DEBUG) << "OVSDB update for mirror table";
                    const Value& value = payload[1][OvsdbMessage::toString(OvsdbTable::MIRROR)];
                    if (value.IsObject()) {
                        for (Value::ConstMemberIterator itr = value.MemberBegin();
                             itr != value.MemberEnd(); ++itr) {
                            string rowUuid = itr->name.GetString();
                            LOG(DEBUG) << "mirror uuid " << rowUuid;
                            OvsdbRowDetails rowDetails;
                            rowDetails["uuid"] = OvsdbValue(rowUuid);
                            bool addRow = processRowUpdate(itr->value, rowDetails);
                            if (addRow) {
                                LOG(DEBUG) << "received updated row for mirror " << rowUuid;
                                getOvsdbState().updateRow(OvsdbTable::MIRROR, rowUuid, rowDetails);
                            } else {
                                LOG(DEBUG) << "received deleted row for mirror " << rowUuid;
                                getOvsdbState().deleteRow(OvsdbTable::MIRROR, rowUuid);
                            }
                        }
                    }
                } else if (payload[1].HasMember(OvsdbMessage::toString(OvsdbTable::IPFIX))) {
                    LOG(DEBUG) << "OVSDB update for ipfix table";
                    const Value& value = payload[1][OvsdbMessage::toString(OvsdbTable::IPFIX)];
                    if (value.IsObject()) {
                        for (Value::ConstMemberIterator itr = value.MemberBegin();
                             itr != value.MemberEnd(); ++itr) {
                            string rowUuid = itr->name.GetString();
                            LOG(DEBUG) << "ipfix uuid " << rowUuid;
                            OvsdbRowDetails rowDetails;
                            rowDetails["uuid"] = OvsdbValue(rowUuid);
                            bool addRow = processRowUpdate(itr->value, rowDetails);
                            if (addRow) {
                                LOG(DEBUG) << "received updated row for ipfix " << rowUuid;
                                getOvsdbState().updateRow(OvsdbTable::IPFIX, rowUuid, rowDetails);
                            } else {
                                LOG(DEBUG) << "received deleted row for ipfix " << rowUuid;
                                getOvsdbState().deleteRow(OvsdbTable::IPFIX, rowUuid);
                            }
                        }
                    }
                } else if (payload[1].HasMember(OvsdbMessage::toString(OvsdbTable::NETFLOW))) {
                    LOG(DEBUG) << "OVSDB update for netflow table";
                    const Value& value = payload[1][OvsdbMessage::toString(OvsdbTable::NETFLOW)];
                    if (value.IsObject()) {
                        for (Value::ConstMemberIterator itr = value.MemberBegin();
                             itr != value.MemberEnd(); ++itr) {
                            string rowUuid = itr->name.GetString();
                            LOG(DEBUG) << "netflow uuid " << rowUuid;
                            OvsdbRowDetails rowDetails;
                            rowDetails["uuid"] = OvsdbValue(rowUuid);
                            bool addRow = processRowUpdate(itr->value, rowDetails);
                            if (addRow) {
                                LOG(DEBUG) << "received updated row for netflow " << rowUuid;
                                getOvsdbState().updateRow(OvsdbTable::NETFLOW, rowUuid, rowDetails);
                            } else {
                                LOG(DEBUG) << "received deleted row for netflow " << rowUuid;
                                getOvsdbState().deleteRow(OvsdbTable::NETFLOW, rowUuid);
                            }
                        }
                    }
                } else if (payload[1].HasMember(OvsdbMessage::toString(OvsdbTable::PORT))) {
                    LOG(DEBUG) << "OVSDB update for port table";
                    const Value& value = payload[1][OvsdbMessage::toString(OvsdbTable::PORT)];
                    if (value.IsObject()) {
                        for (Value::ConstMemberIterator itr = value.MemberBegin();
                             itr != value.MemberEnd(); ++itr) {
                            string rowUuid = itr->name.GetString();
                            LOG(DEBUG) << "port uuid " << rowUuid;
                            OvsdbRowDetails rowDetails;
                            rowDetails["uuid"] = OvsdbValue(rowUuid);
                            bool addRow = processRowUpdate(itr->value, rowDetails);
                            if (addRow) {
                                LOG(DEBUG) << "received updated row for port " << rowUuid;
                                getOvsdbState().updateRow(OvsdbTable::PORT, rowUuid, rowDetails);
                            } else {
                                LOG(DEBUG) << "received deleted row for port " << rowUuid;
                                getOvsdbState().deleteRow(OvsdbTable::PORT, rowUuid);
                            }
                        }
                    }
                } else if (payload[1].HasMember(OvsdbMessage::toString(OvsdbTable::INTERFACE))) {
                    LOG(DEBUG) << "OVSDB update for interface table";
                    const Value& value = payload[1][OvsdbMessage::toString(OvsdbTable::INTERFACE)];
                    if (value.IsObject()) {
                        for (Value::ConstMemberIterator itr = value.MemberBegin();
                             itr != value.MemberEnd(); ++itr) {
                            string rowUuid = itr->name.GetString();
                            LOG(DEBUG) << "interface uuid " << rowUuid;
                            OvsdbRowDetails rowDetails;
                            rowDetails["uuid"] = OvsdbValue(rowUuid);
                            bool addRow = processRowUpdate(itr->value, rowDetails);
                            if (addRow) {
                                LOG(DEBUG) << "received updated row for interface " << rowUuid;
                                getOvsdbState().updateRow(OvsdbTable::INTERFACE, rowUuid, rowDetails);
                            } else {
                                LOG(DEBUG) << "received deleted row for interface " << rowUuid;
                                getOvsdbState().deleteRow(OvsdbTable::INTERFACE, rowUuid);
                            }
                        }
                    }
                }
            } else {
                LOG(WARNING) << "second elem is not an array";
            }
        } else {
            LOG(WARNING) << "first element in array is not a string";
        }
    } else {
        LOG(WARNING) << "Payload is not an array";
    }
}

void OvsdbConnection::messagesReady() {
    uv_async_send(&writeq_async);
}

}
