/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for PacketLogHandler class
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include "PacketLogHandler.h"
#include "PacketDecoderLayers.h"
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/optional/optional_io.hpp>
#include "IntFlowManager.h"
#include <atomic>
#include <thread>
#include <chrono>

namespace opflexagent {

typedef ParseInfoMetaType PIM;

void LocalClient::run() {
    boost::asio::local::stream_protocol::endpoint invalidEndpoint("");
    if(remoteEndpoint==invalidEndpoint) {
        return;
    }
    LOG(INFO) << "PacketEventExporter started!";
    for(;;) {
        if(stopped) {
            boost::system::error_code ec;
            clientSocket.shutdown(
		    boost::asio::local::stream_protocol::socket::shutdown_both);
            clientSocket.cancel(ec);
            clientSocket.close(ec);
            break;
        }
        if(!connected) {
            try {
                clientSocket.connect(remoteEndpoint);
                connected = true;
                LOG(INFO) << "Connected to packet event exporter socket";
            } catch (std::exception &e) {
                LOG(TRACE) << "Failed to connect to packet event exporter socket:"
                        << e.what();
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }
        {
            std::unique_lock<std::mutex> lk(pktLogger.qMutex);
            pktLogger.cond.wait_for(lk, std::chrono::seconds(1),
                    [this](){return !this->pktLogger.packetTupleQ.empty();});
            if(!pktLogger.packetTupleQ.empty()) {
                StringBuffer buffer;
                Writer<StringBuffer> writer(buffer);
                unsigned event_count = 0;
                writer.StartArray();
                while((event_count < maxEventsPerBuffer) &&
                        !pktLogger.packetTupleQ.empty()) {
                    PacketTuple p = pktLogger.packetTupleQ.front();
                    p.serialize(writer);
                    pktLogger.packetTupleQ.pop();
                    event_count++;
                }
                writer.EndArray();
                pendingDataLen = (buffer.GetSize()>PACKET_EVENT_BUFFER_SIZE)? PACKET_EVENT_BUFFER_SIZE: buffer.GetSize();
                memcpy(send_buffer.data(), buffer.GetString(),
                        pendingDataLen);
            }
        }
        if(pendingDataLen>0) {
            try {
                (void)boost::asio::write(clientSocket,
                        boost::asio::buffer(send_buffer, pendingDataLen));
                pendingDataLen = 0;
            } catch (boost::system::system_error &bse ) {
                LOG(ERROR) << "Failed to write to socket " << bse.what();
                if(bse.code() !=
                   boost::system::errc::resource_unavailable_try_again) {
                    boost::system::error_code ec;
                    clientSocket.cancel(ec);
                    clientSocket.close(ec);
                    connected = false;
                }
                /*TODO: deserialize and requeue events*/
            }
        }
    }
}

bool PacketLogHandler::startListener()
{
    try {
        socketListener.reset(new UdpServer(*this, server_io, addr, port));
    } catch (boost::system::system_error& e) {
        LOG(ERROR) << "Could not bind to socket: "
                     << e.what();
        return false;
    }
    pktDecoder.configure();
    if(!socketListener->startListener()) {
        return false;
    }
    socketListener->startReceive();
    LOG(INFO) << "PacketLogHandler started!";
    return true;
}

bool PacketLogHandler::startExporter()
{
    try {
        exporter.reset(new LocalClient(*this, client_io,
                packetEventNotifSock));
    } catch (boost::system::system_error& e) {
        LOG(ERROR) << "Could not create local client socket: "
                     << e.what();
        return false;
    }
    exporter->run();
    return true;
}

void PacketLogHandler::stopListener()
{
    LOG(INFO) << "PacketLogHandler stopped";
    if(socketListener) {
        socketListener->stop();
    }
    server_io.stop();
}

void PacketLogHandler::stopExporter()
{
    LOG(INFO) << "Exporter stopped";
    if(exporter) {
        exporter->stop();
    }
}

void UdpServer::handleReceive(const boost::system::error_code& error,
      std::size_t bytes_transferred) {

    if (!error || error == boost::asio::error::message_size)
    {
        uint32_t length = (bytes_transferred > PACKET_CAPTURE_BUFFER_SIZE) ?
            PACKET_CAPTURE_BUFFER_SIZE: bytes_transferred;
        this->pktLogger.parseLog(recv_buffer.data(), length);
    }
    if(!stopped) {
        startReceive();
    }
}

bool PacketLogHandler::getDropReason(ParseInfo &p, std::string &dropReason) {
    bool isPermit=false;
    std::string bridge = ((p.meta[PIM::SOURCE_BRIDGE] ==1)? "Int-" :
            ((p.meta[PIM::SOURCE_BRIDGE] ==2)? "Acc-" :""));
    if((p.meta[PIM::SOURCE_BRIDGE] == 1) &&
            (intTableDescMap.find(p.meta[PIM::TABLE_ID])!= intTableDescMap.end())) {
        dropReason = bridge + intTableDescMap[p.meta[PIM::TABLE_ID]].first;
    } else if((p.meta[PIM::SOURCE_BRIDGE] == 2) &&
            (accTableDescMap.find(p.meta[PIM::TABLE_ID]) != accTableDescMap.end())) {
        dropReason = bridge + accTableDescMap[p.meta[PIM::TABLE_ID]].first;
    }

    switch(p.meta[PIM::CAPTURE_REASON]) {
        case 0:
        {
            dropReason += " MISS";
            break;
        }
        case 1:
        {
            dropReason += " DENY";
            break;
        }
        case 2:
        {
            dropReason += " PERMIT";
            isPermit = true;
            break;
        }
    }
    if((p.meta[PIM::CAPTURE_REASON] == 1) || (p.meta[PIM::CAPTURE_REASON]==2)) {
        boost::optional<std::string> ruleUri  = idGen.getStringForId((
            IntFlowManager::getIdNamespace(L24Classifier::CLASS_ID)),
            p.meta[PIM::POLICY_TRIGGERED_DROP]);

        if (ruleUri) {
            dropReason += " "+ruleUri.get();
        }
    }
    
    if(endpointTenantMap.shouldPrintTenant == false) return isPermit;

    std::string sourceTenant = endpointTenantMap.GetMapping(p.meta[PIM::SOURCE_EPG]);
    std::string destinationTenant = endpointTenantMap.GetMapping(p.meta[PIM::DESTINATION_EPG]);
    if(sourceTenant.empty()) sourceTenant = "N/A";
    if(destinationTenant.empty()) destinationTenant = "N/A";
    dropReason += " "+sourceTenant;
    dropReason += " "+destinationTenant;
    return isPermit;
}

void PacketLogHandler::updatePruneFilter(const std::string &filterName, std::shared_ptr<PacketFilterSpec> &pruneSpec) {
    std::lock_guard<std::mutex> lk(pruneMutex);
    userPruneSpec[filterName] = pruneSpec;
}

void PacketLogHandler::deletePruneFilter(const std::string &filterName) {
    std::lock_guard<std::mutex> lk(pruneMutex);
    userPruneSpec.erase(filterName);
}

void PacketLogHandler::pruneLog(ParseInfo &p) {
    for( auto &pruneSpec : defaultPruneSpec) {
        if(pruneSpec.compareTuple(p.packetTuple,*p.pktDecoder)) {
            p.pruneLog = true;
            return;
        }
    }
    { 
        std::lock_guard<std::mutex> lk(pruneMutex);
        for( auto &pruneSpec : userPruneSpec) {
            if(pruneSpec.second->compareTuple(p.packetTuple,*p.pktDecoder)) {
                p.pruneLog = true;
                return;
            }
        }
    }
    p.pruneLog = false;
}

void PacketLogHandler::parseLog(unsigned char *buf , std::size_t length) {
/* Skip printing Geneve Header and Options*/
#define PACKET_DUMP_OFFSET 132
/*Typical length of Packet is TCP ACK 40 Bytes*/
#define PACKET_DUMP_LEN   50
#define PACKET_DUMP_REQUIRED_LEN 232
    ParseInfo p(&pktDecoder);
    int ret = pktDecoder.decode(buf, length, p);
    if(ret) {
        LOG(DEBUG) << "Error parsing packet " << ret;
        std::stringstream str;
        int maxPrintLen = (length <= PACKET_DUMP_REQUIRED_LEN)? length: PACKET_DUMP_LEN;
        for(int i =0; i < maxPrintLen; i++) {
            if(i%32 == 0){
                str << std::endl;
            }
            if(length <= PACKET_DUMP_REQUIRED_LEN) {
                str << std::hex << (uint32_t)buf[i] << " ";
            } else {
                str << std::hex << (uint32_t)buf[PACKET_DUMP_OFFSET+i] << " ";
            }
        }
        LOG(DEBUG) << str.str();
    } else {
        pruneLog(p);
        if(p.pruneLog)
            return;
        std::string dropReason,dropLogMsg;
        bool isPermit = getDropReason(p, dropReason);
        p.packetTuple.setField(0, dropReason);
        dropLogMsg = dropReason + " " + p.parsedString;
        if(!opflexagent::isDropLogConsoleSink()) {
            DROPLOG(dropLogMsg);
        } else {
            LOG(INFO)<< dropLogMsg;
        }
        if(!packetEventNotifSock.empty() && !isPermit )
        {
            {
                std::lock_guard<std::mutex> lk(qMutex);
                if(packetTupleQ.size() < maxOutstandingEvents) {
                    if(throttleActive) {
                        LOG(DEBUG) << "Queueing packet events";
                        throttleActive = false;
                    }
                    packetTupleQ.push(p.packetTuple);
                    if(packetTupleQ.size()  == maxOutstandingEvents) {
                        LOG(DEBUG) << "Max Event queue size ("
                                   << maxOutstandingEvents
                                   << ") throttling packet events";
                        throttleActive = true;
                    }
                }
            }
            cond.notify_one();
        }
    }
}

}
