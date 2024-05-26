/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for PacketLogHandler
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#include <thread>
#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/array.hpp>
#include <boost/bind.hpp>
#include <opflexagent/logging.h>
#include <opflexagent/IdGenerator.h>
#include <opflexagent/EndpointTenantMapper.h>
#include "PacketDecoderLayers.h"
#include <opflexagent/Network.h>
#include <mutex>
#include <condition_variable>
#include <queue>

#pragma once
#ifndef OPFLEXAGENT_PACKETLOGHANDLER_H_
#define OPFLEXAGENT_PACKETLOGHANDLER_H_

#define PACKET_EVENT_BUFFER_SIZE 8192
#define PACKET_CAPTURE_BUFFER_SIZE 12288
namespace opflexagent {

class PacketLogHandler;

/**
 * Class to listen on the given UDP port
 */
class UdpServer
{
public:
    /**
     * Constructor for UDP listener
     * @param logHandler reference to the parent LogHandler
     * @param io_service_ reference to IO service to handle UDP
     * @param addr IP address to listen on
     * @param port listener UDP port
     */
    UdpServer(PacketLogHandler &logHandler,
            boost::asio::io_service& io_service_,
               boost::asio::ip::address &addr, uint16_t port)
    : pktLogger(logHandler), serverSocket(io_service_),
            localEndpoint(addr, port), stopped(false) {
    }
    /**
     * Start UDP listener
     * @return true if bind succeeded
     */
    bool startListener() {
        boost::system::error_code ec;
        serverSocket.open(localEndpoint.protocol());
        boost::asio::socket_base::reuse_address option(true);
        serverSocket.set_option(boost::asio::socket_base::reuse_address(true),
			ec);
        if(ec) {
            LOG(ERROR) << "Failed to set SO_REUSE: " << ec;
            ec=make_error_code(boost::system::errc::success);
        }
        serverSocket.bind(localEndpoint, ec);
        if(ec) {
            LOG(ERROR) << "Failed to bind " << ec;
        }
        return !(ec);
    }
    /**
     * Start UDP receive
     */
    void startReceive() {
        serverSocket.async_receive_from(
            boost::asio::buffer(recv_buffer, PACKET_CAPTURE_BUFFER_SIZE), remoteEndpoint,
            boost::bind(&UdpServer::handleReceive, this,
              boost::asio::placeholders::error,
              boost::asio::placeholders::bytes_transferred));
    }
    /**
     * Stop UDP listener
     */
    void stop() {
        boost::system::error_code ec;
        stopped = true;
        try {
            serverSocket.shutdown(boost::asio::ip::udp::socket::shutdown_both);
        } catch (const std::runtime_error& e) {
            LOG(WARNING) << "Packetlogger failed to shutdown UDP socket: " << e.what();
        }
        try {
            serverSocket.cancel(ec);
        } catch (const std::runtime_error& e) {
            LOG(WARNING) << "Packetlogger failed to cancel UDP socket: " << e.what();
        }
        try {
            serverSocket.close(ec);
        } catch (const std::runtime_error& e) {
            LOG(WARNING) << "Packetlogger failed to close UDP socket: " << e.what();
        }
   }
private:
    /**
     * Handle received UDP packets
     */
    void handleReceive(const boost::system::error_code& error,
      std::size_t bytes_transferred);
    PacketLogHandler &pktLogger;
    boost::asio::ip::udp::socket serverSocket;
    boost::asio::ip::udp::endpoint localEndpoint;
    boost::asio::ip::udp::endpoint remoteEndpoint;
    boost::array<unsigned char, PACKET_CAPTURE_BUFFER_SIZE> recv_buffer;
    std::atomic<bool> stopped;
};

/**
 * Class to connect to a given local socket
 */
class LocalClient
{
public:
    /**
     * Constructor for Local client
     * @param logHandler reference to the parent LogHandler
     * @param client_io io_service instance for client socket
     * @param socketFileName Path of the local socket-file
     */
    LocalClient(PacketLogHandler &logHandler,
            boost::asio::io_service &client_io,
            const std::string &socketFileName)
        : pktLogger(logHandler), clientSocket(client_io),
          remoteEndpoint(socketFileName), stopped(false),
          connected(false), pendingDataLen(0) {
        LOG(INFO) << "Packet Event socket set to " << socketFileName;
    }
    /**
     * Connect to a given local socket and export events
     */
    void run();
    /**
     * Stop Local socket
     */
    void stop() {
        stopped = true;
    }

private:
    PacketLogHandler &pktLogger;
    boost::asio::local::stream_protocol::socket clientSocket;
    boost::asio::local::stream_protocol::endpoint remoteEndpoint;
    boost::array<unsigned char, PACKET_EVENT_BUFFER_SIZE> send_buffer;
    std::atomic<bool> stopped;
    bool connected;
    unsigned pendingDataLen;
    static const unsigned maxEventsPerBuffer=10;
};

class PacketFilterSpec: public PacketTuple {
public:
    PacketFilterSpec():PacketTuple() {
        int field_count = fields.size();
        fields.insert(std::make_pair(field_count++,
                std::make_pair("SourceMacMask", "")));
        fields.insert(std::make_pair(field_count++,
                std::make_pair("DestinationMacMask", "")));
        fields.insert(std::make_pair(field_count++,
                std::make_pair("SourceIPPrefixLength", "")));
        fields.insert(std::make_pair(field_count++,
                std::make_pair("DestinationIPPrefixLength", "")));
    }
    /**
     * Compare Macs with mask
     * @param mac1: Mac address 1
     * @param mac2: Mac address 2
     * @param mask: mask for comparison
     * @return whether matched(true) or not(false)
     * */
    static bool compareMacs(const std::string &mac1, const std::string &mac2, const std::string &mask) {
        opflex::modb::MAC m1(mac1),m2(mac2);
        uint8_t m1Bytes[6],m2Bytes[6];
        m1.toUIntArray(m1Bytes);
        m2.toUIntArray(m2Bytes);
        uint8_t maskBytes[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        if(!mask.empty()) {
            opflex::modb::MAC macMask(mask);
            macMask.toUIntArray(maskBytes);
        }
        for(int i=0;i<6;i++) {
            m1Bytes[i] &= maskBytes[i];
            m2Bytes[i] &= maskBytes[i];
            if(m1Bytes[i] != m2Bytes[i]) {
                return false;
            }
        }
        return true;
    }
    /**
     * Compare IP addresses with mask
     * @param ip1: Ip address 1
     * @param ip2: Ip address 2
     * @param prefixLen: prefix length for comparison
     * @return whether matched(true) or not(false)
     * */
    static bool compareIps(const std::string &ip1, const std::string &ip2, const std::string &prefixLen) {
        using boost::asio::ip::address;
        if (ip1.empty() || ip2.empty()) {
            return false;
        }
        boost::system::error_code ec;
        address addr1 = address::from_string(ip1,ec);
        if (ec){
                return false;
        }
        address addr2 = address::from_string(ip2,ec);
        if (ec){
                return false;
        }
        if(addr1.is_v4() != addr2.is_v4()) {
            return false;
        }
        bool is_v4 = addr1.is_v4();
        bool is_exact_match;
        uint32_t pfxLen;
        if(is_v4) {
            pfxLen = 32;
        } else {
            pfxLen = 128;
        }
        if(!prefixLen.empty()) {
            pfxLen = stoul(prefixLen);
        }
        if((pfxLen > 32) || (pfxLen == 0))
           return false;
        return network::prefix_match( addr1, pfxLen,
                                 addr2, pfxLen, is_exact_match);

    }
    bool compareTuple(PacketTuple &p, PacketDecoder &decoder) {
        std::vector<int> named_match_fields {TFLD_ETH_TYPE, TFLD_IP_PROTO, TFLD_SPORT, TFLD_DPORT};
        std::vector<std::string> base_layer_names {"EProto", "IPProto",
                                                "",""};
        auto base_layer_itr = base_layer_names.begin();
        for (auto &i:named_match_fields) {
            if(!fields[i].second.empty()) {
                /*First try a direct match*/
                if((fields[i].second != p.fields[i].second) &&
                   (fields[i].second+"_unrecognized" != p.fields[i].second)) {
                    uint32_t typeId;
                    std::string layerName;
                    /* Try a name mapping for the protocol number.
                     * Packet Tuple will have the mapping always if known*/
                    if(!(*base_layer_itr).empty() &&
                       ((typeId = decoder.getLayerTypeIdByTypeName(*base_layer_itr))!= 0) &&
                       decoder.getLayerNameByTypeKey(typeId,strtol(fields[i].second.c_str(),NULL,10),layerName) &&
                       (layerName == p.fields[i].second)) {
                        base_layer_itr++;
                        continue;
                    }
                    return false;
                }
            }
            base_layer_itr++;
        }

        std::vector<int> mac_fields {TFLD_SRC_MAC, TFLD_DST_MAC};
        for (auto &i:mac_fields) {
            if(!fields[i].second.empty()) {
                if(!compareMacs(fields[i].second,p.fields[i].second,
                            fields[i+8].second)) {
                    return false;
                }
            }
        }
        std::vector<int> ip_fields {TFLD_SRC_IP, TFLD_DST_IP};
        for (auto &i:ip_fields) {
            if(!fields[i].second.empty()) {
                if(!compareIps(fields[i].second,p.fields[i].second,
                            fields[i+8].second)) {
                    return false;
                }
            }
        }
        return true;
    }
};

/**
 * Class to hold the UDP listener and the packet decoder
 */
class PacketLogHandler {
public:
    /**
     * Constructor for PacketLogHandler
     * @param _io reference to IO service to handle server
     * @param _clientio reference to IO service to handle client
     */
    PacketLogHandler(boost::asio::io_service &_io,
            boost::asio::io_service &_clientio, IdGenerator& idGen_,
            EndpointTenantMapper &_endpointTenantMapper):server_io(_io),
            client_io(_clientio), port(0), stopped(false), throttleActive(false), idGen(idGen_),
            endpointTenantMap(_endpointTenantMapper) {
                /*Prune unused control packets by default*/
                #define LLDP_MAC "01:80:c2:00:00:0e"
                #define MCAST_V6_MAC "33:33:00:00:00:00"
                #define MCAST_MASK "FF:FF:00:00:00:00"
                #define IP_PROTO_IGMP "2"
                #define IP_PROTO_ICMPv6 "58"
                #define IP_PROTO_UDP "17"
                #define MDNS_PORT "5353"
                #define V6_HOP_BY_HOP "0"
                #define MDNS_IPV4 "224.0.0.251"
                #define pushPruneSpec() defaultPruneSpec.push_back(unusedCtrlPacket); unusedCtrlPacket.clear();
                PacketFilterSpec unusedCtrlPacket;
                unusedCtrlPacket.setField(TFLD_DST_MAC, LLDP_MAC);
                pushPruneSpec()
                unusedCtrlPacket.setField(TFLD_IP_PROTO, IP_PROTO_IGMP);
                pushPruneSpec()
                unusedCtrlPacket.setField(TFLD_IP_PROTO, IP_PROTO_ICMPv6);
                unusedCtrlPacket.setField(TFLD_DST_MAC, MCAST_V6_MAC);
                unusedCtrlPacket.setField(TFLD_DMAC_MASK, MCAST_MASK);
                pushPruneSpec()
                unusedCtrlPacket.setField(TFLD_DPORT, MDNS_PORT);
                unusedCtrlPacket.setField(TFLD_IP_PROTO, IP_PROTO_UDP);
                unusedCtrlPacket.setField(TFLD_DST_MAC, MCAST_V6_MAC);
                unusedCtrlPacket.setField(TFLD_DMAC_MASK, MCAST_MASK);
                pushPruneSpec()
                unusedCtrlPacket.setField(TFLD_IP_PROTO, V6_HOP_BY_HOP);
                unusedCtrlPacket.setField(TFLD_DST_MAC, MCAST_V6_MAC);
                unusedCtrlPacket.setField(TFLD_DMAC_MASK, MCAST_MASK);
                pushPruneSpec()
                unusedCtrlPacket.setField(TFLD_DPORT, MDNS_PORT);
                unusedCtrlPacket.setField(TFLD_SPORT, MDNS_PORT);
                unusedCtrlPacket.setField(TFLD_IP_PROTO, IP_PROTO_UDP);
                unusedCtrlPacket.setField(TFLD_DST_IP, MDNS_IPV4);
                pushPruneSpec()
    }
    /**
     * set IPv4 listening address for the socket
     * @param _addr IPv4 address
     * @param _port UDP port number
     */
    void setAddress(boost::asio::ip::address &_addr, uint16_t _port=6081)
    { port = _port; addr = _addr; }
    /**
     * set socketfile path for the unix client socket
     * @param sockfilePath file system path for notification socket
     */
    void setNotifSock(const std::string &sockfilePath)
    { packetEventNotifSock = sockfilePath; }

    /**
     * Map of table_id to (Table name, Drop Reason) for use by
     * table drop counters. Redefining here as the original definition
     * is in a datapath specific include file
     */
    typedef std::unordered_map<unsigned, std::pair<std::string,std::string>>
                TableDescriptionMap;
    /**
     * Set Integration bridge table description map
     * @param tableDesc table description map
     */
    void setIntBridgeTableDescription(TableDescriptionMap &tableDesc)
    { intTableDescMap = tableDesc; }
    /**
     * Set Access bridge table description map
     * @param tableDesc table description map
     */
    void setAccBridgeTableDescription(TableDescriptionMap &tableDesc)
    { accTableDescMap = tableDesc; }
    /**
     * Start packet logging
     */
    virtual bool startListener();
    /**
     * Start exporter
     */
    bool startExporter();
    /**
     * Stop packet logging
     */
    void stopListener();
    /**
     * Stop exporter
     */
    void stopExporter();
    /**
     * extract drop reason from parsedInfo
     * @param p Parsing context
     * @param dropReason extracted drop reason
     * @return true if this is a permit log
     */
    bool getDropReason(ParseInfo &p, std::string &dropReason);
    /**
     * Call packet decoder as an async callback
     * @param buf packet buffer
     * @param length total length of packet
     */
    void parseLog(unsigned char *buf , std::size_t length);
    /**
     * Prune logs based on config
     * @param p Parsing context
     */
    void pruneLog(ParseInfo &p);
    /**
     * Update user configured prune filters
     * @param filterName Filter name
     * @param pruneSpec Pruning spec
     */
    void updatePruneFilter(const std::string &filterName,
            std::shared_ptr<PacketFilterSpec> &pruneSpec);
    /**
     * Delete user configured prune filters
     * @param filterName Filter name
     */
    void deletePruneFilter(const std::string &filterName);

protected:
    ///@{
    /** Member names are self-explanatory */
    boost::asio::io_service &server_io;
    boost::asio::io_service &client_io;
    std::unique_ptr<UdpServer> socketListener;
    std::unique_ptr<LocalClient> exporter;
    PacketDecoder pktDecoder;
    boost::asio::ip::address addr;
    std::string packetEventNotifSock;
    uint16_t port;
    bool stopped;
    std::mutex qMutex;
    std::mutex pruneMutex;
    std::condition_variable cond;
    std::queue<PacketTuple> packetTupleQ;
    bool throttleActive;
    TableDescriptionMap intTableDescMap, accTableDescMap;
    static const unsigned maxOutstandingEvents=30;
    friend UdpServer;
    friend LocalClient;
    IdGenerator& idGen;
    EndpointTenantMapper& endpointTenantMap;
    std::vector<PacketFilterSpec> defaultPruneSpec;
    std::unordered_map<std::string, std::shared_ptr<PacketFilterSpec>> userPruneSpec;
    ///@}
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_PACKETLOGHANDLER_H */
