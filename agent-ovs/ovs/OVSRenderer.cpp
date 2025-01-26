/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for OVSRenderer class
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include "OVSRenderer.h"
#include <opflexagent/logging.h>
#include <sstream>
#include <boost/asio/placeholders.hpp>
#include <openvswitch/vlog.h>

namespace opflexagent {

using std::bind;
using opflex::ofcore::OFFramework;
using boost::property_tree::ptree;
using boost::asio::deadline_timer;
using boost::asio::placeholders::error;

static const std::string ID_NMSPC_CONNTRACK("conntrack");
static const boost::posix_time::milliseconds CLEANUP_INTERVAL(3*60*1000);

#define PACKET_LOGGER_PIDDIR LOCALSTATEDIR"/lib/opflex-agent-ovs/pids"
#define LOOPBACK "127.0.0.1"

OVSRendererPlugin::OVSRendererPlugin() {
    /* No good way to redirect OVS logs to our logs, suppress them for now */
    vlog_set_levels(NULL, VLF_ANY_DESTINATION, VLL_OFF);
}

std::unordered_set<std::string> OVSRendererPlugin::getNames() const {
    return {"stitched-mode", "openvswitch"};
}

Renderer* OVSRendererPlugin::create(Agent& agent) const {
    return new OVSRenderer(agent);
}

OVSRenderer::OVSRenderer(Agent& agent_)
    : Renderer(agent_), ctZoneManager(idGen),
      intSwitchManager(agent_, intFlowExecutor, intFlowReader,
                       intPortMapper),
      tunnelEpManager(&agent_),
      intFlowManager(agent_, intSwitchManager, idGen,
                     ctZoneManager, tunnelEpManager),
      accessSwitchManager(agent_, accessFlowExecutor,
                          accessFlowReader, accessPortMapper),
      accessFlowManager(agent_, accessSwitchManager, idGen, ctZoneManager),
      endpointTenantMapper(&agent_, &accessSwitchManager, agent_.getAgentIOService()),
      pktInHandler(agent_, intFlowManager, dnsManager),
      interfaceStatsManager(&agent_, intSwitchManager.getPortMapper(),
                            accessSwitchManager.getPortMapper()),
      contractStatsManager(&agent_, idGen, intSwitchManager),
      serviceStatsManager(&agent_, idGen, intSwitchManager,
                           intFlowManager),
      secGrpStatsManager(&agent_, idGen, accessSwitchManager),
      tableDropStatsManager(&agent_, idGen, intSwitchManager,
              accessSwitchManager),
      dnsManager(agent_),
      natStatsManager(&agent_, idGen, intSwitchManager, intFlowManager),

      encapType(IntFlowManager::ENCAP_NONE),
      tunnelRemotePort(0), uplinkVlan(0),
      virtualRouter(true), routerAdv(true),
      endpointAdvMode(AdvertManager::EPADV_GRATUITOUS_BROADCAST),
      tunnelEndpointAdvMode(AdvertManager::EPADV_RARP_BROADCAST),
      tunnelEndpointAdvIntvl(300),
      virtualDHCP(true), connTrack(true), ctZoneRangeStart(0),
      ctZoneRangeEnd(0), ovsdbUseLocalTcpPort(false), ifaceStatsEnabled(true), ifaceStatsInterval(0),
      contractStatsEnabled(true), contractStatsInterval(0),
      serviceStatsFlowDisabled(false), serviceStatsEnabled(true), serviceStatsInterval(0),
      secGroupStatsEnabled(true), secGroupStatsInterval(0),
      tableDropStatsEnabled(true), tableDropStatsInterval(0),
      natStatsEnabled(false), natStatsInterval(0),
      spanRenderer(agent_), netflowRendererIntBridge(agent_), netflowRendererAccessBridge(agent_),
      qosRenderer(agent_), started(false), dropLogRemotePort(6081), dropLogLocalPort(50000),
      pktLogger(pktLoggerIO, exporterIO, idGen, endpointTenantMapper)
{

}

OVSRenderer::~OVSRenderer() {

}

void OVSRenderer::start() {
    if (started) return;

    if (intBridgeName == "") {
        LOG(ERROR) << "OVS integration bridge name not set";
        return;
    }

    if (encapType == IntFlowManager::ENCAP_NONE)
        LOG(WARNING)
            << "No encapsulation type specified; only local traffic will work";
    if (flowIdCache == "")
        LOG(WARNING) << "No flow ID cache directory specified";
    if (mcastGroupFile == "")
        LOG(WARNING) << "No multicast group file specified";
    if (dnsCacheDir == "")
        LOG(WARNING) << "No DNS cached directory specified";

    started = true;
    LOG(INFO) << "Starting stitched-mode renderer using"
              << " integration bridge " << intBridgeName
              << " and access bridge "
              << (accessBridgeName == "" ? "[none]" : accessBridgeName);

    if (encapType == IntFlowManager::ENCAP_VXLAN ||
        encapType == IntFlowManager::ENCAP_IVXLAN) {
        tunnelEpManager.setUplinkIface(uplinkIface);
        tunnelEpManager.setUplinkVlan(uplinkVlan);
        tunnelEpManager.setParentRenderer(this);
        tunnelEpManager.start();
    }

    if (!flowIdCache.empty())
        idGen.setPersistLocation(flowIdCache);

    if (connTrack) {
        ctZoneManager.setCtZoneRange(ctZoneRangeStart, ctZoneRangeEnd);
        ctZoneManager.enableNetLink(true);
        ctZoneManager.init(ID_NMSPC_CONNTRACK);

        intFlowManager.enableConnTrack();
        accessFlowManager.enableConnTrack();
    }

    intFlowManager.setEncapType(encapType);
    intFlowManager.setEncapIface(encapIface);
    intFlowManager.setUplinkIface(uplinkNativeIface);
    intFlowManager.setFloodScope(IntFlowManager::ENDPOINT_GROUP);
    if (encapType == IntFlowManager::ENCAP_VXLAN ||
        encapType == IntFlowManager::ENCAP_IVXLAN) {
        assert(tunnelRemotePort != 0);
        intFlowManager.setTunnel(tunnelRemoteIp, tunnelRemotePort);
    }
    intFlowManager.setVirtualRouter(virtualRouter, routerAdv, virtualRouterMac);
    intFlowManager.setVirtualDHCP(virtualDHCP, virtualDHCPMac);
    intFlowManager.setMulticastGroupFile(mcastGroupFile);
    intFlowManager.setEndpointAdv(endpointAdvMode, tunnelEndpointAdvMode,
            tunnelEndpointAdvIntvl);
    if(!dropLogIntIface.empty()) {
        intFlowManager.setDropLog(dropLogIntIface, dropLogRemoteIp,
                dropLogRemotePort);
    }
    if(!dropLogAccessIface.empty()) {
        accessFlowManager.setDropLog(dropLogAccessIface, dropLogRemoteIp,
                        dropLogRemotePort);
    }

    intSwitchManager.registerStateHandler(&intFlowManager);
    intSwitchManager.start(intBridgeName);
    if (accessBridgeName != "") {
        accessSwitchManager.registerStateHandler(&accessFlowManager);
        accessSwitchManager.start(accessBridgeName);
    }
    intFlowManager.start(serviceStatsFlowDisabled, natStatsEnabled);
    intFlowManager.registerModbListeners();

    if (accessBridgeName != "") {
        accessFlowManager.start();
    }
    endpointTenantMapper.start();
    dnsManager.setCacheDir(dnsCacheDir);
    dnsManager.start();

    pktInHandler.registerConnection(intSwitchManager.getConnection(),
                                    (accessBridgeName != "")
                                    ? accessSwitchManager.getConnection()
                                    : NULL);
    pktInHandler.setPortMapper(&intSwitchManager.getPortMapper(),
                               (accessBridgeName != "")
                               ? &accessSwitchManager.getPortMapper()
                               : NULL);
    pktInHandler.setFlowReader(&intSwitchManager.getFlowReader());
    pktInHandler.start();

    if (ifaceStatsEnabled) {
        interfaceStatsManager.setTimerInterval(ifaceStatsInterval);
        interfaceStatsManager.
            registerConnection(intSwitchManager.getConnection(),
                               (accessBridgeName != "")
                               ? accessSwitchManager.getConnection()
                               : NULL);
        interfaceStatsManager.start();
    }
    if (contractStatsEnabled) {
        contractStatsManager.setTimerInterval(contractStatsInterval);
        contractStatsManager.setAgentUUID(getAgent().getUuid());
        contractStatsManager.
            registerConnection(intSwitchManager.getConnection());
        contractStatsManager.start();
    }
    if (serviceStatsEnabled) {
        serviceStatsManager.setTimerInterval(serviceStatsInterval);
        serviceStatsManager.setAgentUUID(getAgent().getUuid());
        serviceStatsManager.
            registerConnection(intSwitchManager.getConnection());
        serviceStatsManager.start();
    }
    if (secGroupStatsEnabled && accessBridgeName != "") {
        secGrpStatsManager.setTimerInterval(secGroupStatsInterval);
        secGrpStatsManager.setAgentUUID(getAgent().getUuid());
        secGrpStatsManager.
            registerConnection(accessSwitchManager.getConnection());
        secGrpStatsManager.start();
    }
    if (tableDropStatsEnabled) {
        tableDropStatsManager.setTimerInterval(tableDropStatsInterval);
        tableDropStatsManager.setAgentUUID(getAgent().getUuid());

        tableDropStatsManager.
            registerConnection(intSwitchManager.getConnection(),
                               (accessBridgeName != "")
                               ? accessSwitchManager.getConnection()
                               : NULL);
        tableDropStatsManager.start();
    }
    if (natStatsEnabled) {
        natStatsManager.setTimerInterval(natStatsInterval);
        natStatsManager.setAgentUUID(getAgent().getUuid());
        natStatsManager.registerConnection(intSwitchManager.getConnection());
        natStatsManager.start();
    }
    //Create any threads after starting the packet logger.
    //This is necessary so that fork works correctly. Fork
    //requires that no threads be active because files in the parent
    //process are duplicated as part of fork to the child process and
    //threads can hold resources while parent is forking
    startPacketLogger();

    intSwitchManager.connect();
    if (accessBridgeName != "") {
        accessSwitchManager.connect();
    }

    {
        const std::lock_guard<std::mutex> guard(timer_mutex);
        cleanupTimer.reset(new deadline_timer(getAgent().getAgentIOService()));
        cleanupTimer->expires_from_now(CLEANUP_INTERVAL);
        cleanupTimer->async_wait(bind(&OVSRenderer::onCleanupTimer,
                                      this, error));
    }

    ovsdbConnection.reset(new OvsdbConnection(ovsdbUseLocalTcpPort));
    ovsdbConnection->start();
    ovsdbConnection->connect();

    //Register with extraconfig manager for drop prune and out of band config handling
    getAgent().getExtraConfigManager().registerListener(this);

    if (getAgent().isFeatureEnabled(FeatureList::ERSPAN))
        spanRenderer.start(accessBridgeName, ovsdbConnection.get());
    netflowRendererIntBridge.start(intBridgeName, ovsdbConnection.get());
    netflowRendererAccessBridge.start(accessBridgeName, ovsdbConnection.get());
    qosRenderer.start(intBridgeName, ovsdbConnection.get());

}

void OVSRenderer::stop() {
    if (!started) return;
    started = false;

    LOG(DEBUG) << "Stopping stitched-mode renderer";

    {
        const std::lock_guard<std::mutex> guard(timer_mutex);
        if (cleanupTimer) {
            cleanupTimer->cancel();
        }
    }

    if (ifaceStatsEnabled)
        interfaceStatsManager.stop();
    if (serviceStatsEnabled)
        serviceStatsManager.stop();
    if (contractStatsEnabled)
        contractStatsManager.stop();
    if (secGroupStatsEnabled)
        secGrpStatsManager.stop();
    if(tableDropStatsEnabled)
        tableDropStatsManager.stop();
    if (natStatsEnabled)
        natStatsManager.stop();
    pktInHandler.stop();
    dnsManager.stop();
    intFlowManager.stop();
    accessFlowManager.stop();

    intSwitchManager.stop();
    accessSwitchManager.stop();
    endpointTenantMapper.stop();
    if (getAgent().isFeatureEnabled(FeatureList::ERSPAN))
        spanRenderer.stop();
    netflowRendererIntBridge.stop();
    netflowRendererAccessBridge.stop();
    qosRenderer.stop();
    ovsdbConnection->stop();

    if (encapType == IntFlowManager::ENCAP_VXLAN ||
        encapType == IntFlowManager::ENCAP_IVXLAN) {
        tunnelEpManager.stop();
    }
    stopPacketLogger();
}

#define DEF_FLOWID_CACHEDIR \
    LOCALSTATEDIR"/lib/opflex-agent-ovs/ids"
#define DEF_MCAST_GROUPFILE \
    LOCALSTATEDIR"/lib/opflex-agent-ovs/mcast/opflex-groups.json"
#define DEF_DNS_CACHEDIR \
    LOCALSTATEDIR"/lib/opflex-agent-ovs/dns"

void OVSRenderer::setProperties(const ptree& properties) {
    static const std::string OVS_BRIDGE_NAME("ovs-bridge-name");
    static const std::string INT_BRIDGE_NAME("int-bridge-name");
    static const std::string ACCESS_BRIDGE_NAME("access-bridge-name");

    static const std::string ENCAP_VXLAN("encap.vxlan");
    static const std::string ENCAP_IVXLAN("encap.ivxlan");
    static const std::string ENCAP_VLAN("encap.vlan");

    static const std::string UPLINK_NATIVE_IFACE("uplink-native-iface");
    static const std::string UPLINK_IFACE("uplink-iface");
    static const std::string UPLINK_VLAN("uplink-vlan");
    static const std::string ENCAP_IFACE("encap-iface");
    static const std::string REMOTE_IP("remote-ip");
    static const std::string REMOTE_PORT("remote-port");
    static const std::string LOCAL_PORT("local-port");
    static const std::string INT_BR_IFACE("int-br-iface");
    static const std::string ACC_BR_IFACE("access-br-iface");

    static const std::string VIRTUAL_ROUTER("forwarding"
                                            ".virtual-router.enabled");
    static const std::string VIRTUAL_ROUTER_MAC("forwarding"
                                                ".virtual-router.mac");

    static const std::string VIRTUAL_ROUTER_RA("forwarding.virtual-router"
                                               ".ipv6.router-advertisement");

    static const std::string VIRTUAL_DHCP("forwarding.virtual-dhcp.enabled");
    static const std::string VIRTUAL_DHCP_MAC("forwarding.virtual-dhcp.mac");

    static const std::string ENDPOINT_ADV("forwarding."
                                          "endpoint-advertisements.enabled");
    static const std::string ENDPOINT_ADV_MODE("forwarding."
                                               "endpoint-advertisements.mode");
    static const std::string ENDPOINT_TNL_ADV_MODE("forwarding."
                               "endpoint-advertisements.tunnel-endpoint-mode");
    static const std::string ENDPOINT_TNL_ADV_INTVL("forwarding."
                                   "endpoint-advertisements.tunnel-endpoint-interval");

    static const std::string FLOWID_CACHE_DIR("flowid-cache-dir");
    static const std::string MCAST_GROUP_FILE("mcast-group-file");
    static const std::string DNS_CACHE_DIR("dns-cache-dir");

    static const std::string CONN_TRACK("forwarding.connection-tracking."
                                        "enabled");
    static const std::string CONN_TRACK_RANGE_START("forwarding."
                                                    "connection-tracking."
                                                    "zone-range.start");
    static const std::string CONN_TRACK_RANGE_END("forwarding."
                                                  "connection-tracking."
                                                  "zone-range.end");

    static const std::string STATS_INTERFACE_ENABLED("statistics"
                                                     ".interface.enabled");
    static const std::string STATS_INTERFACE_INTERVAL("statistics"
                                                      ".interface.interval");
    static const std::string STATS_CONTRACT_ENABLED("statistics"
                                                    ".contract.enabled");
    static const std::string STATS_CONTRACT_INTERVAL("statistics"
                                                    ".contract.interval");
    static const std::string STATS_SERVICE_FLOWDISABLED("statistics"
                                                        ".service.flow-disabled");
    static const std::string STATS_SERVICE_ENABLED("statistics"
                                                  ".service.enabled");
    static const std::string STATS_SERVICE_INTERVAL("statistics"
                                                   ".service.interval");
    static const std::string STATS_SECGROUP_ENABLED("statistics"
                                                    ".security-group.enabled");
    static const std::string STATS_SECGROUP_INTERVAL("statistics"
                                                     ".security-group"
                                                     ".interval");
    static const std::string TABLE_DROP_STATS_ENABLED("statistics"
                                                      ".table-drop.enabled");
    static const std::string TABLE_DROP_STATS_INTERVAL("statistics"
                                                       ".table-drop.interval");
    static const std::string STATS_NAT_ENABLED("statistics"
                                               ".nat.enabled");
    static const std::string STATS_NAT_INTERVAL("statistics"
                                                ".nat.interval");
    static const std::string DROP_LOG_ENCAP_GENEVE("drop-log.geneve");
    static const std::string REMOTE_NAMESPACE("namespace");
    static const std::string OVSDB_USE_LOCAL_TCPPORT("ovsdb-use-local-tcp-port");

    intBridgeName =
        properties.get<std::string>(OVS_BRIDGE_NAME, "br-int");
    intBridgeName =
        properties.get<std::string>(INT_BRIDGE_NAME, intBridgeName);
    accessBridgeName =
        properties.get<std::string>(ACCESS_BRIDGE_NAME, "");

    boost::optional<const ptree&> ivxlan =
        properties.get_child_optional(ENCAP_IVXLAN);
    boost::optional<const ptree&> vxlan =
        properties.get_child_optional(ENCAP_VXLAN);
    boost::optional<const ptree&> vlan =
        properties.get_child_optional(ENCAP_VLAN);

    boost::optional<const ptree&> dropLogEncapGeneve =
            properties.get_child_optional(DROP_LOG_ENCAP_GENEVE);


    encapType = IntFlowManager::ENCAP_NONE;
    int count = 0;
    if (ivxlan) {
        LOG(ERROR) << "Encapsulation type ivxlan unsupported";
        count += 1;
    }
    if (vlan) {
        encapType = IntFlowManager::ENCAP_VLAN;
        encapIface = vlan.get().get<std::string>(ENCAP_IFACE, "");
        uplinkNativeIface = vlan.get().get<std::string>(UPLINK_NATIVE_IFACE, "");
        count += 1;
    }
    if (vxlan) {
        encapType = IntFlowManager::ENCAP_VXLAN;
        encapIface = vxlan.get().get<std::string>(ENCAP_IFACE, "");
        uplinkIface = vxlan.get().get<std::string>(UPLINK_IFACE, "");
        uplinkNativeIface = vxlan.get().get<std::string>(UPLINK_NATIVE_IFACE, "");
        uplinkVlan = vxlan.get().get<uint16_t>(UPLINK_VLAN, 0);
        tunnelRemoteIp = vxlan.get().get<std::string>(REMOTE_IP, "");
        tunnelRemotePort = vxlan.get().get<uint16_t>(REMOTE_PORT, 4789);
        count += 1;
    }

    if (count > 1) {
        LOG(WARNING) << "Multiple encapsulation types specified for "
                     << "stitched-mode renderer";
    }

    if(dropLogEncapGeneve) {
        dropLogIntIface = dropLogEncapGeneve.get().get<std::string>(INT_BR_IFACE, "");
        dropLogAccessIface = dropLogEncapGeneve.get().get<std::string>(ACC_BR_IFACE, "");
        dropLogRemoteIp = dropLogEncapGeneve.get().get<std::string>(REMOTE_IP, "192.168.1.2");
        dropLogRemotePort = dropLogEncapGeneve.get().get<uint16_t>(REMOTE_PORT, 6081);
        dropLogLocalPort = dropLogEncapGeneve.get().get<uint16_t>(LOCAL_PORT, 50000);
    }

    virtualRouter = properties.get<bool>(VIRTUAL_ROUTER, true);
    virtualRouterMac =
        properties.get<std::string>(VIRTUAL_ROUTER_MAC, "00:22:bd:f8:19:ff");
    routerAdv = properties.get<bool>(VIRTUAL_ROUTER_RA, false);
    virtualDHCP = properties.get<bool>(VIRTUAL_DHCP, true);
    virtualDHCPMac =
        properties.get<std::string>(VIRTUAL_DHCP_MAC, "00:22:bd:f8:19:ff");

    if (properties.get<bool>(ENDPOINT_ADV, true) == false) {
        endpointAdvMode = AdvertManager::EPADV_DISABLED;
    } else {
        std::string epAdvStr =
            properties.get<std::string>(ENDPOINT_ADV_MODE,
                                        "gratuitous-broadcast");
        if (epAdvStr == "gratuitous-unicast") {
            endpointAdvMode = AdvertManager::EPADV_GRATUITOUS_UNICAST;
        } else if (epAdvStr == "router-request") {
            endpointAdvMode = AdvertManager::EPADV_ROUTER_REQUEST;
        } else {
            endpointAdvMode = AdvertManager::EPADV_GRATUITOUS_BROADCAST;
        }
    }

    std::string tnlEpAdvStr =
        properties.get<std::string>(ENDPOINT_TNL_ADV_MODE,
                                    "garp-rarp-broadcast");
    if (tnlEpAdvStr == "gratuitous-broadcast") {
        tunnelEndpointAdvMode = AdvertManager::EPADV_GRATUITOUS_BROADCAST;
    } else if(tnlEpAdvStr == "disabled") {
        tunnelEndpointAdvMode = AdvertManager::EPADV_DISABLED;
    } else if(tnlEpAdvStr == "rarp-broadcast") {
        tunnelEndpointAdvMode = AdvertManager::EPADV_RARP_BROADCAST;
    } else {
        tunnelEndpointAdvMode = AdvertManager::EPADV_GARP_RARP_BROADCAST;
    }

    tunnelEndpointAdvIntvl =
        properties.get<uint64_t>(ENDPOINT_TNL_ADV_INTVL,
                                    300);

    connTrack = properties.get<bool>(CONN_TRACK, true);
    ctZoneRangeStart = properties.get<uint16_t>(CONN_TRACK_RANGE_START, 1);
    ctZoneRangeEnd = properties.get<uint16_t>(CONN_TRACK_RANGE_END, 65534);

    flowIdCache = properties.get<std::string>(FLOWID_CACHE_DIR,
                                              DEF_FLOWID_CACHEDIR);

    mcastGroupFile = properties.get<std::string>(MCAST_GROUP_FILE,
                                                 DEF_MCAST_GROUPFILE);

    dnsCacheDir = properties.get<std::string>(DNS_CACHE_DIR,
                                              DEF_DNS_CACHEDIR);

    ovsdbUseLocalTcpPort = properties.get<bool>(OVSDB_USE_LOCAL_TCPPORT, false);

    ifaceStatsEnabled = properties.get<bool>(STATS_INTERFACE_ENABLED, true);
    contractStatsEnabled = properties.get<bool>(STATS_CONTRACT_ENABLED, true);
    serviceStatsFlowDisabled = properties.get<bool>(STATS_SERVICE_FLOWDISABLED, false);
    serviceStatsEnabled = properties.get<bool>(STATS_SERVICE_ENABLED, true);
    secGroupStatsEnabled = properties.get<bool>(STATS_SECGROUP_ENABLED, true);
    ifaceStatsInterval = properties.get<long>(STATS_INTERFACE_INTERVAL, 30000);
    tableDropStatsEnabled = properties.get<bool>(TABLE_DROP_STATS_ENABLED, true);
    natStatsEnabled = properties.get<bool>(STATS_NAT_ENABLED, false);

    contractStatsInterval =
        properties.get<long>(STATS_CONTRACT_INTERVAL, 10000);
    serviceStatsInterval =
        properties.get<long>(STATS_SERVICE_INTERVAL, 10000);
    secGroupStatsInterval =
        properties.get<long>(STATS_SECGROUP_INTERVAL, 10000);
    tableDropStatsInterval =
        properties.get<long>(TABLE_DROP_STATS_INTERVAL, 30000);
    natStatsInterval = 
        properties.get<long>(STATS_NAT_INTERVAL, 10000);
    if (ifaceStatsInterval <= 0) {
        ifaceStatsEnabled = false;
    }
    if (contractStatsInterval <= 0) {
        contractStatsEnabled = false;
    }
    if (secGroupStatsInterval <= 0) {
        secGroupStatsEnabled = false;
    }
    if(tableDropStatsInterval <= 0) {
        tableDropStatsEnabled = false;
    }
    if (natStatsInterval <= 0) {
        natStatsEnabled = false;
    }
}

static bool connTrackIdGarbageCb(EndpointManager& endpointManager,
                                 opflex::ofcore::OFFramework& framework,
                                 const std::string& nmspc,
                                 const std::string& str) {
    if (str.empty()) return false;
    if (str[0] == '/') {
        // a URI means a routing domain (in IntFlowManager)
        return IdGenerator::uriIdGarbageCb
            <modelgbp::gbp::RoutingDomain>(framework, nmspc, str);
    } else {
        // a UUID means an endpoint UUID (in AccessFlowManager)
        return (bool)endpointManager.getEndpoint(str);
    }
}

void OVSRenderer::onCleanupTimer(const boost::system::error_code& ec) {
    if (ec) return;

    idGen.cleanup();
    intFlowManager.cleanup();
    accessFlowManager.cleanup();

    IdGenerator::garbage_cb_t gcb =
        bind(connTrackIdGarbageCb,
             std::ref(getEndpointManager()),
             std::ref(getFramework()), _1, _2);
    idGen.collectGarbage(ID_NMSPC_CONNTRACK, std::move(gcb));

    if (started) {
        const std::lock_guard<std::mutex> guard(timer_mutex);
        cleanupTimer->expires_from_now(CLEANUP_INTERVAL);
        cleanupTimer->async_wait(bind(&OVSRenderer::onCleanupTimer,
                                      this, error));
    }
}

void OVSRenderer::startPacketLogger() {
    if(dropLogIntIface.empty() && dropLogAccessIface.empty()) {
        LOG(DEBUG) << "DropLog interfaces not configured";
        return;
    }
    boost::system::error_code ec;
    boost::asio::ip::address addr = boost::asio::ip::address::from_string(LOOPBACK, ec);
    if(ec) {
        LOG(ERROR) << "PacketLogger: Failed to convert address " << LOOPBACK;
    }
    pktLogger.setAddress(addr, dropLogLocalPort);
    pktLogger.setNotifSock(getAgent().getPacketEventNotifSock());
    PacketLogHandler::TableDescriptionMap tblDescMap;
    intSwitchManager.getForwardingTableList(tblDescMap);
    pktLogger.setIntBridgeTableDescription(tblDescMap);
    accessSwitchManager.getForwardingTableList(tblDescMap);
    pktLogger.setAccBridgeTableDescription(tblDescMap);
    pktLogger.startListener();
    if(!getAgent().getPacketEventNotifSock().empty()) {
        exporterThread.reset(new std::thread([this]() {
           this->pktLogger.startExporter();
        }));
    }
    packetLoggerThread.reset(new std::thread([this]() {
       this->pktLoggerIO.run();
    }));
}
static void convertPruneFilter(std::shared_ptr<PacketDropLogPruneSpec> &sourceSpec,
        shared_ptr<PacketFilterSpec> &filter) {
    if(sourceSpec->srcIp) {
        filter->setField(TFLD_SRC_IP,sourceSpec->srcIp.get().to_string());
    }
    if(sourceSpec->srcPfxLen) {
        std::stringstream strSrcPfxLen;
        strSrcPfxLen << (int)sourceSpec->srcPfxLen.get();
        LOG(DEBUG) << "spfxLen " << strSrcPfxLen.str() << endl;
        filter->setField(TFLD_SPFX_LEN,strSrcPfxLen.str());
    }
    if(sourceSpec->dstIp) {
        filter->setField(TFLD_DST_IP,sourceSpec->dstIp.get().to_string());
    }
    if(sourceSpec->dstPfxLen) {
        std::stringstream strDstPfxLen;
        strDstPfxLen << (int)sourceSpec->dstPfxLen.get();
        LOG(DEBUG) << "dpfxLen " << strDstPfxLen.str() << endl;
        filter->setField(TFLD_DPFX_LEN,strDstPfxLen.str());
    }
    if(sourceSpec->srcMac) {
        filter->setField(TFLD_SRC_MAC,sourceSpec->srcMac.get().toString());
    }
    if(sourceSpec->srcMacMask) {
        filter->setField(TFLD_SMAC_MASK,sourceSpec->srcMacMask.get().toString());
    }
    if(sourceSpec->dstMac) {
        filter->setField(TFLD_DST_MAC,sourceSpec->dstMac.get().toString());
    }
    if(sourceSpec->dstMacMask) {
        filter->setField(TFLD_DMAC_MASK,sourceSpec->dstMacMask.get().toString());
    }
    if(sourceSpec->ipProto) {
        std::stringstream strIpProto;
        strIpProto << (uint16_t)sourceSpec->ipProto.get();
        filter->setField(TFLD_IP_PROTO,strIpProto.str());
    }
    if(sourceSpec->sport) {
        std::stringstream strSport;
        strSport << sourceSpec->sport.get();
        filter->setField(TFLD_SPORT,strSport.str());
    }
    if(sourceSpec->dport) {
        std::stringstream strDport;
        strDport << sourceSpec->dport.get();
        filter->setField(TFLD_DPORT,strDport.str());
    }
}

void OVSRenderer::packetDropPruneConfigUpdated(const std::string& filterName) {
    using namespace std;
    using namespace boost;
    std::shared_ptr<PacketDropLogPruneSpec> sourceSpec;
    if(!getAgent().getExtraConfigManager().getPacketDropPruneSpec(filterName, sourceSpec)){
        pktLogger.deletePruneFilter(filterName);
        return;
    }
    std::shared_ptr<PacketFilterSpec> filter(new PacketFilterSpec());
    convertPruneFilter(sourceSpec, filter);
    pktLogger.updatePruneFilter(filterName, filter);
}

void OVSRenderer::outOfBandConfigUpdated(std::shared_ptr<OutOfBandConfigSpec> &sptr) {
    using namespace std;
    using namespace boost;
    if (!sptr) {
        intFlowManager.restartTunnelEndpointAdv(tunnelEndpointAdvMode,
            tunnelEndpointAdvIntvl);
        return;
    }
    intFlowManager.restartTunnelEndpointAdv(AdvertManager::EPADV_GARP_RARP_BROADCAST,
            sptr->tunnelEpAdvInterval);
}   

void OVSRenderer::stopPacketLogger() {
    pktLogger.stopListener();
    pktLogger.stopExporter();
    if(exporterThread) {
        exporterThread->join();
        exporterThread.reset();
    }
    if(packetLoggerThread) {
        packetLoggerThread->join();
        packetLoggerThread.reset();
    }
}

} /* namespace opflexagent */

extern "C" const opflexagent::RendererPlugin* init_renderer_plugin() {
    static const opflexagent::OVSRendererPlugin smrPlugin;

    return &smrPlugin;
}
