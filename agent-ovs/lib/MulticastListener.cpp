/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for MulticastListener class
 *
 * Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/MulticastListener.h>
#include <opflexagent/logging.h>

#include <boost/asio/socket_base.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/ip/multicast.hpp>

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>


namespace opflexagent {

namespace ba = boost::asio;
using std::shared_ptr;
using std::unique_ptr;
using std::unordered_set;
using std::string;
using std::vector;

#define LISTEN_PORT 34242

bool MulticastListener::resolveInterface(const std::string& ifname,
                                         ba::ip::address_v4& addr_v4,
                                         unsigned int& if_index) {
    // Get interface index
    if_index = if_nametoindex(ifname.c_str());
    if (if_index == 0) {
        LOG(ERROR) << "Interface not found: " << ifname;
        return false;
    }

    // Get IPv4 address for the interface
    struct ifaddrs *ifaddr, *ifa;
    bool found_v4 = false;

    if (getifaddrs(&ifaddr) == -1) {
        LOG(ERROR) << "Failed to get interface addresses";
        return false;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr)
            continue;

        if (ifname == ifa->ifa_name && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
            boost::system::error_code ec;
            addr_v4 = ba::ip::address_v4::from_string(ip_str, ec);
            if (!ec) {
                found_v4 = true;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);

    if (!found_v4) {
        LOG(WARNING) << "No IPv4 address found for interface: " << ifname
                     << " (IPv4 multicast will not be available on this interface)";
    }

    return true;  // Return true if we got the interface index (IPv6 will still work)
}

MulticastListener::MulticastListener(ba::io_service& io_service_,
                                     const vector<string>& interfaces)
    : io_service(io_service_), running(true) {

    LOG(INFO) << "Starting multicast listener";

    // Resolve interfaces to addresses/indices if specified
    if (!interfaces.empty()) {
        LOG(INFO) << "Restricting multicast membership to specified interfaces";
        for (const auto& ifname : interfaces) {
            ba::ip::address_v4 addr_v4;
            unsigned int if_index = 0;
            if (resolveInterface(ifname, addr_v4, if_index)) {
                if (!addr_v4.is_unspecified()) {
                    interface_addrs_v4.push_back(addr_v4);
                    LOG(INFO) << "Added interface " << ifname
                              << " with IPv4 address " << addr_v4;
                }
                interface_indices_v6.push_back(if_index);
                LOG(INFO) << "Added interface " << ifname
                          << " with index " << if_index << " for IPv6";
            }
        }
    }

    try {
        unique_ptr<ba::ip::udp::socket> v4(new ba::ip::udp::socket(io_service));
        ba::ip::udp::endpoint v4_endpoint(ba::ip::udp::v4(), LISTEN_PORT);

        v4->open(v4_endpoint.protocol());
        v4->set_option(ba::socket_base::reuse_address(true));
        v4->bind(v4_endpoint);
        socket_v4 = std::move(v4);
    } catch (boost::system::system_error& e) {
        LOG(WARNING) << "Could not bind to IPv4 socket: "
                     << e.what();
    }

    try {
        unique_ptr<ba::ip::udp::socket> v6(new ba::ip::udp::socket(io_service));
        ba::ip::udp::endpoint v6_endpoint(ba::ip::udp::v6(), LISTEN_PORT);

        v6->open(v6_endpoint.protocol());
        v6->set_option(ba::socket_base::reuse_address(true));
        v6->set_option(ba::ip::v6_only(true));
        v6->bind(v6_endpoint);
        socket_v6 = std::move(v6);
    } catch (boost::system::system_error& e) {
        LOG(WARNING) << "Could not bind to IPv6 socket: "
                     << e.what();
    }

    if (!socket_v4 && !socket_v6) {
        throw std::runtime_error("Could not bind to any socket");
    }
}

MulticastListener::~MulticastListener() {
    stop();
}

void MulticastListener::do_stop() {
    if (socket_v4) {
        socket_v4->shutdown(boost::asio::ip::udp::socket::shutdown_both);
        socket_v4->close();
        socket_v4.reset();
    }
    if (socket_v6) {
        socket_v6->shutdown(boost::asio::ip::udp::socket::shutdown_both);
        socket_v6->close();
        socket_v6.reset();
    }
}

void MulticastListener::stop() {
    if (!running) return;
    running = false;

    LOG(INFO) << "Shutting down";
    try {
        io_service.dispatch([this]() { MulticastListener::do_stop(); });
    } catch (const boost::system::system_error &e) {
        LOG(WARNING) << "Failed to shutdown multicast socket cleanly: " << e.what();
    }
}

void MulticastListener::join(const std::string& mcast_address) {
    boost::system::error_code ec;
    ba::ip::address addr = ba::ip::address::from_string(mcast_address, ec);
    if (ec) {
        LOG(ERROR) << "Cannot join invalid multicast group: "
                     << mcast_address << ": " << ec.message();
        return;
    } else if (!addr.is_multicast()) {
        LOG(ERROR) << "Address is not a multicast address: " << addr;
        return;
    }

    LOG(INFO) << "Joining group " << addr;

    if (addr.is_v4()) {
        if (!socket_v4) {
            LOG(ERROR) << "Could not join group "
                       << addr << ": " << "IPv4 socket not available";
            return;
        }

        if (interface_addrs_v4.empty()) {
            // No interface restriction - join on all interfaces
            socket_v4->set_option(ba::ip::multicast::join_group(addr), ec);
            if (ec)
                LOG(ERROR) << "Could not join group " << addr << ": " << ec.message();
        } else {
            // Join on each specified interface
            for (const auto& if_addr : interface_addrs_v4) {
                socket_v4->set_option(
                    ba::ip::multicast::join_group(addr.to_v4(), if_addr), ec);
                if (ec) {
                    LOG(ERROR) << "Could not join group " << addr
                               << " on interface " << if_addr << ": " << ec.message();
                } else {
                    LOG(DEBUG) << "Joined group " << addr << " on interface " << if_addr;
                }
            }
        }
    } else {
        if (!socket_v6) {
            LOG(ERROR) << "Could not join group "
                       << addr << ": " << "IPv6 socket not available";
            return;
        }

        if (interface_indices_v6.empty()) {
            // No interface restriction - join on all interfaces
            socket_v6->set_option(ba::ip::multicast::join_group(addr), ec);
            if (ec)
                LOG(ERROR) << "Could not join group " << addr << ": " << ec.message();
        } else {
            // Join on each specified interface
            for (unsigned int if_index : interface_indices_v6) {
                socket_v6->set_option(
                    ba::ip::multicast::join_group(addr.to_v6(), if_index), ec);
                if (ec) {
                    LOG(ERROR) << "Could not join group " << addr
                               << " on interface index " << if_index << ": " << ec.message();
                } else {
                    LOG(DEBUG) << "Joined group " << addr << " on interface index " << if_index;
                }
            }
        }
    }
}

void MulticastListener::leave(const std::string& mcast_address) {
    boost::system::error_code ec;
    ba::ip::address addr = ba::ip::address::from_string(mcast_address, ec);
    if (ec)
        return;

    LOG(INFO) << "Leaving group " << addr;

    if (addr.is_v4()) {
        if (!socket_v4)
            return;

        if (interface_addrs_v4.empty()) {
            // No interface restriction - leave on all interfaces
            socket_v4->set_option(ba::ip::multicast::leave_group(addr), ec);
            if (ec)
                LOG(ERROR) << "Could not leave group " << addr << ": " << ec.message();
        } else {
            // Leave on each specified interface
            for (const auto& if_addr : interface_addrs_v4) {
                socket_v4->set_option(
                    ba::ip::multicast::leave_group(addr.to_v4(), if_addr), ec);
                if (ec) {
                    LOG(ERROR) << "Could not leave group " << addr
                               << " on interface " << if_addr << ": " << ec.message();
                } else {
                    LOG(DEBUG) << "Left group " << addr << " on interface " << if_addr;
                }
            }
        }
    } else {
        if (!socket_v6)
            return;

        if (interface_indices_v6.empty()) {
            // No interface restriction - leave on all interfaces
            socket_v6->set_option(ba::ip::multicast::leave_group(addr), ec);
            if (ec)
                LOG(ERROR) << "Could not leave group " << addr << ": " << ec.message();
        } else {
            // Leave on each specified interface
            for (unsigned int if_index : interface_indices_v6) {
                socket_v6->set_option(
                    ba::ip::multicast::leave_group(addr.to_v6(), if_index), ec);
                if (ec) {
                    LOG(ERROR) << "Could not leave group " << addr
                               << " on interface index " << if_index << ": " << ec.message();
                } else {
                    LOG(DEBUG) << "Left group " << addr << " on interface index " << if_index;
                }
            }
        }
    }
}

void MulticastListener::sync(const shared_ptr<unordered_set<string> >& naddrs) {
    auto it = addresses.begin();
    while (it != addresses.end()) {
        if (naddrs->find(*it) == naddrs->end()) {
            leave(*it);
            it = addresses.erase(it);
        } else {
            ++it;
        }
    }
    for (const std::string& addr : *naddrs) {
        if (addresses.find(addr) == addresses.end()) {
            join(addr);
            addresses.insert(addr);
        }
    }
}

} /* namespace opflexagent */
