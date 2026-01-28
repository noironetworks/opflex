/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for MulticastListener
 *
 * Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_MULTICAST_LISTENER_H
#define OPFLEXAGENT_MULTICAST_LISTENER_H

#include <memory>
#include <unordered_set>
#include <vector>
#include <string>

#include <boost/noncopyable.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address_v4.hpp>

namespace opflexagent {

/**
 * A server that simply subscribes to a set of multicast addresses and
 * holds them open.
 */
class MulticastListener : private boost::noncopyable {
public:
    /**
     * Instantiate the listener
     *
     * @param io_service the io_service object
     * @param interfaces list of interface names to bind multicast to
     *                   (empty means all interfaces)
     */
    MulticastListener(boost::asio::io_service& io_service,
                      const std::vector<std::string>& interfaces = {});

    /**
     * Destroy the server and clean up all state
     */
    ~MulticastListener();

    /**
     * Stop the server
     */
    void stop();

    /**
     * Make the subscriptions match the given set
     */
    void sync(const std::shared_ptr<std::unordered_set<std::string> >& addrs);

private:
    boost::asio::io_service& io_service;
    std::unique_ptr<boost::asio::ip::udp::socket> socket_v4;
    std::unique_ptr<boost::asio::ip::udp::socket> socket_v6;
    std::unordered_set<std::string> addresses;
    std::atomic<bool> running;

    // Interface filtering for multicast membership
    std::vector<boost::asio::ip::address_v4> interface_addrs_v4;
    std::vector<unsigned int> interface_indices_v6;

    void join(const std::string& mcast_address);
    void leave(const std::string& mcast_address);

    void do_stop();

    // Resolve interface name to IPv4 address and interface index
    static bool resolveInterface(const std::string& ifname,
                                 boost::asio::ip::address_v4& addr_v4,
                                 unsigned int& if_index);
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_MULTICAST_LISTENER_H */
