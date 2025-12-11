/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation of interface utility functions
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <cerrno>
#include <cstring>

#include <opflex/modb/MAC.h>
#include <opflexagent/interface_utils.h>
#include <opflexagent/logging.h>

namespace opflexagent {

using std::string;

#ifdef HAVE_IFADDRS_H
string getInterfaceMac(const string& iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        int err = errno;
        LOG(ERROR) << "Socket creation failed when getting MAC address of "
            << iface << ", error: " << strerror(err);
        return "";
    }

    ifreq ifReq;
    /* Note: ifReq.ifr_name is 16 bytes. Ensure at most we can copy only 15 bytes.
     * 1 byte must be reserved for null terminating the string */
    auto maxSize = strnlen(iface.c_str(), sizeof(ifReq.ifr_name)-1);
    strncpy(ifReq.ifr_name, iface.c_str(), maxSize);
    ifReq.ifr_name[maxSize] = '\0';
    if (ioctl(sock, SIOCGIFHWADDR, &ifReq) != -1) {
        close(sock);
        return
            opflex::modb::MAC((uint8_t*)(ifReq.ifr_hwaddr.sa_data)).toString();
    } else {
        int err = errno;
        close(sock);
        LOG(ERROR) << "ioctl to get MAC address failed for " << iface
            << ", error: " << strerror(err);
        return "";
    }
}

string getInterfaceAddressV4(const string& iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
        int err = errno;
        LOG(ERROR) << "Socket creation failed when getting IPv4 address of "
             << iface << ", error: " << strerror(err);
        return "";
    }

    ifreq ifReq;
    /* Note: ifReq.ifr_name is 16 bytes. Ensure at most we can copy only 15 bytes.
     * 1 byte must be reserved for null terminating the string */
    auto maxSize = strnlen(iface.c_str(), sizeof(ifReq.ifr_name)-1);
    strncpy(ifReq.ifr_name, iface.c_str(), maxSize);
    ifReq.ifr_name[maxSize] = '\0';
    if (ioctl(sock, SIOCGIFADDR, &ifReq) != -1) {
        close(sock);
        char host[NI_MAXHOST];
        int s = getnameinfo(&ifReq.ifr_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
            LOG(ERROR) << "getnameinfo() failed: " << gai_strerror(s);
            return "";
        }
        return host;
    } else {
        int err = errno;
        close(sock);
        LOG(ERROR) << "ioctl to get IPv4 address failed for " << iface
            << ", error: " << strerror(err);
        return "";
    }
}
#else
string getInterfaceMac(const string& iface) {
    LOG(ERROR) << "Cannot get interface MAC address: unsupported platform";
    return "";
}

string getInterfaceAddressV4(const string& iface) {
    LOG(ERROR) << "Cannot get interface IPv4 address: unsupported platform";
    return "";
}
#endif

} /* namespace opflexagent */
