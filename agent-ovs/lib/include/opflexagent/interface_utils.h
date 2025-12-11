/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Interface utility functions for querying network interface properties
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <string>

#pragma once
#ifndef OPFLEXAGENT_INTERFACE_UTILS_H
#define OPFLEXAGENT_INTERFACE_UTILS_H

namespace opflexagent {

/**
 * Get the MAC address for a given interface name
 *
 * @param iface the interface name
 * @return the MAC address as a string, or empty string on error
 */
std::string getInterfaceMac(const std::string& iface);

/**
 * Get the IPv4 address for a given interface name
 *
 * @param iface the interface name
 * @return the IPv4 address as a string, or empty string on error
 */
std::string getInterfaceAddressV4(const std::string& iface);

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_INTERFACE_UTILS_H */
