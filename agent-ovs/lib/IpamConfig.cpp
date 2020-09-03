/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for IpamConfig class.
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <iostream>
#include <opflexagent/IpamConfig.h>

namespace opflexagent {

std::ostream & operator<<(std::ostream &os, const IpamConfig& ipam) {
    os << "IpamConfig["
       << "uuid=" << ipam.getUUID();
    if (ipam.getMap().size() > 0) {
        bool first = true;
        os << ",map=[";
        for (auto it : ipam.getMap()) {
            if (first) first = false;
            else os << ",";
            os << "(" << it.first
               << "," << it.second << ")";
        }
        os << "]";
    }
    os << "]";

    return os;
}

} /* namespace opflexagent */
