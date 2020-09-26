/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for qos Listener
 *
 * Copyright (c) 2020 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_QOSLISTENER_H
#define OPFLEX_QOSLISTENER_H

#include <opflexagent/QosConfigState.h>

namespace opflexagent {

using namespace std;

/**
 * class defining api for listening to qos updates
 */
class QosListener  {
public:
    /**
     * destroy qos listener and clean up all state.
     */
    virtual ~QosListener() {};

    /**
     * called when  qos config has been deleted
     * @param interface is name of the interface.
     */
    virtual void qosDeleted(const string& interface) {}

    /**
     * Called when ingress qos paramaters are updated.
     * @param interface is name of the interface.
     */
     virtual void ingressQosUpdated(const string& interface) {}

     /**
      * Called when egress qos paramaters are updated.
      * @param interface is name of the interface.
      */
     virtual void egressQosUpdated(const string& interface) {}

     /**
      * Called when dscp qos paramaters are updated.
      * @param interface is name of the interface.
      */
     virtual void dscpQosUpdated(const string& interface) {}
};
}
#endif // OPFLEX_QOSLISTENER_H
