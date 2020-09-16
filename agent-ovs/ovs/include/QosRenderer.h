/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for QosRenderer
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */


#ifndef OPFLEX_QOSRENDERER_H
#define OPFLEX_QOSRENDERER_H

#include <boost/noncopyable.hpp>
#include <opflexagent/QosListener.h>
#include "JsonRpcRenderer.h"


namespace opflexagent {

/**
 * class to render Qos export config on a virtual switch
 */
class QosRenderer : public QosListener,
                        public JsonRpcRenderer,
                        private boost::noncopyable {

public:
    /**
     * constructor for QosRenderer
     * @param agent_ reference to an agent instance
     */
    QosRenderer(Agent& agent_);

    /**
     * Start the renderer
     * @param swName Switch to connect to
     * @param conn OVSDB connection
     */
    virtual void start(const std::string& swName, OvsdbConnection* conn);

    /**
     * Module stop
     */
    void stop();

    /**
     * called when Qos for an interface is deleted.
     * @param interface Name of the interface.
     */
    virtual void qosDeleted(const string& interface);

    /**
     * called ingress qos parameters is updated for an interface.
     * @param interface Name of the interface.
     */
    virtual void ingressQosUpdated(const string& interface);

    /**
     * called egress qos parameters is updated for an interface.
     * @param interface Name of the interface.
     */
    virtual void egressQosUpdated(const string& interface);

    /**
     * handle ingress qos parameters update.
     * @param interface Name of the interface.
     */
    void handleIngressQosUpdate(const string& interface);

    /**
     * handle egress qos parameters update.
     * @param interface Name of the interface.
     */
    void handleEgressQosUpdate(const string& interface);

     /**
     * called to update ingress qos parameters for an interface.
     * @param interface Name of the interface.
     * @param rate ingress rate for interface.
     * @param burst ingress burst for interface.
     * @param dscpMarking dscp to be marked on header
     */
    void updateIngressQosParams(const string& interface, const uint64_t& rate, const uint64_t& burst, const int& dscpMarking);

    /**
     * called to update egress qos parameters  for an interface.
     * @param interface Name of the interface.
     * @param rate egress rate of the interface.
     * @param burst egress burst of the interface.
     */
    void updateEgressQosParams(const string& interface, const uint64_t& rate, const uint64_t& burst);

    /**
     * delete ingress qos parameters update.
     * @param interface Name of the interface.
     */
    void deleteIngressQos(const string& interface);

    /**
     * delete egress qos parameters update.
     * @param interface Name of the interface.
     */
    void deleteEgressQos(const string& interface);


private:
    void updateConnectCb(const boost::system::error_code& ec, const string& interface);
    void delConnectCb(const boost::system::error_code& ec, const string& interface);
};
}
#endif //OPFLEX_QOSRENDERER_H
