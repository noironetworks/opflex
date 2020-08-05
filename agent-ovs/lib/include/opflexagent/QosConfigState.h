/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for qos config object
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_QOSCONFIGSTATE
#define OPFLEX_QOSCONFIGSTATE

#include <opflex/modb/URI.h>


namespace opflexagent
{

using namespace std;
using namespace opflex::modb;

/**
 * represent qos config object
 */
class QosConfigState
{

private:
    uint64_t rate;
    uint64_t burst;
    URI uri;
    string name;

public:
    /**
     * constructor that takes a URI that points to a Bandwidth object
     * @param uri_ URI to a Session object
     * @param name_ name of Session object
     */
    QosConfigState(const URI& uri_, const string& name_) :
	rate(0),
	burst(0),
        uri(uri_),
        name(name_)
     { };
    /**
     *  get the name of this QosConfig
     *  @return string name of QosConfig
     */  
    const string& getName() const { return name; };
    /**
     * get the burst of QosConfig
     * @return burst QosConfig
     */
    const uint64_t& getBurst() const { return burst; };
    /**
     * set the burst of QosConfig
     * @param[in] burst_ burst of QosConfig
     */
    void setBurst(const uint64_t& burst_ ) {burst = burst_; };
    /**
     * get the rate of QosConfig
     * @return rate QosConfig
     */
    const uint64_t& getRate() const { return rate; };
    /**
     * set the rate of QosConfig
     * @param[in] rate_ rate of QosConfig
     */
    void setRate(const uint64_t& rate_ ) {rate = rate_; };
    /**
     * gets the URI of QosConfig 
     * @return URI of QosConfig
     *
     */
    const URI& getUri() const { return uri; };
};
} // namespace opflexagent
#endif
