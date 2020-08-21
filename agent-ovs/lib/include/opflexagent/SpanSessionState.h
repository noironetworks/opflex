/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for Span Listener
 *
 * Copyright (c) 2019 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEX_SPANSESSIONSTATE_H
#define OPFLEX_SPANSESSIONSTATE_H

#include <unordered_set>

#include <opflex/modb/URI.h>
#include <modelgbp/gbp/DirectionEnumT.hpp>
#include <modelgbp/platform/AdminStateEnumT.hpp>
#include <modelgbp/span/ErspanVersionEnumT.hpp>
#include <boost/asio.hpp>
#include <utility>


namespace opflexagent {

using namespace std;
using namespace boost::asio::ip;
using namespace opflex::modb;

/**
 * class to represent a source end point
 */
class SourceEndpoint {
    public:
        /**
         * constructor takes a name and port
         * @param[in] name_ name of localEp
         * @param[in] port_ source port name on the vswitch
         * @param[in] dir_ direction to be set
         */
        SourceEndpoint(string name_, string port_, const unsigned char dir_) :
            name(std::move(name_)), port(std::move(port_)), dir(dir_) {};

        /**
         * Copy constructor
         */
        SourceEndpoint(const SourceEndpoint& copy) = default;

        /**
         * Assignment operator
         */
        SourceEndpoint& operator=(const SourceEndpoint& rhs) = default;

        /**
         * gets the name of the source end point
         * @return name of source end point
         */
        const string& getName() const { return name; };
        /**
         * gets the port name of the source end point
         * @return name of port source end point
         */
        const string& getPort() const { return port; };
        /**
         * gets the direction of spanned traffic
         * @return a value from DirectionEnumT.
         */
        unsigned char getDirection() const { return dir; };

    private:
        string name;
        string port;
        unsigned char dir;
};

/**
 * class to represent a span session.
 */
class SessionState {
    public:
        /**
         * comparison criteria for adding to srcEndPoint set
         */
        struct SrcCompare {
        public:
            /**
             * compare the port strings of the source end points
             * @param src1 shared pointer to source end point 1
             * @param src2 shared pointer to source end point 2
             * @return bool true if comparison passes.
             */
            bool operator()(const SourceEndpoint& src1,
                            const SourceEndpoint& src2) const {
                return src1.getPort() == src2.getPort();
            }
        };
        /**
         * hash function fpr srcEndPoint set
         */
        struct SrcHash {
        public:
            /**
             * hashes the concatenation of port and direction
             * @param src shared pointer to source end point
             * @return size_t
             */
            size_t operator()(const SourceEndpoint& src) const {
                string strHash(src.getPort());
                strHash += src.getDirection();
                return std::hash<string>()(strHash);
            }
        };

        /**
         * typedef for source end point set
         */
        typedef unordered_set<SourceEndpoint, SrcHash, SrcCompare> srcEpSet;

        /**
         * constructor that takes a URI that points to a Session object
         * @param uri_ URI of a Session object
         * @param name_ name of Session object
         */
        SessionState(const URI& uri_, string name_) :
            uri(uri_), name(std::move(name_)),
            adminState(modelgbp::platform::AdminStateEnumT::CONST_OFF),
            version(modelgbp::span::ErspanVersionEnumT::CONST_V2),
            sessionId(1) {};

        /**
         * gets the URI, which points to a Session object
         * @return a URI
         */
        const URI& getUri() const { return uri;};

        /**
         * add a source end point to the internal map
         * @param srcEp shared pointer to a SourceEndpoint object.
         */
        void addSrcEndpoint(const SourceEndpoint& srcEp);

        /**
         * are there any src endpoints
         * @return has src endpoints
         */
        bool hasSrcEndpoints() const;

        /**
         * get a copy of the source end points
         * @param ep reference to end point set
         */
        void getSrcEndpointSet(srcEpSet& ep);

        /**
         * get the destination of the ERSPAN session
         * @return dst IP
         */
        const address& getDestination() { return destination; }

        /**
         * set the destination of the ERSPAN session
         * @param destination_ dst IP
         */
        void setDestination(const address& destination_) {
            destination = destination_;
        }

        /**
         * gets the name string for this object
         * @return the name attribute string.
         */
        const string& getName() const { return name; };

        /**
         * get session admin state
         * @returns admin state of session
         */
        uint8_t getAdminState() const { return adminState;};

        /**
         * set session admin state
         * @param ast admin state of session
         */
        void setAdminState(const uint8_t ast) { adminState = ast;};
        /**
        * get ERSPAN version setting
        * @return ERSPAN version
        */
       uint8_t getVersion() const { return version; };
       /**
        * set ERSPAN version
        * @param ver ERSPAN version
        */
       void setVersion(uint8_t ver) { version = ver;};

       /**
        * Get the session ID
        * @return session ID
        */
       uint16_t getSessionId() const { return sessionId; }

       /**
        * Set the session ID
        */
       void setSessionId(uint16_t id) { sessionId = id; }

       /**
         * Get the dest port name
         * @return session ID
         */
        const string& getDestPort() const { return destPort; }

        /**
         * Set the dest port name
         */
        void setDestPort(const string& port) { destPort = port; }

    private:
        URI uri;
        string name;
        uint8_t adminState;
        uint8_t version;
        uint16_t sessionId;
        string destPort;

        srcEpSet srcEndpoints;
        // mapping DstSummary to dst IP
        address destination;
};

/**
 * ERSPAN params
 */
class ErspanParams {
public:
    /**
     * Default constructor
     */
    ErspanParams() : ver(0), sessionId(1) {}

    /**
     * Copy constructor
     */
    ErspanParams(const ErspanParams& copy) = default;

    /**
     * Assignment operator
     */
    ErspanParams& operator=(const ErspanParams& rhs) = default;

    /**
     * Get the ERSPAN version
     *
     * @return 1 for Type II, 2 for Type III
     */
    unsigned int getVersion() const {
        return ver;
    }

    /**
     * Set the ERSPAN version
     *
     * @param version ERSPAN version
     */
    void setVersion(unsigned int version) {
        ver = version;
    }

    /**
     * Get the ERSPAN session dest IP
     * @return dest IP
     */
    const string& getRemoteIp() const {
        return remoteIp;
    }

    /**
     * Set the ERSPAN session dest IP
     * @param remoteIp_ ERSPAN session dest IP
     */
    void setRemoteIp(const string& remoteIp_) {
        remoteIp = remoteIp_;
    }

    /**
     * Get the ERSPAN port name
     * @return ERSPAN port name
     */
    const string& getPortName() const {
        return portName;
    }

    /**
     * Set the ERSPAN port name
     * @param portName_ ERSPAN port name
     */
    void setPortName(const string& portName_) {
        portName = portName_;
    }

    /**
     * Get the session ID
     * @return session ID
     */
    uint16_t getSessionId() const { return sessionId; }

    /**
     * Set the session ID
     */
    void setSessionId(uint16_t id) { sessionId = id; }


private:

    unsigned int ver;
    string remoteIp;
    string portName;
    uint16_t sessionId;
};
}

#endif // SPANSESSIONSTATE_H
