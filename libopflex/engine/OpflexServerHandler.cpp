/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for OpflexServerHandler
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

/* This must be included before anything else */
#if HAVE_CONFIG_H
#  include <config.h>
#endif


#include <sstream>

#include <boost/optional.hpp>

#include "opflex/logging/internal/logging.hpp"
#include "opflex/engine/internal/OpflexMessage.h"
#include "opflex/engine/internal/OpflexServerHandler.h"
#include "opflex/engine/internal/GbpOpflexServerImpl.h"

namespace opflex {
namespace engine {
namespace internal {

using boost::optional;
using rapidjson::Value;
using rapidjson::Writer;
using modb::mointernal::StoreClient;
using ofcore::OFConstants;
using test::GbpOpflexServer;

void OpflexServerHandler::connected() {

}

void OpflexServerHandler::disconnected() {

}

void OpflexServerHandler::ready() {
    LOG(INFO) << "[" << getConnection()->getRemotePeer() << "] "
              << "Handshake succeeded";

    setState(READY);
}

class SendIdentityRes : public OpflexMessage {
public:
    SendIdentityRes(const rapidjson::Value& id,
                    const std::string& name_,
                    const std::string& domain_,
                    const optional<std::string>& your_location_,
                    const uint8_t roles_,
                    const test::GbpOpflexServer::peer_vec_t& peers_,
                    const std::vector<std::string>& proxies_)
        : OpflexMessage("send_identity", RESPONSE, &id),
          name(name_), domain(domain_), your_location(your_location_),
          roles(roles_), peers(peers_), proxies(proxies_) {}

    virtual void serializePayload(yajr::rpc::SendHandler& writer) const {
        (*this)(writer);
    }

    virtual SendIdentityRes* clone() {
        return new SendIdentityRes(*this);
    }

    virtual bool operator()(yajr::rpc::SendHandler& writer) const {
        writer.StartObject();
        writer.String("name");
        writer.String(name.c_str());
        writer.String("domain");
        writer.String(domain.c_str());
        if (your_location || !proxies.empty()) {
            writer.String("your_location");
            writer.String(your_location.get().c_str());
            writer.String("data");
            writer.StartObject();
            int i = 0;
            for(const std::string& proxy: proxies) {
                switch(i) {
                    case 0:
                        writer.String("proxy_v4");
                        break;
                    case 1:
                        writer.String("proxy_v6");
                        break;
                    case 2:
                        writer.String("proxy_mac");
                        break;
                }
                writer.String(proxy.c_str());
                i++;
            }
            writer.EndObject();
        }
        writer.String("my_role");
        writer.StartArray();
        if (roles & OFConstants::POLICY_ELEMENT)
            writer.String("policy_element");
        if (roles & OFConstants::POLICY_REPOSITORY)
            writer.String("policy_repository");
        if (roles & OFConstants::ENDPOINT_REGISTRY)
            writer.String("endpoint_registry");
        if (roles & OFConstants::OBSERVER)
            writer.String("observer");
        writer.EndArray();
        writer.String("peers");
        writer.StartArray();
        for (const GbpOpflexServer::peer_t& peer : peers) {
            writer.StartObject();
            writer.String("role");
            writer.StartArray();
            if (peer.first & OFConstants::POLICY_ELEMENT)
                writer.String("policy_element");
            if (peer.first & OFConstants::POLICY_REPOSITORY)
                writer.String("policy_repository");
            if (peer.first & OFConstants::ENDPOINT_REGISTRY)
                writer.String("endpoint_registry");
            if (peer.first & OFConstants::OBSERVER)
                writer.String("observer");
            writer.EndArray();
            writer.String("connectivity_info");
            writer.String(peer.second.c_str());
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
        return true;
    }

private:
    std::string name;
    std::string domain;
    optional<std::string> your_location;
    uint8_t roles;
    test::GbpOpflexServer::peer_vec_t peers;
    std::vector<std::string> proxies;
};

class PolicyResolveRes : public OpflexMessage {
public:
    PolicyResolveRes(const rapidjson::Value& id,
                     GbpOpflexServerImpl& server_,
                     const std::vector<modb::reference_t>& mos_)
        : OpflexMessage("policy_resolve", RESPONSE, &id),
          server(server_),
          mos(mos_) {}

    virtual void serializePayload(yajr::rpc::SendHandler& writer) const {
        (*this)(writer);
    }

    virtual PolicyResolveRes* clone() {
        return new PolicyResolveRes(*this);
    }

    virtual bool operator()(yajr::rpc::SendHandler& writer) const {
        MOSerializer& serializer = server.getSerializer();
        modb::mointernal::StoreClient* client = server.getSystemClient();

        writer.StartObject();
        writer.String("policy");
        writer.StartArray();
        for (const modb::reference_t& p : mos) {
            try {
                serializer.serialize(p.first, p.second,
                                     *client, writer,
                                     true);
            } catch (const std::out_of_range& e) {
                // policy doesn't exist locally
            }
        }
        writer.EndArray();
        writer.EndObject();
        return true;
    }

protected:
    GbpOpflexServerImpl& server;
    std::vector<modb::reference_t> mos;
};

class EndpointResolveRes : public OpflexMessage {
public:
    EndpointResolveRes(const rapidjson::Value& id,
                     GbpOpflexServerImpl& server_,
                     const std::vector<modb::reference_t>& mos_)
        : OpflexMessage("endpoint_resolve", RESPONSE, &id),
          server(server_),
          mos(mos_) {}

    virtual void serializePayload(yajr::rpc::SendHandler& writer) const {
        (*this)(writer);
    }

    virtual EndpointResolveRes* clone() {
        return new EndpointResolveRes(*this);
    }

    virtual bool operator()(yajr::rpc::SendHandler& writer) const {
        MOSerializer& serializer = server.getSerializer();
        modb::mointernal::StoreClient* client = server.getSystemClient();

        writer.StartObject();
        writer.String("endpoint");
        writer.StartArray();
        for (const modb::reference_t& p : mos) {
            try {
                serializer.serialize(p.first, p.second,
                                     *client, writer,
                                     true);
            } catch (const std::out_of_range& e) {
                // endpoint doesn't exist locally
            }
        }
        writer.EndArray();
        writer.EndObject();
        return true;
    }

protected:
    GbpOpflexServerImpl& server;
    std::vector<modb::reference_t> mos;
};

void OpflexServerHandler::handleSendIdentityReq(const rapidjson::Value& id,
                                                const Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got send_identity req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrIdentReqs();
    std::stringstream sb;
    sb << "127.0.0.1:" << server->getPort();
    SendIdentityRes* res =
        new SendIdentityRes(id, sb.str(), "testdomain",
                            std::string("location_string"),
                            server->getRoles(),
                            server->getPeers(),
                            server->getProxies());
    conn->sendMessage(res, true);
    ready();
}

void OpflexServerHandler::handlePolicyResolveReq(const rapidjson::Value& id,
                                                 const Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got policy_resolve req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrPolResolves();

    bool found = true;
    Value::ConstValueIterator it;
    std::vector<modb::reference_t> mos;
    for (it = payload.Begin(); it != payload.End(); ++it) {
        if (!it->IsObject()) {
            sendErrorRes(id, "ERROR", "Malformed message: not an object");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }
        if (!it->HasMember("subject")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }
        if (it->HasMember("policy_ident")) {
            sendErrorRes(id, "EUNSUPPORTED",
                         "Policy resolution by ident is not supported");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }
        if (!it->HasMember("policy_uri")) {
            sendErrorRes(id, "ERROR", "Malformed message: no policy_uri");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }
        if (!it->HasMember("prr")) {
            sendErrorRes(id, "ERROR", "Malformed message: no prr");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }

        const Value& subjectv = (*it)["subject"];
        const Value& puriv = (*it)["policy_uri"];
        if (!subjectv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: subject is not a string");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }
        if (!puriv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: policy_uri is not a string");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }

        const Value& prrv = (*it)["prr"];
        if (!prrv.IsInt64()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: prr is not an integer");
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }
        int64_t lifetime = prrv.GetInt64();
        modb::URI puri(puriv.GetString());
        conn->addUri(puri, lifetime);
        try {
            const modb::ClassInfo& ci =
                server->getStore().getClassInfo(subjectv.GetString());
            modb::reference_t mo(ci.getId(), puri);

            {
                boost::lock_guard<boost::mutex> guard(resolutionMutex);
                if (resolutions.find(mo) == resolutions.end())
                    found = false;
                resolutions.insert(mo);
            }
            mos.push_back(mo);
            // see if resolved MO is present for stats tracking
            StoreClient& client = *server->getSystemClient();
            std::shared_ptr<const modb::mointernal::ObjectInstance> oi;
            client.get(ci.getId(), puri, oi);
            if (!oi) {
                conn->getOpflexStats()->incrPolUnavailableResolves();
            }
        } catch (const std::out_of_range& e) {
            sendErrorRes(id, "ERROR",
                         std::string("Unknown subject: ") +
                         subjectv.GetString());
            conn->getOpflexStats()->incrPolResolveErrs();
            return;
        }
    }

    if (flakyMode && !found) {
        LOG(INFO) << "Flaking out";
        return;
    }

    PolicyResolveRes* res =
        new PolicyResolveRes(id, *server, mos);
    getConnection()->sendMessage(res, true);
}

void OpflexServerHandler::handlePolicyUnresolveReq(const rapidjson::Value& id,
                                                   const rapidjson::Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got policy_unresolve req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrPolUnresolves();
    Value::ConstValueIterator it;
    for (it = payload.Begin(); it != payload.End(); ++it) {
        if (!it->IsObject()) {
            sendErrorRes(id, "ERROR", "Malformed message: not an object");
            conn->getOpflexStats()->incrPolUnresolveErrs();
            return;
        }
        if (!it->HasMember("subject")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint");
            conn->getOpflexStats()->incrPolUnresolveErrs();
            return;
        }
        if (it->HasMember("policy_ident")) {
            sendErrorRes(id, "EUNSUPPORTED",
                         "Policy resolution by ident is not supported");
            conn->getOpflexStats()->incrPolUnresolveErrs();
            return;
        }
        if (!it->HasMember("policy_uri")) {
            sendErrorRes(id, "ERROR", "Malformed message: no policy_uri");
            conn->getOpflexStats()->incrPolUnresolveErrs();
            return;
        }

        const Value& subjectv = (*it)["subject"];
        const Value& puriv = (*it)["policy_uri"];
        if (!subjectv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: subject is not a string");
            conn->getOpflexStats()->incrPolUnresolveErrs();
            return;
        }
        if (!puriv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: policy_uri is not a string");
            conn->getOpflexStats()->incrPolUnresolveErrs();
            return;
        }

        try {
            const modb::ClassInfo& ci =
                server->getStore().getClassInfo(subjectv.GetString());
            modb::URI puri(puriv.GetString());
            {
                boost::lock_guard<boost::mutex> guard(resolutionMutex);
                resolutions.erase(std::make_pair(ci.getId(), puri));
            }
            conn->clearUri(puri);
        } catch (const std::out_of_range& e) {
            sendErrorRes(id, "ERROR",
                         std::string("Unknown subject: ") +
                         subjectv.GetString());
            conn->getOpflexStats()->incrPolUnresolveErrs();
            return;
        }
    }

    OpflexMessage* res =
        new GenericOpflexMessage("policy_unresolve",
                                 OpflexMessage::RESPONSE, &id);
    getConnection()->sendMessage(res, true);
}

void OpflexServerHandler::handleEPDeclareReq(const rapidjson::Value& id,
                                             const rapidjson::Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got endpoint_declare req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrEpDeclares();
    StoreClient::notif_t notifs;
    StoreClient& client = *server->getSystemClient();
    MOSerializer& serializer = server->getSerializer();

    Value::ConstValueIterator it;
    for (it = payload.Begin(); it != payload.End(); ++it) {
        if (!it->IsObject()) {
            sendErrorRes(id, "ERROR", "Malformed message: not an object");
            conn->getOpflexStats()->incrEpDeclareErrs();
            return;
        }
        if (!it->HasMember("endpoint")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint");
            conn->getOpflexStats()->incrEpDeclareErrs();
            return;
        }
        if (!it->HasMember("prr")) {
            sendErrorRes(id, "ERROR", "Malformed message: no prr");
            conn->getOpflexStats()->incrEpDeclareErrs();
            return;
        }

        const Value& endpoint = (*it)["endpoint"];
        const Value& prr = (*it)["prr"];

        if (!endpoint.IsArray()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: endpoint is not an array");
            conn->getOpflexStats()->incrEpDeclareErrs();
            return;
        }
        if (!prr.IsInt()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: prr is not an integer");
            conn->getOpflexStats()->incrEpDeclareErrs();
            return;
        }

        Value::ConstValueIterator ep_it;
        for (ep_it = endpoint.Begin(); ep_it != endpoint.End(); ++ep_it) {
            const Value& mo = *ep_it;
            serializer.deserialize(mo, client, true, &notifs, false);
        }
    }
    if (flakyMode) {
        bool shouldFlake = false;
        for (const StoreClient::notif_t::value_type& v : notifs) {
            modb::reference_t r(v.second, v.first);
            if (declarations.find(r) == declarations.end()) {
                client.remove(v.second, v.first, false, NULL);
                declarations.insert(r);
                shouldFlake = true;
            }
        }
        if (shouldFlake) {
            LOG(INFO) << "Flaking out";
            return;
        }
    }
    client.deliverNotifications(notifs);

    OpflexMessage* res =
        new GenericOpflexMessage("endpoint_declare",
                                 OpflexMessage::RESPONSE, &id);
    conn->sendMessage(res, true);
}

void OpflexServerHandler::handleEPUndeclareReq(const rapidjson::Value& id,
                                               const rapidjson::Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got endpoint_unndeclare req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrEpUndeclares();
    StoreClient::notif_t notifs;
    StoreClient& client = *server->getSystemClient();

    Value::ConstValueIterator it;
    for (it = payload.Begin(); it != payload.End(); ++it) {
        if (!it->IsObject()) {
            sendErrorRes(id, "ERROR", "Malformed message: not an object");
            conn->getOpflexStats()->incrEpUndeclareErrs();
            return;
        }
        if (!it->HasMember("subject")) {
            sendErrorRes(id, "ERROR", "Malformed message: no subject");
            conn->getOpflexStats()->incrEpUndeclareErrs();
            return;
        }
        if (!it->HasMember("endpoint_uri")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint_uri");
            conn->getOpflexStats()->incrEpUndeclareErrs();
            return;
        }

        const Value& subjectv = (*it)["subject"];
        const Value& euriv = (*it)["endpoint_uri"];
        if (!subjectv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: subject is not a string");
            conn->getOpflexStats()->incrEpUndeclareErrs();
            return;
        }
        if (!euriv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: endpoint_uri is not a string");
            conn->getOpflexStats()->incrEpUndeclareErrs();
            return;
        }
        try {
            const modb::ClassInfo& ci =
                server->getStore().getClassInfo(subjectv.GetString());
            modb::URI euri(euriv.GetString());
            client.remove(ci.getId(), euri, false, &notifs);
            client.queueNotification(ci.getId(), euri, notifs);
        } catch (const std::out_of_range& e) {
            sendErrorRes(id, "ERROR",
                         std::string("Unknown subject: ") +
                         subjectv.GetString());
            conn->getOpflexStats()->incrEpUndeclareErrs();
            return;
        }

    }
    client.deliverNotifications(notifs);

    OpflexMessage* res =
        new GenericOpflexMessage("endpoint_undeclare",
                                 OpflexMessage::RESPONSE, &id);
    conn->sendMessage(res, true);
}

void OpflexServerHandler::handleEPResolveReq(const rapidjson::Value& id,
                                             const rapidjson::Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got endpoint_resolve req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrEpResolves();
    Value::ConstValueIterator it;
    std::vector<modb::reference_t> mos;
    for (it = payload.Begin(); it != payload.End(); ++it) {
        if (!it->IsObject()) {
            sendErrorRes(id, "ERROR", "Malformed message: not an object");
            conn->getOpflexStats()->incrEpResolveErrs();
            return;
        }
        if (!it->HasMember("subject")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint");
            conn->getOpflexStats()->incrEpResolveErrs();
            return;
        }
        if (it->HasMember("endpoint_ident")) {
            sendErrorRes(id, "EUNSUPPORTED",
                         "Endpoint resolution by ident is not supported");
            conn->getOpflexStats()->incrEpResolveErrs();
            return;
        }
        if (!it->HasMember("endpoint_uri")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint_uri");
            conn->getOpflexStats()->incrEpResolveErrs();
            return;
        }

        const Value& subjectv = (*it)["subject"];
        const Value& puriv = (*it)["endpoint_uri"];
        if (!subjectv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: subject is not a string");
            conn->getOpflexStats()->incrEpResolveErrs();
            return;
        }
        if (!puriv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: endpoint_uri is not a string");
            conn->getOpflexStats()->incrEpResolveErrs();
            return;
        }

        try {
            const modb::ClassInfo& ci =
                server->getStore().getClassInfo(subjectv.GetString());
            modb::URI puri(puriv.GetString());
            modb::reference_t mo(ci.getId(), puri);
            {
                boost::lock_guard<boost::mutex> guard(resolutionMutex);
                resolutions.insert(mo);
            }
            mos.push_back(mo);
        } catch (const std::out_of_range& e) {
            sendErrorRes(id, "ERROR",
                         std::string("Unknown subject: ") +
                         subjectv.GetString());
            conn->getOpflexStats()->incrEpResolveErrs();
            return;
        }
    }

    EndpointResolveRes* res =
        new EndpointResolveRes(id, *server, mos);
    conn->sendMessage(res, true);
}

void OpflexServerHandler::handleEPUnresolveReq(const rapidjson::Value& id,
                                               const rapidjson::Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got endpoint_unresolve req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrEpUnresolves();
    Value::ConstValueIterator it;
    for (it = payload.Begin(); it != payload.End(); ++it) {
        if (!it->IsObject()) {
            sendErrorRes(id, "ERROR", "Malformed message: not an object");
            conn->getOpflexStats()->incrEpUnresolveErrs();
            return;
        }
        if (!it->HasMember("subject")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint");
            conn->getOpflexStats()->incrEpUnresolveErrs();
            return;
        }
        if (it->HasMember("endpoint_ident")) {
            sendErrorRes(id, "EUNSUPPORTED",
                         "Endpoint resolution by ident is not supported");
            conn->getOpflexStats()->incrEpUnresolveErrs();
            return;
        }
        if (!it->HasMember("endpoint_uri")) {
            sendErrorRes(id, "ERROR", "Malformed message: no endpoint_uri");
            conn->getOpflexStats()->incrEpUnresolveErrs();
            return;
        }

        const Value& subjectv = (*it)["subject"];
        const Value& puriv = (*it)["endpoint_uri"];
        if (!subjectv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: subject is not a string");
            conn->getOpflexStats()->incrEpUnresolveErrs();
            return;
        }
        if (!puriv.IsString()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: endpoint_uri is not a string");
            conn->getOpflexStats()->incrEpUnresolveErrs();
            return;
        }

        try {
            const modb::ClassInfo& ci =
                server->getStore().getClassInfo(subjectv.GetString());
            modb::URI puri(puriv.GetString());
            {
                boost::lock_guard<boost::mutex> guard(resolutionMutex);
                resolutions.erase(std::make_pair(ci.getId(), puri));
            }
        } catch (const std::out_of_range& e) {
            sendErrorRes(id, "ERROR",
                         std::string("Unknown subject: ") +
                         subjectv.GetString());
            conn->getOpflexStats()->incrEpUnresolveErrs();
            return;
        }
    }

    OpflexMessage* res =
        new GenericOpflexMessage("endpoint_unresolve",
                                 OpflexMessage::RESPONSE, &id);
    conn->sendMessage(res, true);
}

void OpflexServerHandler::handleEPUpdateRes(uint64_t reqId,
                                            const rapidjson::Value& payload) {
    // nothing to do
}

void OpflexServerHandler::handleStateReportReq(const rapidjson::Value& id,
                                               const rapidjson::Value& payload) {
    OpflexServerConnection* conn = dynamic_cast<OpflexServerConnection*>(getConnection());
    if (!conn)
        return;

    LOG(DEBUG) << "Got state_report req from " << conn->getRemotePeer();
    conn->getOpflexStats()->incrStateReports();
    StoreClient::notif_t notifs;
    StoreClient& client = *server->getSystemClient();
    MOSerializer& serializer = server->getSerializer();

    Value::ConstValueIterator it;
    for (it = payload.Begin(); it != payload.End(); ++it) {
        if (!it->IsObject()) {
            sendErrorRes(id, "ERROR", "Malformed message: not an object");
            conn->getOpflexStats()->incrStateReportErrs();
            return;
        }
        if (!it->HasMember("observable")) {
            sendErrorRes(id, "ERROR", "Malformed message: no observable");
            conn->getOpflexStats()->incrStateReportErrs();
            return;
        }

        const Value& observable = (*it)["observable"];

        if (!observable.IsArray()) {
            sendErrorRes(id, "ERROR",
                         "Malformed message: observable is not an array");
            conn->getOpflexStats()->incrStateReportErrs();
            return;
        }

        Value::ConstValueIterator ep_it;
        for (ep_it = observable.Begin(); ep_it != observable.End(); ++ep_it) {
            const Value& mo = *ep_it;
            serializer.deserialize(mo, client, true, &notifs, false);
        }
    }
    client.deliverNotifications(notifs);

    OpflexMessage* res =
        new GenericOpflexMessage("state_report",
                                 OpflexMessage::RESPONSE, &id);
    conn->sendMessage(res, true);
}

bool OpflexServerHandler::hasResolution(modb::class_id_t class_id,
                                        const modb::URI& uri) {
    boost::lock_guard<boost::mutex> guard(resolutionMutex);
    return resolutions.find(std::make_pair(class_id, uri)) != resolutions.end();
}

} /* namespace internal */
} /* namespace engine */
} /* namespace opflex */
