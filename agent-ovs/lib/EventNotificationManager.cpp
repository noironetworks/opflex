/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Implementation for EventNotificationManager class.
 *
 * Copyright (c) 2024 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <opflexagent/EventNotificationManager.h>
#include <opflexagent/Agent.h>
#include <opflexagent/logging.h>

#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/filewritestream.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/error/en.h>

#include <boost/filesystem.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace opflexagent {

using std::string;
using std::unique_ptr;
using std::make_unique;
using std::lock_guard;
using std::mutex;
using boost::optional;
namespace fs = boost::filesystem;
using opflex::modb::URI;

EventNotificationManager::EventNotificationManager(Agent& agent_, 
                                                   const string& eventsDir_)
    : agent(agent_), eventsDir(eventsDir_), started(false) {
    fsWatcher = make_unique<FSWatcher>();
}

EventNotificationManager::~EventNotificationManager() {
    stop();
}

void EventNotificationManager::start() {
    if (started) return;

    if (eventsDir.empty()) {
        LOG(DEBUG) << "Events directory not configured, EventNotificationManager disabled";
        return;
    }

    if (!fs::exists(eventsDir)) {
        LOG(INFO) << "Events directory " << eventsDir << " does not exist, creating it";
        try {
            fs::create_directories(eventsDir);
        } catch (const fs::filesystem_error& e) {
            LOG(ERROR) << "Failed to create events directory: " << e.what();
            return;
        }
    }

    LOG(INFO) << "Starting EventNotificationManager with events directory: " << eventsDir;
    
    fsWatcher->addWatch(eventsDir, *this);
    fsWatcher->setInitialScan(true);
    fsWatcher->start();
    
    started = true;
}

void EventNotificationManager::stop() {
    if (!started) return;
    
    LOG(INFO) << "Stopping EventNotificationManager";
    fsWatcher->stop();
    
    lock_guard<mutex> guard(subscriptions_mutex);
    activeSubscriptions.clear();
    
    started = false;
}

void EventNotificationManager::setEventsDirectory(const string& eventsDir_) {
    eventsDir = eventsDir_;
}

void EventNotificationManager::updated(const fs::path& filePath) {
    string filename = filePath.filename().string();
    
    if (filename.size() < 14 || filename.substr(filename.size() - 14) != ".subscriptions") {
        return;
    }
    
    LOG(DEBUG) << "Subscription file updated: " << filePath;
    
    auto subscription = parseSubscriptionFile(filePath);
    if (subscription) {
        lock_guard<mutex> guard(subscriptions_mutex);
        activeSubscriptions[subscription->uuid] = std::move(subscription);
        LOG(INFO) << "Loaded subscription file: " << filePath;
    } else {
        LOG(ERROR) << "Failed to parse subscription file: " << filePath;
    }
}

void EventNotificationManager::deleted(const fs::path& filePath) {
    string filename = filePath.filename().string();
    
    if (filename.size() < 14 || filename.substr(filename.size() - 14) != ".subscriptions") {
        return;
    }
    
    LOG(DEBUG) << "Subscription file deleted: " << filePath;
    
    string prefix = filename.substr(0, filename.find(".subscriptions"));
    
    lock_guard<mutex> guard(subscriptions_mutex);
    for (auto it = activeSubscriptions.begin(); it != activeSubscriptions.end(); ++it) {
        if (it->second->filePath == filePath) {
            LOG(INFO) << "Removed subscription for UUID: " << it->first;
            activeSubscriptions.erase(it);
            break;
        }
    }
    
    fs::path notificationPath = getNotificationPath(filePath);
    if (fs::exists(notificationPath)) {
        try {
            fs::remove(notificationPath);
            LOG(DEBUG) << "Removed corresponding notification file: " << notificationPath;
        } catch (const fs::filesystem_error& e) {
            LOG(WARNING) << "Failed to remove notification file " << notificationPath 
                        << ": " << e.what();
        }
    }
}

void EventNotificationManager::handlePlatformConfigDeleted(const URI& uri) {
    lock_guard<mutex> guard(subscriptions_mutex);
    
    for (const auto& pair : activeSubscriptions) {
        const SubscriptionFile& subFile = *pair.second;
        
        for (const auto& subscription : subFile.subscriptions) {
            if (matchesSubscription(subscription, uri, SubscriptionState::DELETED)) {
                NotificationFile notification;
                notification.uuid = subFile.uuid;
                
                EventEntry event(uri);
                event.timestamp = getCurrentTimestamp(subFile.timeZone, subFile.timeFormat);
                event.state = SubscriptionState::DELETED;
                
                fs::path notificationPath = getNotificationPath(subFile.filePath);
                
                notification.events.push_back(event);
                
                writeNotificationFile(notification, notificationPath);
                LOG(INFO) << "Generated notification for PlatformConfig deleted event in: " 
                         << notificationPath;
                break;
            }
        }
    }
}

unique_ptr<EventNotificationManager::SubscriptionFile> 
EventNotificationManager::parseSubscriptionFile(const fs::path& filePath) {
    std::ifstream file(filePath.string());
    if (!file.is_open()) {
        LOG(ERROR) << "Could not open subscription file: " << filePath;
        return nullptr;
    }
    
    string content((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    file.close();
    
    rapidjson::Document document;
    document.Parse(content.c_str());
    
    if (document.HasParseError()) {
        LOG(ERROR) << "JSON parse error in " << filePath << ": " 
                  << rapidjson::GetParseError_En(document.GetParseError());
        return nullptr;
    }
    
    if (!document.IsObject() || !document.HasMember("uuid") || 
        !document.HasMember("subscriptions")) {
        LOG(ERROR) << "Invalid subscription file format: " << filePath;
        return nullptr;
    }
    
    auto result = make_unique<SubscriptionFile>();
    result->filePath = filePath;
    result->uuid = document["uuid"].GetString();
    
    if (document.HasMember("time-zone")) {
        result->timeZone = document["time-zone"].GetString();
    }
    
    if (document.HasMember("time-format")) {
        result->timeFormat = document["time-format"].GetString();
    }
    
    const auto& subscriptions = document["subscriptions"];
    if (!subscriptions.IsArray()) {
        LOG(ERROR) << "subscriptions field must be an array in: " << filePath;
        return nullptr;
    }
    
    for (const auto& sub : subscriptions.GetArray()) {
        if (!sub.IsObject() || !sub.HasMember("type") || !sub.HasMember("subject")) {
            LOG(WARNING) << "Skipping invalid subscription entry in: " << filePath;
            continue;
        }
        
        Subscription subscription;
        subscription.type = parseSubscriptionType(sub["type"].GetString());
        subscription.subject = sub["subject"].GetString();
        
        if (sub.HasMember("state")) {
            subscription.state = parseSubscriptionState(sub["state"].GetString());
        } else {
            subscription.state = SubscriptionState::ANY;
        }
        
        if (sub.HasMember("uri") && subscription.type == SubscrationType::URI) {
            try {
                subscription.uri = URI(sub["uri"].GetString());
            } catch (const std::exception& e) {
                LOG(WARNING) << "Invalid URI in subscription: " << sub["uri"].GetString();
                continue;
            }
        }
        
        result->subscriptions.push_back(subscription);
    }
    
    return result;
}

unique_ptr<EventNotificationManager::NotificationFile>
EventNotificationManager::parseNotificationFile(const fs::path& filePath) {
    std::ifstream file(filePath.string());
    if (!file.is_open()) {
        return nullptr;
    }
    
    string content((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    file.close();
    
    rapidjson::Document document;
    document.Parse(content.c_str());
    
    if (document.HasParseError() || !document.IsObject() ||
        !document.HasMember("uuid") || !document.HasMember("events")) {
        return nullptr;
    }
    
    auto result = make_unique<NotificationFile>();
    result->uuid = document["uuid"].GetString();
    
    const auto& events = document["events"];
    if (events.IsArray()) {
        for (const auto& event : events.GetArray()) {
            if (event.IsObject() && event.HasMember("uri") && 
                event.HasMember("timestamp") && event.HasMember("state")) {
                EventEntry entry(URI(event["uri"].GetString()));
                entry.timestamp = event["timestamp"].GetString();
                entry.state = parseSubscriptionState(event["state"].GetString());
                result->events.push_back(entry);
            }
        }
    }
    
    return result;
}

void EventNotificationManager::writeNotificationFile(const NotificationFile& notification,
                                                    const fs::path& filePath) {
    rapidjson::Document document;
    document.SetObject();
    auto& allocator = document.GetAllocator();
    
    document.AddMember("uuid", rapidjson::Value(notification.uuid.c_str(), allocator), allocator);
    
    rapidjson::Value events(rapidjson::kArrayType);
    for (const auto& event : notification.events) {
        rapidjson::Value eventObj(rapidjson::kObjectType);
        eventObj.AddMember("uri", rapidjson::Value(event.uri.toString().c_str(), allocator), allocator);
        eventObj.AddMember("timestamp", rapidjson::Value(event.timestamp.c_str(), allocator), allocator);
        eventObj.AddMember("state", rapidjson::Value(subscriptionStateToString(event.state).c_str(), allocator), allocator);
        events.PushBack(eventObj, allocator);
    }
    document.AddMember("events", events, allocator);
    
    FILE* fp = fopen(filePath.string().c_str(), "w");
    if (!fp) {
        LOG(ERROR) << "Could not open notification file for writing: " << filePath;
        return;
    }
    
    char writeBuffer[65536];
    rapidjson::FileWriteStream os(fp, writeBuffer, sizeof(writeBuffer));
    rapidjson::PrettyWriter<rapidjson::FileWriteStream> writer(os);
    document.Accept(writer);
    
    fclose(fp);
}

fs::path EventNotificationManager::getNotificationPath(const fs::path& subscriptionPath) {
    string filename = subscriptionPath.filename().string();
    string prefix = filename.substr(0, filename.find(".subscriptions"));
    return subscriptionPath.parent_path() / (prefix + ".notifications");
}

bool EventNotificationManager::matchesSubscription(const Subscription& subscription,
                                                  const URI& eventUri,
                                                  SubscriptionState eventState) {
    if (subscription.state != SubscriptionState::ANY && 
        subscription.state != eventState) {
        return false;
    }
    
    if (subscription.type == SubscrationType::URI) {
        return subscription.uri && subscription.uri.get() == eventUri;
    } else if (subscription.type == SubscrationType::CLASS) {
	// TODO: The implementation should probably get the MO from
	//       the MODB using the URI, and get the subject. This
	//       will do for now.
        vector<string> elements;
        eventUri.getElements(elements);
        auto rit = elements.rbegin();
        for (; rit != elements.rend(); ++rit) {
            if ((*rit) == subscription.subject) {
                return true;
            }
        }
    }
    
    return false;
}

string EventNotificationManager::getCurrentTimestamp(const optional<string>& timeZone,
                                                   const optional<string>& timeFormat) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    
    // Determine time format to use
    string format = "%Y-%m-%d %H:%M:%S";
    bool includeMs = true;
    
    if (timeFormat) {
        if (timeFormat.get() == "ISO8601") {
            format = "%Y-%m-%dT%H:%M:%S";
            includeMs = true;
        } else if (timeFormat.get() == "RFC3339") {
            format = "%Y-%m-%dT%H:%M:%S";
            includeMs = true;
        } else if (timeFormat.get() == "UNIX") {
            ss << time_t;
            if (includeMs) {
                ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
            }
            return ss.str();
        } else {
            format = timeFormat.get();
        }
    }
    
    // Handle timezone - for now, support UTC and local time
    std::tm* timeinfo;
    if (timeZone && timeZone.get() == "UTC") {
        timeinfo = std::gmtime(&time_t);
    } else {
        timeinfo = std::localtime(&time_t);
    }
    
    ss << std::put_time(timeinfo, format.c_str());
    
    if (includeMs && timeFormat && (timeFormat.get() == "ISO8601" || timeFormat.get() == "RFC3339")) {
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        if (timeZone && timeZone.get() == "UTC") {
            ss << "Z";
        }
    } else if (includeMs && (!timeFormat || timeFormat.get().find("%f") == string::npos)) {
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    }
    
    return ss.str();
}

EventNotificationManager::SubscriptionState 
EventNotificationManager::parseSubscriptionState(const string& stateStr) {
    if (stateStr == "created") return SubscriptionState::CREATED;
    if (stateStr == "updated") return SubscriptionState::UPDATED;
    if (stateStr == "deleted") return SubscriptionState::DELETED;
    return SubscriptionState::ANY;
}

string EventNotificationManager::subscriptionStateToString(SubscriptionState state) {
    switch (state) {
        case SubscriptionState::CREATED: return "created";
        case SubscriptionState::UPDATED: return "updated";
        case SubscriptionState::DELETED: return "deleted";
        case SubscriptionState::ANY: return "any";
    }
    return "any";
}

EventNotificationManager::SubscrationType 
EventNotificationManager::parseSubscriptionType(const string& typeStr) {
    if (typeStr == "uri") return SubscrationType::URI;
    return SubscrationType::CLASS;
}

} /* namespace opflexagent */
