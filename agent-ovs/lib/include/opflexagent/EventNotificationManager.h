/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Include file for Event Notification Manager
 *
 * Copyright (c) 2024 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#pragma once
#ifndef OPFLEXAGENT_EVENTNOTIFICATIONMANAGER_H
#define OPFLEXAGENT_EVENTNOTIFICATIONMANAGER_H

#include <opflexagent/FSWatcher.h>
#include <opflex/modb/URI.h>

#include <boost/filesystem.hpp>
#include <boost/noncopyable.hpp>
#include <rapidjson/document.h>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>

namespace opflexagent {

class Agent;

/**
 * Manages event notifications based on subscription files and generates
 * notification files when subscribed events occur.
 */
class EventNotificationManager : private boost::noncopyable, 
                               public FSWatcher::Watcher {
public:
    /**
     * Construct a new EventNotificationManager
     *
     * @param agent Reference to the agent
     * @param eventsDir Path to the events directory containing subscription files
     */
    EventNotificationManager(Agent& agent, const std::string& eventsDir);

    /**
     * Destructor
     */
    virtual ~EventNotificationManager();

    /**
     * Start the event notification manager
     */
    void start();

    /**
     * Stop the event notification manager
     */
    void stop();

    /**
     * Set the events directory path
     *
     * @param eventsDir Path to the events directory
     */
    void setEventsDirectory(const std::string& eventsDir);

    /**
     * Handle platform config deleted event
     *
     * @param uri URI of the deleted platform config object
     */
    void handlePlatformConfigDeleted(const opflex::modb::URI& uri);

    // FSWatcher::Watcher interface
    virtual void updated(const boost::filesystem::path& filePath) override;
    virtual void deleted(const boost::filesystem::path& filePath) override;

private:
    /**
     * Subscription state for event notifications
     */
    enum class SubscriptionState {
        CREATED,
        UPDATED, 
        DELETED,
        ANY
    };

    /**
     * Subscription type for managed objects
     */
    enum class SubscriptionType {
        CLASS,
        URI
    };

    /**
     * Individual subscription entry
     */
    struct Subscription {
        SubscriptionType type;
        SubscriptionState state;
        boost::optional<opflex::modb::URI> uri;
        std::string subject;
    };

    /**
     * Complete subscription file contents
     */
    struct SubscriptionFile {
        std::string uuid;
        std::vector<Subscription> subscriptions;
        boost::filesystem::path filePath;
        boost::optional<std::string> timeZone;
        boost::optional<std::string> timeFormat;
    };

    /**
     * Event entry for notification files
     */
    struct EventEntry {
        opflex::modb::URI uri;
        std::string timestamp;
        SubscriptionState state;
        // Constructor taking a string to initialize uri_member
        EventEntry(const std::string& uri_str) : uri(uri_str) {};

        // Constructor taking an existing URI object
        EventEntry(const opflex::modb::URI& uri_obj) : uri(uri_obj) {};
    };

    /**
     * Notification file contents
     */
    struct NotificationFile {
        std::string uuid;
        std::vector<EventEntry> events;
    };

    /**
     * Parse a subscription file
     *
     * @param filePath Path to the subscription file
     * @return Parsed subscription data or nullptr if parsing failed
     */
    std::unique_ptr<SubscriptionFile> parseSubscriptionFile(
        const boost::filesystem::path& filePath);

    /**
     * Write a notification file
     *
     * @param notification Notification data to write
     * @param filePath Path where to write the notification file
     */
    void writeNotificationFile(const NotificationFile& notification,
                              const boost::filesystem::path& filePath);

    /**
     * Get the notification file path for a given subscription file
     *
     * @param subscriptionPath Path to the subscription file
     * @return Path to the corresponding notification file
     */
    boost::filesystem::path getNotificationPath(
        const boost::filesystem::path& subscriptionPath);

    /**
     * Check if a subscription matches the given event
     *
     * @param subscription The subscription to check
     * @param eventUri URI of the event
     * @param eventState State of the event
     * @return true if the subscription matches
     */
    bool matchesSubscription(const Subscription& subscription,
                           const opflex::modb::URI& eventUri,
                           SubscriptionState eventState);

    /**
     * Get current timestamp in log format
     *
     * @param timeZone Optional timezone specification (e.g., "UTC", "America/New_York")
     * @param timeFormat Optional time format specification (e.g., "%Y-%m-%d %H:%M:%S", "ISO8601")
     * @return Formatted timestamp string
     */
    std::string getCurrentTimestamp(const boost::optional<std::string>& timeZone = boost::none,
                                   const boost::optional<std::string>& timeFormat = boost::none);

    /**
     * Convert string to subscription state enum
     *
     * @param stateStr String representation of state
     * @return SubscriptionState enum value
     */
    SubscriptionState parseSubscriptionState(const std::string& stateStr);

    /**
     * Convert subscription state enum to string
     *
     * @param state SubscriptionState enum value
     * @return String representation
     */
    std::string subscriptionStateToString(SubscriptionState state);

    /**
     * Convert string to subscription type enum
     *
     * @param typeStr String representation of type
     * @return SubscriptionType enum value
     */
    SubscriptionType parseSubscriptionType(const std::string& typeStr);

    Agent& agent;
    std::string eventsDir;
    std::unique_ptr<FSWatcher> fsWatcher;
    
    std::mutex subscriptions_mutex;
    std::unordered_map<std::string, std::unique_ptr<SubscriptionFile>> activeSubscriptions;
    
    bool started;
};

} /* namespace opflexagent */

#endif /* OPFLEXAGENT_EVENTNOTIFICATIONMANAGER_H */
