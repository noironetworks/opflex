/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Test suite for EventNotificationManager
 *
 * Copyright (c) 2024 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

#include <boost/test/unit_test.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/operations.hpp>

#include <opflexagent/EventNotificationManager.h>
#include <opflexagent/test/BaseFixture.h>
#include <opflexagent/logging.h>

#include <fstream>
#include <thread>
#include <chrono>

namespace opflexagent {

using std::string;
using std::shared_ptr;
using opflex::modb::URI;
using opflex::modb::URIBuilder;

namespace fs = boost::filesystem;

class EventNotificationManagerFixture : public BaseFixture {
public:
    EventNotificationManagerFixture() 
        : BaseFixture(),
          temp_dir(fs::temp_directory_path() / fs::unique_path()),
          eventMgr(agent, temp_dir.string() + "/events") {
        
        fs::create_directories(temp_dir / "events");
        eventMgr.setEventsDirectory(temp_dir.string() + "/events");
    }
    
    virtual ~EventNotificationManagerFixture() {
        eventMgr.stop();
        fs::remove_all(temp_dir);
    }

    void writeSubscriptionFile(const string& filename, const string& content) {
        fs::path subscriptionPath = temp_dir / "events" / filename;
        std::ofstream file(subscriptionPath.string());
        file << content;
        file.close();
    }

    bool notificationFileExists(const string& filename) {
        fs::path notificationPath = temp_dir / "events" / filename;
        return fs::exists(notificationPath);
    }

    string readNotificationFile(const string& filename) {
        fs::path notificationPath = temp_dir / "events" / filename;
        if (!fs::exists(notificationPath)) {
            return "";
        }
        
        std::ifstream file(notificationPath.string());
        string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
        file.close();
        return content;
    }

protected:
    fs::path temp_dir;
    EventNotificationManager eventMgr;
};

BOOST_AUTO_TEST_SUITE(EventNotificationManager_test)

BOOST_FIXTURE_TEST_CASE(basic_startup_shutdown, EventNotificationManagerFixture) {
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    eventMgr.stop();
}

BOOST_FIXTURE_TEST_CASE(subscription_file_parsing, EventNotificationManagerFixture) {
    string subscriptionContent = R"({
        "uuid": "test-uuid-123",
        "subscriptions": [
            {
                "type": "class",
                "state": "deleted",
                "subject": "PlatformConfig"
            }
        ]
    })";
    
    writeSubscriptionFile("test.subscriptions", subscriptionContent);
    
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    URI platformConfigUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("test-config")
        .build();
    
    eventMgr.handlePlatformConfigDeleted(platformConfigUri);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(notificationFileExists("test.notifications"));
    
    string notificationContent = readNotificationFile("test.notifications");
    BOOST_CHECK(!notificationContent.empty());
    BOOST_CHECK(notificationContent.find("test-uuid-123") != string::npos);
    BOOST_CHECK(notificationContent.find("deleted") != string::npos);
    BOOST_CHECK(notificationContent.find("PolicyUniverse/PlatformConfig/test-config/") != string::npos);
}

BOOST_FIXTURE_TEST_CASE(uri_based_subscription, EventNotificationManagerFixture) {
    URI specificConfigUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("specific-config")
        .build();
    
    string subscriptionContent = R"({
        "uuid": "uri-test-uuid",
        "subscriptions": [
            {
                "type": "uri",
                "state": "deleted",
                "uri": ")" + specificConfigUri.toString() + R"(",
                "subject": "PlatformConfig"
            }
        ]
    })";
    
    writeSubscriptionFile("uri_test.subscriptions", subscriptionContent);
    
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Test with matching URI
    eventMgr.handlePlatformConfigDeleted(specificConfigUri);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(notificationFileExists("uri_test.notifications"));
    
    // Test with non-matching URI
    URI differentConfigUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("different-config")
        .build();
    
    // Remove existing notification file
    fs::remove(temp_dir / "events" / "uri_test.notifications");
    
    eventMgr.handlePlatformConfigDeleted(differentConfigUri);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(!notificationFileExists("uri_test.notifications"));
}

BOOST_FIXTURE_TEST_CASE(state_filtering, EventNotificationManagerFixture) {
    string subscriptionContent = R"({
        "uuid": "state-filter-uuid",
        "subscriptions": [
            {
                "type": "class",
                "state": "created",
                "subject": "PlatformConfig"
            }
        ]
    })";
    
    writeSubscriptionFile("state_filter.subscriptions", subscriptionContent);
    
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    URI configUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("test-config")
        .build();
    
    // Should not generate notification for deleted event when subscription is for created
    eventMgr.handlePlatformConfigDeleted(configUri);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(!notificationFileExists("state_filter.notifications"));
}

BOOST_FIXTURE_TEST_CASE(any_state_subscription, EventNotificationManagerFixture) {
    string subscriptionContent = R"({
        "uuid": "any-state-uuid",
        "subscriptions": [
            {
                "type": "class",
                "subject": "PlatformConfig"
            }
        ]
    })";
    
    writeSubscriptionFile("any_state.subscriptions", subscriptionContent);
    
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    URI configUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("test-config")
        .build();
    
    eventMgr.handlePlatformConfigDeleted(configUri);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(notificationFileExists("any_state.notifications"));
}

BOOST_FIXTURE_TEST_CASE(multiple_subscriptions, EventNotificationManagerFixture) {
    string subscription1 = R"({
        "uuid": "multi-uuid-1",
        "subscriptions": [
            {
                "type": "class",
                "state": "deleted",
                "subject": "PlatformConfig"
            }
        ]
    })";
    
    string subscription2 = R"({
        "uuid": "multi-uuid-2", 
        "subscriptions": [
            {
                "type": "class",
                "state": "deleted",
                "subject": "PlatformConfig"
            }
        ]
    })";
    
    writeSubscriptionFile("multi1.subscriptions", subscription1);
    writeSubscriptionFile("multi2.subscriptions", subscription2);
    
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    URI configUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("test-config")
        .build();
    
    eventMgr.handlePlatformConfigDeleted(configUri);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(notificationFileExists("multi1.notifications"));
    BOOST_CHECK(notificationFileExists("multi2.notifications"));
}

BOOST_FIXTURE_TEST_CASE(invalid_subscription_file, EventNotificationManagerFixture) {
    string invalidJson = R"({
        "invalid": "json structure"
    })";
    
    writeSubscriptionFile("invalid.subscriptions", invalidJson);
    
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    URI configUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("test-config")
        .build();
    
    // Should not crash or generate notification for invalid subscription
    eventMgr.handlePlatformConfigDeleted(configUri);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(!notificationFileExists("invalid.notifications"));
}

BOOST_FIXTURE_TEST_CASE(file_deletion, EventNotificationManagerFixture) {
    string subscriptionContent = R"({
        "uuid": "delete-test-uuid",
        "subscriptions": [
            {
                "type": "class",
                "state": "deleted",
                "subject": "PlatformConfig"
            }
        ]
    })";
    
    writeSubscriptionFile("delete_test.subscriptions", subscriptionContent);
    
    eventMgr.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Generate a notification first
    URI configUri = URIBuilder()
        .addElement("PolicyUniverse")
        .addElement("PlatformConfig")
        .addElement("test-config")
        .build();
    
    eventMgr.handlePlatformConfigDeleted(configUri);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    BOOST_CHECK(notificationFileExists("delete_test.notifications"));
    
    // Remove subscription file
    fs::remove(temp_dir / "events" / "delete_test.subscriptions");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Notification file should be removed as well
    BOOST_CHECK(!notificationFileExists("delete_test.notifications"));
}

BOOST_AUTO_TEST_SUITE_END()

} /* namespace opflexagent */
