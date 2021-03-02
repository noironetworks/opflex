/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Opflex server
 *
 * Copyright (c) 2014 Cisco Systems, Inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <unistd.h>
#include <csignal>
#include <sys/inotify.h>

#include <string>
#include <vector>
#include <iostream>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include <modelgbp/dmtree/Root.hpp>
#include <modelgbp/metadata/metadata.hpp>
#include <opflex/test/GbpOpflexServer.h>
#include <opflex/ofcore/OFFramework.h>
#include <opflex/ofcore/OFConstants.h>

#include <opflexagent/logging.h>
#include <opflexagent/cmd.h>
#include <rapidjson/filereadstream.h>
#ifdef HAVE_GRPC_SUPPORT
#include "GbpClient.h"
#endif
#include <opflexagent/PrometheusManager.h>
#include <opflexagent/Agent.h>
#include "StatsIO.h"

using std::string;
using std::make_pair;
namespace po = boost::program_options;
using opflex::test::GbpOpflexServer;
using opflex::ofcore::OFConstants;
using namespace opflexagent;
using opflex::modb::Mutator;

void sighandler(int sig) {
    LOG(INFO) << "Got " << strsignal(sig) << " signal";
}

#define SERVER_ROLES \
        (OFConstants::POLICY_REPOSITORY |     \
         OFConstants::ENDPOINT_REGISTRY |     \
         OFConstants::OBSERVER)
#define LOCALHOST "127.0.0.1"
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
#define DEF_INSPECT_SOCKET LOCALSTATEDIR"/run/opflex-server-inspect.sock"

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    // Parse command line options
    po::options_description desc("Allowed options");
    try {
        desc.add_options()
            ("help,h", "Print this help message")
            ("log", po::value<string>()->default_value(""),
             "Log to the specified file (default standard out)")
            ("level", po::value<string>()->default_value("info"),
             "Use the specified log level (default info)")
            ("daemon", "Run the opflex server as a daemon")
            ("disable-prometheus", "Disable exporting metrics to prometheus")
            ("enable-prometheus-localhost", "Export prometheus port only on localhost")
            ("policy,p", po::value<string>()->default_value(""),
             "Read the specified policy file to seed the MODB")
            ("ssl_castore", po::value<string>()->default_value("/etc/ssl/certs/"),
             "Use the specified path or certificate file as the SSL CA store")
            ("ssl_key", po::value<string>()->default_value(""),
             "Enable SSL and use the private key specified")
            ("ssl_pass", po::value<string>()->default_value(""),
             "Use the specified password for the private key")
            ("gbp_sock", po::value<string>()->default_value(DEF_INSPECT_SOCKET),
             "Use the specified socket for gbp_inspect")
            ("peer", po::value<std::vector<string> >(),
             "A peer specified as hostname:port to return in identity response")
            ("transport_mode_proxies", po::value<std::vector<string> >(),
             "3 transport_mode_proxy IPv4 addresses specified to return "
             "in identity response")
            ("grpc_address", po::value<string>()->default_value("localhost:19999"),
             "GRPC server address for policy updates")
            ("grpc_conf", po::value<string>()->default_value(""),
             "GRPC config file, should be in same directory as policy file")
            ("prr_interval_secs", po::value<int>()->default_value(60),
             "How often to wakeup io thread to check for prr timeouts")
            ("stats_interval_secs", po::value<int>()->default_value(15),
             "How often to wakeup io thread to check for stats timeouts")
            ("server_port", po::value<int>()->default_value(8009),
             "Port on which server passively listens");
    } catch (const boost::bad_lexical_cast& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    bool daemon = false;
    bool enable_prometheus = true;
    bool enable_localhost_only = false;
    std::string log_file;
    std::string level_str;
    std::string policy_file;
    boost::filesystem::path pf_path;
    boost::filesystem::path pf_dir;
    std::string ssl_castore;
    std::string ssl_key;
    std::string ssl_pass;
    std::vector<std::string> peers;
    std::vector<std::string> transport_mode_proxies;
    int prr_interval_secs, stats_interval_secs, server_port;
#ifdef HAVE_GRPC_SUPPORT
    std::string grpc_address;
    std::string grpc_conf_file;
#endif
    std::string gbp_socket;
    char buf[EVENT_BUF_LEN];
    int fd, wd;

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv).
                  options(desc).run(), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << desc;
            return 0;
        }
        if (vm.count("daemon")) {
            daemon = true;
        }
        if (vm.count("disable-prometheus"))
            enable_prometheus = false;
        if (vm.count("enable-prometheus-localhost"))
            enable_localhost_only = true;
        log_file = vm["log"].as<string>();
        level_str = vm["level"].as<string>();
        policy_file = vm["policy"].as<string>();
        ssl_castore = vm["ssl_castore"].as<string>();
        ssl_key = vm["ssl_key"].as<string>();
        ssl_pass = vm["ssl_pass"].as<string>();
        gbp_socket = vm["gbp_sock"].as<string>();
        if (vm.count("peer"))
            peers = vm["peer"].as<std::vector<string> >();
        if(vm.count("transport_mode_proxies")) {
            transport_mode_proxies =
                vm["transport_mode_proxies"].as<std::vector<string>>();
        }
#ifdef HAVE_GRPC_SUPPORT
        grpc_conf_file = vm["grpc_conf"].as<string>();
        if (grpc_conf_file != "") {
            FILE* fp = fopen(grpc_conf_file.c_str(), "r");
            if (fp == NULL) {
                LOG(ERROR) << "Could not open grpc_conf file "
                           << grpc_conf_file << " for reading";
            } else {
                char buffer[1024];
                rapidjson::FileReadStream f(fp, buffer, sizeof(buffer));
                rapidjson::Document d;
                d.ParseStream<0, rapidjson::UTF8<>,
                    rapidjson::FileReadStream>(f);
                fclose(fp);
                if (d.IsObject()) {
                    if (d.HasMember("grpc-address")) {
                        const rapidjson::Value& grpc_addressv = d["grpc-address"];
                        if (grpc_addressv.IsString())
                            grpc_address = grpc_addressv.GetString();
                   }
                }
            }
        }
        if (grpc_address == "")
            grpc_address = vm["grpc_address"].as<string>();
#endif
        prr_interval_secs = vm["prr_interval_secs"].as<int>();
        stats_interval_secs = vm["stats_interval_secs"].as<int>();
        server_port = vm["server_port"].as<int>();
    } catch (const po::unknown_option& e) {
        std::cerr << e.what() << std::endl;
        return 2;
    } catch (const std::bad_cast& e) {
        std::cerr << e.what() << std::endl;
        return 3;
    }

    if (daemon)
        daemonize();

    initLogging(level_str, false /*syslog*/, log_file, "opflex-server");

    try {
        GbpOpflexServer::peer_vec_t peer_vec;
        for (const std::string& pstr : peers)
            peer_vec.push_back(make_pair(SERVER_ROLES, pstr));
        if (peer_vec.size() == 0)
            peer_vec.push_back(make_pair(SERVER_ROLES, LOCALHOST":"
                                         +std::to_string(server_port)));

        opflex::ofcore::OFFramework framework;
        framework.enableInspector(gbp_socket);
        framework.setModel(modelgbp::getMetadata());
        framework.start();

        Mutator mutator(framework, "init");
        std::shared_ptr<modelgbp::dmtree::Root> root =
            modelgbp::dmtree::Root::createRootElement(framework);
        Agent::createUniverse(root);
        mutator.commit();

        GbpOpflexServer server(server_port, SERVER_ROLES, peer_vec,
                               transport_mode_proxies,
                               framework.getStore(),
                               prr_interval_secs);
#ifdef HAVE_GRPC_SUPPORT
        LOG(INFO) << "Connecting to gbp-server at address: "
                  << grpc_address;
        GbpClient client(grpc_address, server);
#endif

        ServerPrometheusManager prometheusManager;
        if (enable_prometheus)
            prometheusManager.start(enable_localhost_only);
        StatsIO statsIO(prometheusManager,
                        server, framework, stats_interval_secs);
        statsIO.start();

        if (policy_file != "") {
            server.readPolicy(policy_file);
        }

        if (ssl_key != "") {
            server.enableSSL(ssl_castore, ssl_key, ssl_pass);
        }

        server.start();
        signal(SIGINT | SIGTERM, sighandler);
        fd = inotify_init();
        if (fd < 0) {
            LOG(ERROR) << "Could not initialize inotify: "
                       << strerror(errno);
            goto cleanup;
        }
        pf_path = policy_file;
        pf_dir = pf_path.parent_path();
        wd = inotify_add_watch(fd, pf_dir.c_str(), IN_CLOSE_WRITE);
        if (wd < 0) {
            LOG(ERROR) << "Could not add inotify watch for "
                       << policy_file << ": "
                       << strerror(errno);
            goto cleanup;
        } else {
            LOG(INFO) << "Watching policy/conf directory: "
                      << pf_dir;
        }
        while (true) {
            ssize_t len = read(fd, buf, sizeof buf);
            if (len < 0 && errno != EAGAIN) {
                LOG(ERROR) << "Error while reading inotify events: "
                           << strerror(errno);
                goto cleanup;
            }

            if (len < 0) continue;

            const struct inotify_event *event;
            for (char* ptr = buf; ptr < buf + len;
                 ptr += sizeof(struct inotify_event) + event->len) {
                 event = (const struct inotify_event *) ptr;

                if ((event->mask & IN_CLOSE_WRITE) && event->len > 0) {
                    LOG(INFO) << "Policy/Config dir modified : " << pf_dir;
                    statsIO.stop();
                    prometheusManager.stop();
#ifdef HAVE_GRPC_SUPPORT
                    client.Stop();
#endif
                    /* should be stopped after client */
                    server.stop();
                    framework.stop();
                    // Check argv[0] to curb LGTM warning:
                    // https://lgtm.com/rules/2163130737/
                    if (execv("/usr/local/bin/opflex_server", argv)) {
                        LOG(ERROR) << "opflex_server failed to restart self"
                                   << strerror(errno);
                        goto cleanup;
                    }
                } else {
                    break;
                }
            }
        }
cleanup:
        statsIO.stop();
        prometheusManager.stop();
#ifdef HAVE_GRPC_SUPPORT
        client.Stop();
#endif
        server.stop();
        framework.stop();
    } catch (const std::exception& e) {
        LOG(ERROR) << "Fatal error: " << e.what();
        return 4;
    } catch (...) {
        LOG(ERROR) << "Unknown fatal error";
        return 5;
    }
}
