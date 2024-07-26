/* -*- C++ -*-; c-basic-offset: 4; indent-tabs-mode: nil */
/*
 * Main implementation for OVS agent
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
#include <opflexagent/Agent.h>
#include <opflexagent/cmd.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/program_options.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/line.hpp>

#include <condition_variable>

using std::string;
namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
using namespace opflexagent;

#define DEFAULT_CONF SYSCONFDIR"/opflex-agent-ovs/opflex-agent-ovs.conf"

class strip_comments : public boost::iostreams::line_filter {
private:
    std::string do_filter(const std::string& line) override {
        // for now we only support comments that begin the line
        auto trimmed = line;
        boost::trim(trimmed);
        if (boost::starts_with(trimmed, "#") ||
            boost::starts_with(trimmed, "//")) {
            return std::string();
        }
        return line;
    }
};

static void readConfig(Agent& agent, const string& configFile) {
    pt::ptree properties;

    LOG(INFO) << "Reading configuration from " << configFile;

    std::ifstream file(configFile, std::ios_base::in | std::ios_base::binary);
    boost::iostreams::filtering_streambuf<boost::iostreams::input> inbuf;
    inbuf.push(strip_comments());
    inbuf.push(file);
    std::istream instream(&inbuf);

    try {
        pt::read_json(instream, properties);
    } catch (pt::json_parser_error& e) {
        LOG(ERROR) << "Error parsing config file: " << configFile << "("
                   << e.line() << "): " << e.message();
        throw;
    }
    agent.setProperties(properties);
}

bool isConfigPath(const fs::path& file) {
    const string fstr = file.filename().string();
    if (boost::algorithm::ends_with(fstr, ".conf") &&
        !boost::algorithm::starts_with(fstr, ".")) {
        return true;
    }

    return false;
}

bool isRebootConfigPath(const fs::path& file) {
    const string fstr = file.filename().string();
    if (boost::algorithm::ends_with(fstr, ".conf") &&
        (boost::algorithm::starts_with(fstr, "reboot") ||
         boost::algorithm::starts_with(fstr, "reset"))) {
        LOG(INFO) << "Config filename: " << fstr;
        return true;
    }
    return false;
}

class AgentLauncher : FSWatcher::Watcher {
public:
    AgentLauncher(bool watch_, std::vector<string>& configFiles_,
    LogParams &logParams_)
        : watch(watch_), configFiles(configFiles_),
          stopped(false), need_reload(false), need_reset(false), logParams(logParams_){}

    int run() {
        try {
            FSWatcher configWatcher;

            addWatches(configWatcher);
            configWatcher.setInitialScan(false);
            configWatcher.start();

            while (true) {
                std::unique_lock<std::mutex> lock(mutex);
                opflex::ofcore::OFFramework framework;
                Agent agent(framework, logParams);

                configure(agent);
                agent.start();

                while (true) {
                    cond.wait(lock, [this]{ return stopped || need_reload || need_reset; });
                    if (stopped) {
                        break;
                    }
                    if (!stopped && need_reload) {
                        LOG(INFO) << "Reloading agent because of " <<
                            "configuration update";
                        break;
                    }
                    if (!stopped && need_reset) {
                        if (agent.shouldReset()) {
                            LOG(WARNING) << "Disconnect from existing peers and " <<
                                "fallback to configured list because of configuration update";
                            framework.resetAllUnconfiguredPeers();
                        }
                        need_reset = false;
                        continue;
                    }
                }

                agent.stop();

                if (stopped) {
                    configWatcher.stop();
                    return 0;
                }
                need_reload = false;
            }

        } catch (pt::json_parser_error& e) {
            return 4;
        } catch (const std::exception& e) {
            LOG(ERROR) << "Fatal error: " << e.what();
            return 2;
        } catch (...) {
            LOG(ERROR) << "Unknown fatal error";
            return 3;
        }
    }

    void updated(const boost::filesystem::path& filePath) override {
        if (!isConfigPath(filePath))
            return;

        if (filePath.filename() == "reset.conf") {
            LOG(INFO) << "Triggering peer reset because of change to " << filePath;
            std::unique_lock<std::mutex> lock(mutex);
            need_reset = true;
        } else {
            LOG(INFO) << "Triggering reload because of change to " << filePath;
            std::unique_lock<std::mutex> lock(mutex);
            need_reload = true;
        }
        cond.notify_all();
    }

    void deleted(const boost::filesystem::path& filePath) override {
        updated(filePath);
    }

    void stop() {
        {
            std::unique_lock<std::mutex> lock(mutex);
            stopped = true;
        }
        cond.notify_all();
    }

private:
    bool watch;
    std::vector<string>& configFiles;
    bool stopped;
    bool need_reload;
    bool need_reset;
    LogParams logParams;
    std::mutex mutex;
    std::condition_variable cond;

    void addWatches(FSWatcher& configWatcher) {
        if (!watch) return;
        for (const string& configFile : configFiles) {
            if (fs::is_directory(configFile)) {
                LOG(INFO) << "Watching configuration directory "
                          << configFile << " for changes";
                configWatcher.addWatch(configFile, *this);
            }
        }
    }

    void configure(Agent& agent) {
        for (const string& configFile : configFiles) {
            if (fs::is_directory(configFile)) {
                LOG(INFO) << "Reading configuration from config directory "
                          << configFile;

                fs::directory_iterator end;
                std::set<string> files;
                for (fs::directory_iterator it(configFile);
                     it != end; ++it) {
                    if (isConfigPath(it->path()) && !isRebootConfigPath(it->path())) {
                        files.insert(it->path().string());
                    }
                }
                for (const std::string& fstr : files) {
                    readConfig(agent, fstr);
                }
            } else {
                readConfig(agent, configFile);
            }
        }

        agent.applyProperties();
    }
};

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    // Parse command line options
    po::options_description desc("Allowed options");
    try {
        desc.add_options()
            ("help,h", "Print this help message")
            ("version,v", "print version information and git hash")
            ("config,c",
             po::value<std::vector<string> >(),
             "Read configuration from the specified files or directories")
            ("watch,w", "Watch configuration directories for changes")
            ("log", po::value<string>()->default_value(""),
             "Log to the specified file (default standard out)")
            ("drop_log", po::value<string>()->default_value(""),
             "Log drops to the specified file (default standard out)")
            ("level", po::value<string>()->default_value("info"),
             "Use the specified log level (default info). "
             "Overridden by log level in configuration file")
            ("syslog", "Log to syslog instead of file or standard out")
            ("drop_log_syslog", "Log drops to syslog instead of file or standard out")
            ("daemon", "Run the agent as a daemon");
    } catch (const boost::bad_lexical_cast& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    bool daemon = false;
    bool watch = false;
    bool logToSyslog = false,dropLogSyslog = false;
    std::string log_file, dropLogFile;
    std::string level_str;

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
        if (vm.count("version")) {
            std::cout << "version = " << PACKAGE_VERSION
                      << " last git commit hash = " << GITHASH << "\n";
            return 0;
        }
        if (vm.count("daemon")) {
            daemon = true;
        }
        if (vm.count("watch")) {
            watch = true;
        }
        log_file = vm["log"].as<string>();
        dropLogFile = vm["drop_log"].as<string>();
        level_str = vm["level"].as<string>();
        if (vm.count("drop_log_syslog")) {
            dropLogSyslog = true;
        }
        if (vm.count("syslog")) {
            logToSyslog = true;
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 2;
    }

    if (daemon)
        daemonize();

    initLogging(level_str, logToSyslog, log_file);
    initDropLogging(dropLogSyslog, dropLogFile);

    // Initialize agent and configuration
    std::vector<string> configFiles;
    if (vm.count("config"))
        try {
            configFiles = vm["config"].as<std::vector<string> >();
        } catch (const boost::bad_any_cast& e) {
            std::cerr << e.what() << std::endl;
            return 4;
        }
    else
        configFiles.push_back(DEFAULT_CONF);

    sigset_t waitset;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIGINT);
    sigaddset(&waitset, SIGTERM);
    sigprocmask(SIG_BLOCK, &waitset, nullptr);
    LogParams _logParams = std::make_tuple(level_str, logToSyslog, log_file);
    AgentLauncher launcher(watch, configFiles, _logParams);
    std::thread signal_thread([&launcher, &waitset]() {
            int sig;
            int result = sigwait(&waitset, &sig);
            if (result == 0) {
                LOG(INFO) << "Got " << strsignal(sig) << " signal";
            } else {
                LOG(ERROR) << "Failed to wait for signals: " << errno;
            }
            launcher.stop();
        });

    int rc = launcher.run();
    if (rc) exit(rc);
    signal_thread.join();
    return 0;
}
