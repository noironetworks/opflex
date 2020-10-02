#include <opflexagent/logging.h>
#include <opflexagent/GbpBpfMaps.h>
#include <boost/program_options.hpp>

#include <string>
#include <memory>

using namespace opflexagent;
namespace po = boost::program_options;
using std::string;

std::shared_ptr<Conntrack4Map> conntrack4Map_ptr;
std::shared_ptr<Conntrack6Map> conntrack6Map_ptr;

int main(int argc, char** argv) {

    conntrack4Map_ptr = std::make_shared<Conntrack4Map>();
    conntrack6Map_ptr = std::make_shared<Conntrack6Map>();

    po::options_description desc("Allowed options");
    try {
        desc.add_options()
            ("help,h", "Print this help message")
            ("dump,d", "Dump specified maps")
            ("map,m", po::value<string>()->default_value(""),
             "name of the map to operate on")
            ("log", po::value<string>()->default_value(""),
             "Log to the specified file (default standard out)")
            ("level", po::value<string>()->default_value("warning"),
             "Use the specified log level (default warning)")
            ("syslog", "Log to syslog instead of file or standard out")
            ;
    } catch (const boost::bad_lexical_cast& e) {
        LOG(ERROR) << "exception while processing description: " << e.what();
        return 1;
    }

    bool log_to_syslog = false;
    string log_file;
    string level_str;
    string map_name;
    bool dump;
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
        log_file = vm["log"].as<string>();
        level_str = vm["level"].as<string>();
        if (vm.count("syslog")) {
            log_to_syslog = true;
        }
        if (vm.count("dump")) {
            dump = true;
        }
        map_name = vm["map"].as<string>();
    } catch (const po::unknown_option& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch (const std::bad_cast& e) {
        std::cerr << e.what() << std::endl;
        return 2;
    }

    initLogging(level_str, log_to_syslog, log_file, "map-ctrl");

    if (dump) {
        if (map_name == "conntrack4_map")
            conntrack4Map_ptr->dumpMap(std::cout);
        else if (map_name == "conntrack6_map")
            conntrack6Map_ptr->dumpMap(std::cout);
    }

    conntrack4Map_ptr.reset();
    conntrack6Map_ptr.reset();

    return 0;
}
