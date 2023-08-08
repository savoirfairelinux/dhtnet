#include "dnc.h"

#include <string>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <getopt.h>

#include <netinet/in.h>

struct dhtnc_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::string ip_add {};
    std::string bootstrap_ip {};
    std::string bootstrap_port {};
    in_port_t port {};
    dht::InfoHash peer_id {};
};

static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"port", required_argument, nullptr, 'p'},
       {"ip", required_argument, nullptr, 'i'},
       {"listen", no_argument, nullptr, 'l'},
       {"bootstrap_ip", required_argument, nullptr, 'b'},
       {"bootstrap_port", required_argument, nullptr, 'P'},
       {nullptr, 0, nullptr, 0}};

dhtnc_params
parse_args(int argc, char** argv)
{
    dhtnc_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvp:i:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            params.help = true;
            break;
        case 'v':
            params.version = true;
            break;
        case 'p':
            params.port = std::stoi(optarg);
            break;
        case 'i':
            params.ip_add = optarg;
            break;
        case 'l':
            params.listen = true;
            break;
        case 'b':
            params.bootstrap_ip = optarg;
            break;
        case 'P':
            params.bootstrap_port = optarg;
            break;
        default:
            std::cerr << "Invalid option" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // If not listening, the peer_id argument is required
    if (!params.listen) {
        if (optind < argc) {
            params.peer_id = dht::InfoHash(argv[optind]);
            optind++; // Move to the next argument
        } else {
            std::cerr << "Error: Missing peer_id argument.\n";
            exit(EXIT_FAILURE);
        }
    }

    // default values
    if (params.port == 0)
        params.port = 22;
    if (params.ip_add.empty())
        params.ip_add = "127.0.0.1";
    if (params.bootstrap_ip.empty())
        params.bootstrap_ip = "bootstrap.jami.net";
    if (params.bootstrap_port.empty())
        params.bootstrap_port = "4222";
    return params;
}

static void
setSipLogLevel()
{
    char* envvar = getenv("SIPLOGLEVEL");

    int level = 0;

    if (envvar != nullptr) {
        level = std::stoi(envvar);

        // From 0 (min) to 6 (max)
        level = std::max(0, std::min(level, 6));
    }

    pj_log_set_level(level);
    pj_log_set_log_func([](int level, const char* data, int /*len*/) {
    });
}

int
main(int argc, char** argv)
{
    setSipLogLevel();
    auto params = parse_args(argc, argv);
    auto identity = dhtnet::loadIdentity();

    std::unique_ptr<dhtnet::Dnc> dhtnc;
    if (params.listen) {
        // create dnc instance
        dhtnc = std::make_unique<dhtnet::Dnc>(identity, params.bootstrap_ip, params.bootstrap_port);
    } else {
        dhtnc = std::make_unique<dhtnet::Dnc>(identity,
                                              params.bootstrap_ip,
                                              params.bootstrap_port,
                                              params.peer_id,
                                              params.port,
                                              params.ip_add);
    }
    fmt::print("DhtNC 1.0\n");
    fmt::print("Loaded identity: {}\n", identity.second->getId());
    dhtnc->run();
}
