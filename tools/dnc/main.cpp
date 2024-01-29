/*
 *  Copyright (C) 2023 Savoir-faire Linux Inc.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "dnc.h"
#include "common.h"
#include "dhtnet_crtmgr/dhtnet_crtmgr.h"

#include <string>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <getopt.h>
#if __has_include(<fmt/std.h>)
#include <fmt/std.h>
#else
#include <fmt/ostream.h>
#endif
#include <netinet/in.h>
#include <yaml-cpp/yaml.h>
#include <fstream>

struct dhtnc_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::filesystem::path privateKey {};
    std::filesystem::path ca {};
    std::string bootstrap {};
    std::string remote_host {};
    in_port_t remote_port {};
    dht::InfoHash peer_id {};
    std::string turn_host {};
    std::string turn_user {};
    std::string turn_pass {};
    std::string turn_realm {};
    std::string dnc_configuration {};
    bool anonymous_cnx {false};
};

static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"port", required_argument, nullptr, 'P'},
       {"ip", required_argument, nullptr, 'i'},
       {"listen", no_argument, nullptr, 'l'},
       {"bootstrap", required_argument, nullptr, 'b'},
       {"privateKey", required_argument, nullptr, 'p'},
       {"turn_host", required_argument, nullptr, 't'},
       {"turn_user", required_argument, nullptr, 'u'},
       {"turn_pass", required_argument, nullptr, 'w'},
       {"turn_realm", required_argument, nullptr, 'r'},
       {"CA", required_argument, nullptr, 'c'},
       {"dnc_configuration", required_argument, nullptr, 'd'},
       {"anonymous_cnx", no_argument, nullptr, 'a'},
       {nullptr, 0, nullptr, 0}};

dhtnc_params
parse_args(int argc, char** argv)
{
    dhtnc_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "ahvlw:r:u:t:P:b:p:i:c:d:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            params.help = true;
            break;
        case 'v':
            params.version = true;
            break;
        case 'P':
            params.remote_port = std::stoi(optarg);
            break;
        case 'i':
            params.remote_host = optarg;
            break;
        case 'l':
            params.listen = true;
            break;
        case 'b':
            params.bootstrap = optarg;
            break;
        case 'p':
            params.privateKey = optarg;
            break;
        case 't':
            params.turn_host = optarg;
            break;
        case 'u':
            params.turn_user = optarg;
            break;
        case 'w':
            params.turn_pass = optarg;
            break;
        case 'r':
            params.turn_realm = optarg;
            break;
        case 'c':
            params.ca = optarg;
            break;
        case 'd':
            params.dnc_configuration = optarg;
            break;
        case 'a':
            params.anonymous_cnx = true;
            break;
        default:
            std::cerr << "Invalid option" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // If not listening, the peer_id argument is required
    if (!params.listen && !params.help && !params.version) {
        if (optind < argc) {
            params.peer_id = dht::InfoHash(argv[optind]);
            optind++; // Move to the next argument
        } else {
            std::cerr << "Error: Missing peer_id argument.\n";
            exit(EXIT_FAILURE);
        }
    }

    // extract values from dnc yaml file
    if (!params.dnc_configuration.empty()) {
        printf("read configuration file: %s\n", params.dnc_configuration.c_str());
        std::ifstream config_file(params.dnc_configuration);
        if (!config_file.is_open()) {
            std::cerr << "Error: Could not open configuration file.\n";
        } else {
            YAML::Node config = YAML::Load(config_file);
            if (config["bootstrap"] && params.bootstrap.empty()) {
                params.bootstrap = config["bootstrap"].as<std::string>();
            }
            if (config["privateKey"] && params.privateKey.empty()) {
                params.privateKey = config["privateKey"].as<std::string>();
            }
            if (config["turn_host"] && params.turn_host.empty()) {
                params.turn_host = config["turn_host"].as<std::string>();
            }
            if (config["turn_user"] && params.turn_user.empty()) {
                params.turn_user = config["turn_user"].as<std::string>();
            }
            if (config["turn_pass"] && params.turn_pass.empty()) {
                params.turn_pass = config["turn_pass"].as<std::string>();
            }
            if (config["turn_realm"] && params.turn_realm.empty()) {
                params.turn_realm = config["turn_realm"].as<std::string>();
            }
            if (config["CA"] && params.ca.empty()) {
                params.ca = config["CA"].as<std::string>();
            }
            if (config["ip"] && params.remote_host.empty()) {
                params.dnc_configuration = config["ip"].as<std::string>();
            }
            if (config["port"] && params.remote_port == 0) {
                params.remote_port = config["port"].as<int>();
            }
            if (config["anonymous"] && !params.anonymous_cnx) {
                params.anonymous_cnx = config["anonymous"].as<bool>();
            }
        }
    }
    return params;
}

static void
setSipLogLevel()
{
    int level = 0;
    if (char* envvar = getenv("SIPLOGLEVEL")) {
        // From 0 (min) to 6 (max)
        level = std::clamp(std::stoi(envvar), 0, 6);
    }

    pj_log_set_level(level);
    pj_log_set_log_func([](int level, const char* data, int len) {
        fmt::print("{}", std::string_view(data, len));
    });
}

int
main(int argc, char** argv)
{
    setSipLogLevel();
    auto params = parse_args(argc, argv);

    if (params.help) {
        fmt::print("Usage: dnc [options] [PEER_ID]\n"
                   "\nOptions:\n"
                   "  -h, --help            Show this help message and exit.\n"
                   "  -v, --version         Display the program version.\n"
                   "  -P, --port            Specify the port option with an argument.\n"
                   "  -i, --ip              Specify the ip option with an argument.\n"
                   "  -l, --listen          Start the program in listen mode.\n"
                   "  -b, --bootstrap       Specify the bootstrap option with an argument.\n"
                   "  -p, --privateKey      Specify the privateKey option with an argument.\n"
                   "  -t, --turn_host       Specify the turn_host option with an argument.\n"
                   "  -u, --turn_user       Specify the turn_user option with an argument.\n"
                   "  -w, --turn_pass       Specify the turn_pass option with an argument.\n"
                   "  -r, --turn_realm      Specify the turn_realm option with an argument.\n"
                   "  -C, --CA              Specify the CA option with an argument.\n"
                   "  -d, --dnc_configuration Specify the dnc_configuration option with an argument.\n"
                   "  -a, --anonymous_cnx   Enable the anonymous mode.\n");
        return EXIT_SUCCESS;
    }

    if (params.version) {
        fmt::print("dnc v1.0\n");
        return EXIT_SUCCESS;
    }
    auto identity = dhtnet::loadIdentity(params.privateKey, params.ca);
    fmt::print("Loaded identity: {}\n", identity.second->getId());

    fmt::print("dnc 1.0\n");

    std::unique_ptr<dhtnet::Dnc> dhtnc;
    if (params.listen) {
        // create dnc instance
        dhtnc = std::make_unique<dhtnet::Dnc>(identity,
                                              params.bootstrap,
                                              params.turn_host,
                                              params.turn_user,
                                              params.turn_pass,
                                              params.turn_realm,
                                              params.anonymous_cnx);
    } else {
        dhtnc = std::make_unique<dhtnet::Dnc>(identity,
                                              params.bootstrap,
                                              params.peer_id,
                                              params.remote_host,
                                              params.remote_port,
                                              params.turn_host,
                                              params.turn_user,
                                              params.turn_pass,
                                              params.turn_realm);
    }
    dhtnc->run();
    return EXIT_SUCCESS;
}
