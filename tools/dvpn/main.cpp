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
#include "dvpn.h"
#include "common.h"

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

struct dhtvpn_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::filesystem::path path {};
    std::string bootstrap {};
    dht::InfoHash peer_id {};
    std::string turn_host {};
    std::string turn_user {};
    std::string turn_pass {};
    std::string turn_realm {};
    std::string configuration_file {};
    std::string ca {};
    std::string dvpn_configuration_file {};
};

static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"listen", no_argument, nullptr, 'l'},
       {"bootstrap", required_argument, nullptr, 'b'},
       {"id_path", required_argument, nullptr, 'I'},
       {"turn_host", required_argument, nullptr, 't'},
       {"turn_user", required_argument, nullptr, 'u'},
       {"turn_pass", required_argument, nullptr, 'w'},
       {"turn_realm", required_argument, nullptr, 'r'},
       {"vpn_configuration_file", required_argument, nullptr, 'c'},
       {"CA", required_argument, nullptr, 'C'},
       {"dvpn_configuration_file", required_argument, nullptr, 'd'},
       {nullptr, 0, nullptr, 0}};

dhtvpn_params
parse_args(int argc, char** argv)
{
    dhtvpn_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvlw:r:u:t:I:b:c:C:d:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            params.help = true;
            break;
        case 'v':
            params.version = true;
            break;
        case 'l':
            params.listen = true;
            break;
        case 'b':
            params.bootstrap = optarg;
            break;
        case 'I':
            params.path = optarg;
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
            params.configuration_file = optarg;
            break;
        case 'C':
            params.ca = optarg;
            break;
        case 'd':
            params.dvpn_configuration_file = optarg;
            break;
        default:
            std::cerr << "Invalid option" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
    // extract values from dvpn yaml file
    if (!params.dvpn_configuration_file.empty()) {
        printf("read configuration file: %s\n", params.dvpn_configuration_file.c_str());
        std::ifstream config_file(params.dvpn_configuration_file);
        if (!config_file.is_open()) {
            std::cerr << "Error: Could not open configuration file.\n";
        } else {
            YAML::Node config = YAML::Load(config_file);
            if (config["bootstrap"] && params.bootstrap.empty()) {
                params.bootstrap = config["bootstrap"].as<std::string>();
            }
            if (config["id_path"] && params.path.empty()) {
                params.path = config["id_path"].as<std::string>();
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
            if (config["configuration_file"] && params.configuration_file.empty()) {
                params.configuration_file = config["configuration_file"].as<std::string>();
            }
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

    // default values

    if (params.bootstrap.empty())
        params.bootstrap = "bootstrap.jami.net";
    if (params.path.empty())
        params.path = std::filesystem::path(getenv("HOME")) / ".dhtnet";
    if (params.turn_host.empty())
        params.turn_host = "turn.jami.net";
    if (params.turn_user.empty())
        params.turn_user = "ring";
    if (params.turn_pass.empty())
        params.turn_pass = "ring";
    if (params.turn_realm.empty())
        params.turn_realm = "ring";
    if (params.configuration_file.empty())
        params.configuration_file = std::filesystem::path(__FILE__).parent_path()/"test_config.yaml";

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
        fmt::print(
            "Usage: dvpn [options] [PEER_ID]\n"
            "\nOptions:\n"
            "  -h, --help            Show this help message and exit.\n"
            "  -v, --version         Display the program version.\n"
            "  -l, --listen          Start the program in listen mode.\n"
            "  -b, --bootstrap       Specify the bootstrap option with an argument.\n"
            "  -I, --id_path         Specify the id_path option with an argument.\n"
            "  -t, --turn_host       Specify the turn_host option with an argument.\n"
            "  -u, --turn_user       Specify the turn_user option with an argument.\n"
            "  -w, --turn_pass       Specify the turn_pass option with an argument.\n"
            "  -r, --turn_realm      Specify the turn_realm option with an argument.\n"
            "  -c, --vpn_configuration_file Specify the vpn_configuration_file path option with an argument.\n"
            "  -C, --CA              Specify the CA path option with an argument.\n"
            "  -d, --dvpn_configuration_file Specify the dvpn_configuration_file path option with an argument.\n"
            "\n");
        return EXIT_SUCCESS;
    }
    if (params.version) {
        fmt::print("dvpn v1.0\n");
        return EXIT_SUCCESS;
    }

    fmt::print("dvpn 1.0\n");

    auto identity = dhtnet::loadIdentity(params.path, params.ca);
    fmt::print("Loaded identity: {} from {}\n", identity.second->getId(), params.path);

    std::unique_ptr<dhtnet::Dvpn> dvpn;
    if (params.listen) {
        // create dvpn instance
        dvpn = std::make_unique<dhtnet::DvpnServer>(params.path,
                                                    identity,
                                                    params.bootstrap,
                                                    params.turn_host,
                                                    params.turn_user,
                                                    params.turn_pass,
                                                    params.turn_realm,
                                                    params.configuration_file);
    } else {
        dvpn = std::make_unique<dhtnet::DvpnClient>(params.peer_id,
                                                    params.path,
                                                    identity,
                                                    params.bootstrap,
                                                    params.turn_host,
                                                    params.turn_user,
                                                    params.turn_pass,
                                                    params.turn_realm,
                                                    params.configuration_file);
    }
    dvpn->run();
    return EXIT_SUCCESS;
}
