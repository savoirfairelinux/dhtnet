/*
 *  Copyright (C) 2004-2025 Savoir-faire Linux Inc.
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

struct dhtvpn_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::filesystem::path privateKey {};
    std::string bootstrap {};
    dht::InfoHash peer_id {};
    std::string turn_host {};
    std::string turn_user {};
    std::string turn_pass {};
    std::string turn_realm {};
    std::string configuration_file {};
    std::filesystem::path cert {};
    std::string configuration {};
    bool anonymous_cnx {false};
};

static const constexpr struct option long_options[] = {
    {"help",              no_argument,       nullptr, 'h'},
    {"version",           no_argument,       nullptr, 'v'},
    {"listen",            no_argument,       nullptr, 'l'},
    {"bootstrap",         required_argument, nullptr, 'b'},
    {"privateKey",        required_argument, nullptr, 'p'},
    {"turn_host",         required_argument, nullptr, 't'},
    {"turn_user",         required_argument, nullptr, 'u'},
    {"turn_pass",         required_argument, nullptr, 'w'},
    {"turn_realm",        required_argument, nullptr, 'r'},
    {"vpn_configuration", required_argument, nullptr, 'C'},
    {"certificate",       required_argument, nullptr, 'c'},
    {"configuration",     required_argument, nullptr, 'd'},
    {"anonymous",         no_argument,       nullptr, 'a'},
    {nullptr,             0,                 nullptr, 0  }
};

dhtvpn_params
parse_args(int argc, char** argv)
{
    dhtvpn_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvlab:t:u:w:r:p:c:C:d:", long_options, nullptr)) != -1) {
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
        case 'a':
            params.anonymous_cnx = true;
            break;
        case 'b':
            params.bootstrap = optarg;
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
            params.cert = optarg;
            break;
        case 'p':
            params.privateKey = optarg;
            break;
        case 'C':
            params.configuration_file = optarg;
            break;
        case 'd':
            params.configuration = optarg;
            break;
        default:
            std::cerr << "Invalid option" << std::endl;
            exit(EXIT_FAILURE);
        }
    }
    // extract values from dvpn yaml file
    if (!params.configuration.empty()) {
        printf("read configuration file: %s\n", params.configuration.c_str());
        std::ifstream config_file(params.configuration);
        if (!config_file.is_open()) {
            std::cerr << "Error: Unable to open configuration file.\n";
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
            if (config["certificate"] && params.cert.empty()) {
                params.cert = config["certificate"].as<std::string>();
            }
            if (config["configuration_file"] && params.configuration_file.empty()) {
                params.configuration_file = config["configuration_file"].as<std::string>();
            }
            if (config["anonymous"] && !params.anonymous_cnx) {
                params.anonymous_cnx = config["anonymous"].as<bool>();
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
    pj_log_set_log_func([](int level, const char* data, int len) { Log("{}", std::string_view(data, len)); });
}

int
main(int argc, char** argv)
{
    setSipLogLevel();
    auto params = parse_args(argc, argv);

    if (params.help) {
        Log("Usage: dvpn [options] [PEER_ID]\n"
            "\nOptions:\n"
            "  -h, --help                      Show this help message and exit.\n"
            "  -v, --version                   Display the program version.\n"
            "  -l, --listen                    Start the program in listen mode.\n"
            "  -b, --bootstrap [ADDRESS]       Specify the bootstrap option with an argument.\n"
            "  -t, --turn_host [ADDRESS]       Specify the turn_host option with an argument.\n"
            "  -u, --turn_user [USER]          Specify the turn_user option with an argument.\n"
            "  -w, --turn_pass [SECRET]        Specify the turn_pass option with an argument.\n"
            "  -r, --turn_realm [REALM]        Specify the turn_realm option with an argument.\n"
            "  -C, --vpn_configuration [FILE]  Specify the vpn_configuration path option with an argument.\n"
            "  -c, --certificate [FILE]        Specify the certificate path option with an argument.\n"
            "  -p, --privateKey [FILE]         Specify the privateKey option with an argument.\n"
            "  -d, --configuration [FILE]      Specify the configuration path option with an argument.\n"
            "  -a, --anonymous                 Specify the anonymous option with an argument.\n"
            "\n");
        return EXIT_SUCCESS;
    }
    if (params.version) {
        Log("dvpn v1.0\n");
        return EXIT_SUCCESS;
    }

    Log("dvpn 1.0\n");

    auto identity = dhtnet::loadIdentity(params.privateKey, params.cert);
    if (!identity.first || !identity.second) {
        fmt::print(stderr, "Hint: To generate new identity files, run: dhtnet-crtmgr --interactive\n");
        return EXIT_FAILURE;
    }
    Log("Loaded identity: {}\n", identity.second->getId());

    std::unique_ptr<dhtnet::Dvpn> dvpn;
    if (params.listen) {
        // create dvpn instance
        dvpn = std::make_unique<dhtnet::DvpnServer>(identity,
                                                    params.bootstrap,
                                                    params.turn_host,
                                                    params.turn_user,
                                                    params.turn_pass,
                                                    params.turn_realm,
                                                    params.configuration_file,
                                                    params.anonymous_cnx);
    } else {
        dvpn = std::make_unique<dhtnet::DvpnClient>(params.peer_id,
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
