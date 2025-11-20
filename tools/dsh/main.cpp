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
#include "dsh.h"
#include "../common.h"
#include "dhtnet_crtmgr/dhtnet_crtmgr.h"

#include <string>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <getopt.h>

#include <netinet/in.h>
#if __has_include(<fmt/std.h>)
#include <fmt/std.h>
#else
#include <fmt/ostream.h>
#endif
#include <yaml-cpp/yaml.h>
#include <fstream>

namespace {

struct dhtsh_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::filesystem::path privateKey {};
    std::string bootstrap {};
    dht::PkId peer_id {};
    std::string binary {};
    std::filesystem::path cert {};
    std::string turn_host {};
    std::string turn_user {};
    std::string turn_pass {};
    std::string turn_realm {};
    std::string configuration {};
    bool anonymous_cnx {false};
};

static const constexpr struct option long_options[] = {
    {"help",          no_argument,       nullptr, 'h'},
    {"version",       no_argument,       nullptr, 'v'},
    {"listen",        no_argument,       nullptr, 'l'},
    {"bootstrap",     required_argument, nullptr, 'b'},
    {"binary",        required_argument, nullptr, 's'},
    {"privateKey",    required_argument, nullptr, 'p'},
    {"certificate",   required_argument, nullptr, 'c'},
    {"turn_host",     required_argument, nullptr, 't'},
    {"turn_user",     required_argument, nullptr, 'u'},
    {"turn_pass",     required_argument, nullptr, 'w'},
    {"turn_realm",    required_argument, nullptr, 'r'},
    {"configuration", required_argument, nullptr, 'd'},
    {"anonymous",     no_argument,       nullptr, 'a'},
    {nullptr,         0,                 nullptr, 0  }
};

dhtsh_params
parse_args(int argc, char** argv)
{
    dhtsh_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvlab:s:p:c:r:w:u:t:d:", long_options, nullptr)) != -1) {
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
        case 's':
            params.binary = optarg;
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
            params.cert = optarg;
            break;
        case 'd':
            params.configuration = optarg;
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
            params.peer_id = dht::PkId(argv[optind]);
            optind++; // Move to the next argument
        } else {
            std::cerr << "Error: Missing peer_id argument.\n";
            exit(EXIT_FAILURE);
        }
    }

    // extract values from dsh yaml file
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
            if (config["binary"] && params.binary.empty()) {
                params.binary = config["binary"].as<std::string>();
            }
            if (config["anonymous"] && !params.anonymous_cnx) {
                params.anonymous_cnx = config["anonymous"].as<bool>();
            }
        }
    }
    return params;
}

void
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

} // namespace

int
main(int argc, char** argv)
{
    setSipLogLevel();
    auto params = parse_args(argc, argv);

    if (params.help) {
        Log("Usage: dsh [OPTIONS] [PEER_ID]\n"
            "\nOptions:\n"
            "  -h, --help                  Show this help message and exit.\n"
            "  -v, --version               Display the program version.\n"
            "  -l, --listen                Start the program in listen mode.\n"
            "  -b, --bootstrap [ADDRESS]   Specify the bootstrap option with an argument.\n"
            "  -s, --binary [COMMAND]      Specify the binary option with an argument.\n"
            "  -p, --privateKey [FILE]     Specify the privateKey option with an argument.\n"
            "  -c, --certificate [FILE]    Specify the certificate option with an argument.\n"
            "  -d, --configuration [FILE]  Specify the configuration file option with an argument.\n"
            "  -t, --turn_host [ADDRESS]   Specify the turn_host option with an argument.\n"
            "  -u, --turn_user [USER]      Specify the turn_user option with an argument.\n"
            "  -w, --turn_pass [SECRET]    Specify the turn_pass option with an argument.\n"
            "  -r, --turn_realm [REALM]    Specify the turn_realm option with an argument.\n"
            "  -a, --anonymous             Enable anonymous connection.\n");
        return EXIT_SUCCESS;
    }
    if (params.version) {
        Log("dsh v1.0\n");
        return EXIT_SUCCESS;
    }

    Log("dsh 1.0\n");

    auto identity = dhtnet::loadIdentity(params.privateKey, params.cert);
    if (!identity.first || !identity.second) {
        fmt::print(stderr, "Hint: To generate new identity files, run: dhtnet-crtmgr --interactive\n");
        return EXIT_FAILURE;
    }
    Log("Loaded identity: {} \n", identity.second->getId());

    std::unique_ptr<dhtnet::Dsh> dhtsh;
    if (params.listen) {
        // create dsh instance
        dhtsh = std::make_unique<dhtnet::Dsh>(identity,
                                              params.bootstrap,
                                              params.turn_host,
                                              params.turn_user,
                                              params.turn_pass,
                                              params.turn_realm,
                                              params.anonymous_cnx);
    } else {
        dhtsh = std::make_unique<dhtnet::Dsh>(identity,
                                              params.bootstrap,
                                              params.peer_id,
                                              params.binary,
                                              params.turn_host,
                                              params.turn_user,
                                              params.turn_pass,
                                              params.turn_realm);
    }

    dhtsh->run();
    return EXIT_SUCCESS;
}
