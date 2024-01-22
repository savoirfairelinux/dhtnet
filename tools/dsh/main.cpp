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
#include "dsh.h"
#include "../common.h"
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

struct dhtsh_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::filesystem::path path {};
    std::string bootstrap {};
    dht::InfoHash peer_id {};
    std::string binary {};
    std::string ca {};
    std::string turn_host {};
    std::string turn_user {};
    std::string turn_pass {};
    std::string turn_realm {};
    std::string dsh_configuration {};
};

static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"listen", no_argument, nullptr, 'l'},
       {"bootstrap", required_argument, nullptr, 'b'},
       {"binary", required_argument, nullptr, 's'},
       {"id_path", required_argument, nullptr, 'I'},
       {"CA", required_argument, nullptr, 'C'},
       {"turn_host", required_argument, nullptr, 't'},
       {"turn_user", required_argument, nullptr, 'u'},
       {"turn_pass", required_argument, nullptr, 'w'},
       {"turn_realm", required_argument, nullptr, 'r'},
       {"dsh_configuration", required_argument, nullptr, 'd'},
       {nullptr, 0, nullptr, 0}};

dhtsh_params
parse_args(int argc, char** argv)
{
    dhtsh_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvls:I:p:i:C:r:w:u:t:d:", long_options, nullptr)) != -1) {
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
        case 'C':
            params.ca = optarg;
            break;
        case 'd':
            params.dsh_configuration = optarg;
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

    // default values
    if (params.bootstrap.empty())
        params.bootstrap = "bootstrap.jami.net";
    if (params.binary.empty())
        params.binary = "bash";
    if (params.path.empty())
        params.path = std::filesystem::path(getenv("HOME")) / ".dhtnet";
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
    pj_log_set_log_func([](int level, const char* data, int /*len*/) {});
}

int
main(int argc, char** argv)
{
    setSipLogLevel();
    auto params = parse_args(argc, argv);

    if (params.help){
        fmt::print("Usage: dsh [OPTIONS] [PEER_ID]\n"
                   "\nOptions:\n"
                   "  -h, --help            Show this help message and exit.\n"
                   "  -v, --version         Display the program version.\n"
                   "  -l, --listen          Start the program in listen mode.\n"
                   "  -b, --bootstrap       Specify the bootstrap option with an argument.\n"
                   "  -s, --binary          Specify the binary option with an argument.\n"
                   "  -I, --id_path         Specify the id_path option with an argument.\n"
                   "  -C, --CA              Specify the CA option with an argument.\n"
                   "  -t, --turn_host       Specify the turn_host option with an argument.\n"
                   "  -u, --turn_user       Specify the turn_user option with an argument.\n"
                   "  -w, --turn_pass       Specify the turn_pass option with an argument.\n"
                   "  -r, --turn_realm      Specify the turn_realm option with an argument.\n");
        return EXIT_SUCCESS;
    }
    if (params.version){
        fmt::print("dsh v1.0\n");
        return EXIT_SUCCESS;
    }

    fmt::print("dsh 1.0\n");

    auto identity = dhtnet::loadIdentity(params.path);
    fmt::print("Loaded identity: {} from {}\n", identity.second->getId(), params.path);

    std::unique_ptr<dhtnet::Dsh> dhtsh;
    if (params.listen) {
        // create dnc instance
        dhtsh = std::make_unique<dhtnet::Dsh>(params.path,
                                              identity,
                                              params.bootstrap,
                                              params.turn_host,
                                              params.turn_user,
                                              params.turn_pass,
                                              params.turn_realm);
    } else {
        dhtsh = std::make_unique<dhtnet::Dsh>(params.path,
                                              identity,
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
