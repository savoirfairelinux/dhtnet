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

struct dhtnc_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::filesystem::path path {};
    std::string bootstrap {};
    std::string remote_host {};
    in_port_t remote_port {};
    dht::InfoHash peer_id {};
    std::string turn_host {};
    std::string turn_user {};
    std::string turn_pass {};
    std::string turn_realm {};
};

static const constexpr struct option long_options[] = {{"help", no_argument, nullptr, 'h'},
                                                       {"version", no_argument, nullptr, 'V'},
                                                       {"port", required_argument, nullptr, 'p'},
                                                       {"ip", required_argument, nullptr, 'i'},
                                                       {"listen", no_argument, nullptr, 'l'},
                                                       {"bootstrap", required_argument, nullptr, 'b'},
                                                       {"id_path", required_argument, nullptr, 'I'},
                                                       {"turn_host", required_argument, nullptr, 't'},
                                                       {"turn_user", required_argument, nullptr, 'u'},
                                                       {"turn_pass", required_argument, nullptr, 'w'},
                                                       {"turn_realm", required_argument, nullptr, 'r'},
                                                       {nullptr, 0, nullptr, 0}};

dhtnc_params
parse_args(int argc, char** argv)
{
    dhtnc_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hVlw:r:u:t:I:b:p:i:", long_options, nullptr)) != -1) {
        // fmt::print("opt: {} {}\n", opt, optarg);
        switch (opt) {
        case 'h':
            params.help = true;
            break;
        case 'V':
            params.version = true;
            break;
        case 'p':
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
    if (params.remote_port == 0)
        params.remote_port = 22;
    if (params.remote_host.empty())
        params.remote_host = "127.0.0.1";
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
    pj_log_set_log_func([](int level, const char* data, int /*len*/) {});
}

int
main(int argc, char** argv)
{
    fmt::print("dnc 1.0\n");
    setSipLogLevel();
    auto params = parse_args(argc, argv);
    auto identity = dhtnet::loadIdentity(params.path);
    fmt::print("Loaded identity: {} from {}\n", identity.second->getId(), params.path);

    std::unique_ptr<dhtnet::Dnc> dhtnc;
    if (params.listen) {
        // create dnc instance
        dhtnc = std::make_unique<dhtnet::Dnc>(params.path, identity, params.bootstrap, params.turn_host, params.turn_user, params.turn_pass, params.turn_realm);
    } else {
        dhtnc = std::make_unique<dhtnet::Dnc>(params.path,
                                              identity,
                                              params.bootstrap,
                                              params.peer_id,
                                              params.remote_host,
                                              params.remote_port
                                            //   params.turn_host,
                                            //   params.turn_user,
                                            //   params.turn_pass,
                                            //   params.turn_realm
                                            );
    }
    dhtnc->run();
    return EXIT_SUCCESS;
}
