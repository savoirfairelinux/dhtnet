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
#include <fmt/std.h>
#include <netinet/in.h>

struct dhtnc_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    bool verbose {false};
    std::filesystem::path path {};
    std::string bootstrap {};
    std::string remote_host {};
    in_port_t remote_port {};
    dht::InfoHash peer_id {};
};

static const constexpr struct option long_options[] = {{"help", no_argument, nullptr, 'h'},
                                                       {"version", no_argument, nullptr, 'V'},
                                                       {"verbose", no_argument, nullptr, 'v'},
                                                       {"port", required_argument, nullptr, 'p'},
                                                       {"ip", required_argument, nullptr, 'i'},
                                                       {"listen", no_argument, nullptr, 'l'},
                                                       {"bootstrap", required_argument, nullptr, 'b'},
                                                       {"id_path", required_argument, nullptr, 'I'},
                                                       {nullptr, 0, nullptr, 0}};

dhtnc_params
parse_args(int argc, char** argv)
{
    dhtnc_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvI:p:i:", long_options, nullptr)) != -1) {
        fmt::print("opt: {} {}\n", opt, optarg);
        switch (opt) {
        case 'h':
            params.help = true;
            break;
        case 'V':
            params.version = true;
            break;
        case 'v':
            params.verbose = true;
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
        params.remote_port = 2000;
    if (params.remote_host.empty())
        params.remote_host = "127.0.0.1";
    if (params.bootstrap.empty())
        params.bootstrap = "bootstrap.jami.net";
    if (params.path.empty())
        params.path = std::filesystem::path(getenv("HOME")) / ".dhtnet";
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
        dhtnc = std::make_unique<dhtnet::Dnc>(params.path, identity, params.bootstrap);
    } else {
        dhtnc = std::make_unique<dhtnet::Dnc>(params.path,
                                              identity,
                                              params.bootstrap,
                                              params.peer_id,
                                              params.remote_host,
                                              params.remote_port);
    }
    dhtnc->run();
    return EXIT_SUCCESS;
}
