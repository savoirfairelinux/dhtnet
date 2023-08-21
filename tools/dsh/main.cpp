/*
 *  Copyright (C) 2004-2023 Savoir-faire Linux Inc.
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

struct dhtsh_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::string bootstrap_ip {};
    std::string bootstrap_port {};
    dht::InfoHash peer_id {};
    std::string binary {};
};

static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"listen", no_argument, nullptr, 'l'},
       {"bootstrap_ip", required_argument, nullptr, 'b'},
       {"bootstrap_port", required_argument, nullptr, 'P'},
       {"binary", required_argument, nullptr, 's'},
       {nullptr, 0, nullptr, 0}};

dhtsh_params
parse_args(int argc, char** argv)
{
    dhtsh_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvp:i:", long_options, nullptr)) != -1) {
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
            params.bootstrap_ip = optarg;
            break;
        case 'P':
            params.bootstrap_port = optarg;
            break;
        case 's':
            params.binary = optarg;
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
    if (params.bootstrap_ip.empty())
        params.bootstrap_ip = "bootstrap.jami.net";
    if (params.bootstrap_port.empty())
        params.bootstrap_port = "4222";
    if (params.binary.empty())
        params.binary = "bash";
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

    std::unique_ptr<dhtnet::Dsh> dhtsh;
    if (params.listen) {

        auto identity = dhtnet::loadIdentity(true);
        // create dnc instance
        dhtsh = std::make_unique<dhtnet::Dsh>(identity, params.bootstrap_ip, params.bootstrap_port);
        fmt::print("Dsh 0.1\n");
        fmt::print("Loaded identity: {}\n", identity.second->getId());
    } else {
        auto identity = dhtnet::loadIdentity(false);
        dhtsh = std::make_unique<dhtnet::Dsh>(identity,
                                              params.bootstrap_ip,
                                              params.bootstrap_port,
                                              params.peer_id,
                                              params.binary);
        fmt::print("Dsh 0.1\n");
        fmt::print("Loaded identity: {}\n", identity.second->getId());
    }

    dhtsh->run();
}
