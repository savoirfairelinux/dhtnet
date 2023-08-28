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

struct dhtsh_params
{
    bool help {false};
    bool version {false};
    bool listen {false};
    std::filesystem::path path {};
    std::string bootstrap {};
    dht::InfoHash peer_id {};
    std::string binary {};
};

static const constexpr struct option long_options[] = {{"help", no_argument, nullptr, 'h'},
                                                       {"version", no_argument, nullptr, 'v'},
                                                       {"listen", no_argument, nullptr, 'l'},
                                                       {"bootstrap", required_argument, nullptr, 'b'},
                                                       {"binary", required_argument, nullptr, 's'},
                                                       {"id_path", required_argument, nullptr, 'I'},
                                                       {nullptr, 0, nullptr, 0}};

dhtsh_params
parse_args(int argc, char** argv)
{
    dhtsh_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvIp:i:", long_options, nullptr)) != -1) {
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
    fmt::print("DSH 1.0\n");
    setSipLogLevel();
    auto params = parse_args(argc, argv);
    auto identity = dhtnet::loadIdentity(params.path);

    std::unique_ptr<dhtnet::Dsh> dhtsh;
    if (params.listen) {
        // create dnc instance
        dhtsh = std::make_unique<dhtnet::Dsh>(params.path, identity, params.bootstrap);
    } else {
        dhtsh = std::make_unique<dhtnet::Dsh>(params.path,
                                              identity,
                                              params.bootstrap,
                                              params.peer_id,
                                              params.binary);
    }

    dhtsh->run();
}
