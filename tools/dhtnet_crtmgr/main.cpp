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
#include "dhtnet_crtmgr.h"


#include <iostream>
#include <unistd.h>
#include <getopt.h>
#if __has_include(<fmt/std.h>)
#include <fmt/std.h>
#else
#include <fmt/ostream.h>
#endif


struct dhtnet_crtmgr_params
{
    bool help {false};
    bool version {false};
    std::filesystem::path ca {};
    std::filesystem::path id {};
    std::filesystem::path privatekey {};
    bool pkid {false};
    std::string name {};
    bool setup {false};
};
static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"CA", required_argument, nullptr, 'c'},
       {"id", required_argument, nullptr, 'i'},
       {"privatekey", required_argument, nullptr, 'p'},
       {"name", required_argument, nullptr, 'n'},
       {"pkid", no_argument, nullptr, 'g'},
       {"setup", no_argument, nullptr, 's'},
       {nullptr, 0, nullptr, 0}};

dhtnet_crtmgr_params
parse_args(int argc, char** argv)
{
    dhtnet_crtmgr_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hgsv:c:i:p:n:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            params.help = true;
            break;
        case 'v':
            params.version = true;
            break;
        case 'c':
            params.ca = optarg;
            break;
        case 'i':
            params.id = optarg;
            break;
        case 'p':
            params.privatekey = optarg;
            break;
        case 'g':
            params.pkid = true;
            break;
        case 'n':
            params.name = optarg;
            break;
        case 's':
            params.setup = true;
            break;
        default:
            std::cerr << "Invalid option" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    if (params.id.empty() && !params.pkid) {
        std::cerr << "Error: The path to save the generated identity is not provided.\n Please specify the path for saving the generated identity using the -i option.\n";        exit(EXIT_FAILURE);
    }
    return params;
}


int
main(int argc, char** argv)
{
    auto params = parse_args(argc, argv);

    if (params.help) {
        fmt::print("Usage: dhtnet-crtmgr [options]\n"
                "\nOptions:\n"
                "  -h, --help            Display this help message and then exit.\n"
                "  -v, --version         Show the version of the program.\n"
                "  -p, --privatekey      Provide the path to the private key as an argument.\n"
                "  -c, --CA              Provide the path to the Certificate Authority as an argument.\n"
                "  -i, --id              Provide the path where the generated identity should be saved as an argument.\n"
                "  -g, --pkid            Display the publickey id used by the server dnc.\n"
                "  -n, --name            Provide the name of the identity to be generated.\n"
                "  -s, --setup           Create an CA and an id.\n");
        return EXIT_SUCCESS;
    }

    if (params.version) {
        fmt::print("dhtnet-crtmgr v1.0\n");
        return EXIT_SUCCESS;
    }
    // check if the public key id is requested
    if (params.pkid) {
        if (params.ca.empty() || params.privatekey.empty()) {
            fmt::print(stderr, "Error: The path to the private key and the Certificate Authority is not provided.\n Please specify the path for the private key and the Certificate Authority using the -p and -c options.\n");
            exit(EXIT_FAILURE);
        }
        auto identity = dhtnet::loadIdentity(params.privatekey, params.ca);
        fmt::print("Public key id: {}\n", identity.second->getId());
        return EXIT_SUCCESS;
    }

    // check if the setup is requested
    if (params.setup) {
        // create CA  with name ca-server
        std::filesystem::path path_ca = params.id / "CA";
        auto ca = dhtnet::generateIdentity(path_ca, "ca-server");
        fmt::print("Generated CA in {}: {} {}\n", path_ca, "ca-server", ca.second->getId());
        // create identity with name id-server
        std::filesystem::path path_id = params.id / "id";
        auto identity = dhtnet::generateIdentity(path_id, "id-server", ca);
        fmt::print("Generated identity in {}: {} {}\n", path_id,"id-server", identity.second->getId());
        return EXIT_SUCCESS;
    }

    if (params.ca.empty() || params.privatekey.empty()) {
        if (params.name.empty()) {
            auto ca = dhtnet::generateIdentity(params.id, "ca");
            fmt::print("Generated CA in {}: {} {}\n", params.id, "ca", ca.second->getId());
        }else{
        auto ca = dhtnet::generateIdentity(params.id, params.name);
        fmt::print("Generated CA in {}: {} {}\n", params.id, params.name, ca.second->getId());
        }
    }else{
        auto ca = dhtnet::loadIdentity(params.privatekey, params.ca);
        if (params.name.empty()) {
            auto id = dhtnet::generateIdentity(params.id, "id", ca);
            fmt::print("Generated identity in {}: {} {}\n", params.id, "id", id.second->getId());
        }else{
            auto id = dhtnet::generateIdentity(params.id, params.name, ca);
            fmt::print("Generated identity in {}: {} {}\n", params.id, params.name, id.second->getId());
        }
    }
    return EXIT_SUCCESS;
}
