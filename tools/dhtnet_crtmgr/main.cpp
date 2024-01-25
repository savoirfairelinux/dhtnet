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
    std::string ca {};
    std::string id {};
};
static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"CA", required_argument, nullptr, 'C'},
       {"id", required_argument, nullptr, 'i'},
       {nullptr, 0, nullptr, 0}};

dhtnet_crtmgr_params
parse_args(int argc, char** argv)
{
    dhtnet_crtmgr_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hv:C:i:", long_options, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            params.help = true;
            break;
        case 'v':
            params.version = true;
            break;
        case 'C':
            params.ca = optarg;
            break;
        case 'i':
            params.id = optarg;
            break;
        default:
            std::cerr << "Invalid option" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    if (params.ca.empty()) {

        std::cerr << "Error: Missing CA path argument.\n";
        exit(EXIT_FAILURE);
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
                   "  -h, --help            Show this help message and exit.\n"
                   "  -v, --version         Display the program version.\n"
                   "  -C, --CA              Specify the CA path option with an argument.\n"
                   "  -i, --id              Specify the id path option with an argument.\n");
        return EXIT_SUCCESS;
    }

    if (params.version) {
        fmt::print("dhtnet-crtmgr v1.0\n");
        return EXIT_SUCCESS;
    }

    if (params.id.empty()) {
        dhtnet::generateCA(params.ca);
        fmt::print("CA generated in {}\n", params.ca);
        return EXIT_SUCCESS;
    }else{
        dhtnet::generateIdentity(params.id, params.ca);
        fmt::print("Identity generated in {}\n", params.id);
        return EXIT_SUCCESS;
    }

}
