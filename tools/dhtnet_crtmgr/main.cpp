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
#include <fstream>
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
    bool interactive {false};
};
static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"CA", required_argument, nullptr, 'c'},
       {"id", required_argument, nullptr, 'o'},
       {"privatekey", required_argument, nullptr, 'p'},
       {"name", required_argument, nullptr, 'n'},
       {"pkid", no_argument, nullptr, 'g'},
       {"setup", no_argument, nullptr, 's'},
       {"interactive", no_argument, nullptr, 'i'},
       {nullptr, 0, nullptr, 0}};

dhtnet_crtmgr_params
parse_args(int argc, char** argv)
{
    dhtnet_crtmgr_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hgsvi:c:o:p:n:", long_options, nullptr)) != -1) {
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
        case 'o':
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
        case 'i':
            params.interactive = true;
            break;
        default:
            std::cerr << "Invalid option" << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    if (params.id.empty() && !params.pkid && !params.help && !params.version && !params.interactive) {
        std::cerr << "Error: The path to save the generated certificate is not provided.\n Please specify the path using the -o option.\n";
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
                "  -h, --help            Display this help message and then exit.\n"
                "  -v, --version         Show the version of the program.\n"
                "  -p, --privatekey      Provide the path to the private key as an argument.\n"
                "  -c, --certificate     Provide the path to the certificate  as an argument.\n"
                "  -o, --output          Provide the path where the generated certificate should be saved as an argument.\n"
                "  -g, --identifier      Display the user identifier.\n"
                "  -n, --name            Provide the name of the certificate to be generated.\n"
                "  -s, --setup           Create an CA and a certificate.\n");
                "  -i, --interactive     Interactively create and setup identities.\n");
        return EXIT_SUCCESS;
    }

    if (params.version) {
        fmt::print("dhtnet-crtmgr v1.0\n");
        return EXIT_SUCCESS;
    }
    // check if the public key id is requested
    if (params.pkid) {
        if (params.ca.empty() || params.privatekey.empty()) {
            fmt::print(stderr, "Error: The path to the private key and the certificate  is not provided.\n Please specify the path for the private key and the certificate  using the -p and -c options.\n");
            exit(EXIT_FAILURE);
        }
        auto identity = dhtnet::loadIdentity(params.privatekey, params.ca);
        fmt::print("Public key id: {}\n", identity.second->getId());
        return EXIT_SUCCESS;
    }

    // check if the interactive mode is requested
    if (params.interactive) {
        // Ask user if he want to setup client or server config
        std::string usage = "";
        do {
            std::cout << "Generate identity for server or client? [(s)erver/(c)lient] (recommended: client): ";
            std::cin >> usage;
        } while (usage != "s" && usage != "c" && usage != "server" && usage != "client");
        if (usage == "s") usage = "server";
        if (usage == "c") usage = "client";

        // In case user select client mode, Ask if we should sign using server CA (required for anonymous: false)
        std::string use_server_ca = "";
        if (usage == "client") {
            do {
                std::cout << "Sign client certificate using server CA? [(y)es/(n)o] (recommended: yes): ";
                std::cin >> use_server_ca;
            } while (use_server_ca != "y" && use_server_ca != "n" && use_server_ca != "yes" && use_server_ca != "no");
            if (use_server_ca == "y") use_server_ca = "yes";
            if (use_server_ca == "n") use_server_ca = "no";
        }

        // Before asking for save folder, pre-compute default locations
        std::filesystem::path home_dir = getenv("HOME");
        if (home_dir.empty()) home_dir = "/tmp/.dnc";
        else if (usage == "server") home_dir = "/etc/dhtnet";
        else home_dir = home_dir / ".dnc";

        std::string input_folder;
        std::getline(std::cin, input_folder); // pre-read: clean the buffer of \n remaining from std::cin >> usage;

        // Ask where to store identity files
        std::filesystem::path folder;
        std::cout << "Enter the path to save identities and config [" << home_dir << "]: ";
        std::getline(std::cin, input_folder);
        folder = input_folder;
        if (folder.empty()) {
            folder = home_dir;
        }
        folder = std::filesystem::absolute(folder);

        std::filesystem::create_directories(folder);
        if (usage == "client") {
            // Use existing CA or generate new CA
            dht::crypto::Identity ca;
            if (use_server_ca == "yes") {
                try {
                    std::filesystem::path server_ca = "/etc/dhtnet/CA";
                    ca = dhtnet::loadIdentity(server_ca / "ca-server.pem", server_ca / "ca-server.crt");
                }
                catch (const std::exception& e) {
                    fmt::print(stderr, "Error: Could not load server CA. Please generate server CA first.\n");
                    return EXIT_FAILURE;
                }
            } else {
                ca = dhtnet::generateIdentity(folder, "ca");
                fmt::print("Generated CA in {}: {} {}\n", folder, "ca", ca.second->getId());
            }

            // Generate client certificate
            auto id = dhtnet::generateIdentity(folder, "certificate", ca);
            fmt::print("Generated certificate in {}: {} {}\n", folder, "certificate", id.second->getId());

            // Create configuration file with generated keys
            std::filesystem::path yaml_config{folder / "config.yml"};
            std::ofstream yaml_file (yaml_config);
            if (yaml_file.is_open()) {
                yaml_file << "bootstrap: \"bootstrap.jami.net\"\n";
                yaml_file << "turn_host: \"turn.jami.net\"\n";
                yaml_file << "turn_user: \"ring\"\n";
                yaml_file << "turn_pass: \"ring\"\n";
                yaml_file << "turn_realm: \"ring\"\n";
                yaml_file << "\n# On client, identities are generaly saved in ~/.dnc/\n"
                yaml_file << "certificate: " << (folder / "certificate.crt") << "\n";
                yaml_file << "privateKey: " << (folder / "certificate.pem") << "\n";
                yaml_file.close();
                fmt::print("Configuration file created in {}\n", yaml_config);
            } else {
                fmt::print(stderr, "Error: Could not create configuration file {}.\n", yaml_config);
                return EXIT_FAILURE;
            }

            // Ask user if he want to configure SSH
            std::string ssh_setup = "";
            do {
                std::cout << "Configure SSH to support dnc protocol? [(y)es/(n)no] (recommended: yes): ";
                std::cin >> ssh_setup;
            } while (ssh_setup != "y" && ssh_setup != "n" && ssh_setup != "yes" && ssh_setup != "no");

            if (ssh_setup == "y" || ssh_setup == "yes") {
                home_dir = getenv("HOME");
                if (home_dir.empty()) {
                    fmt::print(stderr, "Error: HOME environment variable is not set. Cannot configure SSH.\n");
                    return EXIT_FAILURE;
                }
                std::filesystem::path ssh_dir = home_dir / ".ssh";
                if (!std::filesystem::exists(ssh_dir)) {
                    fmt::print(stderr, "Error: {} folder doesn't exist. Install and configure ssh client first.\n", ssh_dir);
                    return EXIT_FAILURE;
                }
                std::filesystem::path ssh_config = ssh_dir / "config";
                if (std::filesystem::exists(ssh_config)) {
                    std::ifstream ssh_file(ssh_config);
                    std::string line;
                    while (std::getline(ssh_file, line)) {
                        if (line.find("Host dnc") != std::string::npos) {
                            fmt::print("Info: dnc configuration already exists in ssh config. File is left untouched\n");
                            return EXIT_SUCCESS;
                        }
                    }
                }
                std::ofstream ssh_file(ssh_config, std::ios::app);
                if (ssh_file.is_open()) {
                    ssh_file << "\nHost dnc/*\n";
                    ssh_file << "    ProxyCommand dnc -d " << yaml_config << " $(basename %h)\n";
                    ssh_file.close();
                    fmt::print("SSH configuration added to {}\n", ssh_config);
                } else {
                    fmt::print(stderr, "Error: Could not open ssh config file.\n");
                    return EXIT_FAILURE;
                }
            }

            return EXIT_SUCCESS;
        } else {
            params.setup = true;
            params.id = folder;
        }
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
        fmt::print("Generated certificate in {}: {} {}\n", path_id,"id-server", identity.second->getId());
        return EXIT_SUCCESS;
    }

    if (params.ca.empty() || params.privatekey.empty()) {
        if (params.name.empty()) {
            auto ca = dhtnet::generateIdentity(params.id, "ca");
            fmt::print("Generated certificate in {}: {} {}\n", params.id, "ca", ca.second->getId());
        }else{
        auto ca = dhtnet::generateIdentity(params.id, params.name);
        fmt::print("Generated certificate in {}: {} {}\n", params.id, params.name, ca.second->getId());
        }
    }else{
        auto ca = dhtnet::loadIdentity(params.privatekey, params.ca);
        if (params.name.empty()) {
            auto id = dhtnet::generateIdentity(params.id, "certificate", ca);
            fmt::print("Generated certificate in {}: {} {}\n", params.id, "certificate", id.second->getId());
        }else{
            auto id = dhtnet::generateIdentity(params.id, params.name, ca);
            fmt::print("Generated certificate in {}: {} {}\n", params.id, params.name, id.second->getId());
        }
    }
    return EXIT_SUCCESS;
}
