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
#include"common.h"

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
    std::filesystem::path output {};
    std::filesystem::path privatekey {};
    bool identifier {false};
    std::string name {};
    bool setup {false};
    bool interactive {false};
};
static const constexpr struct option long_options[]
    = {{"help", no_argument, nullptr, 'h'},
       {"version", no_argument, nullptr, 'v'},
       {"certificate", required_argument, nullptr, 'c'},
       {"output", required_argument, nullptr, 'o'},
       {"privatekey", required_argument, nullptr, 'p'},
       {"name", required_argument, nullptr, 'n'},
       {"identifier", no_argument, nullptr, 'a'},
       {"setup", no_argument, nullptr, 's'},
       {"interactive", no_argument, nullptr, 'i'},
       {nullptr, 0, nullptr, 0}};

dhtnet_crtmgr_params
parse_args(int argc, char** argv)
{
    dhtnet_crtmgr_params params;
    int opt;
    while ((opt = getopt_long(argc, argv, "hvasic:o:p:n:", long_options, nullptr)) != -1) {
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
            params.output = optarg;
            break;
        case 'p':
            params.privatekey = optarg;
            break;
        case 'a':
            params.identifier = true;
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

    if (params.output.empty() && !params.identifier && !params.help && !params.version && !params.interactive) {
        std::cerr << "Error: The path to save the generated certificate is not provided.\n Please specify the path using the -o option.\n";
        exit(EXIT_FAILURE);
    }
    return params;
}


int create_yaml_config(std::filesystem::path file, std::filesystem::path certificate, std::filesystem::path privateKey, bool is_client)
{
    std::ofstream yaml_file (file);
    if (yaml_file.is_open()) {
        yaml_file << "# The bootstrap node serves as the entry point to the DHT network.\n";
        yaml_file << "# By default, bootstrap.jami.net is configured for the public DHT network and should be used for personal use only.\n";
        yaml_file << "# For production environments, it is recommended to set up your own bootstrap node to establish your own DHT network.\n";
        yaml_file << "# Documentation: https://docs.jami.net/en_US/user/lan-only.html#boostraping\n";
        yaml_file << "bootstrap: \"bootstrap.jami.net\"\n";

        yaml_file << "\n# TURN server is used as a fallback for connections if the NAT block all possible connections.\n";
        yaml_file << "# By default is turn.jami.net (which uses coturn) but can be any TURN.\n";
        yaml_file << "# Developer must set up their own TURN server.\n";
        yaml_file << "# Documentation: https://docs.jami.net/en_US/developer/going-further/setting-up-your-own-turn-server.html\n";
        yaml_file << "turn_host: \"turn.jami.net\"\n";
        yaml_file << "turn_user: \"ring\"\n";
        yaml_file << "turn_pass: \"ring\"\n";
        yaml_file << "turn_realm: \"ring\"\n";

        yaml_file << "\n# When verbose is set to true, the server logs all incoming connections\n";
        yaml_file << "verbose: false\n";

        yaml_file << "\n# If true, will send request to use UPNP if available\n";
        yaml_file << "enable_upnp: true\n";

        yaml_file << "\n# On server, identities are saved in /etc/dhtnet/id/\n";
        yaml_file << "# On client, they are generaly saved in ~/.dnc/\n";
        yaml_file << "certificate: " << certificate << "\n";
        yaml_file << "privateKey: " << privateKey << "\n";
        if (is_client) {
            yaml_file << "\n# When dnc server receives connexions, it forwards them to service at specified IP:port requested by CLIENT\n";
            yaml_file << "# By default, it forwards them to SSH server running on localhost at port 22\n";
            yaml_file << "ip: \"127.0.0.1\"\n";
            yaml_file << "port: 22\n";
        } else {
            yaml_file << "\n# When anonymous is set to true, the server accepts any connection without checking CA\n";
            yaml_file << "# When anonymous is set to false, the server allows only connection which are issued by the same CA as the server\n";
            yaml_file << "anonymous: false\n";

            yaml_file << "\n# List of authorized services\n";
            yaml_file << "# Each service is defined by an IP and a port\n";
            yaml_file << "# If no authorized services are defined, the server will accept any connection.\n";
            yaml_file << "authorized_services:\n";
            yaml_file << "  - ip: \"127.0.0.1\"\n";
            yaml_file << "    port: 22\n";
            yaml_file << "  # - ip: \"127.0.0.1\"\n";
            yaml_file << "  #   port: 80\n";
            yaml_file << "  # - ip: \"127.0.0.1\"\n";
            yaml_file << "  #   port: 443\n";
        }
        yaml_file.close();
        Log("Configuration file created in {}\n", file);
    } else {
        fmt::print(stderr, "Error: Unable to create configuration file {}.\n", file);
        return 1;
    }
    return 0;
}

int configure_ssh_config(std::filesystem::path yaml_config)
{
    std::filesystem::path home_dir = getenv("HOME");
    if (home_dir.empty()) {
        fmt::print(stderr, "Error: HOME environment variable is not set. Unable to configure SSH.\n");
        return 1;
    }
    std::filesystem::path ssh_dir = home_dir / ".ssh";
    if (!std::filesystem::exists(ssh_dir)) {
        fmt::print(stderr, "Error: {} folder doesn't exist. Install and configure ssh client first.\n", ssh_dir);
        return 1;
    }
    std::filesystem::path ssh_config = ssh_dir / "config";
    if (std::filesystem::exists(ssh_config)) {
        std::ifstream ssh_file(ssh_config);
        std::string line;
        while (std::getline(ssh_file, line)) {
            if (line.find("Host dnc") != std::string::npos) {
                Log("Info: dnc configuration already exists in ssh config. File is left untouched\n");
                return 0;
            }
        }
    }
    std::ofstream ssh_file(ssh_config, std::ios::app);
    if (ssh_file.is_open()) {
        ssh_file << "\nHost dnc/*\n";
        ssh_file << "    ProxyCommand dnc -d " << yaml_config << " $(basename %h)\n";
        ssh_file.close();
        Log("SSH configuration added to {}\n", ssh_config);
    } else {
        fmt::print(stderr, "Error: Unable to open ssh config file.\n");
        return 1;
    }
    return 0;
}

// https://en.cppreference.com/w/cpp/string/byte/tolower
std::string str_tolower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return std::tolower(c); } // correct
    );
    return s;
}

int
main(int argc, char** argv)
{
    auto params = parse_args(argc, argv);

    if (params.help) {
        Log("Usage: dhtnet-crtmgr [options]\n"
                "\nOptions:\n"
                "  -h, --help                Display this help message and then exit.\n"
                "  -v, --version             Show the version of the program.\n"
                "  -p, --privatekey [FILE]   Provide the path to the private key as an argument.\n"
                "  -c, --certificate [FILE]  Provide the path to the certificate as an argument.\n"
                "  -o, --output [FOLDER]     Provide the path where the generated certificate should be saved as an argument.\n"
                "  -a, --identifier          Display the user identifier.\n"
                "  -n, --name [NAME]         Provide the name of the certificate to be generated.\n"
                "  -s, --setup               Create an CA and a certificate.\n"
                "  -i, --interactive         Interactively create and setup identities.\n");
        return EXIT_SUCCESS;
    }

    if (params.version) {
        Log("dhtnet-crtmgr v1.0\n");
        return EXIT_SUCCESS;
    }
    // check if the public key id is requested
    if (params.identifier) {
        if (params.ca.empty() || params.privatekey.empty()) {
            fmt::print(stderr, "Error: The path to the private key and the certificate is not provided.\n Please specify the path for the private key and the certificate using the -p and -c options.\n");
            exit(EXIT_FAILURE);
        }
        auto identity = dhtnet::loadIdentity(params.privatekey, params.ca);
        Log("Public key id: {}\n", identity.second->getId());
        return EXIT_SUCCESS;
    }

    // check if the interactive mode is requested
    if (params.interactive) {
        // Ask user if he want to setup client or server config
        std::string usage = "";
        do {
            Log("Generate identity for server or client? [(C)lient/(s)erver] (default: client): ");
            std::getline(std::cin, usage);
            usage = str_tolower(usage);
            if (usage == "s") usage = "server";
            if (usage == "c") usage = "client";
            if (usage.empty()) usage = "client";
        } while (usage != "server" && usage != "client");

        // In case user select client mode, Ask if we should sign using server CA (required for anonymous: false)
        std::string use_server_ca = "";
        if (usage == "client") {
            do {
                Log("Sign client certificate using server CA? [Y/n] (default: yes): ");
                std::getline(std::cin, use_server_ca);
                use_server_ca = str_tolower(use_server_ca);
                if (use_server_ca == "y") use_server_ca = "yes";
                if (use_server_ca == "n") use_server_ca = "no";
                if (use_server_ca.empty()) use_server_ca = "yes";
            } while (use_server_ca != "yes" && use_server_ca != "no");
        }

        // Before asking for save folder, pre-compute default locations
        std::filesystem::path home_dir = getenv("HOME");
        if (home_dir.empty()) home_dir = "/tmp/.dnc";
        else if (usage == "server") home_dir = "/etc/dhtnet";
        else home_dir = home_dir / ".dnc";

        std::string input_folder;

        // Ask where to store identity files
        std::filesystem::path folder;
        Log("Enter the path to save identities and config [{}]: ", home_dir);
        std::getline(std::cin, input_folder);
        if (input_folder.empty()) {
            folder = home_dir;
        } else {
            folder = input_folder;
        }
        folder = std::filesystem::absolute(folder);

        std::error_code e;
        std::filesystem::create_directories(folder, e);
        if (e) {
            fmt::print(stderr, "Error: Unable to create directory {}. {}\n", folder, e.message());
            return EXIT_FAILURE;
        }

        if (usage == "client") {
            // Use existing CA or generate new CA
            dht::crypto::Identity ca;
            if (use_server_ca == "yes") {
                try {
                    std::filesystem::path server_ca = "/etc/dhtnet/CA";
                    ca = dhtnet::loadIdentity(server_ca / "ca-server.pem", server_ca / "ca-server.crt");
                    if (!ca.first || !ca.second) {
                        throw std::runtime_error("Failed to load server CA");
                    }
                }
                catch (const std::exception& e) {
                    fmt::print(stderr, "Error: Unable to load server CA. Please generate server CA first.\n");
                    return EXIT_FAILURE;
                }
            } else {
                ca = dhtnet::generateIdentity(folder, "ca");
                if (!ca.first || !ca.second) {
                    fmt::print(stderr, "Error: Unable to generate CA.\n");
                    return EXIT_FAILURE;
                }
                Log("Generated CA in {}: {} {}\n", folder, "ca", ca.second->getId());
            }

            // Generate client certificate
            auto id = dhtnet::generateIdentity(folder, "certificate", ca);
            if (!id.first || !id.second) {
                fmt::print(stderr, "Error: Unable to generate certificate.\n");
                return EXIT_FAILURE;
            }
            Log("Generated certificate in {}: {} {}\n", folder, "certificate", id.second->getId());

            // Create configuration file with generated keys
            std::filesystem::path yaml_config{folder / "config.yml"};
            if (create_yaml_config(yaml_config, folder / "certificate.crt", folder / "certificate.pem", true) != 0) {
                return EXIT_FAILURE;
            }

            // Ask user if he want to configure SSH
            std::string ssh_setup = "";
            do {
                Log("Configure SSH to support dnc protocol? [Y/n] (default: yes): ");
                std::getline(std::cin, ssh_setup);
                ssh_setup = str_tolower(ssh_setup);
                if (ssh_setup == "y") ssh_setup = "yes";
                if (ssh_setup == "n") ssh_setup = "no";
                if (ssh_setup.empty()) ssh_setup = "yes";
            } while (ssh_setup != "yes" && ssh_setup != "no");

            if (ssh_setup == "yes") {
                if (configure_ssh_config(yaml_config) != 0) {
                    return EXIT_FAILURE;
                }
            }

            return EXIT_SUCCESS;
        } else {
            // Create configuration file with generated keys
            std::filesystem::path yaml_config{folder / "dnc.yaml"};
            std::string overwrite = "";
            if (std::filesystem::exists(yaml_config)) {
                do {
                    Log("Configuration file already exists in {}. Overwrite it? [y/N] (default: no): ", yaml_config);
                    std::getline(std::cin, overwrite);
                    overwrite = str_tolower(overwrite);
                    if (overwrite == "y") overwrite = "yes";
                    if (overwrite == "n") overwrite = "no";
                    if (overwrite.empty()) overwrite = "no";
                } while (overwrite != "yes" && overwrite != "no");
            } else {
                overwrite = "yes"; // File doesn't exist, create it
            }
            if (overwrite == "yes") {
                if (create_yaml_config(yaml_config, folder / "id" / "id-server.crt", folder / "id" / "id-server.pem", false) != 0) {
                    return EXIT_FAILURE;
                }
            }
            params.setup = true;
            params.output = folder;
        }
    }

    // check if the setup is requested
    if (params.setup) {
        // create CA  with name ca-server
        std::filesystem::path path_ca = params.output / "CA";
        auto ca = dhtnet::generateIdentity(path_ca, "ca-server");
        if (!ca.first || !ca.second) {
            fmt::print(stderr, "Error: Unable to generate CA.\n");
            return EXIT_FAILURE;
        }
        Log("Generated CA in {}: {} {}\n", path_ca, "ca-server", ca.second->getId());
        // create identity with name id-server
        std::filesystem::path path_id = params.output / "id";
        auto identity = dhtnet::generateIdentity(path_id, "id-server", ca);
        if (!identity.first || !identity.second) {
            fmt::print(stderr, "Error: Unable to generate certificate.\n");
            return EXIT_FAILURE;
        }
        Log("Generated certificate in {}: {} {}\n", path_id,"id-server", identity.second->getId());
        return EXIT_SUCCESS;
    }

    if (params.ca.empty() || params.privatekey.empty()) {
        if (params.name.empty()) {
            auto ca = dhtnet::generateIdentity(params.output, "ca");
            if (!ca.first || !ca.second) {
                fmt::print(stderr, "Error: Unable to generate CA.\n");
                return EXIT_FAILURE;
            }
            Log("Generated certificate in {}: {} {}\n", params.output, "ca", ca.second->getId());
        }else{
            auto ca = dhtnet::generateIdentity(params.output, params.name);
            if (!ca.first || !ca.second) {
                fmt::print(stderr, "Error: Unable to generate CA.\n");
                return EXIT_FAILURE;
            }
            Log("Generated certificate in {}: {} {}\n", params.output, params.name, ca.second->getId());
        }
    }else{
        auto ca = dhtnet::loadIdentity(params.privatekey, params.ca);
        if (params.name.empty()) {
            auto id = dhtnet::generateIdentity(params.output, "certificate", ca);
            if (!id.first || !id.second) {
                fmt::print(stderr, "Error: Unable to generate certificate.\n");
                return EXIT_FAILURE;
            }
            Log("Generated certificate in {}: {} {}\n", params.output, "certificate", id.second->getId());
        }else{
            auto id = dhtnet::generateIdentity(params.output, params.name, ca);
            if (!id.first || !id.second) {
                fmt::print(stderr, "Error: Unable to generate certificate.\n");
                return EXIT_FAILURE;
            }
            Log("Generated certificate in {}: {} {}\n", params.output, params.name, id.second->getId());
        }
    }
    return EXIT_SUCCESS;
}
