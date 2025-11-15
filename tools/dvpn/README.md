# dvpn - Distributed VPN

## Overview

**dvpn** is a VPN tool based on DHTNet library.

**Key Features**:

- **Decentralized Architecture**: Uses a DHT for peer discovery.
- **Client-Server Model**: Supports server and client modes.
- **TUN Interface**: Implements a TUN interface for network communication.
- **VPN Security**: Ensures secure communication channels using cryptography and identity verification.

## Configuration

Before using **dvpn**, follow these steps to update your configuration:

1. Locate the default configuration file at `dhtnet/tools/dvpn/test_config.yaml`.
2. Update the `script_path` section by providing the absolute path for the `dvpn_up.sh` file.

### Options

**dvpn** accepts the following command-line options:

- `-h, --help`: Display help information
- `-V, --version`: Display the version information of **dvpn**.
- `-l, --listen`: Run **dvpn** in listen mode, allowing the program to accept incoming VPN connections.
- `-b, --bootstrap [ADDRESS]`: Specify the address of a bootstrap node to connect to an existing DHT network.
- `-t, --turn_host [ADDRESS]`: Specify the hostname or IP address of the TURN server.
- `-u, --turn_user [USER]`: Specify the username for authentication with the TURN server.
- `-w, --turn_pass [SECRET]`: Specify the password for authentication with the TURN server.
- `-r, --turn_realm [REALM]`: Specify the realm for authentication with the TURN server.
- `-C, --vpn_configuration [FILE]`: Specify the path to the vpn configuration file.
- `-p, --privateKey [FILE]`: Define the path to the private key.
- `-c, --certificate [FILE]`: Specify the path to the certificate.
- `-d, --configuration [FILE]`: Define the path to the YAML configuration file for dvpn.
- `-a, --anonymous`: Activate anonymous connection mode.

To run a dvpn server, you can use the following command:
```shell
sudo ./dvpn -d <YAML_FILE> -l
```

To connect to a dvpn server, you can use the following command:
```shell
sudo ./dvpn -d <YAML_FILE> <server_identifier>
```

**Note**: **dvpn** requires sudo privileges to create and configure TUN interfaces on both the client and server sides.


## VPN Setup Process

For each connection, **dvpn** dynamically creates a new TUN interface, utilizing information read from the configuration file (default: `test_config.yaml`), and passes it to the setup script (default: `dvpn_up.sh`). As a result, the server generates a unique TUN interface for each client, while the client creates only one interface.


Following this, the setup script takes charge of configuring the TUN interface and establishing routing logic for the client, as well as managing Network Address Translation (NAT) for the server.

The configuration file includes the path to the setup script and the IP address and IP peer address prefixes. The server uses these prefixes to generate a valid address, and the client dynamically receives these addresses from the server during the connection process.


The TUN interfaces are configured as follows:

- **Server TUN Interface:** `<server tun address> 255.255.255.255 <client tun address>`
- **Client TUN Interface:** `<client tun address> 255.255.255.255 <server tun address>`
