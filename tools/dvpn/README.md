# dvpn - Distributed VPN

## Overview

**dvpn** is a VPN tool based on DHTNet library.

**Key Features**:

- **Decentralized Architecture**: Utilizes a DHT for peer discovery and communication.
- **Client-Server Model**: Supports both server and client modes for flexible deployment.
- **TUN Interface**: Implements a TUN interface for network communication.
- **VPN Security**: Ensures secure communication channels using cryptography and identity verification.
- **Configuration Flexibility** : Modify configuration settings and the setup script independently, avoiding the need to rebuild the entire project..

## Configuration

Before using **dvpn**, make sure to disable IPv6. To disable IPv6, follow these steps:

1. Open the terminal.
2. Edit the `/etc/sysctl.conf` file using a text editor.
3. Add the following lines at the end of the file:
    ```shell
    net.ipv6.conf.all.disable_ipv6 = 1
    net.ipv6.conf.default.disable_ipv6 = 1
    ```
4. Save the file and exit the text editor.
5. Apply the changes by running the following command:
    ```shell
    sudo sysctl -p
    ```

Additionally, update your configuration file (update the section `script_path`).

### Options

**dvpn** accepts the following command-line options:

- `-h, --help`: Display help information
- `-V, --version`: Display the version information of **dvpn**.
- `-l, --listen`: Run **dvpn** in listen mode, allowing the program to accept incoming VPN connections.
- `-b, --bootstrap <BOOTSTRAP_ADDRESS>`: Specify the address of a bootstrap node to connect to an existing DHT network. This option requires an argument. The default value is "bootstrap.jami.net" if not specified.
- `-I, --id_path <IDENTITY_PATH>`: Specify the path to the identity file, which contains information about your identity and is used for DHT network interactions. This option requires an argument. The default value is "$HOME/.dhtnet" if not specified.
- `-t, --turn_host <TURN_SERVER>`: Specify the hostname or IP address of the TURN (Traversal Using Relays around NAT) server to use for network traversal. This option requires an argument.
- `-u, --turn_user <TURN_USERNAME>`: Specify the username for authentication with the TURN server. This option requires an argument.
- `-w, --turn_pass <TURN_PASSWORD>`: Specify the password for authentication with the TURN server. This option requires an argument.
- `-r, --turn_realm <TURN_REALM>`: Specify the realm for authentication with the TURN server. This option requires an argument.
- `-c, --configuration_path_file <CONF_PATH>`: Specify the path to the configuration file. The default value is "dhtnet/tools/dvpn/test_config.yaml" if not specified.
- `<PEER_ID>`: The peer ID argument is required when not running in listen mode. It specifies the ID of the target peer or device in the DHT network with which the connection should be established.

To run a dvpn server, you can use the following command:
```shell
sudo ./dvpn -l
```

To connect to a dvpn server, you can use the following command:
```shell
sudo ./dvpn <PEER_ID>
```

**Note**: **dvpn** requires sudo privileges to create and configure TUN interfaces on both the client and server sides.


## VPN Setup Process

For each connection, **dvpn** dynamically creates a new TUN interface, utilizing information read from the configuration file (default: `test_config.yaml`), and passes it to the setup script (default: `dvpn_up.sh`). As a result, the server generates a unique TUN interface for each client, while the client creates only one interface.


Following this, the setup script takes charge of configuring the TUN interface and establishing routing logic for the client, as well as managing Network Address Translation (NAT) for the server.

The configuration file includes the path to the setup script and the IP address and IP peer address prefixes. The server uses these prefixes to generate a valid address, and the client dynamically receives these addresses from the server during the connection process.


The TUN interfaces are configured as follows:

- **Server TUN Interface:** `<server tun address> 255.255.255.255 <client tun address>`
- **Client TUN Interface:** `<client tun address> 255.255.255.255 <server tun address>`
