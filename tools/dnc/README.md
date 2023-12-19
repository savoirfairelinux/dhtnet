# dnc - Distributed nc

## Overview

**dnc** is a versatile command-line program that enables network connectivity between peers in a Distributed Hash Table (DHT) network. It allows you to establish connections with other peers or devices and create TCP sockets on remote devices, similar to the traditional `nc` (netcat) utility.

**Key Features**:
- Create TCP sockets on remote devices.
- Establish network connections between peers in a DHT network.
- Supports TURN (Traversal Using Relays around NAT) server for network traversal.
- Provides identity management for secure DHT interactions.

### Options

**dnc** accepts the following command-line options:

- `-h, --help`: Display help information for using **dnc**.
- `-V, --version`: Display the version information of **dnc**.
- `-p, --port <PORT>`: Specify the port number to use for network connections. This option requires an argument. The default value is 22 if not specified.
- `-i, --ip <REMOTE_IP>`: Specify the IP address or hostname of the remote host or device to connect to. This option requires an argument. The default value is "127.0.0.1" if not specified.
- `-l, --listen`: Run **dnc** in listen mode, allowing the program to accept incoming network connections and perform network-related tasks on request.
- `-b, --bootstrap <BOOTSTRAP_ADDRESS>`: Specify the address of a bootstrap node to connect to an existing DHT network. This option requires an argument. The default value is "bootstrap.jami.net" if not specified.
- `-I, --id_path <IDENTITY_PATH>`: Specify the path to the identity file, which contains information about the peer's identity and is used for DHT network interactions. This option requires an argument. The default value is "~/.dhtnet" if not specified.
- `-t, --turn_host <TURN_SERVER>`: Specify the hostname or IP address of the TURN (Traversal Using Relays around NAT) server to use for network traversal. This option requires an argument.
- `-u, --turn_user <TURN_USERNAME>`: Specify the username for authentication with the TURN server. This option requires an argument.
- `-w, --turn_pass <TURN_PASSWORD>`: Specify the password for authentication with the TURN server. This option requires an argument.
- `-r, --turn_realm <TURN_REALM>`: Specify the realm for authentication with the TURN server. This option requires an argument. 
- `<PEER_ID>`: The peer ID argument is required when not running in listen mode. It specifies the ID of the target peer or device in the DHT network with which the connection should be established.

For example, to connect to a remote device with a specific TURN server and identity file, you can use the following command:

```shell
dnc -i <REMOTE_IP> -p <PORT> -t <TURN_SERVER> -u <TURN_USERNAME> -w <TURN_PASSWORD> -r <TURN_REALM> -I <IDENTITY_PATH> <PEER_ID>
```