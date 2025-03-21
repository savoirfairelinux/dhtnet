# dnc - Distributed Netcat

## Introduction

**dnc** is a versatile command-line tool designed to facilitate network communication across a Distributed Hash Table (DHT) network. It mirrors the functionality of the traditional `nc` (netcat) utility, enabling users to initiate TCP connections and create sockets on remote devices within a DHT network framework.

**Main Features:**
- Initiates TCP connections on remote devices.
- Facilitates peer-to-peer network connectivity within a DHT network.
- Incorporates TURN (Traversal Using Relays around NAT) server support for effective NAT traversal.
- Manages identities for enhanced security during DHT network interactions.

## Connection Process

1. **Launch Server and Share Public ID (Server-side):** The server must be launched, and its public ID (hash key) should be shared with the clients who want to connect to it.
2. **Initiate Connection and Request Remote Socket (Client-side):** The client starts a peer-to-peer connection within the DHT network using the server's public ID and requests the server to open a socket at the specified `<ip>` and `<port>`.
3. **Check Certificate:** If anonymous mode is off, the server verifies the client's certificate to ensure it matches the server’s CA. If anonymous mode is on, no certificate check is performed.
4. **Authorize Request:** The server checks if the requested `<ip>:<port>` is authorized based on its rules.
5. **Create Socket:**
    - **If Authorized:** The server opens a socket at the specified `<ip>:<port>` and links it to the DHT socket.
    - **If Not Authorized:** The server rejects the connection.

### Usage Options

**dnc** supports a range of command-line arguments:

- `-h, --help`: Display help information and exit.
- `-v, --version`: Show the version of the program.
- `-P, --port [PORT]`: Define the port for socket creation.
- `-i, --ip [IP]`: Define the IP address for socket creation.
- `-l, --listen`: Launch the program in listening mode.
- `-b, --bootstrap [ADDRESS]`: Set the bootstrap node.
- `-t, --turn_host [ADDRESS]`: Define the TURN server host.
- `-u, --turn_user [USER]`: Define the TURN server username.
- `-w, --turn_pass [SECRET]`: Define the TURN server password.
- `-r, --turn_realm [REALM]`: Specify the TURN server realm.
- `-c, --certificate [FILE]`: Specify the Certificate.
- `-p, --privateKey [FILE]`: Provide a private key.
- `-d, --configuration [FILE]`: Define the dnc configuration with a YAML file path.
- `-a, --anonymous`: Activate anonymous connection mode.
- `-vv, --verbose`: Enable verbose mode.

For additional options, use the `-d` flag with a YAML configuration file:
```shell
dnc -d <YAML_FILE> <PEER_IDENTIFIER>
```
Note: If anonymous mode is off, the server's CA must be shared with the client.

The authorized services `<ip>:<port>` can only be specified in the YAML configuration file. If none are specified, the server will accept all connections.

## Establishing SSH Connections
To facilitate SSH connections to a remote device, dnc client establishes a DHT network connection followed by socket creation request on port 22 by default, assuming an OpenSSH server is operational.

### Prerequisites
- **OpenSSH Installation**
- **[Build dhtnet](../../BUILD.md)**

### Setup the dnc Service
To initiate, generate a certificate authority and a server certificate:

```shell
sudo dhtnet-crtmgr --setup -o /usr/local/etc/dhtnet/
```
The server will cache some values in `/var/run/dhtnet`. If this must be changed,
you can remove the line `Environment="DHTNET_CACHE_DIR=/var/run/dhtnet"` in `dnc.service.in`.
Then, launch the dnc service:
```shell
systemctl start dnc.service
```
Obtain the user identifier with the following command:
```shell
dhtnet-crtmgr -a -p <privateKey_path> -c <cert_path>
```
For the server, use:
```shell
dhtnet-crtmgr -a -c /usr/local/etc/dhtnet/id/id-server.crt -p /usr/local/etc/dhtnet/id/id-server.pem
```

#### Client Connection
To establish a secure connection from the client side, it's necessary to generate a certificate authority (CA) and a certificate. Execute the following commands to set up your identity:

```shell
dhtnet-crtmgr -o <repo_ca> -n ca
dhtnet-crtmgr -o <repo_crt> -n certificate -c <repo_ca>/ca.crt -p <repo_ca>/ca.pem
```
Replace <repo_ca> with the directory path for storing the CA files and <repo_crt> with the path for the client certificate files. Update your YAML configuration file to include <repo_crt>/certificate.pem as the privateKey and <repo_crt>/certificate.crt as the certificate.

To integrate dnc with your SSH workflow, append the following configuration to your SSH configuration file (~/.ssh/config), enhancing the utility of SSH through dnc:

```ssh
Host dnc/*
    IdentityFile /home/<local_user>/.ssh/<key>.pub
    ProxyCommand dnc -d /path/to/yaml/config $(basename %h)
```

This setup allows you to use the "dnc" alias for seamless SSH connections to remote servers. Simply replace <peer_identifier> with the actual server identifier and <ssh_remote_user> with the intended SSH username when initiating a connection:
```sh
ssh <ssh_remote_user>@dnc/<peer_identifier>
```
For exemple:
```sh
ssh mypeer@dnc/2f4975e7b11a0908bd400b27130fe9a496d0f415
```
