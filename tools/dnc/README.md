# dnc - Distributed Netcat

## Introduction

**dnc** is a dynamic command-line tool designed to facilitate network communication across a Distributed Hash Table (DHT) network. It mirrors the functionality of the traditional `nc` (netcat) utility, enabling users to initiate TCP connections and create sockets on remote devices within a DHT network framework.

**Main Features:**
- Initiates TCP connections on remote devices.
- Facilitates peer-to-peer network connectivity within a DHT network.
- Incorporates TURN (Traversal Using Relays around NAT) server support for effective NAT traversal.
- Manages identities for enhanced security during DHT network interactions.

### Usage Options

**dnc** supports a range of command-line arguments:

- `-h, --help`: Display help information and exit.
- `-v, --version`: Show the version of the program.
- `-P, --port`: Define the port for socket creation.
- `-i, --ip`: Define the IP address for socket creation.
- `-l, --listen`: Launch the program in listening mode.
- `-b, --bootstrap`: Set the bootstrap node.
- `-p, --privateKey`: Provide a private key.
- `-t, --turn_host`: Define the TURN server host.
- `-u, --turn_user`: Define the TURN server username.
- `-w, --turn_pass`: Define the TURN server password.
- `-r, --turn_realm`: Specify the TURN server realm.
- `-C, --CA`: Specify the Certificate Authority.
- `-d, --dnc_configuration`: Define the dnc configuration with a YAML file path.
- `-a, --anonymous_cnx`: Activate anonymous connection mode.

For additional options, use the `-d` flag with a YAML configuration file:
```shell
dnc -d <YAML_FILE> <PEER_ID>
```
Note: If anonymous mode is off, the server's CA must be shared with the client.

## Establishing SSH Connections
To facilitate SSH connections to a remote device, dnc establishes a DHT network connection followed by socket creation on port 22, assuming an OpenSSH server is operational.

### Prerequisites
- **OpenSSH Installation**
- **Build dhtnet** (../BUILD.md)

### Starting the dnc Service
To initiate, generate a certificate authority and an ID:

```shell
dhtnet-crtmgr --setup -i /usr/local/etc/dhtnet/
```
Then, launch the dnc service:
```shell
systemctl start dnc.service
```
Obtain the hash ID (public key) with the following command:
```shell
dhtnet-crtmgr -g -p <privateKey_path> -c <cert_path>
```
For the server, use:
```shell
dhtnet-crtmgr -g -c /usr/local/etc/dhtnet/id/id-server.crt -p /usr/local/etc/dhtnet/id/id-server.pem
```

#### Client Connection
From the client side, enhance SSH utility with dnc by adding these lines to your SSH config (`~/.ssh/config`):
```ssh
Host dnc/*
    IdentityFile /home/<local_user>/.ssh/<key>.pub
    ProxyCommand /home/<local_user>/dhtnet/build/dnc -d /path/to/yaml/config $(basename %h)
```

Utilize the previously set "dnc" alias for connecting to a remote server. Replace `<peer_id>` with the server's ID and `<ssh_remote_user>` with your SSH user name:
```sh
ssh <ssh_remote_user>@dnc/<peer_id>
```
Example:
```sh
ssh mypeer@dnc/2f4975e7b11a0908bd400b27130fe9a496d0f415
``