# DHTNet - Lightweight Peer-to-Peer Communication Library

![DHTNet Logo]()

DHTNet is a C++17 library designed to serve as a network overlay that provides an IP network abstraction. Its main objective is to establish secure peer-to-peer connections using public-key authentication.

DHTnet allows you to connect with a device simply by knowing its public key and efficiently manages peer discovery and connectivity establishment, including NAT traversal.

## Features

- **Connection Management**: DHTNet simplifies the establishment and management of connections to peers, streamlining the communication process.

- **Multiplexed Sockets**: It provides multiplexed sockets that allow multiple channels for data transmission, optimizing network resources.

- **UPnP Integration**: DHTNet seamlessly integrates with UPnP, enabling automatic port mapping and enhanced network connectivity.

- **Server TURN Support**: DHTNet includes support for server TURN, used as a fallback for connections if the NAT block all possible connections.


## Documentation

For detailed information on using DHTNet, consult our documentation:

- [ConnectionManager Wiki](https://docs.jami.net/en_US/developer/jami-concepts/connection-manager.html)


## Getting Started using dhtnet package

You can download latest and/or stable builds from https://dhtnet.sfl.io.  
To install .deb, you can use `apt install dhtnet-xxx.deb`, and .rpm can be installed using `dnf install dhtnet_xxx.rpm`.  
On fedora, you may require to install EPEL using `dnf install epel-release`.  
On Redhat / Almalinux, EPEL may also be required, look at each distribution to find the installation command.  


### Setup instructions for server:

1. Create a server config and keys using `dhtnet-crtmgr --interactive` (run as root or with sudo is required).
2. Choose **server** and then use default configuration, or tweak values if you prefer.
3. If you want to review or edit configuration (to enable verbose mode for exemple), open `/etc/dhtnet/dnc.yaml`.
4. When ready, turn your server ON using `systemctl start dnc`. You can verify status using `systemctl status dnc`.

Your **server ID** (needed for clients to connect at you) is printed during the `dhtnet-crtmgr` setup, and is printed at start of logs when starting server with `systemctl start dnc`.
If needed, you can get it anytime using `dhtnet-crtmgr -a -c /etc/dhtnet/id/id-server.crt -p /etc/dhtnet/id/id-server.pem`.


### Setup instructions for client:

1. Create a client config and keys using `dhtnet-crtmgr --interactive` (run as your user is preffered).
2. Choose **client** for the first answer (default)
3. When asked to use server CA, answer depend on your use case:
   - If server and client are setup on same host, answer **yes** is possible.
   - If you are installing only the client, then answer **no**.
   - If you want to enforce security but server is on different host, answer **no** and change keys later (see `anonymous` below).
4. Continue using default configuration or by changing values when wanted.
5. If you want to review or edit configuration (to enable verbose mode for example), open `$HOME/.dnc/config.yml`.

To connect, you can use `dnc -d $HOME/.dnc/config.yml <server ID>`.  
If you answered **yes** at question about setting up ssh for you, then you can use `ssh <user>@dnc/<server ID>` to reach SSH on server using DNC layer.  


### About security and `anonymous` setting:

By default, server allow anyone to establish connection on your server. This is why server don't start by default, and only SSH is allowed.
In server setting, you will find `anonymous` boolean. If you host a public host, keeping `true` is a good choice, but if only a set of device
are allowed to connect to your server, then setting `false` is a better security.
For client, in order to reach a server with `anonymous: false`, it require the client key to be signed by server CA certificate.
Here is how to do it:

1. Get server CA certificate by going in `/etc/dhtnet/CA/` and copy `ca-server.crt` and `ca-server.pem`.
2. Generate a key in `MYPATH` using server certificate :`dhtnet-crtmgr -o MYPATH -c ca-server.crt -p ca-server.pem`
3. Copy the key generated in `MYPATH` in the client folder, for example `$HOME/.dnc/certificate.crt` and `$HOME/.dnc/certificate.pem`
4. If using a different path than example at step 3, edit `$HOME/.dnc/config.yml` to replace `certificate: MYPATH/certificate.crt` and `privateKey: MYPATH/certificate.pem`.

Don't forget to turn `anonymous` to `false` and restart server to take effect using `systemctl restart dnc`

Another security config is the `authorized_services` configuration on server, associated with `ip` and `port` on client.
When DNC establish a connection to remote host, it then try to reach `ip:port` **from this remote host**.
To enable accessing HTTP server running on server host, allow `127.0.0.1:80` on server and use `--port 80` on client for example.


---


## Getting Started with library

Get started with DHTNet by building and installing the library:

- [Build and Install Instructions](BUILD.md)

## Usage Example
In the example repository, there is a client-server application where the client connects to the server and sends a "hello" message.
You can build the example using the project's [Build and Install Instructions](BUILD.md) with `-BUILS_EXAMPLE=ON`.
![Demo](example/client-server_dhtnet.png)

## Dependencies

DHTNet depends on the following libraries:

- **OpenDHT** 2.6, used to launch DHT nodes.
- **[pjproject (our fork)](https://github.com/savoirfairelinux/pjproject)**, used for ICE negotiation.
- **msgpack-c** 1.3+, used for data serialization.
- **GnuTLS** 3.3+, used for cryptographic operations.
- **Nettle** 2.4+, a GnuTLS dependency for crypto.
- **{fmt}** 9.0+, for log formatting.
- **[Argon2](https://github.com/P-H-C/phc-winner-argon2)**, a dependency for key stretching.
- **Readline**, an optional dependency for the DHT tools.

## See also

### [Dnc: Distributed nc](tools/dnc/README.md)

dnc is a command-line program that provides network connectivity between peers in a Distributed Hash Table (DHT) network. It allows peers to establish connections with other peers and create a TCP socket on a remote devices, similar to the behavior of the traditional nc utility.

### [Dsh: Distributed shell](tools/dsh/README.md)

dsh is a Distributed Shell command-line program that enables peers to establish connections with other peers in a Distributed Hash Table (DHT) network and execute a binary on the remote target.


### [Dvpn: Distributed VPN](tools/dvpn/README.md)

dvpn is a VPN tool built on the foundation of the DHTNet library. dvpn supports both server and client modes, offering flexibility in deployment sceanrios.

### [Dhtnet-crtmgr:  DHTNet Certificate Manager](tools/dhtnet_crtmgr/README.md)
dhtnet-crtmgr is a command-line tool designed to manage certificates for the DHTNet network. It provides functionality for generating and signing certificates.

### Using Different Certificates

If the client and server are on the same machine, they should use different certificates for authentication, so make sure to specify different identity file paths for the client and server. This ensures that they use separate certificates.

## Report issues

Report issues on Gitlab: https://git.jami.net/savoirfairelinux/dhtnet/-/issues