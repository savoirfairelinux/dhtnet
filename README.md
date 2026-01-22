# DHTNet - Lightweight Peer-to-Peer Communication Library

<!-- ![DHTNet Logo]() -->

DHTNet is a C++17 library designed to serve as a network overlay that provides an IP network abstraction.
Its main objective is to establish secure peer-to-peer connections using public-key authentication.

DHTNet allows you to connect with a device simply by knowing its public key and efficiently manages peer discovery and connectivity establishment, including NAT traversal.

## Features

- **Connection Management**: DHTNet simplifies the establishment and management of connections to peers, streamlining the communication process.

- **Multiplexed Sockets**: It provides multiplexed sockets that allow multiple channels for data transmission, optimizing network resources.

- **UPnP Integration**: DHTNet seamlessly integrates with UPnP, enabling automatic port mapping and enhanced network connectivity.

- **Server TURN Support**: DHTNet includes support for server TURN, used as a fallback for connections if the NAT block all possible connections.


## Documentation

For detailed information on using DHTNet, consult the Jami documentation:

- [ConnectionManager Wiki](https://docs.jami.net/developer/jami-concepts/connection-manager.html)

## Getting Started with library

Get started with DHTNet by building and installing the library:

- [Build and Install Instructions](BUILD.md)

## Usage Example

In the example repository, there is a client-server application where the client connects to the server and sends a "hello" message.
You can build the example using the project's [Build and Install Instructions](BUILD.md) with `-DBUILD_EXAMPLE=ON`.
![Demo](example/client-server_dhtnet.png)

## Dependencies

DHTNet depends on the following libraries:

- **OpenDHT** 2.6, used to launch DHT nodes.
- **[pjproject (SFL fork)](https://github.com/savoirfairelinux/pjproject)**, used for ICE negotiation.
- **msgpack-c** 1.3+, used for data serialization.
- **GnuTLS** 3.3+, used for cryptographic operations.
- **Nettle** 2.4+, a GnuTLS dependency for crypto.
- **{fmt}** 9.0+, for log formatting.
- **[Argon2](https://github.com/P-H-C/phc-winner-argon2)**, a dependency for key stretching.
- **Readline**, an optional dependency for the DHT tools.

## See also

### [DHTNet package](tools/README.md)

The DHTNet package includes binaries for the tools listed below, along with automation scripts designed to simplify the creation of your own dnc server and dnc client.
The DHTNet package is available for download from the [DHTNet website](https://dhtnet.sfl.io).

### [Dnc: Distributed nc](tools/dnc/README.md)

dnc is a command-line program that provides network connectivity between peers in a Distributed Hash Table (DHT) network. It allows peers to establish connections with other peers and create a TCP socket on a remote devices, similar to the behavior of the traditional nc utility.

### [Dsh: Distributed shell](tools/dsh/README.md)

dsh is a Distributed Shell command-line program that enables peers to establish connections with other peers in a Distributed Hash Table (DHT) network and execute a binary on the remote target.

### [Dvpn: Distributed VPN](tools/dvpn/README.md)

dvpn is a VPN tool built on the foundation of the DHTNet library. dvpn supports both server and client modes, offering flexibility in deployment sceanrios.

### [Dhtnet-crtmgr:  DHTNet Certificate Manager](tools/dhtnet_crtmgr/README.md)
dhtnet-crtmgr is a command-line tool designed to manage certificates for the DHTNet network. It provides functionality for generating and signing certificates.

```{note}
When using any of the tools mentioned above, ensure that the client and server on the same machine use different certificates for authentication.
```

## Report issues

Report issues on GitLab: <https://git.jami.net/savoirfairelinux/dhtnet/-/issues>
