# DHTNet - Lightweight Peer-to-Peer Communication Library

![DHTNet Logo](your-logo.png)

DHTNet is a C++17 library designed to serve as a network overlay that provides an IP network abstraction. Its main objective is to establish secure peer-to-peer connections using public-key authentication.

Dhtnet allows you to connect with a device simply by knowing its public key and efficiently manages peer discovery and connectivity establishment, including NAT traversal.

## Features

- **Connection Management**: DHTNet simplifies the establishment and management of connections to peers, streamlining the communication process.

- **Multiplexed Sockets**: It provides multiplexed sockets that allow multiple channels for data transmission, optimizing network resources.

- **UPnP Integration**: DHTNet seamlessly integrates with UPnP, enabling automatic port mapping and enhanced network connectivity.

- **Server TURN Support**: DHTNet includes support for server TURN, used as a fallback for connections if the NAT block all possible connections.


## Documentation

For detailed information on using DHTNet, consult our documentation:

- [ConnectionManager Wiki](https://docs.jami.net/en_US/developer/connection-manager.html)


## Getting Started

Get started with DHTNet by building and installing the library:

- [Build and Install Instructions](https://github.com/savoirfairelinux/dhtnet/blob/master/BUILD.md)

## Usage Example

```cpp
#include "connectionmanager.h"
#include <opendht/log.h>
#include <opendht/utils.h>
#include <opendht/thread_pool.h>
#include <fmt/core.h>

int main() {
    // Create identities for CA (Certificate Authority), client, and server
    auto ca = dht::crypto::generateIdentity("ca");
    auto id_client = dht::crypto::generateIdentity("client", ca);
    auto id_server = dht::crypto::generateIdentity("server", ca);

    // Create client and server ConnectionManager instances
    auto client = std::make_shared<ConnectionManager>(id_client);
    auto server = std::make_shared<ConnectionManager>(id_server);

    // Launch dht nodes
    client->onDhtConnected(id_client.first->getPublicKey());
    server->onDhtConnected(id_server.first->getPublicKey());

    // Connect the client to the server's device via a channel named "channelName"
    client->connectDevice(id_server.second->getId(), "channelName", [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const dht::InfoHash&) {
        if (socket) {
            // Send a message (example: "Hello") to the server
            std::error_code ec;
            std::string data = "hello";
            socket->write(data.data(), data.size(), ec);
        }
    });

    // Define a callback function for when the server's connection is ready
    server->onConnectionReady([&](const DeviceId& device, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
        if (socket) {
            // Server: Connection succeeded
            fmt::print("Server: Connection succeeded\n");

            // Set a callback for receiving messages
            socket->setOnRecv([&](const uint8_t* data, size_t size) {
               fmt::print("Message received: {}\n", std::string_view(data, data + size)); // Print received message
            });
        } else {
            // Server: Connection failed
            fmt::print("Server: Connection failed\n");
        }
    });

    return 0;
}
```

## Dependencies

DHTNet depends on the following libraries:

- **OpenDHT** 2.6, used to launch DHT nodes.
- **[pjproject](https://github.com/savoirfairelinux/pjproject)**, used for ICE negotiation.
- **msgpack-c** 1.2+, used for data serialization.
- **GnuTLS** 3.3+, used for cryptographic operations.
- **Nettle** 2.4+, a GnuTLS dependency for crypto.
- **{fmt}** 9.0+, for log formatting.


## See also

### Dnc: Distributed nc

dnc is a command-line that provides network connectivity between peers in a Distributed Hash Table (DHT) network. It allows peers to establish connections with other peers and create a TCP socket on a remote devices, similar to the behavior of the traditional nc utility.
#### SSH configuration
To simplify the usage of dnc with SSH, you can add the following lines to your SSH configuration file (`~/.ssh/config`):
```ssh
Host dnc/*
    IdentityFile /home/<local_user>/.ssh/<key>.pub
    ProxyCommand /home/<local_user>/dhtnet/build/dnc -I /home/<local_user>/.dhtnet/client $(basename %h)
```
#### Setting up the Server (Listening)
On the server side, run **dnc** in listen mode to accept incoming connections:

```sh
dnc -l
```
This command instructs dnc to listen for incoming connections and will also print its own ID.
#### Connecting from the Client
On the client side, you can use the "dnc" alias you defined earlier to connect to a remote server. Replace <peer_id> with the actual peer ID you want to connect to, and <ssh_remote_user> with the SSH remote user you intend to use:
```sh
ssh <ssh_remote_user>@dnc/<peer_id>
```
For example:
```sh
ssh mypeer@dnc/2f4975e7b11a0908bd400b27130fe9a496d0f415
```

### Dsh: Distributed shell

dsh is a Distributed Shell command-line that enables peers to establish connections with other peers in a Distributed Hash Table (DHT) network and execute a binary on the remote target.

#### Setting up the Server (Listening) and Default Command

To set up the dsh server to listen for incoming connections and execute bash by default if no file is specified, execute the following command on the server:
```sh
dsh -l
```
#### Connecting from the Client

Replace <peer_id> with the actual peer ID you want to connect to:
```sh
dsh -I /home/<local_user>/.dhtnet/client <peer_id>
```
##### Using Different Certificates

If the client and server are on the same machine, they should use different certificates for authentication, so make sure to specify different identity file paths for the client and server. This ensures that they use separate certificates. In the example above, we specified the client's identity file path as /home/<local_user>/.dhtnet/client