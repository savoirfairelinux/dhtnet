# DHTNet - Lightweight Peer-to-Peer Communication Library

![DHTNet Logo](your-logo.png)

DHTNet is a C++17 library extracted from the GNU Jami project, designed to facilitate peer-to-peer communication and networking. It offers essential functionalities for managing connections to peers and multiplexing sockets to enable seamless communication between devices.

## Features

- **Connection Management**: DHTNet simplifies the establishment and management of connections to peers, streamlining the communication process.

- **Multiplexed Sockets**: It provides multiplexed sockets that allow multiple channels for data transmission, optimizing network resources.

- **UPnP Integration**: DHTNet seamlessly integrates with UPnP, enabling automatic port mapping and enhanced network connectivity.

- **Server TURN Support**: DHTNet includes support for server TURN, used as a fallback for connections if the NAT block all possible connections.


## Documentation

For detailed information on using DHTNet, consult our documentation:

- [DHTNet Wiki](https://github.com/your-repo/DHTNet/wiki)


## Getting Started

Get started with DHTNet by building and installing the library:

- [Build and Install Instructions](https://github.com/your-repo/DHTNet/wiki/Build-the-Library)

## Usage Examples

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
- **OpenDHT**:
- **PJSIP**:
- **{fmt}**:

## See also

### Dnc: Distributed nc
dnc is a program that provides network connectivity between peers in a Distributed Hash Table (DHT) network. It allows peers to establish connections with other peers and create a TCP socket on a remote devices, similar to the behavior of the traditional nc utility.

### Dsh: Distributed shell
dsh is a Distributed Shell program that enables peers to establish connections with other peers in a Distributed Hash Table (DHT) network and execute a binary on the remote target.
