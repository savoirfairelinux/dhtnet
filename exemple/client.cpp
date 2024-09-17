#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"

#include <opendht/crypto.h>

#include <string>
#include <vector>

namespace dhtnet {
dht::crypto::Identity client (dht::crypto::Identity id_server, dht::crypto::Identity ca ) {
    fmt::print("Start client\n");
    // Generate an identity certificate for the client signed by the CA
    auto id_client = dht::crypto::generateIdentity("client", ca);

    // Create client ConnectionManager instance
    auto client = std::make_shared<ConnectionManager>(id_client);

    // Launch dht nodes
    client->onDhtConnected(id_client.first->getPublicKey());

    fmt::print("Client identity: {}\n", id_client.second->getId());
    fmt::print("Server identity: {}\n", id_server.second->getId());
    // Connect the client to the server's device via a channel named "channelName"
    client->connectDevice(id_server.second, "channelName",[&](std::shared_ptr<ChannelSocket> socket, const DeviceId&) {
        fmt::print("Client: Sending request\n");
        if (socket) {
            // Send a message (example: "Hello") to the server
            std::error_code ec;
            std::string msg = "hello";
            fmt::print("Client: Sending message: {}\n", msg);
            // Convert string to buffer (std::vector<unsigned char>)
            std::vector<unsigned char> data(msg.begin(), msg.end());

            socket->write(data.data(), data.size(), ec);
            // To send a flow of data, see the readFromPipe function in tools/common.cpp
            if (ec) {
                fmt::print("Client: Error writing to socket: {}\n", ec.message());
            }else{
                fmt::print("Client: Message sent\n");
            }
        }else{
            fmt::print("Client: Connection failed\n");
            return;
        }
    });

    return id_client;
}

}