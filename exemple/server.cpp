
#include "connectionmanager.h"
#include "fileutils.h"

#include <opendht/log.h>
#include <opendht/crypto.h>

#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <string_view>
namespace dhtnet {
dht::crypto::Identity
server(dht::crypto::Identity ca)
{
    // Generate identity certificate for the server signed by the CA
    auto id_server = dht::crypto::generateIdentity("server", ca);
    fmt::print("Server identity: {}\n", id_server.second->getId());
    // Create server ConnectionManager instance
    auto server = std::make_shared<ConnectionManager>(id_server);

    fmt::print("Start server\n");
    // Launch dht nodes
    server->onDhtConnected(id_server.first->getPublicKey());

    // onICERequest callback
    server->onICERequest([id_server](const DeviceId& device) {
        // you can check if the device is allowed to connect based on its certificate
        // for example, you can check if the device's certificate is signed by a trusted CA
        // consult the tools example for more details
        //
        // This example allows all connections
        fmt::print("Server: ICE request received from {}\n", device.toString());
        return true;
    });

    // onChannelRequest callback
    server->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>& cert, const std::string& name) {
            // you can check if the device is allowed to connect based on the channel name
            // for example, you can check if the channel name is in a list of allowed channels
            //
            // This example allows the connection if the channel name is "channelName"
            fmt::print("Server: Channel request received from {}\n", cert->getLongId());
            if (name == "channelName") {
                return true;
            }
            return true;
        });

    // Define a callback function for when the server's connection is ready
    server->onConnectionReady(
        [&](const DeviceId& device, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            if (socket) {
                // Server: Connection succeeded
                fmt::print("Server: Connection succeeded\n");

                // Set a callback for receiving messages
                socket->setOnRecv([socket](const uint8_t* data, size_t size) {
                    std::cout.write((const char*) data, size);
                    std::cout.flush();
                    return size;
                });
            } else {
                // Server: Connection failed
                fmt::print("Server: Connection failed\n");
            }
        });
    return id_server;
}

} // namespace dhtnet