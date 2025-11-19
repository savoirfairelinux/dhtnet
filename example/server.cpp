
#include "connectionmanager.h"
#include "fileutils.h"

#include <opendht/log.h>
#include <opendht/crypto.h>

#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <string_view>
namespace dhtnet {
void
server(dht::crypto::Identity id_server)
{
    fmt::print("Server identity: {}\n", id_server.second->getLongId());
    // Create an instance of ConnectionManager for the server
    auto server = std::make_shared<ConnectionManager>(id_server);

    fmt::print("Start server\n");
    // Start the DHT node for the server
    server->dhtStarted();

    // Handle ICE connection requests from devices
    // This callback is triggered when a device requests an ICE connection.
    // The callback should decide whether to accept or decline the request.
    server->onICERequest([id_server](const DeviceId& device) {
        // Optional: Add logic to validate the device's certificate
        // Example: Check if the device's certificate is signed by a trusted authority
        // In this example, all devices are allowed to connect
        fmt::print("Server: ICE request received from {}\n", device.toString());
        return true;
    });

    // Handle requests for establishing a communication channel
    // The callback checks if the channel should be opened based on the name or device's certificate.
    server->onChannelRequest([&](const std::shared_ptr<dht::crypto::Certificate>& cert, const std::string& name) {
        // Optional: Add logic to validate the channel name or certificate
        // Example: Allow the connection if the channel name is "channelName"
        fmt::print("Server: Channel request received from {}\n", cert->getLongId());
        return name == "channelName";
    });

    // Define a callback when the connection is established
    server->onConnectionReady(
        [&](const DeviceId& device, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            if (socket) {
                fmt::print("Server: Connection succeeded\n");
                // Set up a callback to handle incoming messages on this connection
                socket->setOnRecv([socket](const uint8_t* data, size_t size) {
                    fmt::print("Server: Received message: {}\n", std::string_view((const char*) data, size));
                    return size;
                });
            } else {
                // The connection failed
                fmt::print("Server: Connection failed\n");
            }
        });

    // Keep the server running indefinitely
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

} // namespace dhtnet

int
main()
{
    // Set the log level to 0 to avoids pj logs
    pj_log_set_level(0);

    // This is the root certificate that will be used to sign other certificates
    auto ca = dht::crypto::generateIdentity("ca");

    auto id_server = dht::crypto::generateIdentity("server", ca);

    dhtnet::server(id_server);

    return 0;
}