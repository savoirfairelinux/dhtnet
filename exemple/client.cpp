#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"

#include <opendht/crypto.h>

#include <string>
#include <vector>

namespace dhtnet {
void
client(dht::crypto::Identity id_client, dht::crypto::Identity id_server)
{
    fmt::print("Start client\n");
    fmt::print("Client identity: {}\n", id_client.second->getId());

    // Create client ConnectionManager instance
    auto client = std::make_shared<ConnectionManager>(id_client);

    // Launch dht node
    client->onDhtConnected(id_client.first->getPublicKey());

    // Connect the client to the server's device via a channel named "channelName"
    client->connectDevice(id_server.second,
                          "channelName",
                          [&](std::shared_ptr<ChannelSocket> socket, const DeviceId&) {
                              fmt::print("Client: Sending request\n");
                              if (socket) {
                                  // Send a message (example: "Hello") to the server
                                  std::error_code ec;
                                  std::string msg = "hello";
                                  fmt::print("Client: Sending message: {}\n", msg);
                                  std::vector<unsigned char> data(msg.begin(), msg.end());

                                  socket->write(data.data(), data.size(), ec);
                                  // For continuous data transmission, refer to the readFromPipe
                                  // function in tools/common.cpp
                                  if (ec) {
                                      fmt::print("Client: Error writing to socket: {}\n",
                                                 ec.message());
                                  } else {
                                      fmt::print("Client: Message sent\n");
                                  }
                              } else {
                                  fmt::print("Client: Connection failed\n");
                                  return;
                              }
                          });

    // keep the client running
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}
} // namespace dhtnet