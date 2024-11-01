#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"

#include <opendht/crypto.h>

#include <string>
#include <vector>

namespace dhtnet {
void
client(dht::crypto::Identity id_client, dht::InfoHash id_server)
{
    fmt::print("Start client\n");
    fmt::print("Client identity: {}\n", id_client.second->getId());

    // Create client ConnectionManager instance
    auto client = std::make_shared<ConnectionManager>(id_client);

    // Connect the client to the server's device via a channel named "channelName"
    client->connectDevice(id_server,
                          "channelName",
                          [&](std::shared_ptr<ChannelSocket> socket, const dht::InfoHash&) {
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

int
main(int argc, char** argv)
{
    // Set the log level to 0 to avoids pj logs
    pj_log_set_level(0);

    // This is the root certificate that will be used to sign other certificates
    auto ca = dht::crypto::generateIdentity("ca_client");

    auto id_client = dht::crypto::generateIdentity("client", ca);

    auto id_server = dht::InfoHash(argv[1]);

    dhtnet::client(id_client, id_server);


    return 0;
}