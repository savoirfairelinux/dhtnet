#include "connectionmanager.h"
#include "multiplexed_socket.h"
#include <asio.hpp>

namespace dhtnet {

class DhtNc {
public:
    // Build a server
    DhtNc(dht::crypto::Identity identity);
    // Build a client
    DhtNc(dht::crypto::Identity identity, dht::PkId peer_id, int port = 22, const std::string& ip_add = "localhost");

    ~DhtNc();

    /**
     * Attempt to retrieve the identity from the .ssh directory, and if none is found, generate a new certification.
     * @return dht::crypto::Identity
    */
    dht::crypto::Identity loadIdentity();

private:
    std::unique_ptr<ConnectionManager> connectionManager;
    std::shared_ptr<Logger> logger;
    std::shared_ptr<asio::io_context> ioContext;
    std::thread ioContextRunner;

    std::pair<std::string, std::string> parseName(const std::string_view name);
    void readFromStdin(std::shared_ptr<ChannelSocket> socket);
    void readFromTcpSocket(std::shared_ptr<ChannelSocket> multiplexed_socket,std::shared_ptr<asio::ip::tcp::socket> socket);
    // Add any additional private member functions or variables if needed
};

} // namespace dhtnet
