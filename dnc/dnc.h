#include "connectionmanager.h"
#include "multiplexed_socket.h"
#include "ice_transport_factory.h"
#include "certstore.h"

#include <asio.hpp>

namespace dhtnet {
/**
     * Attempt to retrieve the identity from the .ssh directory, and if none is found, generate a new certification.
     * @return dht::crypto::Identity
    */
    dht::crypto::Identity loadIdentity();

class dnc {
public:
    // Build a server
    dnc(dht::crypto::Identity identity, const std::string& bootstrap_ip_add, const std::string& bootstrap_port);
    // Build a client
    dnc(dht::crypto::Identity identity, const std::string& bootstrap_ip_add, const std::string& bootstrap_port, dht::InfoHash peer_id, int port, const std::string& ip_add);
    void run();
    ~dnc();


private:
    std::unique_ptr<ConnectionManager> connectionManager;
    std::shared_ptr<Logger> logger;
    tls::CertificateStore certStore;
    IceTransportFactory iceFactory;
    std::shared_ptr<asio::io_context> ioContext;
    std::thread ioContextRunner;

    std::shared_ptr<asio::posix::stream_descriptor> stdinDescriptor;

    std::pair<std::string, std::string> parseName(const std::string_view name);
    void readFromStdin(std::shared_ptr<ChannelSocket> socket);
    void readFromTcpSocket(std::shared_ptr<ChannelSocket> multiplexed_socket,std::shared_ptr<asio::ip::tcp::socket> socket);
    // Add any additional private member functions or variables if needed
};

} // namespace dhtnet
