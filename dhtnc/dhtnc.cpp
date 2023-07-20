#include "dhtnc.h"
#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"


#include <opendht/crypto.h>

#include <asio.hpp>

#include <iostream>
#include <chrono>
#include <string>
#include <string_view>
#include <filesystem>
#include <unistd.h>
#include <fcntl.h>
#include <memory>
namespace dhtnet
{
std::pair<std::string, std::string> DhtNc::parseName(const std::string_view name)
{
    // name is in the format of "nc//:ip_add:port"
    size_t colonPos = name.find(':', 6);
    std::string ip_add = std::string(name.substr(6, colonPos - 6));
    std::string port = std::string(name.substr(colonPos + 1));
    return std::make_pair(ip_add, port);
}

void DhtNc::readFromStdin(std::shared_ptr<ChannelSocket> socket) {
    // Create a buffer to read data into
    std::array<uint8_t, 65536> buffer;

    // Create a shared_ptr to the stream_descriptor
    std::shared_ptr<asio::posix::stream_descriptor> stdinDescriptor =
        std::make_shared<asio::posix::stream_descriptor>(*ioContext, ::dup(STDIN_FILENO));

    // Start reading asynchronously from stdin
    asio::async_read(
        *stdinDescriptor,
        asio::buffer(buffer),
        [&](const asio::error_code& error, size_t bytesRead) {
            if (!error) {
                // Process the data received in the buffer
                std::error_code ec;
                socket->write(buffer.data(), bytesRead, ec);
                if (!ec) {
                    // Continue reading more data
                    readFromStdin(socket);
                } else {
                    logger->error("Error writing to socket: {}", ec.message());
                }
            } else {
                logger->error("Error reading from stdin: {}", error.message());
            }
        }
    );

}

void DhtNc::readFromTcpSocket(std::shared_ptr<ChannelSocket> multiplexed_socket,std::shared_ptr<asio::ip::tcp::socket> socket) {
    // Create a buffer to read data into
    std::array<uint8_t, 65536> buffer;

    // Start reading asynchronously from the socket
    socket->async_read_some(
        asio::buffer(buffer),
        [&](const asio::error_code& error, size_t bytesRead) {
            if (!error) {
                std::error_code ec;
                multiplexed_socket->write(buffer.data(), bytesRead, ec);
                if (!ec) {
                    // Continue reading more data
                    readFromTcpSocket(multiplexed_socket, socket);
                } else {
                    logger->error("Error writing to multiplexed socket: {}", ec.message());
                }
            } else {
                logger->error("Error reading from TCP socket: {}", error.message());
            }
        }
    );
}

DhtNc::DhtNc(dht::crypto::Identity identity)
{
    logger = std::shared_ptr<Logger>();
    ioContext = std::make_shared<asio::io_context>();
    ioContextRunner = std::thread([context = ioContext, logger = logger]
    {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            logger -> error("Error in ioContextRunner: {}", ex.what());
        } });

    // DHT node creation: To make a connection manager at first a DHT node should be created

    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = identity;
    dhtConfig.threaded = true;
    auto userCertStore = std::make_unique<tls::CertificateStore>("dhtnc", logger);
    dht::DhtRunner::Context dhtContext;
    dhtContext.certificateStore = [&](const dht::InfoHash &pk_id)
    {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = userCertStore->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    auto runner = std::make_shared<dht::DhtRunner>();
    runner->run(dhtConfig, std::move(dhtContext));
    // DHT node creation end:
    // ConnectionManager creation:
    auto config = std::make_unique<ConnectionManager::Config>();
    config->dht = runner;
    config->id = identity;

    config->ioContext = ioContext;

    std::filesystem::path currentPath = std::filesystem::current_path();
    std::filesystem::path tempDirPath = currentPath / "test_temp_dir";
    config->cachePath = tempDirPath.string();
    // create a connection manager

    connectionManager = std::make_unique<ConnectionManager>(move(config)) ;

    connectionManager -> onICERequest([this](const dht::Hash<32>&)
    { // handle ICE request
        logger->debug("ICE request received");
        return true;
    });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk{mtx};

    connectionManager-> onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&,
                                const std::string &name)
        {
                            // handle channel request
                            logger->debug("Channel request received");
                            return true; });

    connectionManager->onConnectionReady(
        [&](const DeviceId &,
            const std::string &name,
            std::shared_ptr<ChannelSocket> socket_received)
        {
            try
            {
                // Create a TCP resolver to resolve the server hostname and port
                auto parsedName = parseName(name);
                asio::ip::tcp::resolver resolver(*ioContext);
                asio::ip::tcp::resolver::results_type endpoints =
                    resolver.resolve(parsedName.first, parsedName.second);

                // Create a TCP socket
                auto socket = std::make_shared<asio::ip::tcp::socket>(*ioContext);
                asio::async_connect(*socket, endpoints,
                    [this, socket, socket_received](const std::error_code &error, const asio::ip::tcp::endpoint & ep)
                    {
                        if (!error)
                        {
                            logger->debug("Connected to the server!");
                            socket_received->setOnRecv([socket](const uint8_t* data, size_t size){
                                auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                                asio::async_write(*socket, asio::buffer(*data_copy),
                                    [data_copy](const std::error_code& error, std::size_t bytesWritten) {
                                        if (error) {
                                            //logger->error("Write error: {}", error.message());
                                        }
                                    });
                                return size;
                            });
                            readFromTcpSocket(socket_received,socket);
                        }
                        else
                        {
                            logger->error("Connection error: {}", error.message());
                        }
                    });

            }
            catch (std::exception &e)
            {
                // std::cerr << "Exception: " << e.what() << std::endl;
                logger->error("Exception: {}", e.what());
            }
        });
}

DhtNc::DhtNc(dht::crypto::Identity identity, dht::PkId peer_id, int port, const std::string &ip_add) : DhtNc(identity)
{
    connectionManager-> connectDevice(peer_id,
                                    "nc://" + ip_add + ":" + std::to_string(port),
                                    [&](std::shared_ptr<ChannelSocket> socket,
                                        const DeviceId &)
                                    {
                                        if (socket)
                                        {
                                            socket->setOnRecv([this, socket](const uint8_t* data, size_t size){
                                                auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                                                logger->debug(reinterpret_cast<const char*>(data_copy->data()), data_copy->size());
                                                return size;
                                            });

                                            readFromStdin(socket);


                                        }

                                    });
}

dht::crypto::Identity DhtNc::loadIdentity()
{
    try
    {
        const std::string sshDir = std::string(getenv("HOME")) + "/.ssh";
        std::filesystem::directory_iterator endIter;
        for (std::filesystem::directory_iterator iter(sshDir); iter != endIter; ++iter)
        {
            if (iter->path().extension() == ".pub")
            {
                // auto userCertStore = std::make_unique<tls::CertificateStore>(dht::tools::loadfile (iter->path()));
                //  Load public key
                auto publicKey = std::make_unique<dht::crypto::PublicKey>(fileutils::loadFile(iter->path()));
                // Load private key
                auto privateKey = std::make_unique<dht::crypto::PrivateKey>(fileutils::loadFile(std::filesystem::path(iter->path()).replace_extension("")));
                // Generate certificate
                // auto certificate = std::make_unique<dht::crypto::Certificate>(std::move(publicKey), std::move(privateKey));
                auto certificate = std::make_unique<dht::crypto::Certificate>(dht::crypto::Certificate::generate(*privateKey, "dhtnc"));
                // return
                return dht::crypto::Identity(std::move(privateKey), std::move(certificate));
                break;
            }
        }
    }
    catch (const std::exception &e)
    {
        return dht::crypto::generateIdentity("dhtnc");
    }
    return dht::crypto::generateIdentity("dhtnc");
}

DhtNc::~DhtNc()
{
    ioContext->stop();
    ioContextRunner.join();
}
} // namespace dhtnc