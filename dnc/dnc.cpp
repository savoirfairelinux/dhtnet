#include "dnc.h"
#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"

#include <opendht/log.h>
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
std::pair<std::string, std::string> dnc::parseName(const std::string_view name)
{
    // Find the position of the first ':' character after "nc//"
    size_t ip_add_start = name.find("nc//") + 6; // Adding 5 to skip "nc//"
    size_t colonPos = name.find(':', ip_add_start);

    if (colonPos == std::string::npos) {
        // Return an empty pair if ':' is not found
        return std::make_pair("", "");
    }

    std::string ip_add(name.substr(ip_add_start, colonPos - ip_add_start));
    std::string port(name.substr(colonPos + 1));

    return std::make_pair(ip_add, port);
}

void dnc::readFromStdin(std::shared_ptr<ChannelSocket> socket) {
    // Create a buffer to read data into
    auto buffer = std::make_shared<std::vector<uint8_t>>(65536);


    // Create a shared_ptr to the stream_descriptor
    if (!stdinDescriptor)
        stdinDescriptor = std::make_shared<asio::posix::stream_descriptor>(*ioContext, ::dup(STDIN_FILENO));

    // Start reading asynchronously from stdin

    asio::async_read(
        *stdinDescriptor,
        asio::buffer(*buffer),
        asio::transfer_at_least(1),
        [this, socket, buffer](const asio::error_code& error, size_t bytesRead) {
            if (!error) {
                // Process the data received in the buffer
                std::error_code ec;
                // print the data to stdout
                socket->write(buffer->data(), bytesRead, ec);
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

void dnc::readFromTcpSocket(std::shared_ptr<ChannelSocket> multiplexed_socket, std::shared_ptr<asio::ip::tcp::socket> socket) {
    // Create a buffer to read data into
    auto buffer = std::make_shared<std::vector<uint8_t>>(65536);

    // Start reading asynchronously from the socket
    socket->async_read_some(
        asio::buffer(*buffer),
        [this, multiplexed_socket, socket, buffer](const asio::error_code& error, size_t bytesRead) {
            if (!error) {
                if (bytesRead > 0) {
                    std::error_code ec;
                    multiplexed_socket->write(buffer->data(), bytesRead, ec);
                    if (!ec) {
                        // Continue reading more data
                        readFromTcpSocket(multiplexed_socket, socket);
                    } else {
                        logger->error("Error writing to multiplexed socket: {}", ec.message());
                    }
                } else {
                    // The remote end closed the connection, handle it accordingly
                    logger->error("Connection closed by remote end");
                }
            } else {
                // An error occurred during the read operation
                logger->error("Error reading from TCP socket: {}", error.message());
                multiplexed_socket->shutdown();
                logger->error("Shutdown channel socket");
            }
        }
    );
}



dnc::dnc(dht::crypto::Identity identity, const std::string& bootstrap_ip_add, const std::string& bootstrap_port)
: logger(dht::log::getStdLogger()), certStore("certstore", logger)
{
    std::filesystem::create_directories("certstore");
    logger = dht::log::getStdLogger();
    ioContext = std::make_shared<asio::io_context>();
    ioContextRunner = std::thread([context = ioContext, logger = logger]
    {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            logger->error("Error in ioContextRunner: {}", ex.what());
        } });

    // DHT node creation: To make a connection manager at first a DHT node should be created

    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = identity;
    dhtConfig.threaded = true;
    dhtConfig.peer_discovery = false;
    dhtConfig.peer_publish = false;
    dht::DhtRunner::Context dhtContext;
    //dhtContext.logger = logger;
    dhtContext.identityAnnouncedCb = [&](bool ok)
    {
        logger->error("Identity annoucned {}\n", ok);
    };
    dhtContext.certificateStore = [&](const dht::InfoHash &pk_id)
    {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = certStore.getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    auto runner = std::make_shared<dht::DhtRunner>();
    runner->run(dhtConfig, std::move(dhtContext));
    runner->bootstrap(bootstrap_ip_add, bootstrap_port);

    // DHT node creation end:
    // ConnectionManager creation:
    auto config = std::make_unique<ConnectionManager::Config>();
    config->dht = runner;
    config->id = identity;
    config->ioContext = ioContext;
    config->certStore = &certStore;
    // config->logger = logger;
    config->factory = &iceFactory;

    std::filesystem::path currentPath = std::filesystem::current_path();
    std::filesystem::path tempDirPath = currentPath / "test_temp_dir";
    config->cachePath = tempDirPath.string();
    // create a connection manager
    connectionManager = std::make_unique<ConnectionManager>(move(config));
    connectionManager->onDhtConnected(identity.first->getPublicKey());
    connectionManager->onICERequest([this](const dht::Hash<32>&)
    { // handle ICE request
        logger->error("ICE request received");
        return true;
    });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk{mtx};

    connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&,
                                const std::string &name)
        {
            // handle channel request
            logger->error("Channel request received");
            return true;
        });

    connectionManager->onConnectionReady(
        [&](const DeviceId &,
            const std::string &name,
            std::shared_ptr<ChannelSocket> socket_received)
        {
            if (name.empty())
            {
                // Handle the empty input case here
                return;
            }
            try
            {
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
                            logger->error("Connected!");
                            socket_received->setOnRecv([socket,this](const uint8_t* data, size_t size){
                            auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                            asio::async_write(*socket, asio::buffer(*data_copy),
                                [data_copy, this](const std::error_code& error, std::size_t bytesWritten) {
                                    if (error) {
                                        logger->error("Write error: {}", error.message());
                                    }
                                });
                            return size;
                            });
                            readFromTcpSocket(socket_received,socket);
                            // run command (data_copy) with std::system
                            // const char* command = reinterpret_cast<const char*>(data_copy->data());
                            // int result = std::system(command);

                        //});

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

dnc::dnc(dht::crypto::Identity identity, const std::string& bootstrap_ip_add, const std::string& bootstrap_port, dht::InfoHash peer_id, int port, const std::string& ip_add) : dnc(identity, bootstrap_ip_add, bootstrap_port)
{
    std::condition_variable cv;
    auto name = fmt::format("nc://{:s}:{:d}", ip_add, port);
    connectionManager->connectDevice(peer_id,
                                    name,
                                    [&](std::shared_ptr<ChannelSocket> socket,
                                        const dht::InfoHash &)
            {
                if (socket)
                {
                    socket->setOnRecv([this, socket](const uint8_t* data, size_t size){
                        //auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                        logger->error((const char*)data, size);
                        std::cout.write((const char*)data, size);
                        return size;
                    });
                    readFromStdin(socket);

                    socket->onShutdown([this](){
                        logger->error("Exit program");
                        std::exit(EXIT_FAILURE);;
                    });
                }
            });

    connectionManager->onConnectionReady(
        [&](const DeviceId &,
            const std::string &name,
            std::shared_ptr<ChannelSocket> socket_received)
        {
            logger->error("Connected!");
        });
}

void dnc::run() {
    ioContext->run();
}

dht::crypto::Identity loadIdentity()
{
    std::string idDir = std::string(getenv("HOME")) + "/.dnc";

    try
    {
        std::filesystem::directory_iterator endIter;
        for (std::filesystem::directory_iterator iter(idDir); iter != endIter; ++iter)
        {
            if (iter->path().extension() == ".pem")
            {
                // fmt::print("Loading identity from: {}\n", idDir);
                auto privateKey = std::make_unique<dht::crypto::PrivateKey>(fileutils::loadFile(std::filesystem::path(iter->path())));
                // Generate certificate
                auto certificate = std::make_unique<dht::crypto::Certificate>(dht::crypto::Certificate::generate(*privateKey, "dhtnc"));
                // return
                return dht::crypto::Identity(std::move(privateKey), std::move(certificate));
            }
        }
    }
    catch (const std::exception &e) {
        fmt::print(stderr, "Error loadind key from .ssh: {}\n", e.what());
    }

    auto ca = dht::crypto::generateIdentity("ca");
    auto id = dht::crypto::generateIdentity("dhtnc", ca);
    // fmt::print("Saving identity to: {}\n", idDir);
    // idDir += "/id";
    // dht::crypto::saveIdentity(id, idDir);
    return id;
}

dnc::~dnc()
{
    ioContext->stop();
    ioContextRunner.join();
}
}

