/*
 *  Copyright (C) 2023 Savoir-faire Linux Inc.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "dnc.h"
#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"
#include "../common.h"

#include <opendht/log.h>
#include <opendht/crypto.h>
#include <asio.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <string_view>
#include <filesystem>
#include <memory>

namespace dhtnet {
std::pair<std::string, std::string>
Dnc::parseName(const std::string_view name)
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

// Build a server
Dnc::Dnc(dht::crypto::Identity identity,
         const std::string& bootstrap,
         const std::string& turn_host,
         const std::string& turn_user,
         const std::string& turn_pass,
         const std::string& turn_realm,
         const bool anonymous,
         const bool verbose,
         const std::map<std::string, std::vector<int>> authorized_services)
    :logger(verbose ? dht::log::getStdLogger() : nullptr),
    ioContext(std::make_shared<asio::io_context>()),
    iceFactory(std::make_shared<IceTransportFactory>(logger))
{
    ioContextRunner = std::thread([context = ioContext, logger = logger] {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            if (logger)
                logger->error("Error in ioContextRunner: {}", ex.what());
        }
    });

    certStore = std::make_shared<tls::CertificateStore>(cachePath()/"certStore", logger);
    trustStore = std::make_shared<tls::TrustStore>(*certStore);

    auto ca = identity.second->issuer;
    trustStore->setCertificateStatus(ca->getId().toString(), tls::TrustStore::PermissionStatus::ALLOWED);

    auto config = connectionManagerConfig(identity,
                                          bootstrap,
                                          logger,
                                          certStore,
                                          ioContext,
                                          iceFactory,
                                          turn_host,
                                          turn_user,
                                          turn_pass,
                                          turn_realm);
    // create a connection manager
    connectionManager = std::make_unique<ConnectionManager>(std::move(config));

    connectionManager->onDhtConnected(identity.first->getPublicKey());
    connectionManager->onICERequest([this, identity, anonymous](const DeviceId& deviceId) {
        auto cert = certStore->getCertificate(deviceId.toString());
        return trustStore->isAllowed(*cert, anonymous);
    });

    std::mutex mtx;
    std::unique_lock lk {mtx};

    connectionManager->onChannelRequest(
        [authorized_services, this](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
            // handle channel request
            if (authorized_services.empty()) {
                // Accept all connections if no authorized services are provided
                return true;
            }
            // parse channel name to get the ip address and port: nc://<ip>:<port>
            auto parsedName = parseName(name);
            const std::string &ip = parsedName.first;
            int port = 0;
            try {
                port = std::stoi(parsedName.second);
            }
            catch (std::exception const &err) {
                fmt::print(stderr, "Rejecting connection: port '{}' is not a valid number", parsedName.second);
                return false;
            }

            // Check if the IP is authorized
            auto it = authorized_services.find(ip);
            if (it == authorized_services.end()) {
                // Reject the connection if the ip is not authorized
                fmt::print("Rejecting connection to {}:{}", ip, port);
                return false;
            }

            // Check if the port is authorized
            const auto &ports = it->second;
            if (std::find(ports.begin(), ports.end(), port) == ports.end()) {
                // Reject the connection if the port is not authorized
                fmt::print("Rejecting connection to {}:{}", ip, port);
                return false;
            }
            fmt::print("Accepting connection to {}:{}", ip, port);
            return true;
        });

    connectionManager->onConnectionReady([&](const DeviceId&,
                                             const std::string& name,
                                             std::shared_ptr<ChannelSocket> mtlxSocket) {
        if (name.empty()) {
            // Handle the empty input case here
            return;
        }
        try {
            auto parsedName = parseName(name);
            fmt::print("Connecting to {}:{}", parsedName.first, parsedName.second);

            asio::ip::tcp::resolver resolver(*ioContext);
            asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(parsedName.first,
                                                                               parsedName.second);

            // Create a TCP socket
            auto socket = std::make_shared<asio::ip::tcp::socket>(*ioContext);
            socket->open(asio::ip::tcp::v4());
            socket->set_option(asio::socket_base::keep_alive(true));
            asio::async_connect(
                *socket,
                endpoints,
                [this, socket, mtlxSocket](const std::error_code& error,
                                           const asio::ip::tcp::endpoint& ep) {
                    if (!error) {
                        fmt::print("Connected!\n");
                        mtlxSocket->setOnRecv([socket, this](const uint8_t* data, size_t size) {
                            auto data_copy = std::make_shared<std::vector<uint8_t>>(data,
                                                                                    data + size);
                            asio::async_write(*socket,
                                              asio::buffer(*data_copy),
                                              [data_copy, this](const std::error_code& error,
                                                                std::size_t bytesWritten) {
                                                  if (error) {
                                                    fmt::print("Write error: {}\n", error.message());
                                                  }

                                              });
                            return size;
                        });
                        // Create a buffer to read data into
                        auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
                        readFromPipe(mtlxSocket, socket, buffer);
                    } else {
                        fmt::print("Connection error: {}\n", error.message());
                        mtlxSocket->shutdown();
                    }
                });

        } catch (std::exception& e) {
            fmt::print("Exception: {}\n", e.what());
        }
    });
}
// Build a client
Dnc::Dnc(dht::crypto::Identity identity,
         const std::string& bootstrap,
         dht::InfoHash peer_id,
         const std::string& remote_host,
         int remote_port,
         const std::string& turn_host,
         const std::string& turn_user,
         const std::string& turn_pass,
         const std::string& turn_realm,
         const bool verbose)
    : Dnc(identity, bootstrap,turn_host,turn_user,turn_pass, turn_realm, true, verbose, {})
{
    std::condition_variable cv;
    auto name = fmt::format("nc://{:s}:{:d}", remote_host, remote_port);
    fmt::print("Requesting socket: %s\n", name.c_str());
    connectionManager->connectDevice(
        peer_id, name, [&](std::shared_ptr<ChannelSocket> socket, const dht::InfoHash&) {
            if (socket) {
                socket->setOnRecv([this, socket](const uint8_t* data, size_t size) {
                    std::cout.write((const char*) data, size);
                    std::cout.flush();
                    return size;
                });
                // Create a buffer to read data into
                auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);

                // Create a shared_ptr to the stream_descriptor
                auto stdinPipe = std::make_shared<asio::posix::stream_descriptor>(*ioContext,
                                                                                  ::dup(
                                                                                      STDIN_FILENO));
                readFromPipe(socket, stdinPipe, buffer);

                socket->onShutdown([this]() {
                    fmt::print("Exit program\n");
                    ioContext->stop();
                });
            }
        });

    connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> mtlxSocket) {
            fmt::print("Connected!\n");
        });
}

void
Dnc::run()
{
    ioContext->run();
}

Dnc::~Dnc()
{
    ioContext->stop();
    ioContextRunner.join();
}
} // namespace dhtnet
