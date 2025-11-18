/*
 *  Copyright (C) 2004-2025 Savoir-faire Linux Inc.
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
#include <fmt/std.h>

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <string_view>
#include <filesystem>
#include <memory>
#include <charconv>

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
         const std::map<std::string, std::vector<uint16_t>> authorized_services,
         const bool enable_upnp)
    : logger(verbose ? dht::log::getStdLogger() : nullptr)
    , iceFactory(std::make_shared<IceTransportFactory>(logger))
    , ioContext(std::make_shared<asio::io_context>())
{
    certStore = std::make_shared<tls::CertificateStore>(cachePath() / "certStore", logger);
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
                                          turn_realm,
                                          enable_upnp);
    // create a connection manager
    connectionManager = std::make_unique<ConnectionManager>(std::move(config));

    connectionManager->dhtStarted();
    connectionManager->onICERequest([this, identity, anonymous](const DeviceId& deviceId) {
        auto cert = certStore->getCertificate(deviceId.toString());
        return trustStore->isAllowed(*cert, anonymous);
    });

    std::mutex mtx;
    std::unique_lock lk {mtx};

    connectionManager->onChannelRequest([authorized_services, this](const std::shared_ptr<dht::crypto::Certificate>&,
                                                                    const std::string& name) {
        // handle channel request
        if (authorized_services.empty()) {
            // Accept all connections if no authorized services are provided
            return true;
        }
        // parse channel name to get the ip address and port: nc://<ip>:<port>
        auto parsedName = parseName(name);
        const std::string& ip = parsedName.first;
        uint16_t port = 0;
        auto [ptr, ec] = std::from_chars(parsedName.second.data(),
                                         parsedName.second.data() + parsedName.second.size(),
                                         port);
        if (ec != std::errc()) {
            fmt::print(stderr, "Rejecting connection: '{}' is not a valid port number: {}\n", parsedName.second, ec);
            return false;
        }

        // Check if the IP is authorized
        auto it = authorized_services.find(ip);
        if (it == authorized_services.end()) {
            // Reject the connection if the ip is not authorized
            Log("Rejecting connection to {}:{}", ip, port);
            return false;
        }

        // Check if the port is authorized
        const auto& ports = it->second;
        if (std::find(ports.begin(), ports.end(), port) == ports.end()) {
            // Reject the connection if the port is not authorized
            Log("Rejecting connection to {}:{}", ip, port);
            return false;
        }
        Log("Accepting connection to {}:{}", ip, port);
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
            Log("Connecting to {}:{}", parsedName.first, parsedName.second);

            asio::ip::tcp::resolver resolver(*ioContext);
            asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(parsedName.first, parsedName.second);

            // Create a TCP socket
            auto socket = std::make_shared<asio::ip::tcp::socket>(*ioContext);
            socket->open(asio::ip::tcp::v4());
            socket->set_option(asio::socket_base::keep_alive(true));
            asio::async_connect(*socket,
                                endpoints,
                                [socket, mtlxSocket](const std::error_code& error, const asio::ip::tcp::endpoint& ep) {
                                    if (!error) {
                                        Log("Connected!\n");
                                        mtlxSocket->setOnRecv([socket](const uint8_t* data, size_t size) {
                                            auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                                            asio::async_write(*socket,
                                                              asio::buffer(*data_copy),
                                                              [data_copy](const std::error_code& error,
                                                                          std::size_t bytesWritten) {
                                                                  if (error) {
                                                                      Log("Write error: {}\n", error.message());
                                                                  }
                                                              });
                                            return size;
                                        });
                                        // Create a buffer to read data into
                                        auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
                                        readFromPipe(mtlxSocket, socket, buffer);
                                    } else {
                                        Log("Connection error: {}\n", error.message());
                                        mtlxSocket->shutdown();
                                    }
                                });

        } catch (std::exception& e) {
            Log("Exception: {}\n", e.what());
        }
    });
}
// Build a client
Dnc::Dnc(dht::crypto::Identity identity,
         const std::string& bootstrap,
         dht::PkId peer_id,
         const std::string& remote_host,
         int remote_port,
         const std::string& turn_host,
         const std::string& turn_user,
         const std::string& turn_pass,
         const std::string& turn_realm,
         const bool verbose,
         const bool enable_upnp)
    : Dnc(std::move(identity), bootstrap, turn_host, turn_user, turn_pass, turn_realm, true, verbose, {}, enable_upnp)
{
    std::condition_variable cv;
    auto name = fmt::format("nc://{:s}:{:d}", remote_host, remote_port);
    Log("Requesting socket: {}\n", name.c_str());
    connectionManager->connectDevice(peer_id, name, [&](std::shared_ptr<ChannelSocket> socket, const dht::PkId&) {
        if (socket) {
            socket->setOnRecv([socket](const uint8_t* data, size_t size) {
                std::cout.write((const char*) data, size);
                std::cout.flush();
                return size;
            });
            // Create a buffer to read data into
            auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);

            // Create a shared_ptr to the stream_descriptor
            auto stdinPipe = std::make_shared<asio::posix::stream_descriptor>(*ioContext, ::dup(STDIN_FILENO));
            readFromPipe(socket, stdinPipe, buffer);

            socket->onShutdown([this](std::error_code ec) {
                Log("Exit program {}\n", ec.message());
                ioContext->stop();
            });
        }
    });

    connectionManager->onConnectionReady([&](const DeviceId&,
                                             const std::string& name,
                                             std::shared_ptr<ChannelSocket> mtlxSocket) { Log("Connected!\n"); });
}

void
Dnc::run()
{
    auto work = asio::make_work_guard(*ioContext);
    ioContext->run();
}

Dnc::~Dnc()
{
    ioContext->stop();
}
} // namespace dhtnet
