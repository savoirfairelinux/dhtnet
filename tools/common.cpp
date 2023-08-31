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
#include "certstore.h"
#include "connectionmanager.h"
#include "common.h"
#include "fileutils.h"
#include "ice_transport.h"

#include <opendht/crypto.h>
#include <string>
#include <filesystem>
#include <unistd.h>
#include <fcntl.h>
#include <asio.hpp>

namespace dhtnet {

dht::crypto::Identity
loadIdentity(const std::filesystem::path& path)
{
    if (!std::filesystem::exists(path)) {
        std::filesystem::create_directory(path);
    }
    try {
        for (const auto& path : std::filesystem::directory_iterator(path)) {
            auto p = path.path();
            if (p.extension() == ".pem") {
                auto privateKey = std::make_unique<dht::crypto::PrivateKey>(fileutils::loadFile(p));
                auto certificate = std::make_unique<dht::crypto::Certificate>(
                    fileutils::loadFile(p.replace_extension(".crt")));
                return dht::crypto::Identity(std::move(privateKey), std::move(certificate));
            }
        }
    } catch (const std::exception& e) {
        fmt::print(stderr, "Error loadind key from .dhtnetTools: {}\n", e.what());
    }

    auto ca = dht::crypto::generateIdentity("ca");
    auto id = dht::crypto::generateIdentity("dhtnc", ca);
    fmt::print("Generated new identity: {}\n", id.first->getPublicKey().getId());
    dht::crypto::saveIdentity(id, path / "id");
    return id;
}

std::unique_ptr<ConnectionManager::Config>
connectionManagerConfig(const std::filesystem::path& path,
                        dht::crypto::Identity identity,
                        const std::string& bootstrap,
                        std::shared_ptr<Logger> logger,
                        tls::CertificateStore& certStore,
                        std::shared_ptr<asio::io_context> ioContext,
                        IceTransportFactory& iceFactory,
                        const std::string& turn_host,
                        const std::string& turn_user,
                        const std::string& turn_pass,
                        const std::string& turn_realm)
{
    std::filesystem::create_directories(path / "certstore");

    // DHT node creation: To make a connection manager at first a DHT node should be created
    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = identity;
    dhtConfig.threaded = true;
    dhtConfig.peer_discovery = false;
    dhtConfig.peer_publish = false;
    dht::DhtRunner::Context dhtContext;
    dhtContext.identityAnnouncedCb = [logger](bool ok) {
        if (logger)
            logger->debug("Identity announced {}\n", ok);
    };
    dhtContext.certificateStore = [&](const dht::InfoHash& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = certStore.getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    auto runner = std::make_shared<dht::DhtRunner>();
    runner->run(dhtConfig, std::move(dhtContext));
    runner->bootstrap(bootstrap);

    // DHT node creation end:
    // ConnectionManager creation:
    auto config = std::make_unique<ConnectionManager::Config>();
    config->dht = runner;
    config->id = identity;
    config->ioContext = ioContext;
    config->certStore = &certStore;
    config->factory = &iceFactory;
    config->cachePath = path;
    config->logger = logger;
    config->turnServer = turn_host;
    config->turnServerUserName = turn_user;
    config->turnServerPwd = turn_pass;
    config->turnServerRealm = turn_realm;


    return std::move(config);
}
template<typename T>
void
readFromPipe(std::shared_ptr<ChannelSocket> socket, T input, Buffer buffer)
{
    asio::async_read(*input,
                     asio::buffer(*buffer),
                     asio::transfer_at_least(1),
                     [socket, input, buffer](const asio::error_code& error, size_t bytesRead) {
                         if (!error) {
                             // Process the data received in the buffer
                             std::error_code ec;
                             // Write the data to the socket
                             socket->write(buffer->data(), bytesRead, ec);
                             if (!ec) {
                                 // Continue reading more data
                                 readFromPipe(socket, input, buffer);
                             } else {
                                 fmt::print(stderr, "Error writing to socket: {}\n", ec.message());
                             }
                         } else if (error == asio::error::eof) {
                                // Connection closed cleanly by peer.
                                socket->shutdown();
                         }else{
                            fmt::print(stderr, "Error reading from stdin: {}\n", error.message());
                         }
                     });
}

template void readFromPipe(std::shared_ptr<ChannelSocket> socket,
                           std::shared_ptr<asio::posix::stream_descriptor> input,
                           Buffer buffer);
template void readFromPipe(std::shared_ptr<ChannelSocket> socket,
                           std::shared_ptr<asio::ip::tcp::socket> input,
                           Buffer buffer);

} // namespace dhtnet