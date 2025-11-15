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

std::filesystem::path cachePath()
{
    auto* cache_path = getenv("DHTNET_CACHE_DIR");
    if (cache_path) {
        return std::filesystem::path(cache_path);
    }
    auto* home = getenv("HOME");
    if (home) {
        return std::filesystem::path(home) / ".cache" / "dhtnet";
    }
    // If user got no HOME and no DHTNET_CACHE_DIR set, use /tmp
    return std::filesystem::path("/tmp");
}

std::unique_ptr<ConnectionManager::Config>
connectionManagerConfig(dht::crypto::Identity identity,
                        const std::string& bootstrap,
                        std::shared_ptr<Logger> logger,
                        std::shared_ptr<tls::CertificateStore> certStore,
                        std::shared_ptr<asio::io_context> ioContext,
                        std::shared_ptr<IceTransportFactory> iceFactory,
                        const std::string& turn_host,
                        const std::string& turn_user,
                        const std::string& turn_pass,
                        const std::string& turn_realm,
                        const bool enable_upnp)
{
    // DHT node creation: To make a connection manager at first a DHT node should be created
    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = identity;
    dhtConfig.dht_config.node_config.persist_path = (cachePath() / "dht").string();
    dhtConfig.dht_config.cert_cache_all = true;
    dhtConfig.threaded = true;
    dhtConfig.peer_discovery = false;
    dhtConfig.peer_publish = false;
    dht::DhtRunner::Context dhtContext;
    dhtContext.identityAnnouncedCb = [logger](bool ok) {
        if (logger)
            logger->debug("Identity announced {}\n", ok);
    };
    dhtContext.certificateStore = [certStore](const dht::InfoHash& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = certStore->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    dhtContext.certificateStorePkId = [certStore](const dht::PkId& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = certStore->getCertificate(pk_id.toString()))
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
    config->certStore = certStore;
    config->cachePath = cachePath();
    config->factory = iceFactory;
    config->logger = logger;
    if (!turn_host.empty()){
        config->turnEnabled = true;
        config->turnServer = turn_host;
        config->turnServerUserName = turn_user;
        config->turnServerPwd = turn_pass;
        config->turnServerRealm = turn_realm;
    }

    if (enable_upnp) {
        // UPnP configuration
        auto upnpContext = std::make_shared<dhtnet::upnp::UPnPContext>(ioContext, logger);
        auto controller = std::make_shared<dhtnet::upnp::Controller>(upnpContext);
        config->upnpEnabled = true;
        config->upnpCtrl = controller;
    }

    return config;
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