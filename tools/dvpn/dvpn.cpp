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

#include "dvpn.h"
#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"
#include "../common.h"

#include <opendht/log.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/wait.h>
#include <yaml-cpp/yaml.h>
#include <fstream>

struct Config
{
    std::string ip_address;
    std::string ip_peer_address;
    std::string ip_address_ipv6;
    std::string ip_peer_address_ipv6;
    std::string script_path;

    Config(const YAML::Node& node, std::string_view tun_device)
    {
        std::string_view tun_device_str(tun_device);
        auto tun_device_number = tun_device_str.substr(3);

        if (node["ip_address"])
            ip_address = fmt::format("{}{}", node["ip_address"].as<std::string>(), tun_device_number);
        if (node["ip_peer_address"])
            ip_peer_address = fmt::format("{}{}", node["ip_peer_address"].as<std::string>(), tun_device_number);
        if (node["script_path"])
            script_path = node["script_path"].as<std::string>();
        if (node["ip_address_ipv6"])
            ip_address_ipv6 = fmt::format("{}{}", node["ip_address_ipv6"].as<std::string>(), tun_device_number);
        if (node["ip_peer_address_ipv6"])
            ip_peer_address_ipv6 = fmt::format("{}{}",
                                               node["ip_peer_address_ipv6"].as<std::string>(),
                                               tun_device_number);
    }

    YAML::Node toYAML() const
    {
        YAML::Node node;
        node["ip_address"] = ip_address;
        node["ip_peer_address"] = ip_peer_address;
        node["script_path"] = script_path;
        node["ip_address_ipv6"] = ip_address_ipv6;
        node["ip_peer_address_ipv6"] = ip_peer_address_ipv6;
        return node;
    }
};

// Call a script shell
int
call_script_shell(const char* script,
                  const char* remote_tun_ip,
                  const char* tun_ip,
                  const char* tun_device,
                  const char* remote_address,
                  const char* is_client,
                  const char* remote_tun_ip_ipv6,
                  const char* tun_ip_ipv6)
{
    pid_t pid;
    int status;
    std::mutex mtx;
    std::unique_lock lk {mtx};
    if ((pid = fork()) < 0) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        if (execl(script,
                  script,
                  remote_tun_ip,
                  tun_ip,
                  tun_device,
                  remote_address,
                  is_client,
                  remote_tun_ip_ipv6,
                  tun_ip_ipv6,
                  (char*) 0)
            < 0) {
            perror("execl");
            return -1;
        }

    } else {
        while (wait(&status) != pid) {
            // wait for completion
        }
    }
    return 0;
}

int
open_tun(char* dev)
{
    int fd; // file descriptor
    struct ifreq ifr;
    std::mutex mtx;
    std::unique_lock lk {mtx};
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev) {
        /* if a device name was specified, put it in the structure; otherwise,
         * the kernel will try to allocate the "next" device of the
         * specified type */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if (ioctl(fd, TUNSETIFF, (void*) &ifr) < 0) {
        perror("Configuring TUN interface");
        close(fd);
        return -1;
    }
    strcpy(dev, ifr.ifr_name);
    return fd;
}

dhtnet::Dvpn::Dvpn(dht::crypto::Identity identity,
                   const std::string& bootstrap,
                   const std::string& turn_host,
                   const std::string& turn_user,
                   const std::string& turn_pass,
                   const std::string& turn_realm,
                   const std::string& configuration_file)
    : logger(dht::log::getStdLogger())
    , ioContext(std::make_shared<asio::io_context>())
    , iceFactory(std::make_shared<IceTransportFactory>(logger))
    , certStore(std::make_shared<tls::CertificateStore>(cachePath() / "certstore", logger))
    , trustStore(std::make_shared<tls::TrustStore>(*certStore))
{
    auto ca = identity.second->issuer;
    trustStore->setCertificateStatus(ca->getId().toString(), tls::TrustStore::PermissionStatus::ALLOWED);

    auto config = connectionManagerConfig(
        identity, bootstrap, logger, certStore, ioContext, iceFactory, turn_host, turn_user, turn_pass, turn_realm);
    // create a connection manager
    connectionManager = std::make_unique<ConnectionManager>(std::move(config));
    connectionManager->dhtStarted();
}

dhtnet::DvpnServer::DvpnServer(dht::crypto::Identity identity,
                               const std::string& bootstrap,
                               const std::string& turn_host,
                               const std::string& turn_user,
                               const std::string& turn_pass,
                               const std::string& turn_realm,
                               const std::string& configuration_file,
                               bool anonymous)
    : Dvpn(identity, bootstrap, turn_host, turn_user, turn_pass, turn_realm, configuration_file)
{
    std::mutex mtx;
    std::unique_lock lk {mtx};

    connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& channel) {
            // handle channel request
            if (logger)
                logger->debug("Channel request received: {}", channel);
            return true;
        });

    connectionManager->onICERequest([this, identity, anonymous](const DeviceId& deviceId) {
        return trustStore->isAllowed(*certStore->getCertificate(deviceId.toString()), anonymous);
    });
    connectionManager->onConnectionReady(
        [=](const DeviceId&, const std::string& channel, std::shared_ptr<ChannelSocket> socket) {
            char tun_device[IFNAMSIZ] = {0}; // IFNAMSIZ is typically the maximum size for interface names
            // create a TUN interface
            int tun_fd = open_tun(tun_device);
            if (tun_fd < 0) {
                if (logger)
                    logger->error("Error opening TUN interface");
            }
            auto tun_stream = std::make_shared<asio::posix::stream_descriptor>(*ioContext, tun_fd);

            if (socket) {
                // read yaml file
                YAML::Node config = YAML::LoadFile(configuration_file.c_str());
                auto conf = Config(config, tun_device);

                // call script shell function to configure tun interface
                if (call_script_shell(conf.script_path.c_str(),
                                      conf.ip_peer_address.c_str(),
                                      conf.ip_address.c_str(),
                                      tun_device,
                                      strdup(socket->getRemoteAddress().toString().c_str()),
                                      "false",
                                      conf.ip_peer_address_ipv6.c_str(),
                                      conf.ip_address_ipv6.c_str())
                    < 0) {
                    if (logger)
                        logger->error("Error configuring IP address");
                }

                MetaData val;
                val.addrClient = conf.ip_peer_address;
                val.addrServer = conf.ip_address;
                val.addrClientIpv6 = conf.ip_peer_address_ipv6;
                val.addrServerIpv6 = conf.ip_address_ipv6;
                msgpack::sbuffer buffer(64);
                msgpack::pack(buffer, val);

                std::error_code ec;
                int res = socket->write(reinterpret_cast<const uint8_t*>(buffer.data()), buffer.size(), ec);
                if (res < 0) {
                    if (logger)
                        logger->error("Send peer TUN IP addr - error: {}", ec.message());
                }
                auto buffer_data = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
                readFromPipe(socket, tun_stream, buffer_data);
                socket->setOnRecv([tun_stream, this](const uint8_t* data, size_t size) {
                    auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                    asio::async_write(*tun_stream,
                                      asio::buffer(*data_copy),
                                      [data_copy, this](const std::error_code& error, std::size_t bytesWritten) {
                                          if (error) {
                                              if (logger)
                                                  logger->error("Error writing to TUN interface: {}", error.message());
                                          }
                                      });
                    return size;
                });
            }
        });
}

// Build a client
dhtnet::DvpnClient::DvpnClient(dht::InfoHash peer_id,
                               dht::crypto::Identity identity,
                               const std::string& bootstrap,
                               const std::string& turn_host,
                               const std::string& turn_user,
                               const std::string& turn_pass,
                               const std::string& turn_realm,
                               const std::string& configuration_file)
    : Dvpn(identity, bootstrap, turn_host, turn_user, turn_pass, turn_realm, configuration_file)
{
    // connect to a peer
    connectionManager->connectDevice(peer_id, "dvpn://", [=](std::shared_ptr<ChannelSocket> socket, const dht::InfoHash&) {
        if (socket) {
            // create a TUN interface
            tun_fd = open_tun(tun_device);
            if (tun_fd < 0) {
                if (logger)
                    logger->error("Error opening TUN interface");
            }

            tun_stream = std::make_shared<asio::posix::stream_descriptor>(*ioContext, tun_fd);

            socket->setOnRecv([=](const uint8_t* data, size_t size) {
                if (connection_state == CommunicationState::METADATA) {
                    pac_.reserve_buffer(size);
                    memcpy(pac_.buffer(), data, size);
                    pac_.buffer_consumed(size);

                    msgpack::object_handle oh;
                    if (pac_.next(oh)) {
                        try {
                            auto msg = oh.get().as<MetaData>();
                            YAML::Node config = YAML::LoadFile(configuration_file.c_str());
                            auto conf = Config(config, tun_device);
                            // configure tun interface by calling script shell function
                            if (call_script_shell(conf.script_path.c_str(),
                                                  msg.addrServer.c_str(),
                                                  msg.addrClient.c_str(),
                                                  tun_device,
                                                  strdup(socket->getRemoteAddress().toString().c_str()),

                                                  "true",
                                                  msg.addrServerIpv6.c_str(),
                                                  msg.addrClientIpv6.c_str())
                                < 0) {
                                if (logger)
                                    logger->error("Error configuring IP address");
                            }
                            connection_state = CommunicationState::DATA;
                        } catch (...) {
                            if (logger)
                                logger->error("Error parsing metadata");
                        }
                    }
                    return size;
                } else if (connection_state == CommunicationState::DATA) {
                    auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                    asio::async_write(*tun_stream,
                                      asio::buffer(*data_copy),
                                      [data_copy, this](const std::error_code& error, std::size_t bytesWritten) {
                                          if (error) {
                                              if (logger)
                                                  logger->error("Error writing to TUN interface: {}", error.message());
                                          }
                                      });
                    return size;
                }
                return size;
            });
            auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
            readFromPipe(socket, tun_stream, buffer);
        }
    });

    connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& channel, std::shared_ptr<ChannelSocket> socket) {
            if (logger)
                logger->debug("Connected!");
        });
}

void
dhtnet::Dvpn::run()
{
    auto work = asio::make_work_guard(*ioContext);
    ioContext->run();
}

dhtnet::Dvpn::~Dvpn()
{
    ioContext->stop();
}
