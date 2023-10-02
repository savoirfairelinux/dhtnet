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

#include "dvpn.h"
#include "certstore.h"
#include "connectionmanager.h"
#include "fileutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "../common.h"



int open_tap(char *dev) {
    int fd;
    struct ifreq ifr;
    // create mutex
    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("Configuring TAP interface");
        close(fd);
        return -1;
    }

    return fd;
}

int configure_ip_address(const char *dev, const char *ip_address, const char *netmask) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_in addr;
    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Opening socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    // Set the IP address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_address, &(addr.sin_addr)) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }
    memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("SIOCSIFADDR");
        close(sockfd);
        return -1;
    }

    // Set the netmask
    if (inet_pton(AF_INET, netmask, &(addr.sin_addr)) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }
    memcpy(&ifr.ifr_netmask, &addr, sizeof(struct sockaddr));

    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("SIOCSIFNETMASK");
        close(sockfd);
        return -1;
    }

    // Bring the interface up
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("SIOCSIFFLAGS");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

// Build a server
dhtnet::Dvpn::Dvpn(const std::filesystem::path& path,
                   dht::crypto::Identity identity,
                   const std::string& bootstrap,
                   const std::string& turn_host,
                   const std::string& turn_user,
                   const std::string& turn_pass,
                   const std::string& turn_realm,
                   const std::string& tap_device,
                   const std::string& tap_ip,
                   const std::string& tap_netmask ): ioContext(std::make_shared<asio::io_context>())
{
    auto certStore = std::make_shared<tls::CertificateStore>(path / "certstore", logger);
    ioContextRunner = std::thread([context = ioContext, logger = logger] {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            if (logger)
                logger->error("Error in ioContextRunner: {}", ex.what());
        }
    });

    auto config = connectionManagerConfig(path,
                                          identity,
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
    connectionManager->onICERequest([this](const dht::Hash<32>&) { // handle ICE request
        if (logger)
            logger->debug("ICE request received");
        return true;
    });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};

    int tap_fd = open_tap(strdup(tap_device.c_str()));
    if (tap_fd < 0) {
        if (logger)
            logger->error("Error opening TAP interface");
    }

    if (configure_ip_address(strdup(tap_device.c_str()), strdup(tap_ip.c_str()), strdup(tap_netmask.c_str())) < 0) {
        if (logger)
            logger->error("Error configuring IP address");
    }
    auto tap_stream = std::make_shared<asio::posix::stream_descriptor>(*ioContext, tap_fd);

    connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
            // handle channel request
            if (logger)
                logger->debug("Channel request received: {}", name);
            return true;
        });

    connectionManager->onConnectionReady([&,tap_stream](const DeviceId&,
                                             const std::string& name,
                                             std::shared_ptr<ChannelSocket> socket) {
        if (socket) {
            auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
            readFromPipe(socket, tap_stream, buffer);
            socket->setOnRecv([tap_stream, this](const uint8_t* data, size_t size) {
                            auto data_copy = std::make_shared<std::vector<uint8_t>>(data,
                                                                                    data + size);
                            asio::async_write(*tap_stream,
                                                asio::buffer(*data_copy),
                                                [data_copy, this](const std::error_code& error,
                                                                std::size_t bytesWritten) {
                                                    if (error) {
                                                        if (logger)
                                                            logger->error("Error writing to TAP interface: {}",
                                                                        error.message());
                                                    }
                                                });
                            return size;
            });
        }

    });

}
// Build a client
dhtnet::Dvpn::Dvpn(const std::filesystem::path& path,
                   dht::crypto::Identity identity,
                   const std::string& bootstrap,
                   dht::InfoHash peer_id,
                   const std::string& turn_host,
                   const std::string& turn_user,
                   const std::string& turn_pass,
                   const std::string& turn_realm,
                   const std::string& tap_device,
                   const std::string& tap_ip,
                   const std::string& tap_netmask) : Dvpn(path, identity, bootstrap,turn_host,turn_user,turn_pass, turn_realm, tap_device, tap_ip, tap_netmask)
{
    connectionManager->connectDevice(
        peer_id, "dvpn://", [&](std::shared_ptr<ChannelSocket> socket, const dht::InfoHash&) {

            int tap_fd = open_tap(strdup(tap_device.c_str()));
            if (tap_fd < 0) {
                if (logger)
                    logger->error("Error opening TAP interface");
            }

            if (configure_ip_address(strdup(tap_device.c_str()), strdup(tap_ip.c_str()), strdup(tap_netmask.c_str())) < 0) {
                if (logger)
                    logger->error("Error configuring IP address");
            }
            auto tap_stream = std::make_shared<asio::posix::stream_descriptor>(*ioContext, tap_fd);
            if (socket) {
                auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
                readFromPipe(socket, tap_stream, buffer);
                socket->setOnRecv([tap_stream, this](const uint8_t* data, size_t size) {
                                auto data_copy = std::make_shared<std::vector<uint8_t>>(data,
                                                                                        data + size);
                                asio::async_write(*tap_stream,
                                                    asio::buffer(*data_copy),
                                                    [data_copy, this](const std::error_code& error,
                                                                    std::size_t bytesWritten) {
                                                        if (error) {
                                                            if (logger)
                                                                logger->error("Error writing to TAP interface: {}",error.message());
                                                        }
                                                    });
                                return size;
                });
            }

    });

    connectionManager->onConnectionReady([&](const DeviceId&,
                                             const std::string& name,
                                             std::shared_ptr<ChannelSocket> socket_received) {
        if (logger)
            logger->debug("Connected!");
    });
}
void
dhtnet::Dvpn::run()
{
     ioContext->run();
}

dhtnet::Dvpn::~Dvpn() {
    ioContext->stop();
    ioContextRunner.join();
}

