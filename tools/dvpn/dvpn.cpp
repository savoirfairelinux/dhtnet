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
#include <net/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <opendht/log.h>
#include <sys/wait.h>
#include "../common.h"

// Call a script shell
int
call_script_shell(const char* script, bool is_client, char* tun_device, const char* remote_address)
{
    pid_t pid;
    int status;
    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    if ((pid = fork()) < 0) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        // child process
        char is_client_str[10]; // 10 is the maximum size for "client" or "server"
        sprintf(is_client_str, "%s", is_client ? "client" : "server");

        if (execl(script, script, is_client_str, tun_device, remote_address, (char*) 0) < 0) {
            perror("execl");
            return -1;
        }

    } else {
        // parent process
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
    std::unique_lock<std::mutex> lk {mtx};
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

// Build a server
dhtnet::Dvpn::Dvpn(const std::filesystem::path& path,
                   dht::crypto::Identity identity,
                   const std::string& bootstrap,
                   const std::string& turn_host,
                   const std::string& turn_user,
                   const std::string& turn_pass,
                   const std::string& turn_realm)
    : logger(dht::log::getStdLogger())
    , ioContext(std::make_shared<asio::io_context>())
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

    connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& channel) {
            // handle channel request
            if (logger)
                logger->debug("Channel request received: {}", channel);
            return true;
        });

    connectionManager->onConnectionReady([&](const DeviceId&,
                                             const std::string& channel,
                                             std::shared_ptr<ChannelSocket> socket) {
        char tun_device[IFNAMSIZ] = {
            0}; // IFNAMSIZ is typically the maximum size for interface names
        // create a TUN interface
        int tun_fd = open_tun(tun_device);
        if (tun_fd < 0) {
            if (logger)
                logger->error("Error opening TUN interface");
        }

        auto tun_stream = std::make_shared<asio::posix::stream_descriptor>(*ioContext, tun_fd);

        if (socket) {
            // call script shell function
            if (call_script_shell("../tools/dvpn/dvpn_up.sh",
                                  false,
                                  tun_device,
                                  strdup(socket->getRemoteAddress().toString().c_str()))
                < 0) {
                if (logger)
                    logger->error("Error configuring IP address");
            }
            auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
            readFromPipe(socket, tun_stream, buffer);
            socket->setOnRecv([tun_stream, this](const uint8_t* data, size_t size) {
                auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                asio::async_write(*tun_stream,
                                  asio::buffer(*data_copy),
                                  [data_copy, this](const std::error_code& error,
                                                    std::size_t bytesWritten) {
                                      if (error) {
                                          if (logger)
                                              logger->error("Error writing to TUN interface: {}",
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
                   const std::string& turn_realm)
    : Dvpn(path, identity, bootstrap, turn_host, turn_user, turn_pass, turn_realm)
{
    connectionManager->connectDevice(
        peer_id, "dvpn://", [&](std::shared_ptr<ChannelSocket> socket, const dht::InfoHash&) {
            char tun_device[IFNAMSIZ] = {
                0}; // IFNAMSIZ is typically the maximum size for interface names
            int tun_fd = open_tun(tun_device);
            if (tun_fd < 0) {
                if (logger)
                    logger->error("Error opening TUN interface");
            }

            auto tun_stream = std::make_shared<asio::posix::stream_descriptor>(*ioContext, tun_fd);
            if (socket) {
                // call script shell function
                if (call_script_shell("../tools/dvpn/dvpn_up.sh",
                                      true,
                                      tun_device,
                                      strdup(socket->getRemoteAddress().toString().c_str()))
                    < 0) {
                    if (logger)
                        logger->error("Error configuring IP address");
                }
                auto buffer = std::make_shared<std::vector<uint8_t>>(BUFFER_SIZE);
                readFromPipe(socket, tun_stream, buffer);
                socket->setOnRecv([tun_stream, this](const uint8_t* data, size_t size) {
                    auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                    asio::async_write(*tun_stream,
                                      asio::buffer(*data_copy),
                                      [data_copy, this](const std::error_code& error,
                                                        std::size_t bytesWritten) {
                                          if (error) {
                                              if (logger)
                                                  logger
                                                      ->error("Error writing to TUN interface: {}",
                                                              error.message());
                                          }
                                      });
                    return size;
                });
            }
        });

    connectionManager->onConnectionReady([&](const DeviceId&,
                                             const std::string& channel,
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

dhtnet::Dvpn::~Dvpn()
{
    ioContext->stop();
    ioContextRunner.join();
}
