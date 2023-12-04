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

// read yaml file function
std::map<std::string, std::string>
read_configuration(const char* filename, char* tun_device)
{
    // Extract the TUN interface number
    std::string_view tun_device_str(tun_device);
    auto tun_device_number = tun_device_str.substr(3);

    // initialize a map
    std::map<std::string, std::string> conf_map;
    YAML::Node config = YAML::LoadFile(filename);
    if (config["script_path"] && config["ip_address_prefix"] && config["ip_peer_address_prefix"] && config["netmask"]) {
        conf_map["ip_address"] = fmt::format("{}{}",config["ip_address_prefix"].as<std::string>(), tun_device_number);
        conf_map["ip_peer_address"] = fmt::format("{}{}",config["ip_peer_address_prefix"].as<std::string>(), tun_device_number);
        conf_map["netmask"] = config["netmask"].as<std::string>();
        conf_map["script_path"] = config["script_path"].as<std::string>();
    } else {
        std::cout << "Error reading yaml file" << std::endl;
    }
    return conf_map;
}
// Call a script shell
int
call_script_shell(const char* script, char* remote_tun_ip, char* tun_ip,char* netmask, char* tun_device, const char* remote_address, bool is_client)
{
    pid_t pid;
    int status;
    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    if ((pid = fork()) < 0) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        std::string is_client_str = is_client ? "true" : "false";
        if (execl(script, script, remote_tun_ip, tun_ip, netmask, tun_device, remote_address, is_client_str, (char*) 0) < 0) {
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
                   const std::string& turn_realm,
                   const std::string& configuration_file)
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

            auto conf_map = read_configuration(configuration_file.c_str(), tun_device);

            // call script shell function to configure tun interface
            if (call_script_shell(conf_map["script_path"].c_str(),
                                  conf_map["ip_peer_address"].data(),
                                  conf_map["ip_address"].data(),
                                  conf_map["netmask"].data(),
                                  tun_device,
                                  strdup(socket->getRemoteAddress().toString().c_str()),
                                  false)
                < 0) {
                if (logger)
                    logger->error("Error configuring IP address");
            }

            // send conf_map["ip_peer_address"] to client
            std::error_code ec;
            socket->write(reinterpret_cast<const uint8_t*>(conf_map["ip_peer_address"].data()),
                          strlen(conf_map["ip_peer_address"].data()),
                          ec);
            socket->write(reinterpret_cast<const uint8_t*>("---END OF METADATA---"),
                          strlen("---END OF METADATA---"), ec);

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
enum class Communication_State {
    METADATA,
    DATA
};
// Build a client
dhtnet::Dvpn::Dvpn(const std::filesystem::path& path,
                   dht::crypto::Identity identity,
                   const std::string& bootstrap,
                   dht::InfoHash peer_id,
                   const std::string& turn_host,
                   const std::string& turn_user,
                   const std::string& turn_pass,
                   const std::string& turn_realm,
                   const std::string& configuration_file)
    : Dvpn(path, identity, bootstrap, turn_host, turn_user, turn_pass, turn_realm, configuration_file)
{
    // initiate a connection_state object
    Communication_State connection_state = Communication_State::METADATA;

    // create a TUN interface
    char tun_device[IFNAMSIZ] = {0}; // IFNAMSIZ is typically the maximum size for interface names
    int tun_fd = open_tun(tun_device);
    if (tun_fd < 0) {
        if (logger)
            logger->error("Error opening TUN interface");
    }
    // connect to a peer
    connectionManager->connectDevice(
        peer_id, "dvpn://", [&](std::shared_ptr<ChannelSocket> socket, const dht::InfoHash&) {
            auto tun_stream = std::make_shared<asio::posix::stream_descriptor>(*ioContext, tun_fd);
            if (socket && connection_state == Communication_State::DATA) {
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
                                             std::shared_ptr<ChannelSocket> socket) {
        if (logger)
            logger->debug("Connected!");
        if(socket){
            socket->setOnRecv([&](const uint8_t* data, size_t size) {
                auto data_copy = std::make_shared<std::vector<uint8_t>>(data, data + size);
                if (reinterpret_cast<char*>(data_copy->data()) == "---END OF METADATA---")
                    connection_state = Communication_State::DATA;
                else{
                    // configure tun interface by calling script shell function
                   auto conf_map = read_configuration(configuration_file.c_str(), tun_device);

                    // call script shell function to configure tun interface
                    if (call_script_shell(conf_map["script_path"].c_str(),
                                        conf_map["ip_peer_address"].data(),
                                        reinterpret_cast<char*>(data_copy->data()),
                                        conf_map["netmask"].data(),
                                        tun_device,
                                        strdup(socket->getRemoteAddress().toString().c_str()),
                                        true)
                        < 0) {
                        if (logger)
                            logger->error("Error configuring IP address");
                    }

                }
                return size;
            });
        }
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
