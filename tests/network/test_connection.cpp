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

#include "connectionmanager.h"
#include "certstore.h"
#include "ice_transport_factory.h"

#include <opendht/dhtrunner.h>
#include <opendht/crypto.h>
#include <opendht/log.h>

#include <asio/io_context.hpp>

#include <fmt/format.h>

#include <string>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>

static constexpr const char* CHANNEL_NAME = "test";
static constexpr const char* TEST_MESSAGE = "dhtnet-network-test-ping";

struct Options
{
    std::string mode;       // "server" or "client"
    std::string bootstrap;  // bootstrap address
    std::string peerId;     // server's device PkId (client only)
    std::string turnServer; // TURN server address (optional)
    std::string turnUser;   // TURN username
    std::string turnPass;   // TURN password
    std::string turnRealm;  // TURN realm
    int timeout = 60;       // timeout in seconds
};

static Options
parseArgs(int argc, char** argv)
{
    Options opts;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            opts.mode = argv[++i];
        } else if (arg == "--bootstrap" && i + 1 < argc) {
            opts.bootstrap = argv[++i];
        } else if (arg == "--peer-id" && i + 1 < argc) {
            opts.peerId = argv[++i];
        } else if (arg == "--turn" && i + 1 < argc) {
            opts.turnServer = argv[++i];
        } else if (arg == "--turn-user" && i + 1 < argc) {
            opts.turnUser = argv[++i];
        } else if (arg == "--turn-pass" && i + 1 < argc) {
            opts.turnPass = argv[++i];
        } else if (arg == "--turn-realm" && i + 1 < argc) {
            opts.turnRealm = argv[++i];
        } else if (arg == "--timeout" && i + 1 < argc) {
            opts.timeout = std::stoi(argv[++i]);
        }
    }
    return opts;
}

static int
runServer(const Options& opts)
{
    auto logger = dht::log::getStdLogger();

    // Generate identity
    auto ca = dht::crypto::generateIdentity("test-ca-server");
    auto id = dht::crypto::generateIdentity("test-server", ca);

    // Create io context
    auto ioContext = std::make_shared<asio::io_context>();
    auto ioRunner = std::thread([ioContext]() {
        auto work = asio::make_work_guard(*ioContext);
        ioContext->run();
    });

    // Create certificate store
    auto tmpDir = std::filesystem::temp_directory_path() / "dhtnet_test_server";
    std::filesystem::create_directories(tmpDir);
    auto certStore = std::make_shared<dhtnet::tls::CertificateStore>(tmpDir, logger);

    // Create ICE factory
    auto factory = std::make_shared<dhtnet::IceTransportFactory>(logger);

    // Create DHT runner
    auto dht = std::make_shared<dht::DhtRunner>();
    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = id;
    dhtConfig.threaded = true;
    dht::DhtRunner::Context dhtContext;
    dhtContext.certificateStore = [certStore](const dht::PkId& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = certStore->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    dhtContext.logger = logger;
    dht->run(dhtConfig, std::move(dhtContext));
    dht->bootstrap(opts.bootstrap);

    // Create ConnectionManager config
    auto config = std::make_shared<dhtnet::ConnectionManager::Config>();
    config->dht = dht;
    config->id = id;
    config->ioContext = ioContext;
    config->factory = factory;
    config->logger = logger;
    config->certStore = certStore;
    config->cachePath = tmpDir / "cache";
    config->upnpEnabled = false;

    if (!opts.turnServer.empty()) {
        config->turnEnabled = true;
        config->turnServer = opts.turnServer;
        config->turnServerUserName = opts.turnUser;
        config->turnServerPwd = opts.turnPass;
        config->turnServerRealm = opts.turnRealm;
    }

    // Create ConnectionManager
    auto connMgr = std::make_shared<dhtnet::ConnectionManager>(config);

    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;
    int exitCode = 1;

    connMgr->onICERequest([](const dhtnet::DeviceId&) { return true; });

    connMgr->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) { return name == CHANNEL_NAME; });

    connMgr->onConnectionReady(
        [&](const dhtnet::DeviceId& device, const std::string& name, std::shared_ptr<dhtnet::ChannelSocket> socket) {
            if (!socket) {
                fmt::print(stderr, "Server: connection failed\n");
                return;
            }
            fmt::print(stderr, "Server: connection ready from {}\n", device.toString());

            socket->setOnRecv([socket, &mtx, &cv, &done, &exitCode](const uint8_t* data, size_t size) {
                std::string msg(reinterpret_cast<const char*>(data), size);
                fmt::print(stderr, "Server: received '{}'\n", msg);

                // Echo the message back
                std::error_code ec;
                socket->write(data, size, ec);
                if (ec) {
                    fmt::print(stderr, "Server: error writing echo: {}\n", ec.message());
                } else {
                    fmt::print(stderr, "Server: echoed message back\n");
                    std::lock_guard<std::mutex> lk(mtx);
                    exitCode = 0;
                    done = true;
                }
                // Notify after short delay so client can read the echo
                std::thread([&mtx, &cv, &done]() {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    std::lock_guard<std::mutex> lk(mtx);
                    done = true;
                    cv.notify_one();
                }).detach();
                return size;
            });
        });

    connMgr->dhtStarted();

    // Print the device public key ID to stdout (the orchestrator reads this)
    auto devicePkId = id.second->getLongId().toString();
    fmt::print("{}\n", devicePkId);
    std::cout.flush();
    fmt::print(stderr, "Server: device ID = {}\n", devicePkId);

    // Wait for completion or timeout
    {
        std::unique_lock<std::mutex> lk(mtx);
        if (!cv.wait_for(lk, std::chrono::seconds(opts.timeout), [&] { return done; })) {
            fmt::print(stderr, "Server: timed out after {}s\n", opts.timeout);
            exitCode = 1;
        }
    }

    // Cleanup
    dht->shutdown();
    dht->join();
    ioContext->stop();
    if (ioRunner.joinable())
        ioRunner.join();
    std::filesystem::remove_all(tmpDir);
    return exitCode;
}

static int
runClient(const Options& opts)
{
    auto logger = dht::log::getStdLogger();

    if (opts.peerId.empty()) {
        fmt::print(stderr, "Client: --peer-id is required\n");
        return 1;
    }

    // Generate identity
    auto ca = dht::crypto::generateIdentity("test-ca-client");
    auto id = dht::crypto::generateIdentity("test-client", ca);

    // Create io context
    auto ioContext = std::make_shared<asio::io_context>();
    auto ioRunner = std::thread([ioContext]() {
        auto work = asio::make_work_guard(*ioContext);
        ioContext->run();
    });

    // Create certificate store
    auto tmpDir = std::filesystem::temp_directory_path() / "dhtnet_test_client";
    std::filesystem::create_directories(tmpDir);
    auto certStore = std::make_shared<dhtnet::tls::CertificateStore>(tmpDir, logger);

    // Create ICE factory
    auto factory = std::make_shared<dhtnet::IceTransportFactory>(logger);

    // Create DHT runner
    auto dht = std::make_shared<dht::DhtRunner>();
    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = id;
    dhtConfig.threaded = true;
    dht::DhtRunner::Context dhtContext;
    dhtContext.certificateStore = [certStore](const dht::PkId& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = certStore->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    dhtContext.logger = logger;
    dht->run(dhtConfig, std::move(dhtContext));
    dht->bootstrap(opts.bootstrap);

    // Create ConnectionManager config
    auto config = std::make_shared<dhtnet::ConnectionManager::Config>();
    config->dht = dht;
    config->id = id;
    config->ioContext = ioContext;
    config->factory = factory;
    config->logger = logger;
    config->certStore = certStore;
    config->cachePath = tmpDir / "cache";
    config->upnpEnabled = false;

    if (!opts.turnServer.empty()) {
        config->turnEnabled = true;
        config->turnServer = opts.turnServer;
        config->turnServerUserName = opts.turnUser;
        config->turnServerPwd = opts.turnPass;
        config->turnServerRealm = opts.turnRealm;
    }

    // Create ConnectionManager
    auto connMgr = std::make_shared<dhtnet::ConnectionManager>(config);
    connMgr->onICERequest([](const dhtnet::DeviceId&) { return true; });
    connMgr->dhtStarted();

    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;
    int exitCode = 1;

    auto peerId = dhtnet::DeviceId(opts.peerId);

    fmt::print(stderr, "Client: connecting to peer {}\n", opts.peerId);

    connMgr->connectDevice(peerId,
                           CHANNEL_NAME,
                           [&](std::shared_ptr<dhtnet::ChannelSocket> socket, const dhtnet::DeviceId&) {
                               if (!socket) {
                                   fmt::print(stderr, "Client: connection failed (null socket)\n");
                                   std::lock_guard<std::mutex> lk(mtx);
                                   done = true;
                                   cv.notify_one();
                                   return;
                               }
                               fmt::print(stderr, "Client: connected, sending test message\n");

                               // Set up receive handler to get the echo
                               socket->setOnRecv([&](const uint8_t* data, size_t size) {
                                   std::string msg(reinterpret_cast<const char*>(data), size);
                                   fmt::print(stderr, "Client: received echo '{}'\n", msg);
                                   if (msg == TEST_MESSAGE) {
                                       fmt::print(stderr, "Client: echo matches, test PASSED\n");
                                       std::lock_guard<std::mutex> lk(mtx);
                                       exitCode = 0;
                                   } else {
                                       fmt::print(stderr, "Client: echo mismatch, test FAILED\n");
                                   }
                                   {
                                       std::lock_guard<std::mutex> lk(mtx);
                                       done = true;
                                   }
                                   cv.notify_one();
                                   return size;
                               });

                               // Send the test message
                               std::error_code ec;
                               socket->write(reinterpret_cast<const uint8_t*>(TEST_MESSAGE),
                                             std::strlen(TEST_MESSAGE),
                                             ec);
                               if (ec) {
                                   fmt::print(stderr, "Client: error writing message: {}\n", ec.message());
                                   std::lock_guard<std::mutex> lk(mtx);
                                   done = true;
                                   cv.notify_one();
                               }
                           });

    // Wait for completion or timeout
    {
        std::unique_lock<std::mutex> lk(mtx);
        if (!cv.wait_for(lk, std::chrono::seconds(opts.timeout), [&] { return done; })) {
            fmt::print(stderr, "Client: timed out after {}s\n", opts.timeout);
            exitCode = 1;
        }
    }

    // Cleanup
    dht->shutdown();
    dht->join();
    ioContext->stop();
    if (ioRunner.joinable())
        ioRunner.join();
    std::filesystem::remove_all(tmpDir);
    return exitCode;
}

int
main(int argc, char** argv)
{
    auto opts = parseArgs(argc, argv);

    if (opts.mode.empty()) {
        fmt::print(stderr, "Usage: test_connection --mode <server|client> [options]\n");
        fmt::print(stderr, "  --bootstrap <addr:port>   DHT bootstrap address\n");
        fmt::print(stderr, "  --peer-id <id>            Server device ID (client mode)\n");
        fmt::print(stderr, "  --turn <addr:port>        TURN server address\n");
        fmt::print(stderr, "  --turn-user <user>        TURN username\n");
        fmt::print(stderr, "  --turn-pass <pass>        TURN password\n");
        fmt::print(stderr, "  --turn-realm <realm>      TURN realm\n");
        fmt::print(stderr, "  --timeout <seconds>       Timeout (default 60)\n");
        return 1;
    }

    // Suppress PJSIP logs
    pj_log_set_level(0);

    if (opts.mode == "server") {
        return runServer(opts);
    } else if (opts.mode == "client") {
        return runClient(opts);
    } else {
        fmt::print(stderr, "Unknown mode: {}\n", opts.mode);
        return 1;
    }
}
