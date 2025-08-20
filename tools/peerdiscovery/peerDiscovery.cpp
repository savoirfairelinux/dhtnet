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
#include "multiplexed_socket.h"
#include "certstore.h"
#include "string_utils.h"

#include <opendht/log.h>
#include <opendht/utils.h>
#include <opendht/thread_pool.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <readline/readline.h>
#include <readline/history.h>

#include <condition_variable>
#include<fmt/chrono.h>

namespace dhtnet {
using namespace std::literals::chrono_literals;
using clock = std::chrono::high_resolution_clock;


struct ConnectionHandler
{
    dht::crypto::Identity id;
    std::shared_ptr<Logger> logger;
    std::shared_ptr<tls::CertificateStore> certStore;
    std::shared_ptr<dht::DhtRunner> dht;
    std::shared_ptr<ConnectionManager> connectionManager;
    std::shared_ptr<asio::io_context> ioContext;
    std::shared_ptr<std::thread> ioContextRunner;
};

std::unique_ptr<ConnectionHandler>
setupHandler(const std::string& name,
             std::shared_ptr<asio::io_context> ioContext,
             std::shared_ptr<std::thread> ioContextRunner,
             std::shared_ptr<IceTransportFactory> factory,
             std::shared_ptr<Logger> logger)
{
    auto h = std::make_unique<ConnectionHandler>();
    auto ca = dht::crypto::generateIdentity("ca");
    h->id = dht::crypto::generateIdentity(name, ca);
    h->logger = logger;
    h->certStore = std::make_shared<tls::CertificateStore>(name, h->logger);
    h->ioContext = std::make_shared<asio::io_context>();
    h->ioContext = ioContext;
    h->ioContextRunner = ioContextRunner;

    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = h->id;
    dhtConfig.threaded = true;
    dhtConfig.peer_discovery = true;
    dhtConfig.peer_publish = true;

    dht::DhtRunner::Context dhtContext;

    dhtContext.identityAnnouncedCb = [](bool ok) {
        fmt::print("{} Identity announced {}\n", clock::now().time_since_epoch().count(), ok);
    };

    dhtContext.publicAddressChangedCb = [](std::vector<dht::SockAddr> addr) {
        if (addr.size() != 0)
            fmt::print("{} Public address changed\n", clock::now().time_since_epoch().count());
    };

    dhtContext.statusChangedCallback = [](dht::NodeStatus status4, dht::NodeStatus status6) {
        fmt::print("{} Connectivity changed: IPv4: {}, IPv6: {}\n", clock::now().time_since_epoch().count(), dht::statusToStr(status4), dht::statusToStr(status6));
    };


    dhtContext.certificateStore = [c = h->certStore](const dht::InfoHash& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = c->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    // dhtContext.logger = h->logger;

    h->dht = std::make_shared<dht::DhtRunner>();
    h->dht->run(dhtConfig, std::move(dhtContext));

    auto config = std::make_shared<ConnectionManager::Config>();
    config->dht = h->dht;
    config->id = h->id;
    config->ioContext = h->ioContext;
    config->factory = factory;
    config->logger = logger;
    config->certStore = h->certStore;
    config->cachePath = std::filesystem::current_path() / "temp";

    h->connectionManager = std::make_shared<ConnectionManager>(config);
    h->connectionManager->onICERequest([](const DeviceId&) { return true; });
    fmt::print("Identity:{}\n", h->id.second->getId());
    return h;
}

void
print_help()
{
    fmt::print("Commands:\n");
    fmt::print("  help, h, ? - print this help\n");
    fmt::print("  quit, exit, q, x - exit the program\n");
    fmt::print("  connect <peer_id> - connect to a peer\n");
    fmt::print("  cc - connectivity changed\n");
}

} // namespace dhtnet

static void
setSipLogLevel()
{
    int level = 0;
    if (char* envvar = getenv("SIPLOGLEVEL")) {
        // From 0 (min) to 6 (max)
        level = std::clamp(std::stoi(envvar), 0, 6);
    }

    pj_log_set_level(level);
    pj_log_set_log_func([](int level, const char* data, int /*len*/) {});
}

using namespace std::literals::chrono_literals;
int
main(int argc, char** argv)
{
    setSipLogLevel();
    std::shared_ptr<dhtnet::Logger> logger; // = dht::log::getStdLogger();
    auto factory = std::make_shared<dhtnet::IceTransportFactory>(logger);
    auto ioContext = std::make_shared<asio::io_context>();
    auto ioContextRunner = std::make_shared<std::thread>([context = ioContext]() {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            fmt::print(stderr, "Exception: {}\n", ex.what());
        }
    });

    // Create a new DHTNet node
    auto dhtnet = setupHandler("DHT", ioContext, ioContextRunner, factory, logger);

    dhtnet->connectionManager->onDhtConnected(dhtnet->id.first->getPublicKey());

    // Set up a handler for incoming channel requests
    dhtnet->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
            fmt::print("Channel request received: {}\n", name);
            return true;
        });

    while (true) {
        char* l = readline("> ");
        if (not l)
            break;
        std::string_view line {l};
        if (line.empty())
            continue;
        add_history(l);
        auto args = dhtnet::split_string(line, ' ');
        auto command = args[0];
        if (command == "quit" || command == "exit" || command == "q" || command == "x")
            break;
        else if (command == "help" || command == "h" || command == "?") {
            dhtnet::print_help();
        } else if (command == "connect") {
            if (args.size() < 2) {
                fmt::print("Usage: connect <peer_id>\n");
                continue;
            }
            std::condition_variable cv;
            std::mutex mtx;
            std::unique_lock lock {mtx};

            bool ret = false;
            dht::InfoHash peer_id(args[1]);
            dhtnet->connectionManager
                ->connectDevice(peer_id,
                                "channelName",
                                [&](const std::shared_ptr<dhtnet::ChannelSocket>& socket,
                                    const dht::InfoHash&) {
                                    if (socket) {
                                        ret = true;
                                        cv.notify_one();
                                    }
                                });
            if (cv.wait_for(lock, 10s, [&] { return ret; })) {
                fmt::print("Connected to {}\n", peer_id);
            } else {
                fmt::print("Failed to connect to {}\n", peer_id);
            }
        } else if (command == "cc") {
            dhtnet->dht->connectivityChanged();
        } else {
            fmt::print("Unknown command: {}\n", command);
        }
    }
    fmt::print("Stopping…\n");

    ioContext->stop();
    ioContextRunner->join();
}
