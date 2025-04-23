#include "../common.h"

#include "connectionmanager.h"
#include "multiplexed_socket.h"
#include "certstore.h"

#include <opendht/log.h>
#include <opendht/utils.h>
#include <opendht/thread_pool.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

namespace dhtnet {
using namespace std::literals::chrono_literals;
using clock = std::chrono::high_resolution_clock;
using time_point = clock::time_point;
using duration = clock::duration;

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
    h->ioContext = ioContext;
    h->ioContextRunner = ioContextRunner;

    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = h->id;
    dhtConfig.threaded = true;

    dht::DhtRunner::Context dhtContext;
    dhtContext.certificateStore = [c = h->certStore](const dht::InfoHash& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = c->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    // dhtContext.logger = h->logger;

    h->dht = std::make_shared<dht::DhtRunner>();
    h->dht->run(dhtConfig, std::move(dhtContext));
    h->dht->bootstrap("127.0.0.1:36432");
    //h->dht->bootstrap("bootstrap.sfl.io");

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
    return h;
}

struct BenchResult {
    duration connection;
    duration send;
    bool success;
};

BenchResult
runBench(std::shared_ptr<asio::io_context> ioContext,
        std::shared_ptr<std::thread> ioContextRunner,
        std::shared_ptr<IceTransportFactory>& factory,
        std::shared_ptr<Logger> logger)
{
    BenchResult ret;
    std::mutex mtx;
    std::unique_lock lock {mtx};
    std::condition_variable serverConVar;

    auto boostrap_node = std::make_shared<dht::DhtRunner>();
    boostrap_node->run(36432);

    Log("Generating identities…\n");
    auto server = setupHandler("server", ioContext, ioContextRunner, factory, logger);
    auto client = setupHandler("client", ioContext, ioContextRunner, factory, logger);

    client->connectionManager->onDhtConnected(client->id.first->getPublicKey());
    server->connectionManager->onDhtConnected(server->id.first->getPublicKey());

    server->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&,
                                         const std::string& name) {
            return name == "channelName";
        });
    server->connectionManager->onConnectionReady([&](const DeviceId& device, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
        if (socket) {
            Log("Server: Connection succeeded\n");
            socket->setOnRecv([s=socket.get()](const uint8_t* data, size_t size) {
                std::error_code ec;
                return s->write(data, size, ec);
            });
        } else {
            Log("Server: Connection failed\n");
        }
    });

    std::condition_variable cv;
    bool completed = false;
    size_t rx = 0;
    constexpr size_t TX_SIZE = 64 * 1024;
    constexpr size_t TX_NUM = 1024;
    constexpr size_t TX_GOAL = TX_SIZE * TX_NUM;
    time_point start_connect, start_send;

    std::this_thread::sleep_for(3s);
    Log("Connecting…\n");
    start_connect = clock::now();
    client->connectionManager->connectDevice(server->id.second, "channelName", [&](std::shared_ptr<ChannelSocket> socket, const DeviceId&) {
        if (socket) {
            socket->setOnRecv([&](const uint8_t* data, size_t size) {
                rx += size;
                if (rx == TX_GOAL) {
                    auto end = clock::now();
                    ret.send = end - start_send;
                    Log("Streamed {} bytes back and forth in {} ({} kBps)\n", rx, dht::print_duration(ret.send), (unsigned)(rx / (1000 * std::chrono::duration<double>(ret.send).count())));
                    cv.notify_one();
                }
                return size;
            });
            ret.connection = clock::now() - start_connect;
            Log("Connected in {}\n", dht::print_duration(ret.connection));
            std::vector<uint8_t> data(TX_SIZE, (uint8_t)'y');
            std::error_code ec;
            start_send = clock::now();
            for (unsigned i = 0; i < TX_NUM; ++i) {
                socket->write(data.data(), data.size(), ec);
                if (ec)
                    fmt::print(stderr, "error: {}\n", ec.message());
            }
        } else {
            completed = true;
        }
    });
    ret.success = cv.wait_for(lock, 60s, [&] { return completed or rx == TX_GOAL; });
    std::this_thread::sleep_for(500ms);
    return ret;
}


void
bench()
{

    std::shared_ptr<Logger> logger;// = dht::log::getStdLogger();
    auto factory = std::make_shared<IceTransportFactory>(logger);
    auto ioContext = std::make_shared<asio::io_context>();
    auto ioContextRunner = std::make_shared<std::thread>([context = ioContext]() {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            fmt::print(stderr, "Exception: {}\n", ex.what());
        }
    });

    BenchResult total = {0s, 0s, false};
    unsigned total_success = 0;
    constexpr unsigned ITERATIONS = 20;
    for (unsigned i = 0; i < ITERATIONS; ++i) {
        Log("Iteration {}\n", i);
        auto res = runBench(ioContext, ioContextRunner, factory, logger);
        if (res.success) {
            total.connection += res.connection;
            total.send += res.send;
            total_success++;
        }
    }
    Log("Average connection time: {}\n", dht::print_duration(total.connection / total_success));
    Log("Average send time: {}\n", dht::print_duration(total.send / total_success));
    Log("Total success: {}\n", total_success);

    std::this_thread::sleep_for(500ms);
    ioContext->stop();
    ioContextRunner->join();
}

}

static void
setSipLogLevel()
{
    int level = 0;
    if (char* envvar = getenv("SIPLOGLEVEL")) {
        // From 0 (min) to 6 (max)
        level = std::clamp(std::stoi(envvar), 0, 6);
    }

    pj_log_set_level(level);
    pj_log_set_log_func([](int level, const char* data, int /*len*/) {
    });
}

int
main(int argc, char** argv)
{
    setSipLogLevel();
    dhtnet::bench();
    return 0;
}