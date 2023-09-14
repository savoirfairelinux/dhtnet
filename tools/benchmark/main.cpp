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
    std::shared_ptr<ConnectionManager> connectionManager;
};

std::unique_ptr<ConnectionHandler>
setupHandler(const std::string& name,
             std::shared_ptr<Logger> logger)
{
    auto h = std::make_unique<ConnectionHandler>();
    auto ca = dht::crypto::generateIdentity("ca");
    h->id = dht::crypto::generateIdentity(name, ca);
    h->connectionManager = std::make_shared<ConnectionManager>(h->id);
    h->connectionManager->onICERequest([](const DeviceId&) { return true; });
    return h;
}

struct BenchResult {
    duration connection;
    duration send;
    bool success;
};

BenchResult
runBench(std::shared_ptr<Logger> logger,
        size_t TX_SIZE,
        size_t TX_NUM)
{
    BenchResult ret;
    std::mutex mtx;
    std::unique_lock<std::mutex> lock {mtx};
    std::condition_variable serverConVar;
    size_t TX_GOAL = TX_SIZE * TX_NUM;
    time_point start_connect, start_send;

    fmt::print("Generating identities…\n");
    auto server = setupHandler("server", logger);
    auto client = setupHandler("client", logger);

    client->connectionManager->onDhtConnected(client->id.first->getPublicKey());
    server->connectionManager->onDhtConnected(server->id.first->getPublicKey());

    server->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&,
                                         const std::string& name) {
            return name == "channelName";
        });
    server->connectionManager->onConnectionReady([&](const DeviceId& device, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
        if (socket) {
            fmt::print("Server: Connection succeeded\n");
            socket->setOnRecv([&, s=socket.get()](const uint8_t* data, size_t size) {
                std::error_code ec;
                auto now = clock::now();
                fmt::print("Server: got {} bytes after {}\n", size, dht::print_duration(now - start_send));
                return s->write(data, size, ec);
            });
        } else {
            fmt::print("Server: Connection failed\n");
        }
    });

    std::condition_variable cv;
    bool completed = false;
    size_t rx = 0;
    // constexpr size_t TX_SIZE = 64 * 1024;
    // constexpr size_t TX_NUM = 1024;


    std::this_thread::sleep_for(5s);
    fmt::print("Connecting…\n");
    start_connect = clock::now();
    client->connectionManager->connectDevice(server->id.second->getId(), "channelName", [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const dht::InfoHash&) {
        if (socket) {
            socket->setOnRecv([&](const uint8_t* data, size_t size) {
                rx += size;
                if (rx == TX_GOAL) {
                    auto end = clock::now();
                    ret.send = end - start_send;
                    fmt::print("Streamed {} bytes back and forth in {} ({} kBps)\n", rx, dht::print_duration(ret.send), (unsigned)(rx / (1000 * std::chrono::duration<double>(ret.send).count())));
                    cv.notify_one();
                }
                return size;
            });
            ret.connection = clock::now() - start_connect;
            fmt::print("Connected in {}\n", dht::print_duration(ret.connection));
            std::vector<uint8_t> data(TX_SIZE, 'y');
            std::error_code ec;
            start_send = clock::now();
            for (unsigned i = 0; i < TX_NUM; ++i) {
                // fmt::print("Sending {} bytes\n", data.size());
                socket->write(data.data(), data.size(), ec);
                if (ec)
                    fmt::print("error: {}\n", ec.message());
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
bench(size_t TX_SIZE, size_t TX_NUM)
{
    BenchResult total = {0s, 0s, false};
    unsigned total_success = 0;
    constexpr unsigned ITERATIONS = 20;
    for (unsigned i = 0; i < ITERATIONS; ++i) {
        fmt::print("Iteration {}\n", i);
        auto res = runBench(nullptr, TX_SIZE, TX_NUM);
        if (res.success) {
            total.connection += res.connection;
            total.send += res.send;
            total_success++;
        }
    }
    fmt::print("Average connection time: {}\n", dht::print_duration(total.connection / total_success));
    fmt::print("Average send time: {}\n", dht::print_duration(total.send / total_success));
    fmt::print("Total success: {}\n", total_success);

}}

static void
setSipLogLevel()
{
    int level = 0;
    if (char* envvar = getenv("SIPLOGLEVEL")) {
        // From 0 (min) to 6 (max)
        level = std::clamp(std::stoi(envvar), 0, 6);
    }

    fmt::print("Setting SIP log level to {}\n", level);

    pj_log_set_level(level);

}

int
main(int argc, char** argv)
{
    setSipLogLevel();
    dhtnet::bench(1,3);
    return 0;
}