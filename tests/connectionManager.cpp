/*
 *  Copyright (C) 2004-2023 Savoir-faire Linux Inc.
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
#include "test_runner.h"
#include "certstore.h"

#include <opendht/log.h>
#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <fmt/compile.h>

#include <cppunit/TestAssert.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <condition_variable>
#include <iostream>
#include <filesystem>

using namespace std::literals::chrono_literals;

namespace dhtnet {
namespace test {

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

class ConnectionManagerTest : public CppUnit::TestFixture
{
public:
    ConnectionManagerTest() {
        pj_log_set_level(0);
        pj_log_set_log_func([](int level, const char* data, int /*len*/) {});
        // logger->debug("Using PJSIP version {} for {}", pj_get_version(), PJ_OS_NAME);
        // logger->debug("Using GnuTLS version {}", gnutls_check_version(nullptr));
        // logger->debug("Using OpenDHT version {}", dht::version());
        testDir_ = std::filesystem::current_path() / "tmp_tests_connectionManager";
    }
    ~ConnectionManagerTest() {}
    static std::string name() { return "ConnectionManager"; }
    void setUp();
    void tearDown();

    std::shared_ptr<dht::DhtRunner> bootstrap_node;
    dht::crypto::Identity org1Id, org2Id;
    dht::crypto::Identity aliceId, bobId;
    dht::crypto::Identity aliceDevice1Id, bobDevice1Id;

    std::unique_ptr<ConnectionHandler> alice;
    std::unique_ptr<ConnectionHandler> bob;

    std::mutex mtx;
    std::shared_ptr<asio::io_context> ioContext;
    std::shared_ptr<std::thread> ioContextRunner;
    std::shared_ptr<Logger> logger = dht::log::getStdLogger();
    std::shared_ptr<IceTransportFactory> factory;

private:
    std::unique_ptr<ConnectionHandler> setupHandler(const dht::crypto::Identity& id, const std::string& bootstrap = "bootstrap.sfl.io");
    std::filesystem::path testDir_;

    void testConnectDevice();
    void testAcceptConnection();
    void testManyChannels();
    void testMultipleChannels();
    void testMultipleChannelsOneDeclined();
    void testMultipleChannelsSameName();
    void testDeclineConnection();
    void testSendReceiveData();
    void testAcceptsICERequest();
    void testDeclineICERequest();
    void testChannelRcvShutdown();
    void testChannelSenderShutdown();
    void testCloseConnectionWith();
    void testShutdownCallbacks();
    void testFloodSocket();
    void testDestroyWhileSending();
    void testIsConnecting();
    void testIsConnected();
    void testCanSendBeacon();
    void testCannotSendBeacon();
    void testConnectivityChangeTriggerBeacon();
    void testOnNoBeaconTriggersShutdown();
    void testShutdownWhileNegotiating();
    void testGetChannelList();

    CPPUNIT_TEST_SUITE(ConnectionManagerTest);
    CPPUNIT_TEST(testDeclineICERequest);
    CPPUNIT_TEST(testConnectDevice);
    CPPUNIT_TEST(testIsConnecting);
    CPPUNIT_TEST(testIsConnected);
    CPPUNIT_TEST(testAcceptConnection);
    CPPUNIT_TEST(testDeclineConnection);
    // [[disabled-sporadic failures]]CPPUNIT_TEST(testManyChannels);
    CPPUNIT_TEST(testMultipleChannels);
    CPPUNIT_TEST(testMultipleChannelsOneDeclined);
    CPPUNIT_TEST(testMultipleChannelsSameName);
    CPPUNIT_TEST(testSendReceiveData);
    CPPUNIT_TEST(testAcceptsICERequest);
    CPPUNIT_TEST(testChannelRcvShutdown);
    CPPUNIT_TEST(testChannelSenderShutdown);
    CPPUNIT_TEST(testCloseConnectionWith);
    CPPUNIT_TEST(testShutdownCallbacks);
    CPPUNIT_TEST(testFloodSocket);
    CPPUNIT_TEST(testDestroyWhileSending);
    CPPUNIT_TEST(testCanSendBeacon);
    CPPUNIT_TEST(testCannotSendBeacon);
    CPPUNIT_TEST(testConnectivityChangeTriggerBeacon);
    CPPUNIT_TEST(testOnNoBeaconTriggersShutdown);
    CPPUNIT_TEST(testShutdownWhileNegotiating);
    CPPUNIT_TEST(testGetChannelList);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(ConnectionManagerTest, ConnectionManagerTest::name());

std::unique_ptr<ConnectionHandler>
ConnectionManagerTest::setupHandler(const dht::crypto::Identity& id, const std::string& bootstrap)
{
    auto h = std::make_unique<ConnectionHandler>();
    h->id = id;
    h->logger = {};//logger;
    h->certStore = std::make_shared<tls::CertificateStore>(testDir_ / id.second->getName(), nullptr/*h->logger*/);
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
    h->dht->bootstrap(bootstrap);

    auto config = std::make_shared<ConnectionManager::Config>();
    config->dht = h->dht;
    config->id = h->id;
    config->ioContext = h->ioContext;
    config->factory = factory;
    // config->logger = logger;
    config->certStore = h->certStore;
    config->cachePath = testDir_ / id.second->getName() / "temp";

    h->connectionManager = std::make_shared<ConnectionManager>(config);
    h->connectionManager->onICERequest([](const DeviceId&) { return true; });
    h->connectionManager->onDhtConnected(h->id.first->getPublicKey());

    return h;
}

void
ConnectionManagerTest::setUp()
{
    if (not org1Id.first) {
        org1Id = dht::crypto::generateIdentity("org1");
        org2Id = dht::crypto::generateIdentity("org2");
        aliceId = dht::crypto::generateIdentity("alice", org1Id, 2048, true);
        bobId = dht::crypto::generateIdentity("bob", org2Id, 2048, true);
        aliceDevice1Id = dht::crypto::generateIdentity("aliceDevice1", aliceId);
        bobDevice1Id = dht::crypto::generateIdentity("bobDevice1", bobId);
    }

    ioContext = std::make_shared<asio::io_context>();
    ioContextRunner = std::make_shared<std::thread>([context = ioContext]() {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            fmt::print("Exception in ioContextRunner: {}\n", ex.what());
        }
    });
    bootstrap_node = std::make_shared<dht::DhtRunner>();
    bootstrap_node->run(36432);

    factory = std::make_unique<IceTransportFactory>(/*logger*/);
    alice = setupHandler(aliceDevice1Id, "127.0.0.1:36432");
    bob = setupHandler(bobDevice1Id, "127.0.0.1:36432");
}

void
ConnectionManagerTest::tearDown()
{
    // wait_for_removal_of({aliceId, bobId});
    //  Stop the io_context and join the ioContextRunner thread
    ioContext->stop();

    if (ioContextRunner && ioContextRunner->joinable()) {
        ioContextRunner->join();
    }

    bootstrap_node.reset();
    alice.reset();
    bob.reset();
    factory.reset();
    std::filesystem::remove_all(testDir_);
}
void
ConnectionManagerTest::testConnectDevice()
{
    std::condition_variable bobConVar;
    bool isBobRecvChanlReq = false;
    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&,
                                         const std::string& name) {
            std::lock_guard lock {mtx};
            isBobRecvChanlReq = name == "dummyName";
            bobConVar.notify_one();
            return true;
        });

    std::condition_variable alicConVar;
    bool isAlicConnected = false;
    alice->connectionManager->connectDevice(bob->id.second, "dummyName", [&](std::shared_ptr<ChannelSocket> socket, const DeviceId&) {
        std::lock_guard lock {mtx};
        if (socket) {
            isAlicConnected = true;
        }
        alicConVar.notify_one();
    });

    std::unique_lock lock {mtx};
    CPPUNIT_ASSERT(bobConVar.wait_for(lock, 30s, [&] { return isBobRecvChanlReq; }));
    CPPUNIT_ASSERT(alicConVar.wait_for(lock, 30s, [&] { return isAlicConnected; }));
}

void
ConnectionManagerTest::testAcceptConnection()
{
    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string& name) {
            successfullyReceive = name == "git://*";
            return true;
        });

    bob->connectionManager->onConnectionReady(
        [&receiverConnected](const DeviceId&,
                             const std::string& name,
                             std::shared_ptr<ChannelSocket> socket) {
            receiverConnected = socket && (name == "git://*");
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
        return successfullyReceive && successfullyConnected && receiverConnected;
    }));
}

void
ConnectionManagerTest::testDeclineConnection()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool connectCompleted = false;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string&) {
            std::lock_guard lock {mtx};
            successfullyReceive = true;
            cv.notify_one();
            return false;
        });

    bob->connectionManager->onConnectionReady(
        [&receiverConnected](const DeviceId&,
                             const std::string&,
                             std::shared_ptr<ChannelSocket> socket) {
            if (socket)
                receiverConnected = true;
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                std::lock_guard lock {mtx};
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                connectCompleted = true;
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyReceive; }));
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return connectCompleted; }));
    CPPUNIT_ASSERT(!successfullyConnected);
    CPPUNIT_ASSERT(!receiverConnected);
}


void
ConnectionManagerTest::testManyChannels()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::condition_variable cv;
    size_t successfullyConnected = 0;
    size_t accepted = 0;
    size_t receiverConnected = 0;
    size_t successfullyReceived = 0;
    size_t shutdownCount = 0;

    auto acceptAll = [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
        if (name.empty()) return false;
        std::lock_guard lk {mtx};
        accepted++;
        cv.notify_one();
        return true;
    };
    bob->connectionManager->onChannelRequest(acceptAll);
    alice->connectionManager->onChannelRequest(acceptAll);

    auto onReady = [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
        if (not socket or name.empty()) return;
        if (socket->isInitiator())
            return;
        socket->setOnRecv([rxbuf = std::make_shared<std::vector<uint8_t>>(), w = std::weak_ptr(socket)](const uint8_t* data, size_t size) {
            rxbuf->insert(rxbuf->end(), data, data + size);
            if (rxbuf->size() == 32) {
                if (auto socket = w.lock()) {
                    std::error_code ec;
                    socket->write(rxbuf->data(), rxbuf->size(), ec);
                    CPPUNIT_ASSERT(!ec);
                    socket->shutdown();
                }
            }
            return size;
        });
        std::lock_guard lk {mtx};
        receiverConnected++;
        cv.notify_one();
    };
    bob->connectionManager->onConnectionReady(onReady);
    alice->connectionManager->onConnectionReady(onReady);

    // max supported number of channels per side (64k - 2 reserved channels)
    static constexpr size_t N = 1024 * 32 - 1;

    auto onConnect = [&](std::shared_ptr<ChannelSocket> socket, const DeviceId&) {
        CPPUNIT_ASSERT(socket);
        if (socket) {
            std::lock_guard lk {mtx};
            successfullyConnected++;
            cv.notify_one();
        }
        auto data_sent = dht::PkId::get(socket->name());
        socket->setOnRecv([&, data_sent, rxbuf = std::make_shared<std::vector<uint8_t>>()](const uint8_t* data, size_t size) {
            rxbuf->insert(rxbuf->end(), data, data + size);
            if (rxbuf->size() == 32) {
                CPPUNIT_ASSERT(!std::memcmp(data_sent.data(), rxbuf->data(), data_sent.size()));
                std::lock_guard lk {mtx};
                successfullyReceived++;
                cv.notify_one();
            }
            return size;
        });
        socket->onShutdown([&]() {
            std::lock_guard lk {mtx};
            shutdownCount++;
            cv.notify_one();
        });
        std::error_code ec;
        socket->write(data_sent.data(), data_sent.size(), ec);
        CPPUNIT_ASSERT(!ec);
    };

    for (size_t i = 0; i < N; ++i) {
        alice->connectionManager->connectDevice(bob->id.second,
                                                fmt::format("git://{}", i+1),
                                                onConnect);

        bob->connectionManager->connectDevice(alice->id.second,
                                                fmt::format("sip://{}", i+1),
                                                onConnect);

        if (i % 128 == 0)
           std::this_thread::sleep_for(5ms);
    }

    std::unique_lock lk {mtx};
    cv.wait_for(lk, 30s, [&] { return successfullyConnected == N * 2; });
    CPPUNIT_ASSERT_EQUAL(N * 2, successfullyConnected);
    cv.wait_for(lk, 30s, [&] { return accepted == N * 2; });
    CPPUNIT_ASSERT_EQUAL(N * 2, accepted);
    cv.wait_for(lk, 20s, [&] { return receiverConnected == N * 2; });
    CPPUNIT_ASSERT_EQUAL(N * 2, receiverConnected);
    cv.wait_for(lk, 60s, [&] { return successfullyReceived == N * 2; });
    CPPUNIT_ASSERT_EQUAL(N * 2, successfullyReceived);
    cv.wait_for(lk, 60s, [&] { return shutdownCount == N * 2; });
    CPPUNIT_ASSERT_EQUAL(N * 2, shutdownCount);
    lk.unlock();

    // Wait a bit to let at least some channels shutdown
    std::this_thread::sleep_for(10ms);

    // Second time to make sure we can re-use the channels after shutdown
    for (size_t i = 0; i < N; ++i) {
        alice->connectionManager->connectDevice(bob->id.second,
                                                fmt::format("git://{}", N+i+1),
                                                onConnect);

        bob->connectionManager->connectDevice(alice->id.second,
                                                fmt::format("sip://{}", N+i+1),
                                                onConnect);

        if (i % 128 == 0)
           std::this_thread::sleep_for(5ms);
    }

    lk.lock();
    cv.wait_for(lk, 30s, [&] { return successfullyConnected == N * 4; });
    CPPUNIT_ASSERT_EQUAL(N * 4, successfullyConnected);
    cv.wait_for(lk, 30s, [&] { return accepted == N * 4; });
    CPPUNIT_ASSERT_EQUAL(N * 4, accepted);
    cv.wait_for(lk, 20s, [&] { return receiverConnected == N * 4; });
    CPPUNIT_ASSERT_EQUAL(N * 4, receiverConnected);
    cv.wait_for(lk, 60s, [&] { return successfullyReceived == N * 4; });
    CPPUNIT_ASSERT_EQUAL(N * 4, successfullyReceived);
    cv.wait_for(lk, 60s, [&] { return shutdownCount == N * 4; });
    CPPUNIT_ASSERT_EQUAL(N * 4, shutdownCount);
}

void
ConnectionManagerTest::testMultipleChannels()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyConnected2 = false;
    int receiverConnected = 0;

    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name,
                             std::shared_ptr<ChannelSocket> socket) {
            if (not name.empty()) {
                std::lock_guard lk {mtx};
                if (socket)
                    receiverConnected += 1;
                cv.notify_one();
            }
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    std::lock_guard lk {mtx};
                                                    successfullyConnected = true;
                                                    cv.notify_one();
                                                }
                                            });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    std::lock_guard lk {mtx};
                                                    successfullyConnected2 = true;
                                                    cv.notify_one();
                                                }
                                            });

    std::unique_lock lk {mtx};
    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
        return successfullyConnected && successfullyConnected2 && receiverConnected == 2;
    }));
    CPPUNIT_ASSERT(alice->connectionManager->activeSockets() == 1);
}

void
ConnectionManagerTest::testMultipleChannelsOneDeclined()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyNotConnected = false;
    bool successfullyConnected2 = false;
    int receiverConnected = 0;

    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
            if (name == "git://*")
                return false;
            return true;
        });

    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
            if (socket)
                receiverConnected += 1;
            cv.notify_one();
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (!socket)
                                                    successfullyNotConnected = true;
                                                cv.notify_one();
                                            });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket)
                                                    successfullyConnected2 = true;
                                                cv.notify_one();
                                            });

    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
        return successfullyNotConnected && successfullyConnected2 && receiverConnected == 1;
    }));
    CPPUNIT_ASSERT(alice->connectionManager->activeSockets() == 1);
}

void
ConnectionManagerTest::testMultipleChannelsSameName()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyConnected2 = false;
    int receiverConnected = 0;

    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

    bob->connectionManager->onConnectionReady(
        [&receiverConnected](const DeviceId&,
                             const std::string&,
                             std::shared_ptr<ChannelSocket> socket) {
            if (socket)
                receiverConnected += 1;
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });

    // We can open two sockets with the same name, it will be two different channel
    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected2 = true;
                                                }
                                                cv.notify_one();
                                            });

    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
        return successfullyConnected && successfullyConnected2 && receiverConnected == 2;
    }));
}

void
ConnectionManagerTest::testSendReceiveData()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    std::atomic_int events(0);
    bool successfullyConnected = false, successfullyConnected2 = false, successfullyReceive = false,
         receiverConnected = false;
    const uint8_t buf_other[] = {0x64, 0x65, 0x66, 0x67};
    const uint8_t buf_test[] = {0x68, 0x69, 0x70, 0x71};
    bool dataOk = false, dataOk2 = false;

    bob->connectionManager->onChannelRequest(
        [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string&) {
            successfullyReceive = true;
            return true;
        });

    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            if (socket && (name == "test" || name == "other")) {
                receiverConnected = true;
                std::error_code ec;
                auto res = socket->waitForData(std::chrono::milliseconds(5000), ec);
                if (res == 4) {
                    uint8_t buf[4];
                    socket->read(&buf[0], 4, ec);
                    if (name == "test")
                        dataOk = std::equal(std::begin(buf), std::end(buf), std::begin(buf_test));
                    else
                        dataOk2 = std::equal(std::begin(buf), std::end(buf), std::begin(buf_other));
                    events++;
                    cv.notify_one();
                }
            }
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "test",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                    std::error_code ec;
                                                    socket->write(&buf_test[0], 4, ec);
                                                }
                                                events++;
                                                cv.notify_one();
                                            });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "other",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected2 = true;
                                                    std::error_code ec;
                                                    socket->write(&buf_other[0], 4, ec);
                                                }
                                                events++;
                                                cv.notify_one();
                                            });

    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
        return events == 4 && successfullyReceive && successfullyConnected && successfullyConnected2
               && dataOk && dataOk2;
    }));
}

void
ConnectionManagerTest::testAcceptsICERequest()
{
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onICERequest([&](const DeviceId&) {
        successfullyReceive = true;
        return true;
    });

    bob->connectionManager->onConnectionReady(
        [&receiverConnected](const DeviceId&,
                             const std::string& name,
                             std::shared_ptr<ChannelSocket> socket) {
            receiverConnected = socket && (name == "git://*");
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });

    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] {
        return successfullyReceive && successfullyConnected && receiverConnected;
    }));
}

void
ConnectionManagerTest::testDeclineICERequest()
{
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::condition_variable cv;
    bool connectCompleted = false;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onICERequest([&](const DeviceId&) {
        std::lock_guard lock {mtx};
        successfullyReceive = true;
        cv.notify_one();
        return false;
    });

    bob->connectionManager->onConnectionReady(
        [&receiverConnected](const DeviceId&,
                             const std::string& name,
                             std::shared_ptr<ChannelSocket> socket) {
            receiverConnected = socket && (name == "git://*");
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                std::lock_guard lock {mtx};
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                connectCompleted = true;
                                                cv.notify_one();
                                            });

    std::unique_lock lk {mtx};
    CPPUNIT_ASSERT(cv.wait_for(lk, 35s, [&] { return successfullyReceive; }));
    CPPUNIT_ASSERT(cv.wait_for(lk, 35s, [&] { return connectCompleted; }));
    CPPUNIT_ASSERT(!receiverConnected);
    CPPUNIT_ASSERT(!successfullyConnected);
}

void
ConnectionManagerTest::testChannelRcvShutdown()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;
    bool shutdownReceived = false;

    std::shared_ptr<ChannelSocket> bobSock;

    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });

    bob->connectionManager->onConnectionReady(
        [&](const DeviceId& did, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            if (socket && name == "git://*" && did != bob->id.second->getLongId()) {
                bobSock = socket;
                cv.notify_one();
            }
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    socket->onShutdown([&] {
                                                        shutdownReceived = true;
                                                        cv.notify_one();
                                                    });
                                                    successfullyConnected = true;
                                                    cv.notify_one();
                                                }
                                            });

    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return bobSock && successfullyConnected; }));

    bobSock->shutdown();

    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return shutdownReceived; }));
}

void
ConnectionManagerTest::testChannelSenderShutdown()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::condition_variable rcv, scv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;
    bool shutdownReceived = false;

    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string& name) {
            std::lock_guard lk {mtx};
            successfullyReceive = name == "git://*";
            rcv.notify_one();
            return true;
        });

    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            if (socket) {
                socket->onShutdown([&] {
                    std::lock_guard lk {mtx};
                    shutdownReceived = true;
                    scv.notify_one();
                });
            }
            if (not name.empty()) {
                std::lock_guard lk {mtx};
                receiverConnected = socket && (name == "git://*");
                rcv.notify_one();
            }
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    std::lock_guard lk {mtx};
                                                    successfullyConnected = true;
                                                    rcv.notify_one();
                                                    socket->shutdown();
                                                }
                                            });

    std::unique_lock lk {mtx};
    CPPUNIT_ASSERT(rcv.wait_for(lk, 30s, [&] { return successfullyConnected && successfullyReceive && receiverConnected; }));
    CPPUNIT_ASSERT(scv.wait_for(lk, 30s, [&] { return shutdownReceived; }));
}

void
ConnectionManagerTest::testCloseConnectionWith()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    auto bobUri = bob->id.second->issuer->getId().toString();
    std::condition_variable rcv, scv;
    unsigned events(0);
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string& name) {
            std::lock_guard lk {mtx};
            successfullyReceive = name == "git://*";
            return true;
        });

    bob->connectionManager->onConnectionReady([&](const DeviceId&,
                                                  const std::string& name,
                                                  std::shared_ptr<dhtnet::ChannelSocket> socket) {
        if (socket) {
            socket->onShutdown([&] {
                std::lock_guard lk {mtx};
                events++;
                scv.notify_one();
            });
        }
        if (not name.empty()) {
            std::lock_guard lk {mtx};
            receiverConnected = socket && (name == "git://*");
            rcv.notify_one();
        }
    });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    socket->onShutdown([&] {
                                                        std::lock_guard lk {mtx};
                                                        events++;
                                                        scv.notify_one();
                                                    });
                                                    std::lock_guard lk {mtx};
                                                    successfullyConnected = true;
                                                    rcv.notify_one();
                                                }
                                            });

    {
        std::unique_lock lk {mtx};
        rcv.wait_for(lk, 30s, [&] {
            return successfullyReceive && successfullyConnected && receiverConnected;
        });
    }
    std::this_thread::sleep_for(1s);
    // This should trigger onShutdown
    alice->connectionManager->closeConnectionsWith(bobUri);
    std::unique_lock lk {mtx};
    CPPUNIT_ASSERT(scv.wait_for(lk, 10s, [&] { return events == 2; }));
}

// explain algorithm
void
ConnectionManagerTest::testShutdownCallbacks()
{
    auto aliceUri = alice->id.second->issuer->getId().toString();

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::condition_variable rcv, chan2cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string& name) {
            if (name == "1") {
                std::unique_lock lk {mtx};
                successfullyReceive = true;
                rcv.notify_one();
            } else {
                chan2cv.notify_one();
                // Do not return directly. Let the connection be closed
                std::this_thread::sleep_for(10s);
            }
            return true;
        });

    bob->connectionManager->onConnectionReady([&](const DeviceId&,
                                                  const std::string& name,
                                                  std::shared_ptr<dhtnet::ChannelSocket> socket) {
        if (name == "1") {
            std::unique_lock lk {mtx};
            receiverConnected = (bool)socket;
            rcv.notify_one();
        }
    });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "1",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    std::unique_lock lk {mtx};
                                                    successfullyConnected = true;
                                                    rcv.notify_one();
                                                }
                                            });

    std::unique_lock lk {mtx};
    // Connect first channel. This will initiate a mx sock
    CPPUNIT_ASSERT(rcv.wait_for(lk, 30s, [&] {
        return successfullyReceive && successfullyConnected && receiverConnected;
    }));

    // Connect another channel, but close the connection
    bool channel2NotConnected = false;
    alice->connectionManager->connectDevice(bob->id.second,
                                            "2",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const DeviceId&) {
                                                channel2NotConnected = !socket;
                                                rcv.notify_one();
                                            });
    chan2cv.wait_for(lk, 30s);

    // This should trigger onShutdown for second callback
    bob->connectionManager->closeConnectionsWith(aliceUri);
    CPPUNIT_ASSERT(rcv.wait_for(lk, 30s, [&] { return channel2NotConnected; }));
}

void
ConnectionManagerTest::testFloodSocket()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;
    std::shared_ptr<dhtnet::ChannelSocket> rcvSock1, rcvSock2, rcvSock3, sendSock, sendSock2,
        sendSock3;
    bob->connectionManager->onChannelRequest(
        [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string& name) {
            successfullyReceive = name == "1";
            return true;
        });
    bob->connectionManager->onConnectionReady([&](const DeviceId&,
                                                  const std::string& name,
                                                  std::shared_ptr<dhtnet::ChannelSocket> socket) {
        receiverConnected = socket != nullptr;
        if (name == "1")
            rcvSock1 = socket;
        else if (name == "2")
            rcvSock2 = socket;
        else if (name == "3")
            rcvSock3 = socket;
    });
    alice->connectionManager->connectDevice(bob->id.second,
                                            "1",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    sendSock = socket;
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    std::unique_lock lk {mtx};
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] {
        return successfullyReceive && successfullyConnected && receiverConnected;
    }));
    CPPUNIT_ASSERT(receiverConnected);
    successfullyConnected = false;
    receiverConnected = false;
    alice->connectionManager->connectDevice(bob->id.second,
                                            "2",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    sendSock2 = socket;
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
    successfullyConnected = false;
    receiverConnected = false;
    alice->connectionManager->connectDevice(bob->id.second,
                                            "3",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    sendSock3 = socket;
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
    constexpr size_t C = 8000;
    std::string alphabet, shouldRcv, rcv1, rcv2, rcv3;
    std::mutex mtx1, mtx2, mtx3;
    for (int i = 0; i < 100; ++i)
        alphabet += "QWERTYUIOPASDFGHJKLZXCVBNM";
    auto totSize = C * alphabet.size();
    shouldRcv.reserve(totSize);
    rcv1.reserve(totSize);
    rcv2.reserve(totSize);
    rcv3.reserve(totSize);
    rcvSock1->setOnRecv([&](const uint8_t* buf, size_t len) {
        std::lock_guard lk {mtx1};
        rcv1 += std::string_view((const char*)buf, len);
        if (rcv1.size() == totSize)
            cv.notify_one();
        return len;
    });
    rcvSock2->setOnRecv([&](const uint8_t* buf, size_t len) {
        std::lock_guard lk {mtx2};
        rcv2 += std::string_view((const char*)buf, len);
        if (rcv2.size() == totSize)
            cv.notify_one();
        return len;
    });
    rcvSock3->setOnRecv([&](const uint8_t* buf, size_t len) {
        std::lock_guard lk {mtx3};
        rcv3 += std::string_view((const char*)buf, len);
        if (rcv3.size() == totSize)
            cv.notify_one();
        return len;
    });
    for (uint64_t i = 0; i < alphabet.size(); ++i) {
        auto send = std::string(C, alphabet[i]);
        shouldRcv += send;
        std::error_code ec;
        sendSock->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        sendSock2->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        sendSock3->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        CPPUNIT_ASSERT(!ec);
    }
    {
        std::unique_lock lk {mtx1};
        CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return shouldRcv == rcv1; }));
    }
    {
        std::unique_lock lk {mtx2};
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return shouldRcv == rcv2; }));
    }
    {
        std::unique_lock lk {mtx3};
        CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return shouldRcv == rcv3; }));
    }
}

void
ConnectionManagerTest::testDestroyWhileSending()
{
    // Same as test before, but destroy the accounts while sending.
    // This test if a segfault occurs
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });
    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;
    std::shared_ptr<ChannelSocket> rcvSock1, rcvSock2, rcvSock3, sendSock, sendSock2, sendSock3;
    bob->connectionManager->onChannelRequest(
        [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string& name) {
            successfullyReceive = name == "1";
            return true;
        });
    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            receiverConnected = socket != nullptr;
            if (name == "1")
                rcvSock1 = socket;
            else if (name == "2")
                rcvSock2 = socket;
            else if (name == "3")
                rcvSock3 = socket;
        });
    alice->connectionManager->connectDevice(bob->id.second,
                                            "1",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    sendSock = socket;
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] {
        return successfullyReceive && successfullyConnected && receiverConnected;
    }));
    successfullyConnected = false;
    receiverConnected = false;
    alice->connectionManager->connectDevice(bob->id.second,
                                            "2",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    sendSock2 = socket;
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
    successfullyConnected = false;
    receiverConnected = false;
    alice->connectionManager->connectDevice(bob->id.second,
                                            "3",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    sendSock3 = socket;
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyConnected && receiverConnected; }));
    std::string alphabet;
    for (int i = 0; i < 100; ++i)
        alphabet += "QWERTYUIOPASDFGHJKLZXCVBNM";
    rcvSock1->setOnRecv([&](const uint8_t*, size_t len) { return len; });
    rcvSock2->setOnRecv([&](const uint8_t*, size_t len) { return len; });
    rcvSock3->setOnRecv([&](const uint8_t*, size_t len) { return len; });
    for (uint64_t i = 0; i < alphabet.size(); ++i) {
        auto send = std::string(8000, alphabet[i]);
        std::error_code ec;
        sendSock->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        sendSock2->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        sendSock3->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        CPPUNIT_ASSERT(!ec);
    }

    // No need to wait, immediately destroy, no segfault must occurs
}

void
ConnectionManagerTest::testIsConnecting()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false, successfullyReceive = false;

    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) {
            successfullyReceive = true;
            cv.notify_one();
            std::this_thread::sleep_for(2s);
            return true;
        });

    CPPUNIT_ASSERT(!alice->connectionManager->isConnecting(bob->id.second->getLongId(), "sip"));

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    // connectDevice is full async, so isConnecting will be true after a few ms.
    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyReceive; }));
    CPPUNIT_ASSERT(alice->connectionManager->isConnecting(bob->id.second->getLongId(), "sip"));
    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyConnected; }));
    std::this_thread::sleep_for(
        std::chrono::milliseconds(100)); // Just to wait for the callback to finish
    CPPUNIT_ASSERT(!alice->connectionManager->isConnecting(bob->id.second->getLongId(), "sip"));
}

void
ConnectionManagerTest::testIsConnected()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false, successfullyReceive = false;

    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) {
            return true;
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] { return successfullyConnected; }));
    std::this_thread::sleep_for(
        std::chrono::milliseconds(100)); // Just to wait for the callback to finish
    CPPUNIT_ASSERT(alice->connectionManager->isConnected(bob->id.second->getLongId()));
}

void
ConnectionManagerTest::testCanSendBeacon()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;

    std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
            if (socket && socket->name() == "sip")
                bobSocket = socket->underlyingSocket();
            cv.notify_one();
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    aliceSocket = socket->underlyingSocket();
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    // connectDevice is full async, so isConnecting will be true after a few ms.
    CPPUNIT_ASSERT(
        cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket && successfullyConnected; }));
    CPPUNIT_ASSERT(aliceSocket->canSendBeacon());

    // Because onConnectionReady is true before version is sent, we can wait a bit
    // before canSendBeacon is true.
    auto start = std::chrono::steady_clock::now();
    auto aliceCanSendBeacon = false;
    auto bobCanSendBeacon = false;
    do {
        aliceCanSendBeacon = aliceSocket->canSendBeacon();
        bobCanSendBeacon = bobSocket->canSendBeacon();
        if (!bobCanSendBeacon || !aliceCanSendBeacon)
            std::this_thread::sleep_for(1s);
    } while ((not bobCanSendBeacon or not aliceCanSendBeacon)
             and std::chrono::steady_clock::now() - start < 5s);

    CPPUNIT_ASSERT(bobCanSendBeacon && aliceCanSendBeacon);
}

void
ConnectionManagerTest::testCannotSendBeacon()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;

    std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
            if (socket && socket->name() == "sip")
                bobSocket = socket->underlyingSocket();
            cv.notify_one();
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    aliceSocket = socket->underlyingSocket();
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    // connectDevice is full async, so isConnecting will be true after a few ms.
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket; }));

    int version = 1412;
    bobSocket->setOnVersionCb([&](auto v) {
        version = v;
        cv.notify_one();
    });
    aliceSocket->setVersion(0);
    aliceSocket->sendVersion();
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return version == 0; }));
    CPPUNIT_ASSERT(!bobSocket->canSendBeacon());
}

void
ConnectionManagerTest::testConnectivityChangeTriggerBeacon()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;

    std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
            if (socket && socket->name() == "sip")
                bobSocket = socket->underlyingSocket();
            cv.notify_one();
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    aliceSocket = socket->underlyingSocket();
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    // connectDevice is full async, so isConnecting will be true after a few ms.
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket; }));

    bool hasRequest = false;
    bobSocket->setOnBeaconCb([&](auto p) {
        if (p)
            hasRequest = true;
        cv.notify_one();
    });
    alice->connectionManager->connectivityChanged();
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return hasRequest; }));
}

void
ConnectionManagerTest::testOnNoBeaconTriggersShutdown()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;

    std::shared_ptr<MultiplexedSocket> aliceSocket, bobSocket;
    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
            if (socket && socket->name() == "sip")
                bobSocket = socket->underlyingSocket();
            cv.notify_one();
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    aliceSocket = socket->underlyingSocket();
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    // connectDevice is full async, so isConnecting will be true after a few ms.
    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return aliceSocket && bobSocket; }));

    bool isClosed = false;
    aliceSocket->onShutdown([&] {
        isClosed = true;
        cv.notify_one();
    });
    bobSocket->answerToBeacon(false);
    alice->connectionManager->connectivityChanged();
    CPPUNIT_ASSERT(cv.wait_for(lk, 10s, [&] { return isClosed; }));
}

void
ConnectionManagerTest::testShutdownWhileNegotiating()
{
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::unique_lock lk {mtx};
    std::condition_variable cv;
    bool successfullyReceive = false;
    bool notConnected = false;

    bob->connectionManager->onICERequest([&](const DeviceId&) {
        successfullyReceive = true;
        cv.notify_one();
        return true;
    });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                notConnected = !socket;
                                                cv.notify_one();
                                            });

    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return successfullyReceive; }));
    // Manager::instance().setAccountActive(alice->id.second, false, true);

    // Just move destruction on another thread.
    // dht::threadpool::io().run([conMgr =std::move(alice->connectionManager)] {});
    alice->connectionManager.reset();

    CPPUNIT_ASSERT(cv.wait_for(lk, 30s, [&] { return notConnected; }));
}

void
ConnectionManagerTest::testGetChannelList()
{
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    std::condition_variable cv;
    std::unique_lock lk {mtx};
    bool successfullyConnected = false;
    int receiverConnected = 0;
    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
            std::lock_guard lk {mtx};
            if (socket)
                receiverConnected += 1;
            cv.notify_one();
        });
    std::string channelId;
    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                std::lock_guard lk {mtx};
                                                if (socket) {
                                                    channelId = fmt::format(FMT_COMPILE("{:x}"), socket->channel());
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(
        cv.wait_for(lk, 60s, [&] { return successfullyConnected && receiverConnected == 1; }));
    std::vector<std::map<std::string, std::string>> expectedList = {
        {{"id", channelId}, {"name", "git://*"}}};
    auto connectionList = alice->connectionManager->getConnectionList();
    CPPUNIT_ASSERT(!connectionList.empty());
    const auto& connectionInfo = connectionList[0];
    auto it = connectionInfo.find("id");
    CPPUNIT_ASSERT(it != connectionInfo.end());
    auto actualList = alice->connectionManager->getChannelList(it->second);
    CPPUNIT_ASSERT(expectedList.size() == actualList.size());
    for (const auto& expectedMap : expectedList) {
        CPPUNIT_ASSERT(std::find(actualList.begin(), actualList.end(), expectedMap)
                         != actualList.end());
    }
}

} // namespace test
} // namespace dhtnet

JAMI_TEST_RUNNER(dhtnet::test::ConnectionManagerTest::name())
