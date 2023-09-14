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
    ConnectionManagerTest() {}
    ~ConnectionManagerTest() {}
    static std::string name() { return "ConnectionManager"; }
    void setUp();
    void tearDown();

    std::unique_ptr<ConnectionHandler> alice;
    std::unique_ptr<ConnectionHandler> bob;

    // Create a lock to be used in the test units
    std::mutex mtx;
    std::shared_ptr<asio::io_context> ioContext;
    std::shared_ptr<std::thread> ioContextRunner {};
    // std::thread ioContextRunner;
    std::shared_ptr<Logger> logger {};
    std::shared_ptr<IceTransportFactory> factory {};

private:
    std::unique_ptr<ConnectionHandler> setupHandler(const std::string& name);

    void testConnectDevice();
    void testAcceptConnection();
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
    CPPUNIT_TEST(testAcceptConnection);
    CPPUNIT_TEST(testDeclineConnection);
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
ConnectionManagerTest::setupHandler(const std::string& name)
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
    h->dht->bootstrap("bootstrap.jami.net");

    auto config = std::make_shared<ConnectionManager::Config>();
    config->dht = h->dht;
    config->id = h->id;
    config->ioContext = h->ioContext;
    config->factory = factory;
    config->logger = logger;
    config->certStore = h->certStore;

    std::filesystem::path currentPath = std::filesystem::current_path();
    std::filesystem::path tempDirPath = currentPath / "temp";

    config->cachePath = tempDirPath.string();

    h->connectionManager = std::make_shared<ConnectionManager>(config);
    h->connectionManager->onICERequest([](const DeviceId&) { return true; });
    return h;
}

void
ConnectionManagerTest::setUp()
{
    logger = dht::log::getStdLogger();

    logger->debug("Using PJSIP version {} for {}", pj_get_version(), PJ_OS_NAME);
    logger->debug("Using GnuTLS version {}", gnutls_check_version(nullptr));
    logger->debug("Using OpenDHT version {}", dht::version());

    ioContext = std::make_shared<asio::io_context>();
    ioContextRunner = std::make_shared<std::thread>([context = ioContext]() {
        try {
            auto work = asio::make_work_guard(*context);
            context->run();
        } catch (const std::exception& ex) {
            // print the error;
        }
    });
    // ioContextRunner = std::thread([context = ioContext]() {
    //     try {
    //         auto work = asio::make_work_guard(*context);
    //         context->run();
    //     } catch (const std::exception& ex) {
    //         // print the error;
    //     }
    // });
    factory = std::make_unique<IceTransportFactory>(logger);
    alice = setupHandler("alice");
    bob = setupHandler("bob");
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
}
void
ConnectionManagerTest::testConnectDevice()
{
    std::unique_lock<std::mutex> lock {mtx};
    std::condition_variable bobConVar;
    bool isBobRecvChanlReq = false;

    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onChannelRequest(
        [&isBobRecvChanlReq, &bobConVar](const std::shared_ptr<dht::crypto::Certificate>&,
                                         const std::string& name) {
            isBobRecvChanlReq = name == "dumyName";
            bobConVar.notify_one();
            return true;
        });

    std::condition_variable alicConVar;
    bool isAlicConnected = false;
    auto conctDevicCalBack = [&](std::shared_ptr<ChannelSocket> socket, const DeviceId&) {
        if (socket) {
            isAlicConnected = true;
        }
        alicConVar.notify_one();
    };

    alice->connectionManager->connectDevice(bob->id.second, "dumyName", conctDevicCalBack);

    // Step 4: to check if Alice connected to Bob?
    CPPUNIT_ASSERT(alicConVar.wait_for(lock, 60s, [&] { return isAlicConnected; }));
}

void
ConnectionManagerTest::testAcceptConnection()
{
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string&) {
            successfullyReceive = true;
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
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });
    cv.wait_for(lk, 30s);
    CPPUNIT_ASSERT(successfullyReceive);
    CPPUNIT_ASSERT(!successfullyConnected);
    CPPUNIT_ASSERT(!receiverConnected);
}

void
ConnectionManagerTest::testMultipleChannels()
{
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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

    alice->connectionManager->connectDevice(bob->id.second,
                                            "sip://*",
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
    CPPUNIT_ASSERT(alice->connectionManager->activeSockets() == 1);
}

void
ConnectionManagerTest::testMultipleChannelsOneDeclined()
{
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //

    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    std::condition_variable cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onICERequest([&](const DeviceId&) {
        successfullyReceive = true;
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
                                                if (socket) {
                                                    successfullyConnected = true;
                                                }
                                                cv.notify_one();
                                            });

    cv.wait_for(lk, 30s);
    CPPUNIT_ASSERT(successfullyReceive);
    CPPUNIT_ASSERT(!receiverConnected);
    CPPUNIT_ASSERT(!successfullyConnected);
}

void
ConnectionManagerTest::testChannelRcvShutdown()
{
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    std::condition_variable rcv, scv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;
    bool shutdownReceived = false;

    bob->connectionManager->onChannelRequest(
        [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string& name) {
            successfullyReceive = name == "git://*";
            return true;
        });

    bob->connectionManager->onConnectionReady(
        [&](const DeviceId&, const std::string& name, std::shared_ptr<ChannelSocket> socket) {
            if (socket) {
                socket->onShutdown([&] {
                    shutdownReceived = true;
                    scv.notify_one();
                });
            }
            receiverConnected = socket && (name == "git://*");
        });

    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                    rcv.notify_one();
                                                    socket->shutdown();
                                                }
                                            });

    rcv.wait_for(lk, 30s);
    scv.wait_for(lk, 30s);
    CPPUNIT_ASSERT(shutdownReceived);
    CPPUNIT_ASSERT(successfullyReceive);
    CPPUNIT_ASSERT(successfullyConnected);
    CPPUNIT_ASSERT(receiverConnected);
}

void
ConnectionManagerTest::testCloseConnectionWith()
{
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    auto bobUri = bob->id.second->issuer->getId().toString();
    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    std::condition_variable rcv, scv;
    std::atomic_int events(0);
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [&successfullyReceive](const std::shared_ptr<dht::crypto::Certificate>&,
                               const std::string& name) {
            successfullyReceive = name == "git://*";
            return true;
        });

    bob->connectionManager->onConnectionReady([&](const DeviceId&,
                                                  const std::string& name,
                                                  std::shared_ptr<dhtnet::ChannelSocket> socket) {
        if (socket) {
            socket->onShutdown([&] {
                events += 1;
                scv.notify_one();
            });
        }
        receiverConnected = socket && (name == "git://*");
    });

    alice->connectionManager->connectDevice(bob->id.second->getId(),
                                            "git://*",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const dht::InfoHash&) {
                                                if (socket) {
                                                    socket->onShutdown([&] {
                                                        events += 1;
                                                        scv.notify_one();
                                                    });
                                                    successfullyConnected = true;
                                                    rcv.notify_one();
                                                }
                                            });

    rcv.wait_for(lk, 30s);
    // This should trigger onShutdown
    alice->connectionManager->closeConnectionsWith(bobUri);
    CPPUNIT_ASSERT(scv.wait_for(lk, 60s, [&] {
        return events == 2 && successfullyReceive && successfullyConnected && receiverConnected;
    }));
}

// explain algorithm
void
ConnectionManagerTest::testShutdownCallbacks()
{
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    auto aliceUri = alice->id.second->issuer->getId().toString();

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
    std::condition_variable rcv, chan2cv;
    bool successfullyConnected = false;
    bool successfullyReceive = false;
    bool receiverConnected = false;

    bob->connectionManager->onChannelRequest(
        [&successfullyReceive, &chan2cv](const std::shared_ptr<dht::crypto::Certificate>&,
                                         const std::string& name) {
            if (name == "1") {
                successfullyReceive = true;
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
        receiverConnected = socket && (name == "1");
    });

    alice->connectionManager->connectDevice(bob->id.second->getId(),
                                            "1",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const dht::InfoHash&) {
                                                if (socket) {
                                                    successfullyConnected = true;
                                                    rcv.notify_one();
                                                }
                                            });
    // Connect first channel. This will initiate a mx sock
    CPPUNIT_ASSERT(rcv.wait_for(lk, 30s, [&] {
        fmt::print("successfullyReceive: {}\n", successfullyReceive);
        fmt::print("successfullyConnected: {}\n", successfullyConnected);
        fmt::print("receiverConnected: {}\n", receiverConnected);
        return successfullyReceive && successfullyConnected && receiverConnected;
    }));

    // Connect another channel, but close the connection
    bool channel2NotConnected = false;
    alice->connectionManager->connectDevice(bob->id.second->getId(),
                                            "2",
                                            [&](std::shared_ptr<dhtnet::ChannelSocket> socket,
                                                const dht::InfoHash&) {
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    std::mutex mtxRcv {};
    std::string alphabet, shouldRcv, rcv1, rcv2, rcv3;
    for (int i = 0; i < 100; ++i)
        alphabet += "QWERTYUIOPASDFGHJKLZXCVBNM";
    rcvSock1->setOnRecv([&](const uint8_t* buf, size_t len) {
        rcv1 += std::string(buf, buf + len);
        return len;
    });
    rcvSock2->setOnRecv([&](const uint8_t* buf, size_t len) {
        rcv2 += std::string(buf, buf + len);
        return len;
    });
    rcvSock3->setOnRecv([&](const uint8_t* buf, size_t len) {
        rcv3 += std::string(buf, buf + len);
        return len;
    });
    for (uint64_t i = 0; i < alphabet.size(); ++i) {
        auto send = std::string(8000, alphabet[i]);
        shouldRcv += send;
        std::error_code ec;
        sendSock->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        sendSock2->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        sendSock3->write(reinterpret_cast<unsigned char*>(send.data()), send.size(), ec);
        CPPUNIT_ASSERT(!ec);
    }
    CPPUNIT_ASSERT(cv.wait_for(lk, 60s, [&] {
        return shouldRcv == rcv1 && shouldRcv == rcv2 && shouldRcv == rcv3;
    }));
}

void
ConnectionManagerTest::testDestroyWhileSending()
{
    // Same as test before, but destroy the accounts while sending.
    // This test if a segfault occurs
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //
    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });
    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    std::mutex mtxRcv {};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
ConnectionManagerTest::testCanSendBeacon()
{
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey()); //

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    alice->connectionManager->onICERequest([](const DeviceId&) { return true; });

    std::mutex mtx;
    std::unique_lock<std::mutex> lk {mtx};
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
    alice->connectionManager->onDhtConnected(alice->id.first->getPublicKey());
    bob->connectionManager->onDhtConnected(bob->id.first->getPublicKey());

    bob->connectionManager->onICERequest([](const DeviceId&) { return true; });
    std::mutex mtx;
    std::condition_variable cv;
    std::unique_lock<std::mutex> lk {mtx};
    bool successfullyConnected = false;
    int receiverConnected = 0;
    bob->connectionManager->onChannelRequest(
        [](const std::shared_ptr<dht::crypto::Certificate>&, const std::string&) { return true; });
    bob->connectionManager->onConnectionReady(
        [&receiverConnected,
         &cv](const DeviceId&, const std::string&, std::shared_ptr<ChannelSocket> socket) {
            if (socket)
                receiverConnected += 1;

            cv.notify_one();
        });
    std::string channelId;
    alice->connectionManager->connectDevice(bob->id.second,
                                            "git://*",
                                            [&](std::shared_ptr<ChannelSocket> socket,
                                                const DeviceId&) {
                                                if (socket) {
                                                    channelId = std::to_string(socket->channel());
                                                    successfullyConnected = true;
                                                }

                                                cv.notify_one();
                                            });
    CPPUNIT_ASSERT(
        cv.wait_for(lk, 60s, [&] { return successfullyConnected && receiverConnected == 1; }));
    std::vector<std::map<std::string, std::string>> expectedList = {
        {{"channel", channelId}, {"channelName", "git://*"}}};
    auto connectionList = alice->connectionManager->getConnectionList();
    CPPUNIT_ASSERT(!connectionList.empty());
    const auto& connectionInfo = connectionList[0];
    auto it = connectionInfo.find("id");
    CPPUNIT_ASSERT(it != connectionInfo.end());
    std::string connectionId = it->second;
    auto actualList = alice->connectionManager->getChannelList(connectionId);
    CPPUNIT_ASSERT(expectedList.size() == actualList.size());
    CPPUNIT_ASSERT(std::equal(expectedList.begin(), expectedList.end(), actualList.begin()));
    for (const auto& expectedMap : expectedList) {
        auto it = std::find_if(actualList.begin(),
                               actualList.end(),
                               [&](const std::map<std::string, std::string>& actualMap) {
                                   return expectedMap.size() == actualMap.size()
                                          && std::equal(expectedMap.begin(),
                                                        expectedMap.end(),
                                                        actualMap.begin());
                               });
        CPPUNIT_ASSERT(it != actualList.end());
    }
}

} // namespace test
} // namespace dhtnet

JAMI_TEST_RUNNER(dhtnet::test::ConnectionManagerTest::name())
