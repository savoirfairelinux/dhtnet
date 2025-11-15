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

class PeerDiscoveryTest : public CppUnit::TestFixture
{
public:
    PeerDiscoveryTest() {
        pj_log_set_level(0);
        pj_log_set_log_func([](int level, const char* data, int /*len*/) {});
        testDir_ = std::filesystem::current_path() / "tmp_tests_PeerDiscoveryTest";
    }
    ~PeerDiscoveryTest() {}
    static std::string name() { return "PeerDiscoveryTest"; }
    void setUp();
    void tearDown();

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
    std::unique_ptr<ConnectionHandler> setupHandler(const dht::crypto::Identity& id);
    std::filesystem::path testDir_;

    void testConnectDevice();
    CPPUNIT_TEST_SUITE(PeerDiscoveryTest);
    CPPUNIT_TEST(testConnectDevice);

    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(PeerDiscoveryTest, PeerDiscoveryTest::name());

std::unique_ptr<ConnectionHandler>
PeerDiscoveryTest::setupHandler(const dht::crypto::Identity& id)
{
    auto h = std::make_unique<ConnectionHandler>();
    h->id = id;
    h->logger = logger;
    h->certStore = std::make_shared<tls::CertificateStore>(testDir_ / id.second->getName(), nullptr/*h->logger*/);
    h->ioContext = ioContext;
    h->ioContextRunner = ioContextRunner;

    dht::DhtRunner::Config dhtConfig;
    dhtConfig.dht_config.id = h->id;
    dhtConfig.threaded = true;
    dhtConfig.peer_discovery = true;
    dhtConfig.peer_publish = true;

    dht::DhtRunner::Context dhtContext;

    dhtContext.certificateStore = [c = h->certStore](const dht::InfoHash& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = c->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    dhtContext.certificateStorePkId = [c = h->certStore](const dht::PkId& pk_id) {
        std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
        if (auto cert = c->getCertificate(pk_id.toString()))
            ret.emplace_back(std::move(cert));
        return ret;
    };
    dhtContext.logger = h->logger;

    h->dht = std::make_shared<dht::DhtRunner>();
    h->dht->run(dhtConfig, std::move(dhtContext));
    auto config = std::make_shared<ConnectionManager::Config>();
    config->dht = h->dht;
    config->id = h->id;
    config->ioContext = h->ioContext;
    config->factory = factory;
    config->certStore = h->certStore;
    config->cachePath = testDir_ / id.second->getName() / "temp";

    h->connectionManager = std::make_shared<ConnectionManager>(config);
    h->connectionManager->onICERequest([](const DeviceId&) { return true; });
    h->connectionManager->onDhtConnected(h->id.first->getPublicKey());

    return h;
}

void
PeerDiscoveryTest::setUp()
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

    factory = std::make_unique<IceTransportFactory>(/*logger*/);
    alice = setupHandler(aliceDevice1Id);
    bob = setupHandler(bobDevice1Id);
}

void
PeerDiscoveryTest::tearDown()
{
    ioContext->stop();
    if (ioContextRunner && ioContextRunner->joinable()) {
        ioContextRunner->join();
    }
    ioContext.reset();

    alice.reset();
    bob.reset();
    factory.reset();
    std::filesystem::remove_all(testDir_);
}

void PeerDiscoveryTest::testConnectDevice()
{
    std::condition_variable bobConVar;
    bool isBobRecvChanlReq = false;
    bob->connectionManager->onChannelRequest(
        [&](const std::shared_ptr<dht::crypto::Certificate>&,
            const std::string& name) {
            std::lock_guard lock{mtx};
            isBobRecvChanlReq = name == "dummyName";
            bobConVar.notify_one();
            return true;
        });

    std::condition_variable alicConVar;
    bool isAlicConnected = false;
    alice->connectionManager->connectDevice(bob->id.second, "dummyName", [&](std::shared_ptr<ChannelSocket> socket, const DeviceId&) {
        std::lock_guard lock{mtx};
        if (socket) {
            isAlicConnected = true;
        }
        alicConVar.notify_one();
    });

    std::unique_lock lock{mtx};
    CPPUNIT_ASSERT(bobConVar.wait_for(lock, 30s, [&] { return isBobRecvChanlReq; }));
    CPPUNIT_ASSERT(alicConVar.wait_for(lock, 30s, [&] { return isAlicConnected; }));
}

}
}
JAMI_TEST_RUNNER(dhtnet::test::PeerDiscoveryTest::name())
