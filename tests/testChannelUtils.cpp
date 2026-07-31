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
#include <cppunit/TestAssert.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include "test_runner.h"
#include "channel_utils.h"
#include <msgpack.hpp>
#include <asio/io_context.hpp>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <future>

namespace dhtnet {
namespace test {

class ChannelUtilsTest : public CppUnit::TestFixture
{
public:
    static std::string name() { return "channel_utils"; }

    void setUp() {}
    void tearDown() {}

private:
    void testBuildMsgpackReader();
    void testMessageChannel();
    void testRecvCallbackCanStopChannel();
    void testBufferedRecvCallbackCanStopChannel();
    void testShutdownCallbackCanReenterChannel();

    CPPUNIT_TEST_SUITE(ChannelUtilsTest);
    CPPUNIT_TEST(testBuildMsgpackReader);
    CPPUNIT_TEST(testMessageChannel);
    CPPUNIT_TEST(testRecvCallbackCanStopChannel);
    CPPUNIT_TEST(testBufferedRecvCallbackCanStopChannel);
    CPPUNIT_TEST(testShutdownCallbackCanReenterChannel);
    CPPUNIT_TEST_SUITE_END();
};

bool
completesWithoutDeadlock(std::function<void()> operation)
{
    std::packaged_task<void()> task(std::move(operation));
    auto completed = task.get_future();
    std::thread worker(std::move(task));
    if (completed.wait_for(std::chrono::seconds(1)) != std::future_status::ready) {
        worker.detach();
        return false;
    }
    worker.join();
    completed.get();
    return true;
}

struct TestStruct
{
    int a;
    std::string b;
    MSGPACK_DEFINE(a, b);
};

void
ChannelUtilsTest::testBuildMsgpackReader()
{
    std::vector<TestStruct> received;
    auto reader = buildMsgpackReader<TestStruct>([&](TestStruct&& msg) {
        received.emplace_back(std::move(msg));
        return std::error_code();
    });

    TestStruct msg1 {1, "hello"};
    TestStruct msg2 {2, "world"};

    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, msg1);
    msgpack::pack(sbuf, msg2);

    // Feed data in chunks
    const uint8_t* data = reinterpret_cast<const uint8_t*>(sbuf.data());
    size_t size = sbuf.size();

    // Feed first part
    size_t part1 = 2;
    auto res = reader(data, part1);
    CPPUNIT_ASSERT_EQUAL((ssize_t) part1, res);
    CPPUNIT_ASSERT(received.empty());

    // Feed second part
    res = reader(data + part1, size - part1);
    CPPUNIT_ASSERT_EQUAL((ssize_t) (size - part1), res);
    CPPUNIT_ASSERT_EQUAL((size_t) 2, received.size());
    CPPUNIT_ASSERT_EQUAL(1, received[0].a);
    CPPUNIT_ASSERT_EQUAL(std::string("hello"), received[0].b);
    CPPUNIT_ASSERT_EQUAL(2, received[1].a);
    CPPUNIT_ASSERT_EQUAL(std::string("world"), received[1].b);
}

void
ChannelUtilsTest::testMessageChannel()
{
    auto ctx = std::make_shared<asio::io_context>();
    auto socket1 = std::make_shared<ChannelSocketTest>(ctx, dht::PkId(), "test1", 0);
    auto socket2 = std::make_shared<ChannelSocketTest>(ctx, dht::PkId(), "test2", 0);
    ChannelSocketTest::link(socket1, socket2);

    // Test Send
    {
        MessageChannel<TestStruct> channel(socket1, [](TestStruct&&) { return std::error_code(); });
        TestStruct msg {42, "answer"};
        channel.send(msg);

        // Wait for data on socket2
        std::error_code ec;
        int res = socket2->waitForData(std::chrono::seconds(1), ec);
        CPPUNIT_ASSERT_EQUAL(0, ec.value());
        CPPUNIT_ASSERT(res > 0);

        // Verify data
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, msg);

        std::vector<uint8_t> receivedData;
        {
            std::lock_guard<std::mutex> lk(socket2->mutex);
            receivedData = socket2->rx_buf;
        }

        CPPUNIT_ASSERT_EQUAL(sbuf.size(), receivedData.size());
        CPPUNIT_ASSERT(std::memcmp(sbuf.data(), receivedData.data(), sbuf.size()) == 0);
    }

    // Test Receive
    {
        auto socket3 = std::make_shared<ChannelSocketTest>(ctx, dht::PkId(), "test3", 0);
        auto socket4 = std::make_shared<ChannelSocketTest>(ctx, dht::PkId(), "test4", 0);
        ChannelSocketTest::link(socket3, socket4);

        std::vector<TestStruct> received;
        std::condition_variable cv;
        std::mutex mtx;
        bool done = false;

        MessageChannel<TestStruct> channel(socket3, [&](TestStruct&& msg) {
            std::lock_guard<std::mutex> lk(mtx);
            received.emplace_back(std::move(msg));
            done = true;
            cv.notify_one();
            return std::error_code();
        });

        TestStruct msg {100, "receive"};
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, msg);

        std::error_code ec;
        socket4->write(reinterpret_cast<const uint8_t*>(sbuf.data()), sbuf.size(), ec);

        // Wait for callback
        std::unique_lock<std::mutex> lk(mtx);
        CPPUNIT_ASSERT(cv.wait_for(lk, std::chrono::seconds(1), [&] { return done; }));

        CPPUNIT_ASSERT_EQUAL((size_t) 1, received.size());
        CPPUNIT_ASSERT_EQUAL(100, received[0].a);
        CPPUNIT_ASSERT_EQUAL(std::string("receive"), received[0].b);
    }
}

void
ChannelUtilsTest::testRecvCallbackCanStopChannel()
{
    auto socket = std::make_shared<ChannelSocket>(std::weak_ptr<MultiplexedSocket> {}, "test", 1);
    socket->setOnRecv([socket = std::weak_ptr<ChannelSocket>(socket)](const uint8_t*, std::size_t len) {
        auto shared = socket.lock();
        CPPUNIT_ASSERT(shared);
        shared->stop();
        return len;
    });

    CPPUNIT_ASSERT_MESSAGE("Receive callback deadlocked while stopping its channel",
                           completesWithoutDeadlock([socket] { socket->onRecv(std::vector<uint8_t> {1}); }));
}

void
ChannelUtilsTest::testBufferedRecvCallbackCanStopChannel()
{
    auto socket = std::make_shared<ChannelSocket>(std::weak_ptr<MultiplexedSocket> {}, "test", 1);
    socket->onRecv(std::vector<uint8_t> {1});

    CPPUNIT_ASSERT_MESSAGE("Buffered receive callback deadlocked while stopping its channel",
                           completesWithoutDeadlock([socket] {
                               socket->setOnRecv(
                                   [socket = std::weak_ptr<ChannelSocket>(socket)](const uint8_t*, std::size_t len) {
                                       auto shared = socket.lock();
                                       CPPUNIT_ASSERT(shared);
                                       shared->stop();
                                       return len;
                                   });
                           }));
}

void
ChannelUtilsTest::testShutdownCallbackCanReenterChannel()
{
    auto socket = std::make_shared<ChannelSocket>(std::weak_ptr<MultiplexedSocket> {}, "test", 1);
    socket->onShutdown([socket = std::weak_ptr<ChannelSocket>(socket)](const std::error_code&) {
        auto shared = socket.lock();
        CPPUNIT_ASSERT(shared);
        shared->onShutdown([](const std::error_code&) {});
    });

    CPPUNIT_ASSERT_MESSAGE("Shutdown callback deadlocked while re-entering its channel",
                           completesWithoutDeadlock([socket] { socket->stop(); }));
}

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(ChannelUtilsTest, ChannelUtilsTest::name());

} // namespace test
} // namespace dhtnet

JAMI_TEST_RUNNER(dhtnet::test::ChannelUtilsTest::name());
