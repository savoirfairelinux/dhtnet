/*
 * Copyright (C) 2026 Savoir-faire Linux Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include "tls_session.h"
#include "test_runner.h"

#include <cppunit/TestAssert.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <opendht/log.h>

#include <condition_variable>
#include <filesystem>
#include <mutex>

namespace dhtnet::test {
namespace {

class SilentDatagramSocket final : public GenericSocket<uint8_t>
{
public:
    explicit SilentDatagramSocket(bool initiator)
        : initiator_(initiator)
    {}

    void setOnRecv(RecvCb&&) override {}
    bool isReliable() const override { return false; }
    bool isInitiator() const override { return initiator_; }
    int maxPayload() const override { return 1200; }
    int waitForData(std::chrono::milliseconds, std::error_code& ec) const override
    {
        ec = std::make_error_code(std::errc::operation_not_supported);
        return -1;
    }
    std::size_t write(const uint8_t*, std::size_t len, std::error_code& ec) override
    {
        ec.clear();
        return len;
    }
    std::size_t read(uint8_t*, std::size_t, std::error_code& ec) override
    {
        ec = std::make_error_code(std::errc::operation_not_supported);
        return 0;
    }

private:
    bool initiator_;
};

} // namespace

class TlsSessionTest : public CppUnit::TestFixture
{
public:
    static std::string name() { return "tls_session"; }
    void tearDown() override { std::filesystem::remove_all(testDir_); }

private:
    std::filesystem::path testDir_;
    void shutdownInterruptsCookieWait() { checkShutdown(false); }
    void shutdownInterruptsHandshake() { checkShutdown(true); }
    void checkShutdown(bool initiator)
    {
        using namespace std::chrono_literals;
        const auto identity = dht::crypto::generateEcIdentity("tls-shutdown-test");
        const auto logger = dht::log::getStdLogger();
        testDir_ = std::filesystem::temp_directory_path()
                   / ("dhtnet-tls-shutdown-" + identity.second->getId().toString());
        std::promise<tls::DhParams> dhParams;
        dhParams.set_value({});
        tls::CertificateStore store(testDir_, logger);
        tls::TlsParams params {{},
                               {},
                               identity.second,
                               identity.first,
                               dhParams.get_future().share(),
                               store,
                               40s,
                               {},
                               std::make_shared<asio::io_context>(),
                               logger,
                               "SRTP_AES128_CM_HMAC_SHA1_80"};
        std::mutex mutex;
        std::condition_variable cv;
        auto state = tls::TlsSessionState::NONE;
        tls::TlsSession::TlsSessionCallbacks callbacks {
            [&](tls::TlsSessionState next) {
                std::lock_guard lock(mutex);
                state = next;
                cv.notify_one();
            },
            {},
            {},
            {},
        };
        tls::TlsSession session(std::make_unique<SilentDatagramSocket>(initiator), params, callbacks, false);
        {
            std::unique_lock lock(mutex);
            const auto expected = initiator ? tls::TlsSessionState::HANDSHAKE : tls::TlsSessionState::COOKIE;
            CPPUNIT_ASSERT(cv.wait_for(lock, 3s, [&] { return state == expected; }));
        }
        const auto begin = std::chrono::steady_clock::now();
        session.shutdown();
        {
            std::unique_lock lock(mutex);
            CPPUNIT_ASSERT(cv.wait_for(lock, 100ms, [&] { return state == tls::TlsSessionState::SHUTDOWN; }));
        }
        CPPUNIT_ASSERT(std::chrono::steady_clock::now() - begin < 100ms);
    }

    CPPUNIT_TEST_SUITE(TlsSessionTest);
    CPPUNIT_TEST(shutdownInterruptsCookieWait);
    CPPUNIT_TEST(shutdownInterruptsHandshake);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(TlsSessionTest, TlsSessionTest::name());
} // namespace dhtnet::test

JAMI_TEST_RUNNER(dhtnet::test::TlsSessionTest::name());
