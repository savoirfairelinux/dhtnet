/*
 *  Copyright (C) 2004-2025 Savoir-faire Linux Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <cppunit/TestAssert.h>
#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <opendht/log.h>

#include "multiplexed_socket.h"
#include "test_runner.h"
#include "turn_cache.h"


namespace dhtnet {
namespace test {

class TurnCacheTest : public CppUnit::TestFixture
{
public:
    TurnCacheTest()
    {
        testDir_ = std::filesystem::current_path() / "tmp_tests_turnCache";
    }
    ~TurnCacheTest() {}
    static std::string name() { return "TurnCache"; }
    void setUp();
    void tearDown();

    std::shared_ptr<asio::io_context> ioContext;
    std::shared_ptr<std::thread> ioContextRunner;
    std::shared_ptr<Logger> logger = dht::log::getStdLogger();

private:
    std::filesystem::path testDir_;

    void testTurnResolution();
    void testRefreshMultipleTimes();

    CPPUNIT_TEST_SUITE(TurnCacheTest);
    CPPUNIT_TEST(testTurnResolution);
    CPPUNIT_TEST(testRefreshMultipleTimes);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_NAMED_REGISTRATION(TurnCacheTest, TurnCacheTest::name());

void
TurnCacheTest::setUp()
{
    if (!ioContext) {
        ioContext = std::make_shared<asio::io_context>();
        ioContextRunner = std::make_shared<std::thread>([&] {
            auto work = asio::make_work_guard(*ioContext);
            ioContext->run();
        });
    }
}


void
TurnCacheTest::tearDown()
{
    ioContext->stop();
    if (ioContextRunner && ioContextRunner->joinable()) {
        ioContextRunner->join();
    }
    ioContext.reset();
    std::filesystem::remove_all(testDir_);
}

void
TurnCacheTest::testTurnResolution()
{
    auto cachePath = testDir_ / "cache";

    TurnTransportParams turnParams;
    turnParams.domain = "turn.sfl.io";
    turnParams.realm = "sfl";
    turnParams.username = "sfl";
    turnParams.password = "sfl";

    auto turnCache = std::make_shared<TurnCache>("dummyAccount",
                                                 cachePath.string(),
                                                 ioContext,
                                                 logger,
                                                 turnParams,
                                                 true);
    turnCache->refresh();

    // Wait up to 30 seconds for the resolution of the TURN server
    int timeout = 30 * 1000;
    int waitTime = 0;
    int delay = 25;
    while (waitTime < timeout) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        waitTime += delay;

        if (turnCache->getResolvedTurn(AF_INET) ||
            turnCache->getResolvedTurn(AF_INET6)) {
            logger->debug("Waited {} ms for TURN resolution", waitTime);
            break;
        }
    }

    CPPUNIT_ASSERT(turnCache->getResolvedTurn(AF_INET) ||
                   turnCache->getResolvedTurn(AF_INET6));
}

void
TurnCacheTest::testRefreshMultipleTimes()
{
    auto cachePath = testDir_ / "cache";
    bool enabled = true;

    TurnTransportParams turnParams;
    turnParams.domain = "turn.sfl.io";
    turnParams.realm = "sfl";
    turnParams.username = "sfl";
    turnParams.password = "sfl";

    auto turnCache = std::make_shared<TurnCache>("dummyAccount",
                                                 cachePath.string(),
                                                 ioContext,
                                                 logger,
                                                 turnParams,
                                                 enabled);
    // This test is meant to be a regression test for the following issue:
    // https://git.jami.net/savoirfairelinux/dhtnet/-/issues/27
    // Calling refresh twice causes the TurnTransport created by the first call to
    // be destroyed shortly thereafter, which seems to be enough to reliably
    // trigger the bug described in the GitLab issue linked above.
    turnCache->refresh();
    turnCache->refresh();
}

} // namespace test
}

JAMI_TEST_RUNNER(dhtnet::test::TurnCacheTest::name())
