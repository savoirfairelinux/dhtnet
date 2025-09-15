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
#include <fmt/ranges.h>

#include <chrono>
#include <thread>
#if defined(__linux__) || defined(__APPLE__)
#include <dirent.h>
#include <unistd.h>
#endif

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
    // Helper used on Linux/macOS to count open file descriptors to detect leaks.
    static size_t countOpenFds()
    {
#if defined(__linux__) || defined(__APPLE__)
        const char* candidates[] = {"/proc/self/fd", "/dev/fd"};
        for (auto path : candidates) {
            if (auto* dir = opendir(path)) {
                size_t count = 0;
                while (auto* ent = readdir(dir)) {
                    if (ent->d_name[0] == '.' && (ent->d_name[1] == 0 || (ent->d_name[1] == '.' && ent->d_name[2] == 0)))
                        continue; // skip . and ..
                    ++count;
                }
                closedir(dir);
                return count;
            }
        }
        return 0; // fallback if directories not accessible
#else
        return 0; // Not supported on this platform
#endif
    }

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

    // Multi-cycle FD leak regression check.
#if defined(__linux__) || defined(__APPLE__)
    auto baseline = countOpenFds();
    logger->debug("Baseline open FDs: {}", baseline);
    baseline = countOpenFds(); // stabilize
    logger->debug("Baseline open FDs: {}", baseline);
    constexpr unsigned cycles = 10;
    std::vector<size_t> cycleValues; cycleValues.reserve(cycles);
    for (unsigned i = 0; i < cycles; ++i) {
        {
            auto turnCache = std::make_shared<TurnCache>("dummyAccount",
                                                         cachePath.string(),
                                                         ioContext,
                                                         logger,
                                                         turnParams,
                                                         enabled);
            turnCache->refresh();
            turnCache->refresh();
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
        // Wait for async cleanup with limited patience; don't exceed 5s per cycle.
        auto settleStart = std::chrono::steady_clock::now();
        size_t current = countOpenFds();
        while (current > baseline && std::chrono::steady_clock::now() - settleStart < std::chrono::seconds(5)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            current = countOpenFds();
        }
        cycleValues.push_back(current);
        logger->debug("Cycle {} FD count: {} (baseline {})", i, current, baseline);
    }
    auto [minIt, maxIt] = std::minmax_element(cycleValues.begin(), cycleValues.end());
    size_t minVal = *minIt; size_t maxVal = *maxIt;
    logger->debug("FD counts cycles: baseline={}, min={}, max={}, drift={}, values={}",
                  baseline, minVal, maxVal, (maxVal-minVal), cycleValues);
    CPPUNIT_ASSERT_MESSAGE("Excessive absolute FD growth {}", maxVal <= baseline);
#else
    logger->warn("FD leak detection skipped: platform not supported");
#endif
}

} // namespace test
}

JAMI_TEST_RUNNER(dhtnet::test::TurnCacheTest::name())
