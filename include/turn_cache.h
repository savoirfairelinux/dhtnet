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
#pragma once

#include "ip_utils.h"
#include "turn_params.h"

#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <filesystem>

namespace dht {
namespace log {
struct Logger;
}
}

namespace dhtnet {

using Logger = dht::log::Logger;

class TurnTransport;

class TurnCache : public std::enable_shared_from_this<TurnCache>
{
public:
    TurnCache(const std::string& accountId,
              const std::string& cachePath,
              const std::shared_ptr<asio::io_context>& io_context,
              const std::shared_ptr<Logger>& logger,
              const TurnTransportParams& params,
              bool enabled);
    ~TurnCache();

    std::optional<IpAddr> getResolvedTurn(uint16_t family = AF_INET) const;
    /**
     * Pass a new configuration for the cache
     * @param param     The new configuration
     */
    void reconfigure(const TurnTransportParams& params, bool enabled);
    /**
     * Refresh cache from current configuration
     */
    void refresh(const asio::error_code& ec = {});

private:
    std::string accountId_;
    std::filesystem::path cachePath_;
    TurnTransportParams params_;
    std::atomic_bool enabled_ {false};
    /**
     * Avoid to refresh the cache multiple times
     */
    std::atomic_bool isRefreshing_ {false};
    /**
     * This will cache the TURN server resolution each time we launch
     * Jami, or for each connectivityChange()
     */
    void testTurn(IpAddr server);
    std::unique_ptr<TurnTransport> testTurnV4_;
    std::unique_ptr<TurnTransport> testTurnV6_;

    // Used to detect if a TURN server is down.
    void refreshTurnDelay(bool scheduleNext);
    std::chrono::seconds turnRefreshDelay_ {std::chrono::seconds(10)};

    // Store resoved TURN addresses
    mutable std::mutex cachedTurnMutex_ {};
    std::unique_ptr<IpAddr> cacheTurnV4_ {};
    std::unique_ptr<IpAddr> cacheTurnV6_ {};

    void onConnected(const asio::error_code& ec, bool ok, IpAddr server);

    // io
    std::shared_ptr<asio::io_context> io_context;
    std::unique_ptr<asio::steady_timer> refreshTimer_;
    std::unique_ptr<asio::steady_timer> onConnectedTimer_;

    std::mutex shutdownMtx_;

    std::shared_ptr<Logger> logger_;

    // Asio :(
    // https://stackoverflow.com/questions/35507956/is-it-safe-to-destroy-boostasio-timer-from-its-handler-or-handler-dtor
    std::weak_ptr<TurnCache> weak()
    {
        return std::static_pointer_cast<TurnCache>(shared_from_this());
    }
};

} // namespace dhtnet
