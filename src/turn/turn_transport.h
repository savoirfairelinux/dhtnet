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
#pragma once

#include "ip_utils.h"
#include "pj_init_lock.h"
#include "turn_params.h"

#include <opendht/logger.h>

#include <functional>
#include <memory>
#include <string>

namespace dht {
namespace log {
struct Logger;
}
}

namespace dhtnet {

using Logger = dht::log::Logger;

/**
 * This class is used to test connection to TURN servers
 * No other logic is implemented.
 */
class TurnTransport
{
public:
    TurnTransport(const TurnTransportParams& param, std::function<void(bool)>&& cb, const std::shared_ptr<Logger>& logger = {});
    ~TurnTransport();
    void shutdown();

private:
    TurnTransport() = delete;
    PjInitLock pjInitLock_;
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace dhtnet
