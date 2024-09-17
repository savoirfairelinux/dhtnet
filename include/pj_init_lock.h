/*
 *  Copyright (C) 2024 Savoir-faire Linux Inc.
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

#include <fmt/core.h>
#include <mutex>
#include <pj/errno.h>
#include <pj/types.h>

namespace dhtnet {

// PJSIP expects the number of calls to pj_shutdown to match the number of calls
// to pj_init (https://docs.pjsip.org/en/latest/specific-guides/develop/init_shutdown_thread.html).
// The intended behavior seems to be the following:
// - The first call to pj_init actually initializes the library; subsequent calls do nothing.
// - All calls to pj_shutdown do nothing, except the last one which actually performs the shutdown.
// Unfortunately, the way this logic is implemented in PJSIP is not thread-safe, so we're
// responsible for making sure that these functions are unable to be called by two threads at the same time.
class PjInitLock
{
private:
    inline static std::mutex mutex_;

public:
    PjInitLock()
    {
        std::lock_guard lk(mutex_);
        pj_status_t status = pj_init();

        if (status != PJ_SUCCESS) {
            char errorMessage[PJ_ERR_MSG_SIZE];
            pj_strerror(status, errorMessage, sizeof(errorMessage));
            throw std::runtime_error(
                fmt::format("pj_init failed: {}", errorMessage));
        }
    }

    ~PjInitLock()
    {
        std::lock_guard lk(mutex_);
        pj_shutdown();
    }
};

}
