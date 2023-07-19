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

#include <thread>
#include <memory>
#include <asio/io_context.hpp>
#include <fmt/format.h>

// This macro is used to validate that a code is executed from the expected
// thread. It's useful to detect unexpected race on data members.
#define CHECK_VALID_THREAD() \
    if (not isValidThread()) \
        fmt::print("The calling thread {} is not the expected thread: {}\n", getCurrentThread(), threadId_);
        /*JAMI_ERR() << "The calling thread " << getCurrentThread() \
                   << " is not the expected thread: " << threadId_;*/

namespace dhtnet {
namespace upnp {

class UpnpThreadUtil
{
protected:
    std::thread::id getCurrentThread() const { return std::this_thread::get_id(); }

    bool isValidThread() const { return threadId_ == getCurrentThread(); }

    // Upnp context execution queue (same as manager's scheduler)
    // Helpers to run tasks on upnp context queue.
    //static ScheduledExecutor* getScheduler() { return &Manager::instance().scheduler(); }

    template<typename Callback>
    static void runOnUpnpContextQueue(Callback&& cb)
    {
        //getScheduler()->run([cb = std::forward<Callback>(cb)]() mutable { cb(); });
        //ioContext->post(std::move(cb));
    }

    std::shared_ptr<asio::io_context> ioContext;
    std::thread::id threadId_;
};

} // namespace upnp
} // namespace dhtnet
