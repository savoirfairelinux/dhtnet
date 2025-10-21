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
#include "threadloop.h"

#include <ciso646> // fix windows compiler bug

namespace dhtnet {

void
ThreadLoop::mainloop(const std::function<bool()> setup,
                     const std::function<void()> process,
                     const std::function<void()> cleanup)
{
    threadId_ = std::this_thread::get_id();
    try {
        if (setup()) {
            while (state_ == ThreadState::RUNNING)
                process();
            cleanup();
        } else {
            throw std::runtime_error("setup failed");
        }
    } catch (const ThreadLoopException& e) {
        if (logger_) logger_->e("[threadloop:{}] ThreadLoopException: {}", fmt::ptr(this), e.what());
    } catch (const std::exception& e) {
        if (logger_) logger_->e("[threadloop:{}] Unwaited exception: {}", fmt::ptr(this), e.what());
    }
    stop();
}

ThreadLoop::ThreadLoop(std::shared_ptr<dht::log::Logger> logger,
                       const std::function<bool()>& setup,
                       const std::function<void()>& process,
                       const std::function<void()>& cleanup)
    : setup_(setup)
    , process_(process)
    , cleanup_(cleanup)
    , thread_()
    , logger_(std::move(logger))
{}

ThreadLoop::~ThreadLoop()
{
    if (isRunning()) {
        if (logger_) logger_->error("join() should be explicitly called in owner's destructor");
        join();
    }
}

void
ThreadLoop::start()
{
    const auto s = state_.load();

    if (s == ThreadState::RUNNING) {
        if (logger_) logger_->error("already started");
        return;
    }

    // stop pending but not processed by thread yet?
    if (s == ThreadState::STOPPING and thread_.joinable()) {
        if (logger_) logger_->debug("stop pending");
        thread_.join();
    }

    state_ = ThreadState::RUNNING;
    thread_ = std::thread(&ThreadLoop::mainloop, this, setup_, process_, cleanup_);
}

void
ThreadLoop::stop()
{
    if (state_ == ThreadState::RUNNING)
        state_ = ThreadState::STOPPING;
}

void
ThreadLoop::join()
{
    stop();
    if (thread_.joinable())
        thread_.join();
}

void
ThreadLoop::waitForCompletion()
{
    if (thread_.joinable())
        thread_.join();
}

void
ThreadLoop::exit()
{
    stop();
    throw ThreadLoopException();
}

bool
ThreadLoop::isRunning() const noexcept
{
#ifdef _WIN32
    return state_ == ThreadState::RUNNING;
#else
    return thread_.joinable() and state_ == ThreadState::RUNNING;
#endif
}

void
InterruptedThreadLoop::stop()
{
    ThreadLoop::stop();
    cv_.notify_one();
}
} // namespace dhtnet
