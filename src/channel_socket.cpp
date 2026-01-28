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

#include "channel_socket.h"

#include "multiplexed_socket.h"

#include <opendht/thread_pool.h>
#include <opendht/logger.h>

#include <asio/io_context.hpp>

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace dhtnet {

class ChannelSocket::Impl
{
public:
    Impl(std::weak_ptr<MultiplexedSocket> endpoint,
         const std::string& name,
         const uint16_t& channel,
         bool isInitiator,
         std::function<void()> rmFromMxSockCb)
        : name(name)
        , channel(channel)
        , endpoint(std::move(endpoint))
        , isInitiator_(isInitiator)
        , rmFromMxSockCb_(std::move(rmFromMxSockCb))
    {}

    ~Impl() {}

    bool stop()
    {
        if (isShutdown_.exchange(true))
            return false;
        if (shutdownCb_)
            shutdownCb_(ec_shutdown_);
        cv.notify_all();
        if (rmFromMxSockCb_)
            rmFromMxSockCb_();
        return true;
    }

    std::error_code sendEOF()
    {
        if (auto ep = endpoint.lock()) {
            std::error_code ec;
            const uint8_t dummy = '\0';
            ep->write(channel, &dummy, 0, ec);
            return ec;
        }
        return std::make_error_code(std::errc::not_connected);
    }

    ChannelReadyCb readyCb_ {};
    OnShutdownCb shutdownCb_ {};
    std::atomic_bool isShutdown_ {false};
    std::error_code ec_shutdown_ {};
    const std::string name {};
    const uint16_t channel {};
    const std::weak_ptr<MultiplexedSocket> endpoint {};
    const bool isInitiator_ {false};
    std::function<void()> rmFromMxSockCb_;

    bool isAnswered_ {false};
    bool isRemovable_ {false};

    std::vector<uint8_t> buf {};
    std::mutex mutex {};
    std::condition_variable cv {};
    GenericSocket<uint8_t>::RecvCb cb {};
    std::atomic_uint64_t txBytes_ {0};
    std::atomic_uint64_t rxBytes_ {0};
    std::chrono::steady_clock::time_point start_ {std::chrono::steady_clock::now()};
};

ChannelSocketTest::ChannelSocketTest(std::shared_ptr<asio::io_context> ctx,
                                     const DeviceId& deviceId,
                                     const std::string& name,
                                     const uint16_t& channel)
    : pimpl_deviceId(deviceId)
    , pimpl_name(name)
    , pimpl_channel(channel)
    , ioCtx_(*ctx)
{}

ChannelSocketTest::~ChannelSocketTest() {}

void
ChannelSocketTest::link(const std::shared_ptr<ChannelSocketTest>& socket1,
                        const std::shared_ptr<ChannelSocketTest>& socket2)
{
    socket1->remote = socket2;
    socket2->remote = socket1;
}

DeviceId
ChannelSocketTest::deviceId() const
{
    return pimpl_deviceId;
}

const std::string&
ChannelSocketTest::name() const
{
    return pimpl_name;
}

uint16_t
ChannelSocketTest::channel() const
{
    return pimpl_channel;
}

void
ChannelSocketTest::shutdown()
{
    {
        std::unique_lock lk {mutex};
        if (!isShutdown_.exchange(true)) {
            lk.unlock();
            shutdownCb_(ec_shutdown_);
        }
        cv.notify_all();
    }
    if (auto peer = remote.lock()) {
        if (!peer->isShutdown_.exchange(true)) {
            peer->shutdownCb_(ec_shutdown_);
        }
        peer->cv.notify_all();
    }
}

std::size_t
ChannelSocketTest::read(ValueType* buf, std::size_t len, std::error_code& ec)
{
    std::size_t size = std::min(len, this->rx_buf.size());

    for (std::size_t i = 0; i < size; ++i)
        buf[i] = this->rx_buf[i];

    if (size == this->rx_buf.size()) {
        this->rx_buf.clear();
    } else
        this->rx_buf.erase(this->rx_buf.begin(), this->rx_buf.begin() + size);
    return size;
}

std::size_t
ChannelSocketTest::write(const ValueType* buf, std::size_t len, std::error_code& ec)
{
    if (isShutdown_) {
        ec = std::make_error_code(std::errc::broken_pipe);
        return -1;
    }
    txBytes_ += len;
    ec = {};
    dht::ThreadPool::computation().run([r = remote, data = std::vector<uint8_t>(buf, buf + len)]() mutable {
        if (auto peer = r.lock())
            peer->onRecv(std::move(data));
    });
    return len;
}

int
ChannelSocketTest::waitForData(std::chrono::milliseconds timeout, std::error_code& ec) const
{
    std::unique_lock lk {mutex};
    cv.wait_for(lk, timeout, [&] { return !rx_buf.empty() or isShutdown_; });
    return rx_buf.size();
}

void
ChannelSocketTest::setOnRecv(RecvCb&& cb)
{
    std::lock_guard lkSockets(mutex);
    if (this->cb) {
        throw std::runtime_error("Recv callback already set");
    }
    this->cb = std::move(cb);
    if (!rx_buf.empty() && this->cb) {
        this->cb(rx_buf.data(), rx_buf.size());
        rx_buf.clear();
    }
}

void
ChannelSocketTest::onRecv(std::vector<uint8_t>&& pkt)
{
    rxBytes_ += pkt.size();
    std::lock_guard lkSockets(mutex);
    if (cb) {
        cb(pkt.data(), pkt.size());
        return;
    }
    rx_buf.insert(rx_buf.end(), std::make_move_iterator(pkt.begin()), std::make_move_iterator(pkt.end()));
    cv.notify_all();
}

void
ChannelSocketTest::onReady(ChannelReadyCb&& cb)
{}

void
ChannelSocketTest::onShutdown(OnShutdownCb&& cb)
{
    std::unique_lock lk {mutex};
    shutdownCb_ = std::move(cb);

    if (isShutdown_) {
        lk.unlock();
        shutdownCb_(ec_shutdown_);
    }
}

ChannelSocket::ChannelSocket(std::weak_ptr<MultiplexedSocket> endpoint,
                             const std::string& name,
                             const uint16_t& channel,
                             bool isInitiator,
                             std::function<void()> rmFromMxSockCb)
    : pimpl_ {std::make_unique<Impl>(endpoint, name, channel, isInitiator, std::move(rmFromMxSockCb))}
{}

ChannelSocket::~ChannelSocket() {}

DeviceId
ChannelSocket::deviceId() const
{
    if (auto ep = pimpl_->endpoint.lock()) {
        return ep->deviceId();
    }
    return {};
}

const std::string&
ChannelSocket::name() const
{
    return pimpl_->name;
}

uint16_t
ChannelSocket::channel() const
{
    return pimpl_->channel;
}

bool
ChannelSocket::isReliable() const
{
    if (auto ep = pimpl_->endpoint.lock()) {
        return ep->isReliable();
    }
    return false;
}

bool
ChannelSocket::isInitiator() const
{
    return pimpl_->isInitiator_;
}

int
ChannelSocket::maxPayload() const
{
    if (auto ep = pimpl_->endpoint.lock()) {
        return ep->maxPayload();
    }
    return -1;
}

void
ChannelSocket::setOnRecv(RecvCb&& cb)
{
    std::unique_lock lkSockets(pimpl_->mutex);
    pimpl_->cb = std::move(cb);
    if (!pimpl_->buf.empty() && pimpl_->cb) {
        auto result = pimpl_->cb(pimpl_->buf.data(), pimpl_->buf.size());
        pimpl_->buf.clear();
        if (result <= 0) {
            pimpl_->ec_shutdown_ = result == 0 ? std::error_code()
                                               : std::make_error_code(static_cast<std::errc>(-result));
            pimpl_->stop();
            lkSockets.unlock();
            pimpl_->sendEOF();
        }
    }
}

void
ChannelSocket::onRecv(std::vector<uint8_t>&& pkt)
{
    pimpl_->rxBytes_ += pkt.size();
    std::unique_lock lkSockets(pimpl_->mutex);
    if (pimpl_->cb) {
        auto result = pimpl_->cb(pkt.data(), pkt.size());
        if (result <= 0) {
            pimpl_->ec_shutdown_ = result == 0 ? std::error_code()
                                               : std::make_error_code(static_cast<std::errc>(-result));
            pimpl_->stop();
            lkSockets.unlock();
            pimpl_->sendEOF();
        }
        return;
    }
    pimpl_->buf.insert(pimpl_->buf.end(), pkt.begin(), pkt.end());
    pimpl_->cv.notify_all();
}

uint64_t
ChannelSocket::txBytes() const
{
    return pimpl_->txBytes_;
}

uint64_t
ChannelSocket::rxBytes() const
{
    return pimpl_->rxBytes_;
}

std::chrono::steady_clock::time_point
ChannelSocket::getStartTime() const
{
    return pimpl_->start_;
}

#ifdef DHTNET_TESTABLE
std::shared_ptr<MultiplexedSocket>
ChannelSocket::underlyingSocket() const
{
    if (auto mtx = pimpl_->endpoint.lock())
        return mtx;
    return {};
}
#endif

void
ChannelSocket::answered()
{
    pimpl_->isAnswered_ = true;
}

void
ChannelSocket::removable()
{
    pimpl_->isRemovable_ = true;
}

bool
ChannelSocket::isRemovable() const
{
    return pimpl_->isRemovable_;
}

bool
ChannelSocket::isAnswered() const
{
    return pimpl_->isAnswered_;
}

void
ChannelSocket::ready(bool accepted)
{
    if (pimpl_->readyCb_)
        pimpl_->readyCb_(accepted);
}

bool
ChannelSocket::stop()
{
    std::lock_guard lk {pimpl_->mutex};
    return pimpl_->stop();
}

void
ChannelSocket::shutdown()
{
    if (!stop())
        return;
    pimpl_->sendEOF();
}

std::size_t
ChannelSocket::read(ValueType* outBuf, std::size_t len, std::error_code& ec)
{
    std::lock_guard lkSockets(pimpl_->mutex);
    std::size_t size = std::min(len, pimpl_->buf.size());

    for (std::size_t i = 0; i < size; ++i)
        outBuf[i] = pimpl_->buf[i];

    pimpl_->buf.erase(pimpl_->buf.begin(), pimpl_->buf.begin() + size);
    return size;
}

std::size_t
ChannelSocket::write(const ValueType* buf, std::size_t len, std::error_code& ec)
{
    if (pimpl_->isShutdown_) {
        ec = std::make_error_code(std::errc::broken_pipe);
        return -1;
    }
    if (auto ep = pimpl_->endpoint.lock()) {
        std::size_t sent = 0;
        do {
            std::size_t toSend = std::min(static_cast<std::size_t>(UINT16_MAX), len - sent);
            auto res = ep->write(pimpl_->channel, buf + sent, toSend, ec);
            if (ec) {
                if (ep->logger())
                    ep->logger()->error("[device {}] Error when writing on channel: {}", ep->deviceId(), ec.message());
                return res;
            }
            sent += toSend;
        } while (sent < len);
        pimpl_->txBytes_ += sent;
        return sent;
    }
    ec = std::make_error_code(std::errc::broken_pipe);
    return -1;
}

int
ChannelSocket::waitForData(std::chrono::milliseconds timeout, std::error_code& ec) const
{
    std::unique_lock lk {pimpl_->mutex};
    pimpl_->cv.wait_for(lk, timeout, [&] { return !pimpl_->buf.empty() or pimpl_->isShutdown_; });
    return pimpl_->buf.size();
}

void
ChannelSocket::onShutdown(OnShutdownCb&& cb)
{
    std::unique_lock lk {pimpl_->mutex};
    if (pimpl_->isShutdown_) {
        lk.unlock();
        cb(pimpl_->ec_shutdown_);
    } else {
        pimpl_->shutdownCb_ = std::move(cb);
    }
}

void
ChannelSocket::onReady(ChannelReadyCb&& cb)
{
    pimpl_->readyCb_ = std::move(cb);
}

void
ChannelSocket::sendBeacon(const std::chrono::milliseconds& timeout)
{
    if (auto ep = pimpl_->endpoint.lock()) {
        ep->sendBeacon(timeout);
    } else {
        shutdown();
    }
}

std::shared_ptr<dht::crypto::Certificate>
ChannelSocket::peerCertificate() const
{
    if (auto ep = pimpl_->endpoint.lock())
        return ep->peerCertificate();
    return {};
}

IpAddr
ChannelSocket::getLocalAddress() const
{
    if (auto ep = pimpl_->endpoint.lock())
        return ep->getLocalAddress();
    return {};
}

IpAddr
ChannelSocket::getRemoteAddress() const
{
    if (auto ep = pimpl_->endpoint.lock())
        return ep->getRemoteAddress();
    return {};
}

} // namespace dhtnet
