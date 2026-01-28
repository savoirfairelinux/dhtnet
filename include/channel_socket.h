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

#include "generic_io.h"
#include "ip_utils.h"

#include <opendht/default_types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

namespace asio {
class io_context;
}

namespace dht {
namespace crypto {
class Certificate;
}
} // namespace dht

namespace dhtnet {

class MultiplexedSocket;
class ChannelSocket;

using DeviceId = dht::PkId;
using ChannelReadyCb = std::function<void(bool)>;
using OnShutdownCb = std::function<void(const std::error_code&)>;

static constexpr auto SEND_BEACON_TIMEOUT = std::chrono::milliseconds(3000);

class ChannelSocketInterface : public GenericSocket<uint8_t>
{
public:
    using SocketType = GenericSocket<uint8_t>;

    virtual DeviceId deviceId() const = 0;
    virtual const std::string& name() const = 0;
    virtual uint16_t channel() const = 0;
    virtual void onReady(ChannelReadyCb&& cb) = 0;
    virtual void onShutdown(OnShutdownCb&& cb) = 0;

    virtual void onRecv(std::vector<uint8_t>&& pkt) = 0;

    virtual uint64_t txBytes() const = 0;
    virtual uint64_t rxBytes() const = 0;
    virtual std::chrono::steady_clock::time_point getStartTime() const = 0;
};

class ChannelSocketTest : public ChannelSocketInterface
{
public:
    ChannelSocketTest(std::shared_ptr<asio::io_context> ctx,
                      const DeviceId& deviceId,
                      const std::string& name,
                      const uint16_t& channel);
    ~ChannelSocketTest();

    static void link(const std::shared_ptr<ChannelSocketTest>& socket1,
                     const std::shared_ptr<ChannelSocketTest>& socket2);

    DeviceId deviceId() const override;
    const std::string& name() const override;
    uint16_t channel() const override;

    bool isReliable() const override { return true; };
    bool isInitiator() const override { return true; };
    int maxPayload() const override { return 0; };

    void shutdown() override;

    std::size_t read(ValueType* buf, std::size_t len, std::error_code& ec) override;
    std::size_t write(const ValueType* buf, std::size_t len, std::error_code& ec) override;
    int waitForData(std::chrono::milliseconds timeout, std::error_code&) const override;
    void setOnRecv(RecvCb&&) override;
    void onRecv(std::vector<uint8_t>&& pkt) override;

    void onReady(ChannelReadyCb&& cb) override;
    void onShutdown(OnShutdownCb&& cb) override;

    uint64_t txBytes() const override { return txBytes_; }
    uint64_t rxBytes() const override { return rxBytes_; }
    std::chrono::steady_clock::time_point getStartTime() const override { return start_; }

    std::vector<uint8_t> rx_buf {};
    mutable std::mutex mutex {};
    mutable std::condition_variable cv {};
    GenericSocket<uint8_t>::RecvCb cb {};

private:
    std::atomic_uint64_t txBytes_ {0};
    std::atomic_uint64_t rxBytes_ {0};
    std::chrono::steady_clock::time_point start_ {std::chrono::steady_clock::now()};

    const DeviceId pimpl_deviceId;
    const std::string pimpl_name;
    const uint16_t pimpl_channel;
    asio::io_context& ioCtx_;
    std::weak_ptr<ChannelSocketTest> remote;
    OnShutdownCb shutdownCb_ {[&](const std::error_code&) {}};
    std::atomic_bool isShutdown_ {false};
    std::error_code ec_shutdown_ {};
};

class ChannelSocket : public ChannelSocketInterface
{
public:
    ChannelSocket(std::weak_ptr<MultiplexedSocket> endpoint,
                  const std::string& name,
                  const uint16_t& channel,
                  bool isInitiator = false,
                  std::function<void()> rmFromMxSockCb = {});
    ~ChannelSocket();

    DeviceId deviceId() const override;
    const std::string& name() const override;
    uint16_t channel() const override;
    bool isReliable() const override;
    bool isInitiator() const override;
    int maxPayload() const override;
    bool stop();
    void shutdown() override;

    void ready(bool accepted);
    void onReady(ChannelReadyCb&& cb) override;
    void onShutdown(OnShutdownCb&& cb) override;

    std::size_t read(ValueType* buf, std::size_t len, std::error_code& ec) override;
    std::size_t write(const ValueType* buf, std::size_t len, std::error_code& ec) override;
    int waitForData(std::chrono::milliseconds timeout, std::error_code&) const override;

    void setOnRecv(RecvCb&&) override;
    void onRecv(std::vector<uint8_t>&& pkt) override;

    void sendBeacon(const std::chrono::milliseconds& timeout = SEND_BEACON_TIMEOUT);
    std::shared_ptr<dht::crypto::Certificate> peerCertificate() const;

#ifdef DHTNET_TESTABLE
    std::shared_ptr<MultiplexedSocket> underlyingSocket() const;
#endif

    uint64_t txBytes() const override;
    uint64_t rxBytes() const override;
    std::chrono::steady_clock::time_point getStartTime() const override;

    void answered();
    bool isAnswered() const;
    void removable();
    bool isRemovable() const;

    IpAddr getLocalAddress() const;
    IpAddr getRemoteAddress() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace dhtnet
