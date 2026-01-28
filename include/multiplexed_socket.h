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

#include "channel_socket.h"
#include "ip_utils.h"

#include <opendht/default_types.h>
#include <condition_variable>

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace asio {
class io_context;
}

namespace dht {
namespace log {
struct Logger;
}
} // namespace dht

namespace dhtnet {

using Logger = dht::log::Logger;
class IceTransport;
class TlsSocketEndpoint;

using OnConnectionRequestCb = std::function<bool(const std::shared_ptr<dht::crypto::Certificate>& /* peer */,
                                                 const uint16_t& /* id */,
                                                 const std::string& /* name */)>;
using OnConnectionReadyCb = std::function<void(const DeviceId& /* deviceId */, const std::shared_ptr<ChannelSocket>&)>;
static constexpr uint16_t CONTROL_CHANNEL {0};
static constexpr uint16_t PROTOCOL_CHANNEL {0xffff};

enum class ChannelRequestState {
    REQUEST,
    ACCEPT,
    DECLINE,
};

/**
 * That msgpack structure is used to request a new channel (id, name)
 * Transmitted over the TLS socket
 */
struct ChannelRequest
{
    std::string name {};
    uint16_t channel {0};
    ChannelRequestState state {ChannelRequestState::REQUEST};
    MSGPACK_DEFINE(name, channel, state)
};

/**
 * A socket divided in channels over a TLS session
 */
class MultiplexedSocket : public std::enable_shared_from_this<MultiplexedSocket>
{
public:
    MultiplexedSocket(std::shared_ptr<asio::io_context> ctx,
                      const DeviceId& deviceId,
                      std::unique_ptr<TlsSocketEndpoint> endpoint,
                      std::shared_ptr<dht::log::Logger> logger = {});
    ~MultiplexedSocket();
    std::shared_ptr<ChannelSocket> addChannel(const std::string& name);

    DeviceId deviceId() const;
    bool isReliable() const;
    bool isInitiator() const;
    int maxPayload() const;

    /**
     * Will be triggered when a new channel is ready
     */
    void setOnReady(OnConnectionReadyCb&& cb);
    /**
     * Will be triggered when the peer asks for a new channel
     */
    void setOnRequest(OnConnectionRequestCb&& cb);

    std::size_t write(uint16_t channel, const uint8_t* buf, std::size_t len, std::error_code& ec);

    /**
     * This will close all channels and send a TLS EOF on the main socket.
     */
    void shutdown();
    bool isRunning() const;

    /**
     * This will wait that eventLoop is stopped and stop it if necessary
     */
    void join();

    /**
     * Will trigger that callback when shutdown() is called
     */
    void onShutdown(OnShutdownCb&& cb);

    /**
     * Get information from socket (channels opened)
     */
    void monitor() const;

    const std::shared_ptr<Logger>& logger();

    /**
     * Get the list of channels
     */
    std::vector<std::map<std::string, std::string>> getChannelList() const;

    /**
     * Send a beacon on the socket and close if no response come
     * @param timeout
     */
    void sendBeacon(const std::chrono::milliseconds& timeout = SEND_BEACON_TIMEOUT);

    uint64_t txBytes() const;
    uint64_t rxBytes() const;
    std::chrono::steady_clock::time_point getStartTime() const;

    /**
     * Get peer's certificate
     */
    std::shared_ptr<dht::crypto::Certificate> peerCertificate() const;

    IpAddr getLocalAddress() const;
    IpAddr getRemoteAddress() const;

    void eraseChannel(uint16_t channel);

    TlsSocketEndpoint* endpoint();

#ifdef DHTNET_TESTABLE
    /**
     * Check if we can send beacon on the socket
     */
    bool canSendBeacon() const;

    /**
     * Decide if yes or not we answer to beacon
     * @param value     New value
     */
    void answerToBeacon(bool value);

    /**
     * Change version sent to the peer
     */
    void setVersion(int version);

    /**
     * Set a callback to detect beacon messages
     */
    void setOnBeaconCb(const std::function<void(bool)>& cb);

    /**
     * Set a callback to detect version messages
     */
    void setOnVersionCb(const std::function<void(int)>& cb);

    /**
     * Send the version
     */
    void sendVersion();
#endif

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace dhtnet

MSGPACK_ADD_ENUM(dhtnet::ChannelRequestState);
