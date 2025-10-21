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
#include "multiplexed_socket.h"
#include "peer_connection.h"
#include "ice_transport.h"
#include "certstore.h"

#include <opendht/logger.h>
#include <opendht/thread_pool.h>

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>

#include <deque>

static constexpr std::size_t IO_BUFFER_SIZE {8192}; ///< Size of char buffer used by IO operations
static constexpr unsigned MULTIPLEXED_SOCKET_VERSION {1};

struct ChanneledMessage
{
    uint16_t channel;
    std::vector<uint8_t> data;
    MSGPACK_DEFINE(channel, data)
};

struct BeaconMsg
{
    bool p;
    MSGPACK_DEFINE_MAP(p)
};

struct VersionMsg
{
    unsigned v;
    MSGPACK_DEFINE_MAP(v)
};

namespace dhtnet {

using clock = std::chrono::steady_clock;
using time_point = clock::time_point;

class MultiplexedSocket::Impl
{
public:
    Impl(MultiplexedSocket& parent,
         std::shared_ptr<asio::io_context> ctx,
         const DeviceId& deviceId,
         std::unique_ptr<TlsSocketEndpoint> ep,
         std::shared_ptr<dht::log::Logger> logger)
        : parent_(parent)
        , logger_(std::move(logger))
        , ctx_(std::move(ctx))
        , deviceId(deviceId)
        , endpoint(std::move(ep))
        , nextChannel_(endpoint->isInitiator() ? 0x0001u : 0x8000u)
        , eventLoopThread_ {[this] {
            try {
                eventLoop();
            } catch (const std::exception& e) {
                if (logger_)
                    logger_->error("[device {}] [CNX] peer connection event loop failure: {}", this->deviceId, e.what());
                shutdown();
            }
        }}
        , beaconTimer_(*ctx_)
    {}

    ~Impl() {}

    void join()
    {
        if (!isShutdown_) {
            if (endpoint)
                endpoint->setOnStateChange({});
            shutdown();
        } else {
            clearSockets();
        }
        if (eventLoopThread_.joinable())
            eventLoopThread_.join();
    }

    void clearSockets()
    {
        decltype(sockets) socks;
        {
            std::lock_guard lkSockets(socketsMutex);
            socks = std::move(sockets);
        }
        for (auto& socket : socks) {
            // Just trigger onShutdown() to make client know
            // No need to write the EOF for the channel, the write will fail because endpoint is
            // already shutdown
            if (socket.second)
                socket.second->stop();
        }
    }

    void shutdown()
    {
        std::unique_lock lk {stateMutex};
        if (isShutdown_.exchange(true))
            return;
        stop.store(true);
        beaconTimer_.cancel();
        if (auto onShutdown = onShutdown_) {
            // Call the callback without holding the lock
            lk.unlock();
            onShutdown();
        } else {
            lk.unlock();
        }
        if (endpoint) {
            std::unique_lock lk(writeMtx);
            endpoint->shutdown();
        }
        clearSockets();
    }

    bool isRunning() const { return !isShutdown_ && !stop; }

    std::shared_ptr<ChannelSocket> makeSocket(const std::string& name, uint16_t channel, bool isInitiator)
    {
        auto& channelSocket = sockets[channel];
        if (not channelSocket)
            channelSocket = std::make_shared<ChannelSocket>(parent_.weak(),
                                                            name,
                                                            channel,
                                                            isInitiator,
                                                            [w = parent_.weak(), channel]() {
                                                                // Remove socket in another thread to avoid any lock
                                                                dht::ThreadPool::io().run([w, channel]() {
                                                                    if (auto shared = w.lock()) {
                                                                        shared->eraseChannel(channel);
                                                                    }
                                                                });
                                                            });
        else {
            if (logger_)
                logger_->warn("[device {}] Received request for existing channel {}", deviceId, channel);
            return {};
        }
        return channelSocket;
    }

    /**
     * Handle packets on the TLS endpoint and parse RTP
     */
    void eventLoop();
    /**
     * Triggered when a new control packet is received
     */
    void handleControlPacket(std::vector<uint8_t>&& pkt);
    void handleProtocolPacket(std::vector<uint8_t>&& pkt);
    bool handleProtocolMsg(const msgpack::object& o);
    /**
     * Triggered when a new packet on a channel is received
     */
    void handleChannelPacket(uint16_t channel, std::vector<uint8_t>&& pkt);
    void onRequest(const std::string& name, uint16_t channel);
    void onAccept(const std::string& name, uint16_t channel);

    void setOnReady(OnConnectionReadyCb&& cb) { onChannelReady_ = std::move(cb); }
    void setOnRequest(OnConnectionRequestCb&& cb) { onRequest_ = std::move(cb); }

    // Beacon
    void sendBeacon(const std::chrono::milliseconds& timeout);
    void handleBeaconRequest();
    void handleBeaconResponse();
    std::atomic_int beaconCounter_ {0};

    bool writeProtocolMessage(const msgpack::sbuffer& buffer);

    MultiplexedSocket& parent_;

    const std::shared_ptr<Logger> logger_;
    const std::shared_ptr<asio::io_context> ctx_;

    OnConnectionReadyCb onChannelReady_ {};
    OnConnectionRequestCb onRequest_ {};
    OnShutdownCb onShutdown_ {};

    const DeviceId deviceId {};
    // Main socket
    std::mutex writeMtx {};
    std::unique_ptr<TlsSocketEndpoint> endpoint {};

    std::mutex socketsMutex {};
    std::map<uint16_t, std::shared_ptr<ChannelSocket>> sockets {};
    uint16_t nextChannel_;

    // Main loop to parse incoming packets
    std::atomic_bool stop {false};
    std::thread eventLoopThread_ {};

    std::mutex stateMutex {};
    std::atomic_bool isShutdown_ {false};
    time_point start_ {clock::now()};
    asio::steady_timer beaconTimer_;

    // version related stuff
    void sendVersion();
    void onVersion(int version);
    std::atomic_bool canSendBeacon_ {false};
    std::atomic_bool answerBeacon_ {true};
    unsigned version_ {MULTIPLEXED_SOCKET_VERSION};
    std::function<void(bool)> onBeaconCb_ {};
    std::function<void(unsigned)> onVersionCb_ {};
};

void
MultiplexedSocket::Impl::eventLoop()
{
    endpoint->setOnStateChange([w = parent_.weak_from_this()](tls::TlsSessionState state) {
        auto ssock = w.lock();
        if (!ssock)
            return false;
        auto& this_ = *ssock->pimpl_;
        if (state == tls::TlsSessionState::SHUTDOWN && !this_.isShutdown_) {
            if (this_.logger_)
                this_.logger_->debug("[device {}] Tls endpoint is down, shutdown multiplexed socket", this_.deviceId);
            this_.shutdown();
            return false;
        }
        return true;
    });
    sendVersion();
    std::error_code ec;
    msgpack::unpacker pac {};
    while (!stop) {
        if (!endpoint) {
            shutdown();
            return;
        }
        pac.reserve_buffer(IO_BUFFER_SIZE);
        int size = endpoint->read(reinterpret_cast<uint8_t*>(&pac.buffer()[0]), IO_BUFFER_SIZE, ec);
        if (size < 0) {
            if (ec && logger_)
                logger_->error("[device {}] Read error detected: {}", deviceId, ec.message());
            shutdown();
            break;
        }
        if (size == 0) {
            // We can close the socket
            shutdown();
            break;
        }

        pac.buffer_consumed(size);
        msgpack::object_handle oh;
        while (pac.next(oh) && !stop) {
            try {
                auto msg = oh.get().as<ChanneledMessage>();
                if (msg.channel == CONTROL_CHANNEL)
                    handleControlPacket(std::move(msg.data));
                else if (msg.channel == PROTOCOL_CHANNEL)
                    handleProtocolPacket(std::move(msg.data));
                else
                    handleChannelPacket(msg.channel, std::move(msg.data));
            } catch (const std::exception& e) {
                if (logger_)
                    logger_->warn("[device {}] Failed to unpacked message of {:d} bytes: {:s}",
                                  deviceId,
                                  size,
                                  e.what());
            } catch (...) {
                if (logger_)
                    logger_->error("[device {}] Unknown exception catched while unpacking message "
                                   "of {:d} bytes",
                                   deviceId,
                                   size);
            }
        }
    }
}

void
MultiplexedSocket::Impl::onAccept(const std::string& name, uint16_t channel)
{
    std::unique_lock lk(socketsMutex);
    auto socket = sockets[channel];
    if (!socket) {
        if (logger_)
            logger_->error("[device {}] Receiving an answer for a non existing channel. This is a bug.", deviceId);
        return;
    }

    lk.unlock();
    onChannelReady_(deviceId, socket);
    socket->ready(true);
    // Due to the callbacks that can take some time, onAccept can arrive after
    // receiving all the data. In this case, the socket should be removed here
    // as handle by onChannelReady_
    lk.lock();
    if (socket->isRemovable())
        sockets.erase(channel);
    else
        socket->answered();
}

void
MultiplexedSocket::Impl::sendBeacon(const std::chrono::milliseconds& timeout)
{
    if (!canSendBeacon_)
        return;
    beaconCounter_++;
    if (logger_)
        logger_->debug("[device {}] Send beacon to peer", deviceId);

    msgpack::sbuffer buffer(8);
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack(BeaconMsg {true});
    if (!writeProtocolMessage(buffer))
        return;
    std::lock_guard lk(stateMutex);
    beaconTimer_.expires_after(timeout);
    beaconTimer_.async_wait([w = parent_.weak()](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted)
            return;
        if (auto shared = w.lock()) {
            if (shared->pimpl_->beaconCounter_ != 0) {
                if (shared->pimpl_->logger_)
                    shared->pimpl_->logger_->error("[device {}] Beacon doesn't get any response. Stopping socket",
                                                   shared->pimpl_->deviceId);
                shared->shutdown();
            }
        }
    });
}

void
MultiplexedSocket::Impl::handleBeaconRequest()
{
    if (!answerBeacon_)
        return;
    // Run this on dedicated thread because some callbacks can take time
    dht::ThreadPool::io().run([w = parent_.weak()]() {
        if (auto shared = w.lock()) {
            msgpack::sbuffer buffer(8);
            msgpack::packer<msgpack::sbuffer> pk(&buffer);
            pk.pack(BeaconMsg {false});
            if (shared->pimpl_->logger_)
                shared->pimpl_->logger_->debug("[device {}] Send beacon response to peer", shared->deviceId());
            shared->pimpl_->writeProtocolMessage(buffer);
        }
    });
}

void
MultiplexedSocket::Impl::handleBeaconResponse()
{
    if (logger_)
        logger_->debug("[device {}] Get beacon response from peer", deviceId);
    beaconCounter_--;
}

bool
MultiplexedSocket::Impl::writeProtocolMessage(const msgpack::sbuffer& buffer)
{
    std::error_code ec;
    int wr = parent_.write(PROTOCOL_CHANNEL, (const unsigned char*) buffer.data(), buffer.size(), ec);
    return wr > 0;
}

void
MultiplexedSocket::Impl::sendVersion()
{
    dht::ThreadPool::io().run([w = parent_.weak()]() {
        if (auto shared = w.lock()) {
            auto version = shared->pimpl_->version_;
            msgpack::sbuffer buffer(8);
            msgpack::packer<msgpack::sbuffer> pk(&buffer);
            pk.pack(VersionMsg {version});
            shared->pimpl_->writeProtocolMessage(buffer);
        }
    });
}

void
MultiplexedSocket::Impl::onVersion(int version)
{
    // Check if version > 1
    if (version >= 1) {
        if (logger_)
            logger_->debug("[device {}] Peer supports beacon", deviceId);
        canSendBeacon_ = true;
    } else {
        if (logger_)
            logger_->warn("[device {}] Peer uses version {:d} which doesn't support beacon", deviceId, version);
        canSendBeacon_ = false;
    }
}

void
MultiplexedSocket::Impl::onRequest(const std::string& name, uint16_t channel)
{
    bool accept;
    if (channel == CONTROL_CHANNEL || channel == PROTOCOL_CHANNEL) {
        if (logger_)
            logger_->warn("[device {}] Channel {:d} is reserved, refusing request", deviceId, channel);
        accept = false;
    } else
        accept = onRequest_(endpoint->peerCertificate(), channel, name);

    std::shared_ptr<ChannelSocket> channelSocket;
    if (accept) {
        std::lock_guard lkSockets(socketsMutex);
        channelSocket = makeSocket(name, channel, false);
        if (not channelSocket) {
            if (logger_)
                logger_->error("[device {}] Channel {:d} already exists, refusing request", deviceId, channel);
            accept = false;
        }
    }

    // Answer to ChannelRequest if accepted
    ChannelRequest val;
    val.channel = channel;
    val.name = name;
    val.state = accept ? ChannelRequestState::ACCEPT : ChannelRequestState::DECLINE;
    msgpack::sbuffer buffer(512);
    msgpack::pack(buffer, val);
    std::error_code ec;
    int wr = parent_.write(CONTROL_CHANNEL, reinterpret_cast<const uint8_t*>(buffer.data()), buffer.size(), ec);
    if (wr < 0) {
        if (ec && logger_)
            logger_->error("[device {}] The write operation failed with error: {:s}", deviceId, ec.message());
        stop.store(true);
        return;
    }

    if (accept) {
        onChannelReady_(deviceId, channelSocket);
        channelSocket->ready(true);
        std::lock_guard lkSockets(socketsMutex);
        if (channelSocket->isRemovable()) {
            sockets.erase(channel);
        } else
            channelSocket->answered();
    }
}

void
MultiplexedSocket::Impl::handleControlPacket(std::vector<uint8_t>&& pkt)
{
    try {
        size_t off = 0;
        while (off != pkt.size()) {
            msgpack::unpacked result;
            msgpack::unpack(result, (const char*) pkt.data(), pkt.size(), off);
            auto object = result.get();
            if (handleProtocolMsg(object))
                continue;
            auto req = object.as<ChannelRequest>();
            if (req.state == ChannelRequestState::REQUEST) {
                dht::ThreadPool::io().run([w = parent_.weak(), req = std::move(req)]() {
                    if (auto shared = w.lock())
                        shared->pimpl_->onRequest(req.name, req.channel);
                });
            } else if (req.state == ChannelRequestState::ACCEPT) {
                onAccept(req.name, req.channel);
            } else {
                // DECLINE or unknown
                std::lock_guard lkSockets(socketsMutex);
                auto channel = sockets.find(req.channel);
                if (channel != sockets.end()) {
                    channel->second->ready(false);
                    channel->second->stop();
                    sockets.erase(channel);
                }
            }
        }
    } catch (const std::exception& e) {
        if (logger_)
            logger_->error("[device {}] Error on the control channel: {}", deviceId, e.what());
    }
}

void
MultiplexedSocket::Impl::handleChannelPacket(uint16_t channel, std::vector<uint8_t>&& pkt)
{
    std::lock_guard lkSockets(socketsMutex);
    auto sockIt = sockets.find(channel);
    if (channel > 0 && sockIt != sockets.end() && sockIt->second) {
        if (pkt.size() == 0) {
            sockIt->second->stop();
            if (sockIt->second->isAnswered())
                sockets.erase(sockIt);
            else
                sockIt->second->removable(); // This means that onAccept didn't happen yet, will be
                                             // removed later.
        } else {
            sockIt->second->onRecv(std::move(pkt));
        }
    } else if (pkt.size() != 0) {
        if (logger_)
            logger_->warn("[device {}] Message of size {} for non-existing channel: {}", deviceId, pkt.size(), channel);
    }
}

bool
MultiplexedSocket::Impl::handleProtocolMsg(const msgpack::object& o)
{
    try {
        if (o.type == msgpack::type::MAP && o.via.map.size > 0) {
            auto key = o.via.map.ptr[0].key.as<std::string_view>();
            if (key == "p") {
                auto msg = o.as<BeaconMsg>();
                if (msg.p)
                    handleBeaconRequest();
                else
                    handleBeaconResponse();
                if (onBeaconCb_)
                    onBeaconCb_(msg.p);
                return true;
            } else if (key == "v") {
                auto msg = o.as<VersionMsg>();
                onVersion(msg.v);
                if (onVersionCb_)
                    onVersionCb_(msg.v);
                return true;
            } else {
                if (logger_)
                    logger_->warn("[device {}] Unknown message type", deviceId);
            }
        }
    } catch (const std::exception& e) {
        if (logger_)
            logger_->error("[device {}] Error on the protocol channel: {}", deviceId, e.what());
    }
    return false;
}

void
MultiplexedSocket::Impl::handleProtocolPacket(std::vector<uint8_t>&& pkt)
{
    // Run this on dedicated thread because some callbacks can take time
    dht::ThreadPool::io().run([w = parent_.weak(), pkt = std::move(pkt)]() {
        auto shared = w.lock();
        if (!shared)
            return;
        try {
            size_t off = 0;
            while (off != pkt.size()) {
                msgpack::unpacked result;
                msgpack::unpack(result, (const char*) pkt.data(), pkt.size(), off);
                auto object = result.get();
                if (shared->pimpl_->handleProtocolMsg(object))
                    return;
            }
        } catch (const std::exception& e) {
            if (shared->pimpl_->logger_)
                shared->pimpl_->logger_->error("[device {}] Error on the protocol channel: {}",
                                               shared->pimpl_->deviceId,
                                               e.what());
        }
    });
}

MultiplexedSocket::MultiplexedSocket(std::shared_ptr<asio::io_context> ctx,
                                     const DeviceId& deviceId,
                                     std::unique_ptr<TlsSocketEndpoint> endpoint,
                                     std::shared_ptr<dht::log::Logger> logger)
    : pimpl_(std::make_unique<Impl>(*this, ctx, deviceId, std::move(endpoint), logger))
{}

MultiplexedSocket::~MultiplexedSocket() {}

std::shared_ptr<ChannelSocket>
MultiplexedSocket::addChannel(const std::string& name)
{
    std::lock_guard lk(pimpl_->socketsMutex);
    if (pimpl_->sockets.size() < UINT16_MAX)
        for (unsigned i = 0; i < UINT16_MAX; ++i) {
            auto c = pimpl_->nextChannel_++;
            if (c == CONTROL_CHANNEL || c == PROTOCOL_CHANNEL || pimpl_->sockets.find(c) != pimpl_->sockets.end())
                continue;
            return pimpl_->makeSocket(name, c, true);
        }
    return {};
}

DeviceId
MultiplexedSocket::deviceId() const
{
    return pimpl_->deviceId;
}

void
MultiplexedSocket::setOnReady(OnConnectionReadyCb&& cb)
{
    pimpl_->onChannelReady_ = std::move(cb);
}

void
MultiplexedSocket::setOnRequest(OnConnectionRequestCb&& cb)
{
    pimpl_->onRequest_ = std::move(cb);
}

bool
MultiplexedSocket::isReliable() const
{
    return true;
}

bool
MultiplexedSocket::isInitiator() const
{
    if (!pimpl_->endpoint) {
        if (pimpl_->logger_)
            pimpl_->logger_->warn("[device {}] No endpoint found for socket", pimpl_->deviceId);
        return false;
    }
    return pimpl_->endpoint->isInitiator();
}

int
MultiplexedSocket::maxPayload() const
{
    if (!pimpl_->endpoint) {
        if (pimpl_->logger_)
            pimpl_->logger_->warn("[device {}] No endpoint found for socket", pimpl_->deviceId);
        return 0;
    }
    return pimpl_->endpoint->maxPayload();
}

std::size_t
MultiplexedSocket::write(uint16_t channel, const uint8_t* buf, std::size_t len, std::error_code& ec)
{
    assert(nullptr != buf);

    if (pimpl_->isShutdown_) {
        ec = std::make_error_code(std::errc::broken_pipe);
        return -1;
    }
    if (len > UINT16_MAX) {
        ec = std::make_error_code(std::errc::message_size);
        return -1;
    }
    bool oneShot = len < 8192;
    msgpack::sbuffer buffer(oneShot ? 16 + len : 16);
    msgpack::packer<msgpack::sbuffer> pk(&buffer);
    pk.pack_array(2);
    pk.pack(channel);
    pk.pack_bin(len);
    if (oneShot)
        pk.pack_bin_body((const char*) buf, len);

    std::unique_lock lk(pimpl_->writeMtx);
    if (!pimpl_->endpoint) {
        if (pimpl_->logger_)
            pimpl_->logger_->warn("[device {}] No endpoint found for socket", pimpl_->deviceId);
        ec = std::make_error_code(std::errc::broken_pipe);
        return -1;
    }
    int res = pimpl_->endpoint->write((const unsigned char*) buffer.data(), buffer.size(), ec);
    if (not oneShot and res >= 0)
        res = pimpl_->endpoint->write(buf, len, ec);
    lk.unlock();
    if (res < 0) {
        if (ec && pimpl_->logger_)
            pimpl_->logger_->error("[device {}] Error when writing on socket: {:s}", pimpl_->deviceId, ec.message());
        shutdown();
    }
    return res;
}

void
MultiplexedSocket::shutdown()
{
    pimpl_->shutdown();
}

bool
MultiplexedSocket::isRunning() const
{
    return pimpl_->isRunning();
}

void
MultiplexedSocket::join()
{
    pimpl_->join();
}

void
MultiplexedSocket::onShutdown(OnShutdownCb&& cb)
{
    std::unique_lock lk {pimpl_->stateMutex};
    if (pimpl_->isShutdown_) {
        lk.unlock();
        cb();
    } else {
        pimpl_->onShutdown_ = std::move(cb);
    }
}

const std::shared_ptr<Logger>&
MultiplexedSocket::logger()
{
    return pimpl_->logger_;
}

void
MultiplexedSocket::monitor() const
{
    auto cert = peerCertificate();
    if (!cert || !cert->issuer)
        return;
    auto now = clock::now();
    if (!pimpl_->logger_)
        return;
    pimpl_->logger_->debug("- Socket with device: {:s} - account: {:s}", deviceId(), cert->issuer->getId());
    pimpl_->logger_->debug("- Duration: {}", dht::print_duration(now - pimpl_->start_));
    pimpl_->endpoint->monitor();
    std::lock_guard lk(pimpl_->socketsMutex);
    for (const auto& [_, channel] : pimpl_->sockets) {
        if (channel)
            pimpl_->logger_->debug("\t\t- Channel {} (count: {}) with name {:s} Initiator: {}",
                                   fmt::ptr(channel.get()),
                                   channel.use_count(),
                                   channel->name(),
                                   channel->isInitiator());
    }
}

void
MultiplexedSocket::sendBeacon(const std::chrono::milliseconds& timeout)
{
    pimpl_->sendBeacon(timeout);
}

std::shared_ptr<dht::crypto::Certificate>
MultiplexedSocket::peerCertificate() const
{
    return pimpl_->endpoint->peerCertificate();
}

#ifdef DHTNET_TESTABLE
bool
MultiplexedSocket::canSendBeacon() const
{
    return pimpl_->canSendBeacon_;
}

void
MultiplexedSocket::answerToBeacon(bool value)
{
    pimpl_->answerBeacon_ = value;
}

void
MultiplexedSocket::setVersion(int version)
{
    pimpl_->version_ = version;
}

void
MultiplexedSocket::setOnBeaconCb(const std::function<void(bool)>& cb)
{
    pimpl_->onBeaconCb_ = cb;
}

void
MultiplexedSocket::setOnVersionCb(const std::function<void(int)>& cb)
{
    pimpl_->onVersionCb_ = cb;
}

void
MultiplexedSocket::sendVersion()
{
    pimpl_->sendVersion();
}

#endif

IpAddr
MultiplexedSocket::getLocalAddress() const
{
    return pimpl_->endpoint->getLocalAddress();
}

IpAddr
MultiplexedSocket::getRemoteAddress() const
{
    return pimpl_->endpoint->getRemoteAddress();
}

TlsSocketEndpoint*
MultiplexedSocket::endpoint()
{
    return pimpl_->endpoint.get();
}

void
MultiplexedSocket::eraseChannel(uint16_t channel)
{
    std::lock_guard lkSockets(pimpl_->socketsMutex);
    auto itSocket = pimpl_->sockets.find(channel);
    if (itSocket != pimpl_->sockets.end())
        pimpl_->sockets.erase(itSocket);
}


std::vector<std::map<std::string, std::string>>
MultiplexedSocket::getChannelList() const
{
    std::lock_guard lkSockets(pimpl_->socketsMutex);
    std::vector<std::map<std::string, std::string>> channelsList;
    channelsList.reserve(pimpl_->sockets.size());
    for (const auto& [_, channel] : pimpl_->sockets) {
        channelsList.emplace_back(std::map<std::string, std::string> {
            {"id", fmt::format("{:x}", channel->channel())},
            {"name", channel->name()},
        });
    }
    return channelsList;
}

} // namespace dhtnet
