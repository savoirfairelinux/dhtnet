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
#include "connectionmanager.h"
#include "peer_connection.h"
#include "upnp/upnp_control.h"
#include "certstore.h"
#include "fileutils.h"
#include "sip_utils.h"
#include "string_utils.h"

#include <opendht/crypto.h>
#include <opendht/thread_pool.h>
#include <opendht/value.h>
#include <asio.hpp>

#include <algorithm>
#include <mutex>
#include <map>
#include <condition_variable>
#include <set>
#include <charconv>
#include <fstream>

namespace dhtnet {
static constexpr std::chrono::seconds DHT_MSG_TIMEOUT {30};
static constexpr uint64_t ID_MAX_VAL = 9007199254740992;

using ValueIdDist = std::uniform_int_distribution<dht::Value::Id>;
using CallbackId = std::pair<dhtnet::DeviceId, dht::Value::Id>;
std::string
callbackIdToString(const dhtnet::DeviceId& did, const dht::Value::Id& vid)
{
    return fmt::format("{} {}", did.to_view(), vid);
}

CallbackId parseCallbackId(std::string_view ci)
{
    auto sep = ci.find(' ');
    std::string_view deviceIdString = ci.substr(0, sep);
    std::string_view vidString = ci.substr(sep + 1);

    dhtnet::DeviceId deviceId(deviceIdString);
    dht::Value::Id vid = std::stoul(std::string(vidString), nullptr, 10);

    return CallbackId(deviceId, vid);
}
struct ConnectionInfo
{
    ~ConnectionInfo()
    {
        if (socket_)
            socket_->join();
    }

    std::mutex mutex_ {};
    bool responseReceived_ {false};
    PeerConnectionRequest response_ {};
    std::unique_ptr<IceTransport> ice_ {nullptr};
    // Used to store currently non ready TLS Socket
    std::unique_ptr<TlsSocketEndpoint> tls_ {nullptr};
    std::shared_ptr<MultiplexedSocket> socket_ {};
    std::set<CallbackId> cbIds_ {};

    std::function<void(bool)> onConnected_;
    std::unique_ptr<asio::steady_timer> waitForAnswer_ {};
};

/**
 * returns whether or not UPnP is enabled and active_
 * ie: if it is able to make port mappings
 */
bool
ConnectionManager::Config::getUPnPActive() const
{
    if (upnpCtrl)
        return upnpCtrl->isReady();
    return false;
}

class ConnectionManager::Impl : public std::enable_shared_from_this<ConnectionManager::Impl>
{
public:
    explicit Impl(std::shared_ptr<ConnectionManager::Config> config_)
        : config_ {std::move(config_)}
        , rand {dht::crypto::getSeededRandomEngine<std::mt19937_64>()}
    {}
    ~Impl() {}

    std::shared_ptr<dht::DhtRunner> dht() { return config_->dht; }
    const dht::crypto::Identity& identity() const { return config_->id; }

    void removeUnusedConnections(const DeviceId& deviceId = {})
    {
        std::vector<std::shared_ptr<ConnectionInfo>> unused {};

        {
            std::lock_guard<std::mutex> lk(infosMtx_);
            for (auto it = infos_.begin(); it != infos_.end();) {
                auto& [key, info] = *it;
                if (info && (!deviceId || key.first == deviceId)) {
                    unused.emplace_back(std::move(info));
                    it = infos_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& info: unused) {
            if (info->tls_)
                info->tls_->shutdown();
            if (info->socket_)
                info->socket_->shutdown();
            if (info->waitForAnswer_)
                info->waitForAnswer_->cancel();
        }
        if (!unused.empty())
            dht::ThreadPool::io().run([infos = std::move(unused)]() mutable { infos.clear(); });
    }

    void shutdown()
    {
        if (isDestroying_.exchange(true))
            return;
        decltype(pendingOperations_) po;
        {
            std::lock_guard<std::mutex> lk(connectCbsMtx_);
            po = std::move(pendingOperations_);
        }
        for (auto& [deviceId, pcbs] : po) {
            for (auto& [id, pending] : pcbs.connecting)
                pending.cb(nullptr, deviceId);
            for (auto& [id, pending] : pcbs.waiting)
                pending.cb(nullptr, deviceId);
        }

        removeUnusedConnections();
    }

    void connectDeviceStartIce(const std::shared_ptr<dht::crypto::PublicKey>& devicePk,
                               const dht::Value::Id& vid,
                               const std::string& connType,
                               std::function<void(bool)> onConnected);
    void onResponse(const asio::error_code& ec, const DeviceId& deviceId, const dht::Value::Id& vid);
    bool connectDeviceOnNegoDone(const DeviceId& deviceId,
                                 const std::string& name,
                                 const dht::Value::Id& vid,
                                 const std::shared_ptr<dht::crypto::Certificate>& cert);
    void connectDevice(const DeviceId& deviceId,
                       const std::string& uri,
                       ConnectCallback cb,
                       bool noNewSocket = false,
                       bool forceNewSocket = false,
                       const std::string& connType = "");
    void connectDevice(const dht::InfoHash& deviceId,
                       const std::string& uri,
                       ConnectCallbackLegacy cb,
                       bool noNewSocket = false,
                       bool forceNewSocket = false,
                       const std::string& connType = "");

    void connectDevice(const std::shared_ptr<dht::crypto::Certificate>& cert,
                       const std::string& name,
                       ConnectCallback cb,
                       bool noNewSocket = false,
                       bool forceNewSocket = false,
                       const std::string& connType = "");
    /**
     * Send a ChannelRequest on the TLS socket. Triggers cb when ready
     * @param sock      socket used to send the request
     * @param name      channel's name
     * @param vid       channel's id
     * @param deviceId  to identify the linked ConnectCallback
     */
    void sendChannelRequest(std::shared_ptr<MultiplexedSocket>& sock,
                            const std::string& name,
                            const DeviceId& deviceId,
                            const dht::Value::Id& vid);
    /**
     * Triggered when a PeerConnectionRequest comes from the DHT
     */
    void answerTo(IceTransport& ice,
                  const dht::Value::Id& id,
                  const std::shared_ptr<dht::crypto::PublicKey>& fromPk);
    bool onRequestStartIce(const PeerConnectionRequest& req);
    bool onRequestOnNegoDone(const PeerConnectionRequest& req);
    void onDhtPeerRequest(const PeerConnectionRequest& req,
                          const std::shared_ptr<dht::crypto::Certificate>& cert);

    void addNewMultiplexedSocket(const CallbackId& id, const std::shared_ptr<ConnectionInfo>& info);
    void onPeerResponse(const PeerConnectionRequest& req);
    void onDhtConnected(const dht::crypto::PublicKey& devicePk);

    const std::shared_future<tls::DhParams> dhParams() const;
    tls::CertificateStore& certStore() const { return *config_->certStore; }

    mutable std::mutex messageMutex_ {};
    std::set<std::string, std::less<>> treatedMessages_ {};

    void loadTreatedMessages();
    void saveTreatedMessages() const;

    /// \return true if the given DHT message identifier has been treated
    /// \note if message has not been treated yet this method st/ore this id and returns true at
    /// further calls
    bool isMessageTreated(std::string_view id);

    const std::shared_ptr<dht::log::Logger>& logger() const { return config_->logger; }

    /**
     * Published IPv4/IPv6 addresses, used only if defined by the user in account
     * configuration
     *
     */
    IpAddr publishedIp_[2] {};

    /**
     * interface name on which this account is bound
     */
    std::string interface_ {"default"};

    /**
     * Get the local interface name on which this account is bound.
     */
    const std::string& getLocalInterface() const { return interface_; }

    /**
     * Get the published IP address, fallbacks to NAT if family is unspecified
     * Prefers the usage of IPv4 if possible.
     */
    IpAddr getPublishedIpAddress(uint16_t family = PF_UNSPEC) const;

    /**
     * Set published IP address according to given family
     */
    void setPublishedAddress(const IpAddr& ip_addr);

    /**
     * Store the local/public addresses used to register
     */
    void storeActiveIpAddress(std::function<void()>&& cb = {});

    /**
     * Create and return ICE options.
     */
    void getIceOptions(std::function<void(IceTransportOptions&&)> cb) noexcept;
    IceTransportOptions getIceOptions() const noexcept;

    /**
     * Inform that a potential peer device have been found.
     * Returns true only if the device certificate is a valid device certificate.
     * In that case (true is returned) the account_id parameter is set to the peer account ID.
     */
    static bool foundPeerDevice(const std::shared_ptr<dht::crypto::Certificate>& crt,
                                dht::InfoHash& account_id, const std::shared_ptr<Logger>& logger);

    bool findCertificate(const dht::PkId& id,
                         std::function<void(const std::shared_ptr<dht::crypto::Certificate>&)>&& cb);
    bool findCertificate(const dht::InfoHash& h, std::function<void(const std::shared_ptr<dht::crypto::Certificate>&)>&& cb);

    /**
     * returns whether or not UPnP is enabled and active
     * ie: if it is able to make port mappings
     */
    bool getUPnPActive() const;

    /**
     * Triggered when a new TLS socket is ready to use
     * @param ok        If succeed
     * @param deviceId  Related device
     * @param vid       vid of the connection request
     * @param name      non empty if TLS was created by connectDevice()
     */
    void onTlsNegotiationDone(bool ok,
                              const DeviceId& deviceId,
                              const dht::Value::Id& vid,
                              const std::string& name = "");

    std::shared_ptr<ConnectionManager::Config> config_;

    mutable std::mt19937_64 rand;

    iOSConnectedCallback iOSConnectedCb_ {};

    std::mutex infosMtx_ {};
    // Note: Someone can ask multiple sockets, so to avoid any race condition,
    // each device can have multiple multiplexed sockets.
    std::map<CallbackId, std::shared_ptr<ConnectionInfo>> infos_ {};

    std::shared_ptr<ConnectionInfo> getInfo(const DeviceId& deviceId, const dht::Value::Id& id)
    {
        std::lock_guard<std::mutex> lk(infosMtx_);
        auto it = infos_.find({deviceId, id});
        if (it != infos_.end())
            return it->second;
        return {};
    }

    std::shared_ptr<ConnectionInfo> getConnectedInfo(const DeviceId& deviceId)
    {
        std::lock_guard<std::mutex> lk(infosMtx_);
        auto it = std::find_if(infos_.begin(), infos_.end(), [&](const auto& item) {
            auto& [key, value] = item;
            return key.first == deviceId && value && value->socket_;
        });
        if (it != infos_.end())
            return it->second;
        return {};
    }

    ChannelRequestCallback channelReqCb_ {};
    ConnectionReadyCallback connReadyCb_ {};
    onICERequestCallback iceReqCb_ {};

    /**
     * Stores callback from connectDevice
     * @note: each device needs a vector because several connectDevice can
     * be done in parallel and we only want one socket
     */
    std::mutex connectCbsMtx_ {};

    struct PendingCb
    {
        std::string name;
        ConnectCallback cb;
    };
    struct PendingOperations {
        std::map<dht::Value::Id, PendingCb> connecting;
        std::map<dht::Value::Id, PendingCb> waiting;
    };

    std::map<DeviceId, PendingOperations> pendingOperations_ {};

    void executePendingOperations(const DeviceId& deviceId, const dht::Value::Id& vid, const std::shared_ptr<ChannelSocket>& sock, bool accepted = true)
    {
        std::vector<PendingCb> ret;
        std::unique_lock<std::mutex> lk(connectCbsMtx_);
        auto it = pendingOperations_.find(deviceId);
        if (it == pendingOperations_.end())
            return;
        auto& pendingOperations = it->second;
        if (vid == 0) {
            // Extract all pending callbacks
            for (auto& [vid, cb] : pendingOperations.connecting)
                ret.emplace_back(std::move(cb));
            pendingOperations.connecting.clear();
            for (auto& [vid, cb] : pendingOperations.waiting)
                ret.emplace_back(std::move(cb));
            pendingOperations.waiting.clear();
        } else if (auto n = pendingOperations.waiting.extract(vid)) {
            // If it's a waiting operation, just move it
            ret.emplace_back(std::move(n.mapped()));
        } else if (auto n = pendingOperations.connecting.extract(vid)) {
            ret.emplace_back(std::move(n.mapped()));
            // If sock is nullptr, execute if it's the last connecting operation
            // If accepted is false, it means that underlying socket is ok, but channel is declined
            if (!sock && pendingOperations.connecting.empty() && accepted) {
                for (auto& [vid, cb] : pendingOperations.waiting)
                    ret.emplace_back(std::move(cb));
                pendingOperations.waiting.clear();
                for (auto& [vid, cb] : pendingOperations.connecting)
                    ret.emplace_back(std::move(cb));
                pendingOperations.connecting.clear();
            }
        }
        if (pendingOperations.waiting.empty() && pendingOperations.connecting.empty())
            pendingOperations_.erase(it);
        lk.unlock();
        for (auto& cb : ret)
            cb.cb(sock, deviceId);
    }

    std::map<dht::Value::Id, std::string> getPendingIds(const DeviceId& deviceId, const dht::Value::Id vid = 0)
    {
        std::map<dht::Value::Id, std::string> ret;
        std::lock_guard<std::mutex> lk(connectCbsMtx_);
        auto it = pendingOperations_.find(deviceId);
        if (it == pendingOperations_.end())
            return ret;
        auto& pendingOp = it->second;
        for (const auto& [id, pc]: pendingOp.connecting) {
            if (vid == 0 || id == vid)
                ret[id] = pc.name;
        }
        for (const auto& [id, pc]: pendingOp.waiting) {
            if (vid == 0 || id == vid)
                ret[id] = pc.name;
        }
        return ret;
    }

    std::shared_ptr<ConnectionManager::Impl> shared()
    {
        return std::static_pointer_cast<ConnectionManager::Impl>(shared_from_this());
    }
    std::shared_ptr<ConnectionManager::Impl const> shared() const
    {
        return std::static_pointer_cast<ConnectionManager::Impl const>(shared_from_this());
    }
    std::weak_ptr<ConnectionManager::Impl> weak()
    {
        return std::static_pointer_cast<ConnectionManager::Impl>(shared_from_this());
    }
    std::weak_ptr<ConnectionManager::Impl const> weak() const
    {
        return std::static_pointer_cast<ConnectionManager::Impl const>(shared_from_this());
    }

    std::atomic_bool isDestroying_ {false};
};

void
ConnectionManager::Impl::connectDeviceStartIce(
    const std::shared_ptr<dht::crypto::PublicKey>& devicePk,
    const dht::Value::Id& vid,
    const std::string& connType,
    std::function<void(bool)> onConnected)
{
    auto deviceId = devicePk->getLongId();
    auto info = getInfo(deviceId, vid);
    if (!info) {
        onConnected(false);
        return;
    }

    std::unique_lock<std::mutex> lk(info->mutex_);
    auto& ice = info->ice_;

    if (!ice) {
        if (config_->logger)
            config_->logger->error("[device {}] No ICE detected", deviceId);
        onConnected(false);
        return;
    }

    auto iceAttributes = ice->getLocalAttributes();
    std::ostringstream icemsg;
    icemsg << iceAttributes.ufrag << "\n";
    icemsg << iceAttributes.pwd << "\n";
    for (const auto& addr : ice->getLocalCandidates(1)) {
        icemsg << addr << "\n";
        if (config_->logger)
            config_->logger->debug("[device {}] Added local ICE candidate {}", deviceId, addr);
    }

    // Prepare connection request as a DHT message
    PeerConnectionRequest val;

    val.id = vid; /* Random id for the message unicity */
    val.ice_msg = icemsg.str();
    val.connType = connType;

    auto value = std::make_shared<dht::Value>(std::move(val));
    value->user_type = "peer_request";

    // Send connection request through DHT
    if (config_->logger)
        config_->logger->debug("[device {}] Sending connection request", deviceId);
    dht()->putEncrypted(dht::InfoHash::get(PeerConnectionRequest::key_prefix
                                           + devicePk->getId().toString()),
                        devicePk,
                        value,
                        [l=config_->logger,deviceId](bool ok) {
                            if (l)
                                l->debug("[device {}] Sent connection request. Put encrypted {:s}",
                                       deviceId,
                                       (ok ? "ok" : "failed"));
                        });
    // Wait for call to onResponse() operated by DHT
    if (isDestroying_) {
        onConnected(true); // This avoid to wait new negotiation when destroying
        return;
    }

    info->onConnected_ = std::move(onConnected);
    info->waitForAnswer_ = std::make_unique<asio::steady_timer>(*config_->ioContext,
                                                                std::chrono::steady_clock::now()
                                                                    + DHT_MSG_TIMEOUT);
    info->waitForAnswer_->async_wait(
        std::bind(&ConnectionManager::Impl::onResponse, this, std::placeholders::_1, deviceId, vid));
}

void
ConnectionManager::Impl::onResponse(const asio::error_code& ec,
                                    const DeviceId& deviceId,
                                    const dht::Value::Id& vid)
{
    if (ec == asio::error::operation_aborted)
        return;
    auto info = getInfo(deviceId, vid);
    if (!info)
        return;

    std::unique_lock<std::mutex> lk(info->mutex_);
    auto& ice = info->ice_;
    if (isDestroying_) {
        info->onConnected_(true); // The destructor can wake a pending wait here.
        return;
    }
    if (!info->responseReceived_) {
        if (config_->logger)
            config_->logger->error("[device {}] no response from DHT to ICE request.", deviceId);
        info->onConnected_(false);
        return;
    }

    if (!info->ice_) {
        info->onConnected_(false);
        return;
    }

    auto sdp = ice->parseIceCandidates(info->response_.ice_msg);

    if (not ice->startIce({sdp.rem_ufrag, sdp.rem_pwd}, std::move(sdp.rem_candidates))) {
        if (config_->logger)
            config_->logger->warn("[device {}] start ICE failed", deviceId);
        info->onConnected_(false);
        return;
    }
    info->onConnected_(true);
}

bool
ConnectionManager::Impl::connectDeviceOnNegoDone(
    const DeviceId& deviceId,
    const std::string& name,
    const dht::Value::Id& vid,
    const std::shared_ptr<dht::crypto::Certificate>& cert)
{
    auto info = getInfo(deviceId, vid);
    if (!info)
        return false;

    std::unique_lock<std::mutex> lk {info->mutex_};
    if (info->waitForAnswer_) {
        // Negotiation is done and connected, go to handshake
        // and avoid any cancellation at this point.
        info->waitForAnswer_->cancel();
    }
    auto& ice = info->ice_;
    if (!ice || !ice->isRunning()) {
        if (config_->logger)
            config_->logger->error("[device {}] No ICE detected or not running", deviceId);
        return false;
    }

    // Build socket
    auto endpoint = std::make_unique<IceSocketEndpoint>(std::shared_ptr<IceTransport>(
                                                            std::move(ice)),
                                                        true);

    // Negotiate a TLS session
    if (config_->logger)
        config_->logger->debug("[device {}] Start TLS session - Initied by connectDevice(). Launched by channel: {} - vid: {}", deviceId, name, vid);
    info->tls_ = std::make_unique<TlsSocketEndpoint>(std::move(endpoint),
                                                     certStore(),
                                                     config_->ioContext,
                                                     identity(),
                                                     dhParams(),
                                                     *cert);

    info->tls_->setOnReady(
        [w = weak(), deviceId = std::move(deviceId), vid = std::move(vid), name = std::move(name)](
            bool ok) {
            if (auto shared = w.lock())
                shared->onTlsNegotiationDone(ok, deviceId, vid, name);
        });
    return true;
}

void
ConnectionManager::Impl::connectDevice(const DeviceId& deviceId,
                                       const std::string& name,
                                       ConnectCallback cb,
                                       bool noNewSocket,
                                       bool forceNewSocket,
                                       const std::string& connType)
{
    if (!dht()) {
        cb(nullptr, deviceId);
        return;
    }
    if (deviceId.toString() == identity().second->getLongId().toString()) {
        cb(nullptr, deviceId);
        return;
    }
    findCertificate(deviceId,
                    [w = weak(),
                     deviceId,
                     name,
                     cb = std::move(cb),
                     noNewSocket,
                     forceNewSocket,
                     connType](const std::shared_ptr<dht::crypto::Certificate>& cert) {
                        if (!cert) {
                            if (auto shared = w.lock())
                                if (shared->config_->logger)
                                    shared->config_->logger->error(
                                        "No valid certificate found for device {}",
                                        deviceId);
                            cb(nullptr, deviceId);
                            return;
                        }
                        if (auto shared = w.lock()) {
                            shared->connectDevice(cert,
                                                  name,
                                                  std::move(cb),
                                                  noNewSocket,
                                                  forceNewSocket,
                                                  connType);
                        } else
                            cb(nullptr, deviceId);
                    });
}

void
ConnectionManager::Impl::connectDevice(const dht::InfoHash& deviceId,
                                       const std::string& name,
                                       ConnectCallbackLegacy cb,
                                       bool noNewSocket,
                                       bool forceNewSocket,
                                       const std::string& connType)
{
    if (!dht()) {
        cb(nullptr, deviceId);
        return;
    }
    if (deviceId.toString() == identity().second->getLongId().toString()) {
        cb(nullptr, deviceId);
        return;
    }
    findCertificate(deviceId,
                    [w = weak(),
                     deviceId,
                     name,
                     cb = std::move(cb),
                     noNewSocket,
                     forceNewSocket,
                     connType](const std::shared_ptr<dht::crypto::Certificate>& cert) {
                        if (!cert) {
                            if (auto shared = w.lock())
                                if (shared->config_->logger)
                                    shared->config_->logger->error(
                                        "No valid certificate found for device {}",
                                        deviceId);
                            cb(nullptr, deviceId);
                            return;
                        }
                        if (auto shared = w.lock()) {
                            shared->connectDevice(cert,
                                                  name,
                                                  [cb, deviceId](const std::shared_ptr<ChannelSocket>& sock, const DeviceId& did){
                                                     cb(sock, deviceId);
                                                  },
                                                  noNewSocket,
                                                  forceNewSocket,
                                                  connType);
                        } else
                            cb(nullptr, deviceId);
                    });
}

void
ConnectionManager::Impl::connectDevice(const std::shared_ptr<dht::crypto::Certificate>& cert,
                                       const std::string& name,
                                       ConnectCallback cb,
                                       bool noNewSocket,
                                       bool forceNewSocket,
                                       const std::string& connType)
{
    // Avoid dht operation in a DHT callback to avoid deadlocks
    dht::ThreadPool::computation().run([w = weak(),
                     name = std::move(name),
                     cert = std::move(cert),
                     cb = std::move(cb),
                     noNewSocket,
                     forceNewSocket,
                     connType] {
        auto devicePk = cert->getSharedPublicKey();
        auto deviceId = devicePk->getLongId();
        auto sthis = w.lock();
        if (!sthis || sthis->isDestroying_) {
            cb(nullptr, deviceId);
            return;
        }
        dht::Value::Id vid = ValueIdDist(1, ID_MAX_VAL)(sthis->rand);
        auto isConnectingToDevice = false;
        {
            std::lock_guard<std::mutex> lk(sthis->connectCbsMtx_);
            auto pendingsIt = sthis->pendingOperations_.find(deviceId);
            if (pendingsIt != sthis->pendingOperations_.end()) {
                const auto& pendings = pendingsIt->second;
                while (pendings.connecting.find(vid) != pendings.connecting.end()
                       && pendings.waiting.find(vid) != pendings.waiting.end()) {
                    vid = ValueIdDist(1, ID_MAX_VAL)(sthis->rand);
                }
            }
            // Check if already connecting
            isConnectingToDevice = pendingsIt != sthis->pendingOperations_.end();
            // Save current request for sendChannelRequest.
            // Note: do not return here, cause we can be in a state where first
            // socket is negotiated and first channel is pending
            // so return only after we checked the info
            if (isConnectingToDevice && !forceNewSocket)
                pendingsIt->second.waiting[vid] = PendingCb {name, std::move(cb)};
            else
                sthis->pendingOperations_[deviceId].connecting[vid] = PendingCb {name, std::move(cb)};
        }

        // Check if already negotiated
        CallbackId cbId(deviceId, vid);
        if (auto info = sthis->getConnectedInfo(deviceId)) {
            std::lock_guard<std::mutex> lk(info->mutex_);
            if (info->socket_) {
                if (sthis->config_->logger)
                    sthis->config_->logger->debug("[device {}] Peer already connected. Add a new channel", deviceId);
                info->cbIds_.emplace(cbId);
                sthis->sendChannelRequest(info->socket_, name, deviceId, vid);
                return;
            }
        }

        if (isConnectingToDevice && !forceNewSocket) {
            if (sthis->config_->logger)
                sthis->config_->logger->debug("[device {}] Already connecting, wait for ICE negotiation", deviceId);
            return;
        }
        if (noNewSocket) {
            // If no new socket is specified, we don't try to generate a new socket
            sthis->executePendingOperations(deviceId, vid, nullptr);
            return;
        }

        // Note: used when the ice negotiation fails to erase
        // all stored structures.
        auto eraseInfo = [w, cbId] {
            if (auto shared = w.lock()) {
                // If no new socket is specified, we don't try to generate a new socket
                shared->executePendingOperations(cbId.first, cbId.second, nullptr);
                std::lock_guard<std::mutex> lk(shared->infosMtx_);
                shared->infos_.erase(cbId);
            }
        };

        // If no socket exists, we need to initiate an ICE connection.
        sthis->getIceOptions([w,
                              deviceId = std::move(deviceId),
                              devicePk = std::move(devicePk),
                              name = std::move(name),
                              cert = std::move(cert),
                              vid,
                              connType,
                              eraseInfo](auto&& ice_config) {
            auto sthis = w.lock();
            if (!sthis) {
                dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
                return;
            }
            ice_config.tcpEnable = true;
            ice_config.onInitDone = [w,
                                     deviceId = std::move(deviceId),
                                     devicePk = std::move(devicePk),
                                     name = std::move(name),
                                     cert = std::move(cert),
                                     vid,
                                     connType,
                                     eraseInfo](bool ok) {
                dht::ThreadPool::io().run([w = std::move(w),
                                           devicePk = std::move(devicePk),
                                           vid = std::move(vid),
                                           eraseInfo,
                                           connType, ok] {
                    auto sthis = w.lock();
                    if (!ok && sthis && sthis->config_->logger)
                        sthis->config_->logger->error("[device {}] Cannot initialize ICE session.", devicePk->getLongId());
                    if (!sthis || !ok) {
                        eraseInfo();
                        return;
                    }
                    sthis->connectDeviceStartIce(devicePk, vid, connType, [=](bool ok) {
                        if (!ok) {
                            dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
                        }
                    });
                });
            };
            ice_config.onNegoDone = [w,
                    deviceId,
                    name,
                     cert = std::move(cert),
                     vid,
                     eraseInfo](bool ok) {
                dht::ThreadPool::io().run([w = std::move(w),
                                           deviceId = std::move(deviceId),
                                           name = std::move(name),
                                           cert = std::move(cert),
                                           vid = std::move(vid),
                                           eraseInfo = std::move(eraseInfo),
                                           ok] {
                    auto sthis = w.lock();
                    if (!ok && sthis && sthis->config_->logger)
                        sthis->config_->logger->error("[device {}] ICE negotiation failed.", deviceId);
                    if (!sthis || !ok || !sthis->connectDeviceOnNegoDone(deviceId, name, vid, cert))
                        eraseInfo();
                });
            };

            auto info = std::make_shared<ConnectionInfo>();
            {
                std::lock_guard<std::mutex> lk(sthis->infosMtx_);
                sthis->infos_[{deviceId, vid}] = info;
            }
            std::unique_lock<std::mutex> lk {info->mutex_};
            ice_config.master = false;
            ice_config.streamsCount = 1;
            ice_config.compCountPerStream = 1;
            info->ice_ = sthis->config_->factory->createUTransport("");
            if (!info->ice_) {
                if (sthis->config_->logger)
                    sthis->config_->logger->error("[device {}] Cannot initialize ICE session.", deviceId);
                eraseInfo();
                return;
            }
            // We need to detect any shutdown if the ice session is destroyed before going to the
            // TLS session;
            info->ice_->setOnShutdown([eraseInfo]() {
                dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
            });
            try {
                info->ice_->initIceInstance(ice_config);
            } catch (const std::exception& e) {
                if (sthis->config_->logger)
                    sthis->config_->logger->error("{}", e.what());
                dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
            }
        });
    });
}

void
ConnectionManager::Impl::sendChannelRequest(std::shared_ptr<MultiplexedSocket>& sock,
                                            const std::string& name,
                                            const DeviceId& deviceId,
                                            const dht::Value::Id& vid)
{
    auto channelSock = sock->addChannel(name);
    channelSock->onShutdown([name, deviceId, vid, w = weak()] {
        auto shared = w.lock();
        if (auto shared = w.lock())
            shared->executePendingOperations(deviceId, vid, nullptr);
    });
    channelSock->onReady(
        [wSock = std::weak_ptr<ChannelSocket>(channelSock), name, deviceId, vid, w = weak()](bool accepted) {
            auto shared = w.lock();
            auto channelSock = wSock.lock();
            if (shared)
                shared->executePendingOperations(deviceId, vid, accepted ? channelSock : nullptr, accepted);
        });

    ChannelRequest val;
    val.name = channelSock->name();
    val.state = ChannelRequestState::REQUEST;
    val.channel = channelSock->channel();
    msgpack::sbuffer buffer(256);
    msgpack::pack(buffer, val);

    std::error_code ec;
    int res = sock->write(CONTROL_CHANNEL,
                          reinterpret_cast<const uint8_t*>(buffer.data()),
                          buffer.size(),
                          ec);
    if (res < 0) {
        // TODO check if we should handle errors here
        if (config_->logger)
            config_->logger->error("[device {}] sendChannelRequest failed - error: {}", deviceId, ec.message());
    }
}

void
ConnectionManager::Impl::onPeerResponse(const PeerConnectionRequest& req)
{
    auto device = req.owner->getLongId();
    if (auto info = getInfo(device, req.id)) {
        if (config_->logger)
            config_->logger->debug("[device {}] New response received", device);
        std::lock_guard<std::mutex> lk {info->mutex_};
        info->responseReceived_ = true;
        info->response_ = std::move(req);
        info->waitForAnswer_->expires_at(std::chrono::steady_clock::now());
        info->waitForAnswer_->async_wait(std::bind(&ConnectionManager::Impl::onResponse,
                                                   this,
                                                   std::placeholders::_1,
                                                   device,
                                                   req.id));
    } else {
        if (config_->logger)
            config_->logger->warn("[device {}] Respond received, but cannot find request", device);
    }
}

void
ConnectionManager::Impl::onDhtConnected(const dht::crypto::PublicKey& devicePk)
{
    if (!dht())
        return;
    dht()->listen<PeerConnectionRequest>(
        dht::InfoHash::get(PeerConnectionRequest::key_prefix + devicePk.getId().toString()),
        [w = weak()](PeerConnectionRequest&& req) {
            auto shared = w.lock();
            if (!shared)
                return false;
            if (shared->isMessageTreated(to_hex_string(req.id))) {
                // Message already treated. Just ignore
                return true;
            }
            if (req.isAnswer) {
                if (shared->config_->logger)
                    shared->config_->logger->debug("[device {}] Received request answer", req.owner->getLongId());
            } else {
                if (shared->config_->logger)
                    shared->config_->logger->debug("[device {}] Received request", req.owner->getLongId());
            }
            if (req.isAnswer) {
                shared->onPeerResponse(req);
            } else {
                // Async certificate checking
                shared->findCertificate(
                    req.from,
                    [w, req = std::move(req)](
                        const std::shared_ptr<dht::crypto::Certificate>& cert) mutable {
                        auto shared = w.lock();
                        if (!shared)
                            return;
                        dht::InfoHash peer_h;
                        if (foundPeerDevice(cert, peer_h, shared->config_->logger)) {
#if TARGET_OS_IOS
                            if (shared->iOSConnectedCb_(req.connType, peer_h))
                                return;
#endif
                            shared->onDhtPeerRequest(req, cert);
                        } else {
                            if (shared->config_->logger)
                                shared->config_->logger->warn(
                                    "[device {}] Received request from untrusted peer",
                                    req.owner->getLongId());
                        }
                    });
            }

            return true;
        },
        dht::Value::UserTypeFilter("peer_request"));
}

void
ConnectionManager::Impl::onTlsNegotiationDone(bool ok,
                                              const DeviceId& deviceId,
                                              const dht::Value::Id& vid,
                                              const std::string& name)
{
    if (isDestroying_)
        return;
    // Note: only handle pendingCallbacks here for TLS initied by connectDevice()
    // Note: if not initied by connectDevice() the channel name will be empty (because no channel
    // asked yet)
    auto isDhtRequest = name.empty();
    if (!ok) {
        if (isDhtRequest) {
            if (config_->logger)
                config_->logger->error("[device {}] TLS connection failure - Initied by DHT request. channel: {} - vid: {}",
                                       deviceId,
                                       name,
                                       vid);
            if (connReadyCb_)
                connReadyCb_(deviceId, "", nullptr);
        } else {
            if (config_->logger)
                config_->logger->error("[device {}] TLS connection failure - Initied by connectDevice. channel: {} - vid: {}",
                                       deviceId,
                                       name,
                                       vid);
            executePendingOperations(deviceId, vid, nullptr);
        }
    } else {
        // The socket is ready, store it
        if (isDhtRequest) {
            if (config_->logger)
                config_->logger->debug("[device {}] Connection is ready - Initied by DHT request. Vid: {}",
                                       deviceId,
                                       vid);
        } else {
            if (config_->logger)
                config_->logger->debug("[device {}] Connection is ready - Initied by connectDevice(). channel: {} - vid: {}",
                                       deviceId,
                                       name,
                                       vid);
        }

        auto info = getInfo(deviceId, vid);
        addNewMultiplexedSocket({deviceId, vid}, info);
        // Finally, open the channel and launch pending callbacks
        if (info->socket_) {
            // Note: do not remove pending there it's done in sendChannelRequest
            for (const auto& [id, name] : getPendingIds(deviceId)) {
                if (config_->logger)
                    config_->logger->debug("[device {}] Send request on TLS socket for channel {}",
                         deviceId, name);
                sendChannelRequest(info->socket_, name, deviceId, id);
            }
        }
    }
}

void
ConnectionManager::Impl::answerTo(IceTransport& ice,
                                  const dht::Value::Id& id,
                                  const std::shared_ptr<dht::crypto::PublicKey>& from)
{
    // NOTE: This is a shortest version of a real SDP message to save some bits
    auto iceAttributes = ice.getLocalAttributes();
    std::ostringstream icemsg;
    icemsg << iceAttributes.ufrag << "\n";
    icemsg << iceAttributes.pwd << "\n";
    for (const auto& addr : ice.getLocalCandidates(1)) {
        icemsg << addr << "\n";
    }

    // Send PeerConnection response
    PeerConnectionRequest val;
    val.id = id;
    val.ice_msg = icemsg.str();
    val.isAnswer = true;
    auto value = std::make_shared<dht::Value>(std::move(val));
    value->user_type = "peer_request";

    if (config_->logger)
        config_->logger->debug("[device {}] Connection accepted, DHT reply", from->getLongId());
    dht()->putEncrypted(dht::InfoHash::get(PeerConnectionRequest::key_prefix
                                           + from->getId().toString()),
                        from,
                        value,
                        [from,l=config_->logger](bool ok) {
                            if (l)
                                l->debug("[device {}] Answer to connection request: put encrypted {:s}",
                                         from->getLongId(),
                                         (ok ? "ok" : "failed"));
                        });
}

bool
ConnectionManager::Impl::onRequestStartIce(const PeerConnectionRequest& req)
{
    auto deviceId = req.owner->getLongId();
    auto info = getInfo(deviceId, req.id);
    if (!info)
        return false;

    std::unique_lock<std::mutex> lk {info->mutex_};
    auto& ice = info->ice_;
    if (!ice) {
        if (config_->logger)
            config_->logger->error("[device {}] No ICE detected", deviceId);
        if (connReadyCb_)
            connReadyCb_(deviceId, "", nullptr);
        return false;
    }

    auto sdp = ice->parseIceCandidates(req.ice_msg);
    answerTo(*ice, req.id, req.owner);
    if (not ice->startIce({sdp.rem_ufrag, sdp.rem_pwd}, std::move(sdp.rem_candidates))) {
        if (config_->logger)
            config_->logger->error("[device {}] Start ICE failed", deviceId);
        ice = nullptr;
        if (connReadyCb_)
            connReadyCb_(deviceId, "", nullptr);
        return false;
    }
    return true;
}

bool
ConnectionManager::Impl::onRequestOnNegoDone(const PeerConnectionRequest& req)
{
    auto deviceId = req.owner->getLongId();
    auto info = getInfo(deviceId, req.id);
    if (!info)
        return false;

    std::unique_lock<std::mutex> lk {info->mutex_};
    auto& ice = info->ice_;
    if (!ice) {
        if (config_->logger)
            config_->logger->error("[device {}] No ICE detected", deviceId);
        return false;
    }

    // Build socket
    auto endpoint = std::make_unique<IceSocketEndpoint>(std::shared_ptr<IceTransport>(
                                                            std::move(ice)),
                                                        false);

    // init TLS session
    auto ph = req.from;
    if (config_->logger)
        config_->logger->debug("[device {}] Start TLS session - Initied by DHT request. vid: {}",
                               deviceId,
                               req.id);
    info->tls_ = std::make_unique<TlsSocketEndpoint>(
        std::move(endpoint),
        certStore(),
        config_->ioContext,
        identity(),
        dhParams(),
        [ph, w = weak()](const dht::crypto::Certificate& cert) {
            auto shared = w.lock();
            if (!shared)
                return false;
            auto crt = shared->certStore().getCertificate(cert.getLongId().toString());
            if (!crt)
                return false;
            return crt->getPacked() == cert.getPacked();
        });

    info->tls_->setOnReady(
        [w = weak(), deviceId = std::move(deviceId), vid = std::move(req.id)](bool ok) {
            if (auto shared = w.lock())
                shared->onTlsNegotiationDone(ok, deviceId, vid);
        });
    return true;
}

void
ConnectionManager::Impl::onDhtPeerRequest(const PeerConnectionRequest& req,
                                          const std::shared_ptr<dht::crypto::Certificate>& /*cert*/)
{
    auto deviceId = req.owner->getLongId();
    if (config_->logger)
        config_->logger->debug("[device {}] New connection request", deviceId);
    if (!iceReqCb_ || !iceReqCb_(deviceId)) {
        if (config_->logger)
            config_->logger->debug("[device {}] Refusing connection", deviceId);
        return;
    }

    // Because the connection is accepted, create an ICE socket.
    getIceOptions([w = weak(), req, deviceId](auto&& ice_config) {
        auto shared = w.lock();
        if (!shared)
            return;
        // Note: used when the ice negotiation fails to erase
        // all stored structures.
        auto eraseInfo = [w, id = req.id, deviceId] {
            if (auto shared = w.lock()) {
                // If no new socket is specified, we don't try to generate a new socket
                shared->executePendingOperations(deviceId, id, nullptr);
                if (shared->connReadyCb_)
                    shared->connReadyCb_(deviceId, "", nullptr);
                std::lock_guard<std::mutex> lk(shared->infosMtx_);
                shared->infos_.erase({deviceId, id});
            }
        };

        ice_config.tcpEnable = true;
        ice_config.onInitDone = [w, req, eraseInfo](bool ok) {
            auto shared = w.lock();
            if (!shared)
                return;
            if (!ok) {
                if (shared->config_->logger)
                    shared->config_->logger->error("[device {}] Cannot initialize ICE session.", req.owner->getLongId());
                dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
                return;
            }

            dht::ThreadPool::io().run(
                [w = std::move(w), req = std::move(req), eraseInfo = std::move(eraseInfo)] {
                    auto shared = w.lock();
                    if (!shared)
                        return;
                    if (!shared->onRequestStartIce(req))
                        eraseInfo();
                });
        };

        ice_config.onNegoDone = [w, req, eraseInfo](bool ok) {
            auto shared = w.lock();
            if (!shared)
                return;
            if (!ok) {
                if (shared->config_->logger)
                    shared->config_->logger->error("[device {}] ICE negotiation failed.", req.owner->getLongId());
                dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
                return;
            }

            dht::ThreadPool::io().run(
                [w = std::move(w), req = std::move(req), eraseInfo = std::move(eraseInfo)] {
                    if (auto shared = w.lock())
                        if (!shared->onRequestOnNegoDone(req))
                            eraseInfo();
                });
        };

        // Negotiate a new ICE socket
        auto info = std::make_shared<ConnectionInfo>();
        {
            std::lock_guard<std::mutex> lk(shared->infosMtx_);
            shared->infos_[{deviceId, req.id}] = info;
        }
        if (shared->config_->logger)
            shared->config_->logger->debug("[device {}] Accepting connection", deviceId);
        std::unique_lock<std::mutex> lk {info->mutex_};
        ice_config.streamsCount = 1;
        ice_config.compCountPerStream = 1; // TCP
        ice_config.master = true;
        info->ice_ = shared->config_->factory->createUTransport("");
        if (not info->ice_) {
            if (shared->config_->logger)
                shared->config_->logger->error("[device {}] Cannot initialize ICE session", deviceId);
            eraseInfo();
            return;
        }
        // We need to detect any shutdown if the ice session is destroyed before going to the TLS session;
        info->ice_->setOnShutdown([eraseInfo]() {
            dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
        });
        try {
            info->ice_->initIceInstance(ice_config);
        } catch (const std::exception& e) {
            if (shared->config_->logger)
                shared->config_->logger->error("{}", e.what());
            dht::ThreadPool::io().run([eraseInfo = std::move(eraseInfo)] { eraseInfo(); });
        }
    });
}

void
ConnectionManager::Impl::addNewMultiplexedSocket(const CallbackId& id, const std::shared_ptr<ConnectionInfo>& info)
{
    info->socket_ = std::make_shared<MultiplexedSocket>(config_->ioContext, id.first, std::move(info->tls_));
    info->socket_->setOnReady(
        [w = weak()](const DeviceId& deviceId, const std::shared_ptr<ChannelSocket>& socket) {
            if (auto sthis = w.lock())
                if (sthis->connReadyCb_)
                    sthis->connReadyCb_(deviceId, socket->name(), socket);
        });
    info->socket_->setOnRequest([w = weak()](const std::shared_ptr<dht::crypto::Certificate>& peer,
                                             const uint16_t&,
                                             const std::string& name) {
        if (auto sthis = w.lock())
            if (sthis->channelReqCb_)
                return sthis->channelReqCb_(peer, name);
        return false;
    });
    info->socket_->onShutdown([w = weak(), deviceId=id.first, vid=id.second]() {
        // Cancel current outgoing connections
        dht::ThreadPool::io().run([w, deviceId, vid] {
            auto sthis = w.lock();
            if (!sthis)
                return;

            std::set<CallbackId> ids;
            if (auto info = sthis->getInfo(deviceId, vid)) {
                std::lock_guard<std::mutex> lk(info->mutex_);
                if (info->socket_) {
                    ids = std::move(info->cbIds_);
                    info->socket_->shutdown();
                }
            }
            for (const auto& cbId : ids)
                sthis->executePendingOperations(cbId.first, cbId.second, nullptr);

            std::lock_guard<std::mutex> lk(sthis->infosMtx_);
            sthis->infos_.erase({deviceId, vid});
        });
    });
}

const std::shared_future<tls::DhParams>
ConnectionManager::Impl::dhParams() const
{
    return dht::ThreadPool::computation().get<tls::DhParams>(
        std::bind(tls::DhParams::loadDhParams, config_->cachePath / "dhParams"));
}

template<typename ID = dht::Value::Id>
std::set<ID, std::less<>>
loadIdList(const std::string& path)
{
    std::set<ID, std::less<>> ids;
    std::ifstream file = fileutils::ifstream(path);
    if (!file.is_open()) {
        //JAMI_DBG("Could not load %s", path.c_str());
        return ids;
    }
    std::string line;
    while (std::getline(file, line)) {
        if constexpr (std::is_same<ID, std::string>::value) {
            ids.emplace(std::move(line));
        } else if constexpr (std::is_integral<ID>::value) {
            ID vid;
            if (auto [p, ec] = std::from_chars(line.data(), line.data() + line.size(), vid, 16);
                ec == std::errc()) {
                ids.emplace(vid);
            }
        }
    }
    return ids;
}

template<typename List = std::set<dht::Value::Id>>
void
saveIdList(const std::filesystem::path& path, const List& ids)
{
    std::ofstream file = fileutils::ofstream(path, std::ios::trunc | std::ios::binary);
    if (!file.is_open()) {
        //JAMI_ERR("Could not save to %s", path.c_str());
        return;
    }
    for (auto& c : ids)
        file << std::hex << c << "\n";
}

void
ConnectionManager::Impl::loadTreatedMessages()
{
    std::lock_guard<std::mutex> lock(messageMutex_);
    auto path = config_->cachePath / "treatedMessages";
    treatedMessages_ = loadIdList<std::string>(path);
    if (treatedMessages_.empty()) {
        auto messages = loadIdList(path);
        for (const auto& m : messages)
            treatedMessages_.emplace(to_hex_string(m));
    }
}

void
ConnectionManager::Impl::saveTreatedMessages() const
{
    dht::ThreadPool::io().run([w = weak()]() {
        if (auto sthis = w.lock()) {
            auto& this_ = *sthis;
            std::lock_guard<std::mutex> lock(this_.messageMutex_);
            fileutils::check_dir(this_.config_->cachePath.c_str());
            saveIdList<decltype(this_.treatedMessages_)>(this_.config_->cachePath / "treatedMessages",
                                                         this_.treatedMessages_);
        }
    });
}

bool
ConnectionManager::Impl::isMessageTreated(std::string_view id)
{
    std::lock_guard<std::mutex> lock(messageMutex_);
    auto res = treatedMessages_.emplace(id);
    if (res.second) {
        saveTreatedMessages();
        return false;
    }
    return true;
}

/**
 * returns whether or not UPnP is enabled and active_
 * ie: if it is able to make port mappings
 */
bool
ConnectionManager::Impl::getUPnPActive() const
{
    return config_->getUPnPActive();
}

IpAddr
ConnectionManager::Impl::getPublishedIpAddress(uint16_t family) const
{
    if (family == AF_INET)
        return publishedIp_[0];
    if (family == AF_INET6)
        return publishedIp_[1];

    assert(family == AF_UNSPEC);

    // If family is not set, prefere IPv4 if available. It's more
    // likely to succeed behind NAT.
    if (publishedIp_[0])
        return publishedIp_[0];
    if (publishedIp_[1])
        return publishedIp_[1];
    return {};
}

void
ConnectionManager::Impl::setPublishedAddress(const IpAddr& ip_addr)
{
    if (ip_addr.getFamily() == AF_INET) {
        publishedIp_[0] = ip_addr;
    } else {
        publishedIp_[1] = ip_addr;
    }
}

void
ConnectionManager::Impl::storeActiveIpAddress(std::function<void()>&& cb)
{
    dht()->getPublicAddress([this, cb = std::move(cb)](std::vector<dht::SockAddr>&& results) {
        bool hasIpv4 {false}, hasIpv6 {false};
        for (auto& result : results) {
            auto family = result.getFamily();
            if (family == AF_INET) {
                if (not hasIpv4) {
                    hasIpv4 = true;
                    if (config_->logger)
                        config_->logger->debug("Store DHT public IPv4 address: {}", result);
                    //JAMI_DBG("Store DHT public IPv4 address : %s", result.toString().c_str());
                    setPublishedAddress(*result.get());
                    if (config_->upnpCtrl) {
                        config_->upnpCtrl->setPublicAddress(*result.get());
                    }
                }
            } else if (family == AF_INET6) {
                if (not hasIpv6) {
                    hasIpv6 = true;
                    if (config_->logger)
                        config_->logger->debug("Store DHT public IPv6 address: {}", result);
                    setPublishedAddress(*result.get());
                }
            }
            if (hasIpv4 and hasIpv6)
                break;
        }
        if (cb)
            cb();
    });
}

void
ConnectionManager::Impl::getIceOptions(std::function<void(IceTransportOptions&&)> cb) noexcept
{
    storeActiveIpAddress([this, cb = std::move(cb)] {
        IceTransportOptions opts = ConnectionManager::Impl::getIceOptions();
        auto publishedAddr = getPublishedIpAddress();

        if (publishedAddr) {
            auto interfaceAddr = ip_utils::getInterfaceAddr(getLocalInterface(),
                                                            publishedAddr.getFamily());
            if (interfaceAddr) {
                opts.accountLocalAddr = interfaceAddr;
                opts.accountPublicAddr = publishedAddr;
            }
        }
        if (cb)
            cb(std::move(opts));
    });
}

IceTransportOptions
ConnectionManager::Impl::getIceOptions() const noexcept
{
    IceTransportOptions opts;
    opts.factory = config_->factory;
    opts.upnpEnable = getUPnPActive();
    opts.upnpContext = config_->upnpCtrl ? config_->upnpCtrl->upnpContext() : nullptr;

    if (config_->stunEnabled)
        opts.stunServers.emplace_back(StunServerInfo().setUri(config_->stunServer));
    if (config_->turnEnabled) {
        if (config_->turnCache) {
            auto turnAddr = config_->turnCache->getResolvedTurn();
            if (turnAddr != std::nullopt) {
                opts.turnServers.emplace_back(TurnServerInfo()
                                                .setUri(turnAddr->toString())
                                                .setUsername(config_->turnServerUserName)
                                                .setPassword(config_->turnServerPwd)
                                                .setRealm(config_->turnServerRealm));
            }
        } else {
            opts.turnServers.emplace_back(TurnServerInfo()
                                                .setUri(config_->turnServer)
                                                .setUsername(config_->turnServerUserName)
                                                .setPassword(config_->turnServerPwd)
                                                .setRealm(config_->turnServerRealm));
        }
        // NOTE: first test with ipv6 turn was not concluant and resulted in multiple
        // co issues. So this needs some debug. for now just disable
        // if (cacheTurnV6 && *cacheTurnV6) {
        //    opts.turnServers.emplace_back(TurnServerInfo()
        //                                      .setUri(cacheTurnV6->toString(true))
        //                                      .setUsername(turnServerUserName_)
        //                                      .setPassword(turnServerPwd_)
        //                                      .setRealm(turnServerRealm_));
        //}
    }
    return opts;
}

bool
ConnectionManager::Impl::foundPeerDevice(const std::shared_ptr<dht::crypto::Certificate>& crt,
                                         dht::InfoHash& account_id,
                                         const std::shared_ptr<Logger>& logger)
{
    if (not crt)
        return false;

    auto top_issuer = crt;
    while (top_issuer->issuer)
        top_issuer = top_issuer->issuer;

    // Device certificate can't be self-signed
    if (top_issuer == crt) {
        if (logger)
            logger->warn("Found invalid (self-signed) peer device: {}", crt->getLongId());
        return false;
    }

    // Check peer certificate chain
    // Trust store with top issuer as the only CA
    dht::crypto::TrustList peer_trust;
    peer_trust.add(*top_issuer);
    if (not peer_trust.verify(*crt)) {
        if (logger)
            logger->warn("Found invalid peer device: {}", crt->getLongId());
        return false;
    }

    // Check cached OCSP response
    if (crt->ocspResponse and crt->ocspResponse->getCertificateStatus() != GNUTLS_OCSP_CERT_GOOD) {
        if (logger)
            logger->error("Certificate {} is disabled by cached OCSP response", crt->getLongId());
        return false;
    }

    account_id = crt->issuer->getId();
    if (logger)
        logger->warn("Found peer device: {} account:{} CA:{}",
              crt->getLongId(),
              account_id,
              top_issuer->getId());
    return true;
}

bool
ConnectionManager::Impl::findCertificate(
    const dht::PkId& id, std::function<void(const std::shared_ptr<dht::crypto::Certificate>&)>&& cb)
{
    if (auto cert = certStore().getCertificate(id.toString())) {
        if (cb)
            cb(cert);
    } else if (cb)
        cb(nullptr);
    return true;
}

bool
ConnectionManager::Impl::findCertificate(const dht::InfoHash& h,
    std::function<void(const std::shared_ptr<dht::crypto::Certificate>&)>&& cb)
{
    if (auto cert = certStore().getCertificate(h.toString())) {
        if (cb)
            cb(cert);
    } else {
        dht()->findCertificate(h,
                              [cb = std::move(cb), this](
                                  const std::shared_ptr<dht::crypto::Certificate>& crt) {
                                  if (crt)
                                      certStore().pinCertificate(crt);
                                  if (cb)
                                      cb(crt);
                              });
    }
    return true;
}

ConnectionManager::ConnectionManager(std::shared_ptr<ConnectionManager::Config> config_)
    : pimpl_ {std::make_shared<Impl>(config_)}
{}

ConnectionManager::~ConnectionManager()
{
    if (pimpl_)
        pimpl_->shutdown();
}

void
ConnectionManager::connectDevice(const DeviceId& deviceId,
                                 const std::string& name,
                                 ConnectCallback cb,
                                 bool noNewSocket,
                                 bool forceNewSocket,
                                 const std::string& connType)
{
    pimpl_->connectDevice(deviceId, name, std::move(cb), noNewSocket, forceNewSocket, connType);
}

void
ConnectionManager::connectDevice(const dht::InfoHash& deviceId,
                                 const std::string& name,
                                 ConnectCallbackLegacy cb,
                                 bool noNewSocket,
                                 bool forceNewSocket,
                                 const std::string& connType)
{
    pimpl_->connectDevice(deviceId, name, std::move(cb), noNewSocket, forceNewSocket, connType);
}


void
ConnectionManager::connectDevice(const std::shared_ptr<dht::crypto::Certificate>& cert,
                                 const std::string& name,
                                 ConnectCallback cb,
                                 bool noNewSocket,
                                 bool forceNewSocket,
                                 const std::string& connType)
{
    pimpl_->connectDevice(cert, name, std::move(cb), noNewSocket, forceNewSocket, connType);
}

bool
ConnectionManager::isConnecting(const DeviceId& deviceId, const std::string& name) const
{
    auto pending = pimpl_->getPendingIds(deviceId);
    return std::find_if(pending.begin(), pending.end(), [&](auto p) { return p.second == name; })
           != pending.end();
}

void
ConnectionManager::closeConnectionsWith(const std::string& peerUri)
{
    std::vector<std::shared_ptr<ConnectionInfo>> connInfos;
    std::set<DeviceId> peersDevices;
    {
        std::lock_guard<std::mutex> lk(pimpl_->infosMtx_);
        for (auto iter = pimpl_->infos_.begin(); iter != pimpl_->infos_.end();) {
            auto const& [key, value] = *iter;
            auto deviceId = key.first;
            auto cert = pimpl_->certStore().getCertificate(deviceId.toString());
            if (cert && cert->issuer && peerUri == cert->issuer->getId().toString()) {
                connInfos.emplace_back(value);
                peersDevices.emplace(deviceId);
                iter = pimpl_->infos_.erase(iter);
            } else {
                iter++;
            }
        }
    }
    // Stop connections to all peers devices
    for (const auto& deviceId : peersDevices) {
        pimpl_->executePendingOperations(deviceId, 0, nullptr);
        // This will close the TLS Session
        pimpl_->removeUnusedConnections(deviceId);
    }
    for (auto& info : connInfos) {
        if (info->socket_)
            info->socket_->shutdown();
        if (info->waitForAnswer_)
            info->waitForAnswer_->cancel();
        if (info->ice_) {
            std::unique_lock<std::mutex> lk {info->mutex_};
            dht::ThreadPool::io().run(
                [ice = std::shared_ptr<IceTransport>(std::move(info->ice_))] {});
        }
    }
}

void
ConnectionManager::onDhtConnected(const dht::crypto::PublicKey& devicePk)
{
    pimpl_->onDhtConnected(devicePk);
}

void
ConnectionManager::onICERequest(onICERequestCallback&& cb)
{
    pimpl_->iceReqCb_ = std::move(cb);
}

void
ConnectionManager::onChannelRequest(ChannelRequestCallback&& cb)
{
    pimpl_->channelReqCb_ = std::move(cb);
}

void
ConnectionManager::onConnectionReady(ConnectionReadyCallback&& cb)
{
    pimpl_->connReadyCb_ = std::move(cb);
}

void
ConnectionManager::oniOSConnected(iOSConnectedCallback&& cb)
{
    pimpl_->iOSConnectedCb_ = std::move(cb);
}

std::size_t
ConnectionManager::activeSockets() const
{
    std::lock_guard<std::mutex> lk(pimpl_->infosMtx_);
    return pimpl_->infos_.size();
}

void
ConnectionManager::monitor() const
{
    std::lock_guard<std::mutex> lk(pimpl_->infosMtx_);
    auto logger = pimpl_->config_->logger;
    if (!logger)
        return;
    logger->debug("ConnectionManager current status:");
    for (const auto& [_, ci] : pimpl_->infos_) {
        if (ci->socket_)
            ci->socket_->monitor();
    }
    logger->debug("ConnectionManager end status.");
}

void
ConnectionManager::connectivityChanged()
{
    std::lock_guard<std::mutex> lk(pimpl_->infosMtx_);
    for (const auto& [_, ci] : pimpl_->infos_) {
        if (ci->socket_)
            ci->socket_->sendBeacon();
    }
}

void
ConnectionManager::getIceOptions(std::function<void(IceTransportOptions&&)> cb) noexcept
{
    return pimpl_->getIceOptions(std::move(cb));
}

IceTransportOptions
ConnectionManager::getIceOptions() const noexcept
{
    return pimpl_->getIceOptions();
}

IpAddr
ConnectionManager::getPublishedIpAddress(uint16_t family) const
{
    return pimpl_->getPublishedIpAddress(family);
}

void
ConnectionManager::setPublishedAddress(const IpAddr& ip_addr)
{
    return pimpl_->setPublishedAddress(ip_addr);
}

void
ConnectionManager::storeActiveIpAddress(std::function<void()>&& cb)
{
    return pimpl_->storeActiveIpAddress(std::move(cb));
}

std::shared_ptr<ConnectionManager::Config>
ConnectionManager::getConfig()
{
    return pimpl_->config_;
}

std::vector<std::map<std::string, std::string>>
ConnectionManager::getConnectionList(const DeviceId& device) const
{
    std::vector<std::map<std::string, std::string>> connectionsList;
    std::lock_guard<std::mutex> lk(pimpl_->infosMtx_);

    for (const auto& [key, ci] : pimpl_->infos_) {
        if (device && key.first != device)
            continue;
        std::map<std::string, std::string> connectionInfo;
        connectionInfo["id"] = callbackIdToString(key.first, key.second);
        connectionInfo["device"] = key.first.toString();
        if (ci->tls_) {
            if (auto cert = ci->tls_->peerCertificate()) {
                connectionInfo["peer"] = cert->issuer->getId().toString();
            }
        }
        if (ci->socket_) {
            connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::Connected));
        } else if (ci->tls_) {
            connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::TLS));
        } else if(ci->ice_)
        {
            connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::ICE));
        }
        if (ci->tls_) {
            std::string remoteAddress = ci->tls_->getRemoteAddress();
            std::string remoteAddressIp = remoteAddress.substr(0, remoteAddress.find(':'));
            std::string remoteAddressPort = remoteAddress.substr(remoteAddress.find(':') + 1);
            connectionInfo["remoteAdress"] = remoteAddressIp;
            connectionInfo["remotePort"] = remoteAddressPort;
        }
        connectionsList.emplace_back(std::move(connectionInfo));
    }

    if (device) {
        auto it = pimpl_->pendingOperations_.find(device);
        if (it != pimpl_->pendingOperations_.end()) {
            const auto& po = it->second;
            for (const auto& [vid, ci] : po.connecting) {
                std::map<std::string, std::string> connectionInfo;
                connectionInfo["id"] = callbackIdToString(device, vid);
                connectionInfo["deviceId"] = vid;
                connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::Connecting));
                connectionsList.emplace_back(std::move(connectionInfo));
            }

            for (const auto& [vid, ci] : po.waiting) {
                std::map<std::string, std::string> connectionInfo;
                connectionInfo["id"] = callbackIdToString(device, vid);
                connectionInfo["deviceId"] = vid;
                connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::Waiting));
                connectionsList.emplace_back(std::move(connectionInfo));
            }
        }
    }
    else {
        for (const auto& [key, po] : pimpl_->pendingOperations_) {
            for (const auto& [vid, ci] : po.connecting) {
                std::map<std::string, std::string> connectionInfo;
                connectionInfo["id"] = callbackIdToString(device, vid);
                connectionInfo["deviceId"] = vid;
                connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::Connecting));
                connectionsList.emplace_back(std::move(connectionInfo));
            }

            for (const auto& [vid, ci] : po.waiting) {
               std::map<std::string, std::string> connectionInfo;
                connectionInfo["id"] = callbackIdToString(device, vid);
                connectionInfo["deviceId"] = vid;
                connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::Waiting));
                connectionsList.emplace_back(std::move(connectionInfo));
            }
        }
    }
    return connectionsList;
}

std::vector<std::map<std::string, std::string>>
ConnectionManager::getChannelList(const std::string& connectionId) const
{
    std::lock_guard<std::mutex> lk(pimpl_->infosMtx_);
    CallbackId cbid = parseCallbackId(connectionId);
    if (pimpl_->infos_.count(cbid) > 0) {
        return pimpl_->infos_[cbid]->socket_->getChannelList();
    } else {
        return {};
    }
}

} // namespace dhtnet
