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

std::string
callbackIdToString(const dhtnet::DeviceId& did, const dht::Value::Id& vid)
{
    return fmt::format("{} {}", did.to_view(), vid);
}

std::pair<dhtnet::DeviceId, dht::Value::Id> parseCallbackId(std::string_view ci)
{
    auto sep = ci.find(' ');
    std::string_view deviceIdString = ci.substr(0, sep);
    std::string_view vidString = ci.substr(sep + 1);

    dhtnet::DeviceId deviceId(deviceIdString);
    dht::Value::Id vid = std::stoul(std::string(vidString), nullptr, 10);
    return {deviceId, vid};
}

std::shared_ptr<ConnectionManager::Config>
createConfig(std::shared_ptr<ConnectionManager::Config> config_)
{
    if (!config_->certStore){
        config_->certStore = std::make_shared<dhtnet::tls::CertificateStore>("client", config_->logger);
    }
    if (!config_->dht) {
        dht::DhtRunner::Config dhtConfig;
        dhtConfig.dht_config.id = config_->id;
        dhtConfig.threaded = true;
        dht::DhtRunner::Context dhtContext;
        dhtContext.certificateStore = [c = config_->certStore](const dht::InfoHash& pk_id) {
            std::vector<std::shared_ptr<dht::crypto::Certificate>> ret;
            if (auto cert = c->getCertificate(pk_id.toString()))
                ret.emplace_back(std::move(cert));
            return ret;
        };
        config_->dht = std::make_shared<dht::DhtRunner>();
        config_->dht->run(dhtConfig, std::move(dhtContext));
        config_->dht->bootstrap("bootstrap.jami.net");
    }
    if (!config_->factory){
        config_->factory = std::make_shared<IceTransportFactory>(config_->logger);
    }
    return config_;
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
    std::set<dht::Value::Id> cbIds_ {};

    std::function<void(bool)> onConnected_;
    std::unique_ptr<asio::steady_timer> waitForAnswer_ {};

    void shutdown() {
        std::lock_guard<std::mutex> lk(mutex_);
        if (tls_)
            tls_->shutdown();
        if (socket_)
            socket_->shutdown();
        if (waitForAnswer_)
            waitForAnswer_->cancel();
        if (ice_) {
            dht::ThreadPool::io().run(
                [ice = std::shared_ptr<IceTransport>(std::move(ice_))] {});
        }
    }

    std::map<std::string, std::string>
    getInfo(const DeviceId& deviceId, dht::Value::Id valueId, tls::CertificateStore& certStore) const
    {
        std::map<std::string, std::string> connectionInfo;
        connectionInfo["id"] = callbackIdToString(deviceId, valueId);
        connectionInfo["device"] = deviceId.toString();
        auto cert = tls_ ? tls_->peerCertificate() : (socket_ ? socket_->peerCertificate() : nullptr);
        if (not cert)
            cert = certStore.getCertificate(deviceId.toString());
        if (cert) {
            connectionInfo["peer"] = cert->issuer->getId().toString();
        }
        if (socket_) {
            connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::Connected));
        } else if (tls_) {
            connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::TLS));
        } else if(ice_) {
            connectionInfo["status"] = std::to_string(static_cast<int>(ConnectionStatus::ICE));
        }
        if (tls_) {
            connectionInfo["remoteAddress"] = tls_->getRemoteAddress();
        }
        return connectionInfo;
    }

};

struct PendingCb {
    std::string name;
    ConnectCallback cb;
};

struct DeviceInfo {
    const DeviceId deviceId;
    mutable std::mutex mtx_ {};
    std::map<dht::Value::Id, std::shared_ptr<ConnectionInfo>> info;
    std::map<dht::Value::Id, PendingCb> connecting;
    std::map<dht::Value::Id, PendingCb> waiting;
    DeviceInfo(DeviceId id) : deviceId {id} {}

    inline bool isConnecting() const {
        return !connecting.empty() || !waiting.empty();
    }

    inline bool empty() const {
        return info.empty() && connecting.empty() && waiting.empty();
    }

    dht::Value::Id newId(std::mt19937_64& rand) const {
        ValueIdDist dist(1, ID_MAX_VAL);
        dht::Value::Id id;
        do {
            id = dist(rand);
        } while (info.find(id) != info.end()
                || connecting.find(id) != connecting.end()
                || waiting.find(id) != waiting.end());
        return id;
    }

    std::shared_ptr<ConnectionInfo> getConnectedInfo() const {
        for (auto& [id, ci] : info) {
            if (ci->socket_)
                return ci;
        }
        return {};
    }

    std::vector<PendingCb> extractPendingOperations(dht::Value::Id vid, const std::shared_ptr<ChannelSocket>& sock, bool accepted = true)
    {
        std::vector<PendingCb> ret;
        if (vid == 0) {
            // Extract all pending callbacks
            ret.reserve(connecting.size() + waiting.size());
            for (auto& [vid, cb] : connecting)
                ret.emplace_back(std::move(cb));
            connecting.clear();
            for (auto& [vid, cb] : waiting)
                ret.emplace_back(std::move(cb));
            waiting.clear();
        } else if (auto n = waiting.extract(vid)) {
            // If it's a waiting operation, just move it
            ret.emplace_back(std::move(n.mapped()));
        } else if (auto n = connecting.extract(vid)) {
            ret.emplace_back(std::move(n.mapped()));
            // If sock is nullptr, execute if it's the last connecting operation
            // If accepted is false, it means that underlying socket is ok, but channel is declined
            if (!sock && connecting.empty() && accepted) {
                for (auto& [vid, cb] : waiting)
                    ret.emplace_back(std::move(cb));
                waiting.clear();
                for (auto& [vid, cb] : connecting)
                    ret.emplace_back(std::move(cb));
                connecting.clear();
            }
        }
        return ret;
    }

    std::vector<std::shared_ptr<ConnectionInfo>> extractUnusedConnections() {
        std::vector<std::shared_ptr<ConnectionInfo>> unused {};
        for (auto& [id, info] : info)
            unused.emplace_back(std::move(info));
        info.clear();
        return unused;
    }

    void executePendingOperations(std::unique_lock<std::mutex>& lock, dht::Value::Id vid, const std::shared_ptr<ChannelSocket>& sock, bool accepted = true) {
        auto ops = extractPendingOperations(vid, sock, accepted);
        lock.unlock();
        for (auto& cb : ops)
            cb.cb(sock, deviceId);
    }
    void executePendingOperations(dht::Value::Id vid, const std::shared_ptr<ChannelSocket>& sock, bool accepted = true) {
        std::unique_lock<std::mutex> lock(mtx_);
        executePendingOperations(lock, vid, sock, accepted);
    }

    std::map<dht::Value::Id, std::string> getPendingIds() const {
        std::map<dht::Value::Id, std::string> ret;
        for (const auto& [id, pc]: connecting)
            ret[id] = pc.name;
        for (const auto& [id, pc]: waiting)
            ret[id] = pc.name;
        return ret;
    }

    std::vector<std::map<std::string, std::string>>
    getConnectionList(tls::CertificateStore& certStore) const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<std::map<std::string, std::string>> ret;
        ret.reserve(info.size());
        for (auto& [id, ci] : info) {
            std::lock_guard<std::mutex> lk(ci->mutex_);
            ret.emplace_back(ci->getInfo(deviceId, id, certStore));
        }
        auto cert = certStore.getCertificate(deviceId.toString());
        for (const auto& [vid, ci] : connecting) {
            ret.emplace_back(std::map<std::string, std::string> {
                {"id", callbackIdToString(deviceId, vid)},
                {"status", std::to_string(static_cast<int>(ConnectionStatus::Connecting))},
                {"device", deviceId.toString()},
                {"peer", cert ? cert->issuer->getId().toString() : ""}
            });
        }
        for (const auto& [vid, ci] : waiting) {
            ret.emplace_back(std::map<std::string, std::string> {
                {"id", callbackIdToString(deviceId, vid)},
                {"status", std::to_string(static_cast<int>(ConnectionStatus::Waiting))},
                {"device", deviceId.toString()},
                {"peer", cert ? cert->issuer->getId().toString() : ""}
            });
        }
        return ret;
    }
};

class DeviceInfoSet {
public:
    std::shared_ptr<DeviceInfo> getDeviceInfo(const DeviceId& deviceId) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = infos_.find(deviceId);
        if (it != infos_.end())
            return it->second;
        return {};
    }

    std::vector<std::shared_ptr<DeviceInfo>> getDeviceInfos() {
        std::vector<std::shared_ptr<DeviceInfo>> deviceInfos;
        std::lock_guard<std::mutex> lk(mtx_);
        deviceInfos.reserve(infos_.size());
        for (auto& [deviceId, info] : infos_)
            deviceInfos.emplace_back(info);
        return deviceInfos;
    }

    std::shared_ptr<DeviceInfo> createDeviceInfo(const DeviceId& deviceId) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto& info = infos_[deviceId];
        if (!info)
            info = std::make_shared<DeviceInfo>(deviceId);
        return info;
    }

    bool removeDeviceInfo(const DeviceId& deviceId) {
        std::lock_guard<std::mutex> lk(mtx_);
        return infos_.erase(deviceId) != 0;
    }

    std::shared_ptr<ConnectionInfo> getInfo(const DeviceId& deviceId, const dht::Value::Id& id) {
        if (auto info = getDeviceInfo(deviceId)) {
            std::lock_guard<std::mutex> lk(info->mtx_);
            auto it = info->info.find(id);
            if (it != info->info.end())
                return it->second;
        }
        return {};
    }

    std::vector<std::shared_ptr<ConnectionInfo>> getConnectedInfos() {
        auto deviceInfos = getDeviceInfos();
        std::vector<std::shared_ptr<ConnectionInfo>> ret;
        ret.reserve(deviceInfos.size());
        for (auto& info : deviceInfos) {
            std::lock_guard<std::mutex> lk(info->mtx_);
            for (auto& [id, ci] : info->info) {
                if (ci->socket_)
                    ret.emplace_back(ci);
            }
        }
        return ret;
    }
    std::vector<std::shared_ptr<DeviceInfo>> shutdown() {
        std::vector<std::shared_ptr<DeviceInfo>> ret;
        std::lock_guard<std::mutex> lk(mtx_);
        ret.reserve(infos_.size());
        for (auto& [deviceId, info] : infos_) {
            ret.emplace_back(std::move(info));
        }
        infos_.clear();
        return ret;
    }

private:
    std::mutex mtx_ {};
    std::map<DeviceId, std::shared_ptr<DeviceInfo>> infos_ {};
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
        : config_ {std::move(createConfig(config_))}
        , rand_ {dht::crypto::getSeededRandomEngine<std::mt19937_64>()}
    {
        loadTreatedMessages();
        if(!config_->ioContext) {
            config_->ioContext = std::make_shared<asio::io_context>();
            ioContextRunner_ = std::make_unique<std::thread>([context = config_->ioContext, l=config_->logger]() {
                try {
                    auto work = asio::make_work_guard(*context);
                    context->run();
                } catch (const std::exception& ex) {
                    if (l) l->error("Exception: {}", ex.what());
                }
            });
        }
    }
    ~Impl() {
        if (ioContextRunner_) {
            if (config_->logger) config_->logger->debug("ConnectionManager: stopping io_context thread");
            config_->ioContext->stop();
            ioContextRunner_->join();
            ioContextRunner_.reset();
        }
    }

    std::shared_ptr<dht::DhtRunner> dht() { return config_->dht; }
    const dht::crypto::Identity& identity() const { return config_->id; }

    void shutdown()
    {
        if (isDestroying_.exchange(true))
            return;
        std::vector<std::shared_ptr<ConnectionInfo>> unused;
        std::vector<std::pair<DeviceId, std::vector<PendingCb>>> pending;
        for (auto& dinfo: infos_.shutdown()) {
            std::lock_guard<std::mutex> lk(dinfo->mtx_);
            auto p = dinfo->extractPendingOperations(0, nullptr, false);
            if (!p.empty())
                pending.emplace_back(dinfo->deviceId, std::move(p));
            auto uc = dinfo->extractUnusedConnections();
            unused.insert(unused.end(), std::make_move_iterator(uc.begin()), std::make_move_iterator(uc.end()));
        }
        for (auto& info: unused)
            info->shutdown();
        for (auto& op: pending)
            for (auto& cb: op.second)
                cb.cb(nullptr, op.first);
        if (!unused.empty())
            dht::ThreadPool::io().run([infos = std::move(unused)]() mutable {
                infos.clear();
            });
    }

    void connectDeviceStartIce(const std::shared_ptr<ConnectionInfo>& info,
                               const std::shared_ptr<dht::crypto::PublicKey>& devicePk,
                               const dht::Value::Id& vid,
                               const std::string& connType,
                               std::function<void(bool)> onConnected);
    void onResponse(const asio::error_code& ec, const std::weak_ptr<ConnectionInfo>& info, const DeviceId& deviceId, const dht::Value::Id& vid);
    bool connectDeviceOnNegoDone(const std::weak_ptr<DeviceInfo>& dinfo, 
                                 const std::shared_ptr<ConnectionInfo>& info, 
                                 const DeviceId& deviceId,
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
    void sendChannelRequest(const std::weak_ptr<DeviceInfo>& dinfo,
                            const std::shared_ptr<MultiplexedSocket>& sock,
                            const std::string& name,
                            const dht::Value::Id& vid);
    /**
     * Triggered when a PeerConnectionRequest comes from the DHT
     */
    void answerTo(IceTransport& ice,
                  const dht::Value::Id& id,
                  const std::shared_ptr<dht::crypto::PublicKey>& fromPk);
    bool onRequestStartIce(const std::shared_ptr<ConnectionInfo>& info, const PeerConnectionRequest& req);
    bool onRequestOnNegoDone(const std::weak_ptr<DeviceInfo>& dinfo, const std::shared_ptr<ConnectionInfo>& info, const PeerConnectionRequest& req);
    void onDhtPeerRequest(const PeerConnectionRequest& req,
                          const std::shared_ptr<dht::crypto::Certificate>& cert);
    /**
     * Triggered when a new TLS socket is ready to use
     * @param ok        If succeed
     * @param deviceId  Related device
     * @param vid       vid of the connection request
     * @param name      non empty if TLS was created by connectDevice()
     */
    void onTlsNegotiationDone(const std::shared_ptr<DeviceInfo>& dinfo, 
                              const std::shared_ptr<ConnectionInfo>& info,
                              bool ok,
                              const DeviceId& deviceId,
                              const dht::Value::Id& vid,
                              const std::string& name = "");

    void addNewMultiplexedSocket(const std::weak_ptr<DeviceInfo>& dinfo, const DeviceId& deviceId, const dht::Value::Id& vid, const std::shared_ptr<ConnectionInfo>& info);
    void onPeerResponse(PeerConnectionRequest&& req);
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

    std::shared_ptr<ConnectionManager::Config> config_;
    std::unique_ptr<std::thread> ioContextRunner_;

    mutable std::mutex randMtx_;
    mutable std::mt19937_64 rand_;

    iOSConnectedCallback iOSConnectedCb_ {};

    DeviceInfoSet infos_ {};

    ChannelRequestCallback channelReqCb_ {};
    ConnectionReadyCallback connReadyCb_ {};
    onICERequestCallback iceReqCb_ {};
    std::atomic_bool isDestroying_ {false};
};

void
ConnectionManager::Impl::connectDeviceStartIce(
    const std::shared_ptr<ConnectionInfo>& info,
    const std::shared_ptr<dht::crypto::PublicKey>& devicePk,
    const dht::Value::Id& vid,
    const std::string& connType,
    std::function<void(bool)> onConnected)
{
    auto deviceId = devicePk->getLongId();
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
        std::bind(&ConnectionManager::Impl::onResponse, this, std::placeholders::_1, info, deviceId, vid));
}

void
ConnectionManager::Impl::onResponse(const asio::error_code& ec,
                                    const std::weak_ptr<ConnectionInfo>& winfo,
                                    const DeviceId& deviceId,
                                    const dht::Value::Id& vid)
{
    if (ec == asio::error::operation_aborted)
        return;
    auto info = winfo.lock();
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
    const std::weak_ptr<DeviceInfo>& dinfo, 
    const std::shared_ptr<ConnectionInfo>& info,
    const DeviceId& deviceId,
    const std::string& name,
    const dht::Value::Id& vid,
    const std::shared_ptr<dht::crypto::Certificate>& cert)
{
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
        [w = weak_from_this(), dinfo, winfo=std::weak_ptr(info), deviceId = std::move(deviceId), vid = std::move(vid), name = std::move(name)](
            bool ok) {
            if (auto shared = w.lock())
                shared->onTlsNegotiationDone(dinfo.lock(), winfo.lock(), ok, deviceId, vid, name);
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
                    [w = weak_from_this(),
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
                    [w = weak_from_this(),
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
                                                  [cb, deviceId](const std::shared_ptr<ChannelSocket>& sock, const DeviceId& /*did*/){
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
    dht::ThreadPool::computation().run([w = weak_from_this(),
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
        auto di = sthis->infos_.createDeviceInfo(deviceId);
        std::unique_lock<std::mutex> lk(di->mtx_);

        dht::Value::Id vid;
        {
            std::lock_guard<std::mutex> lkr(sthis->randMtx_);
            vid = di->newId(sthis->rand_);
        }

        // Check if already connecting
        auto isConnectingToDevice = di->isConnecting();
        // Note: we can be in a state where first
        // socket is negotiated and first channel is pending
        // so return only after we checked the info
        if (isConnectingToDevice && !forceNewSocket)
            di->waiting[vid] = PendingCb {name, std::move(cb)};
        else
            di->connecting[vid] = PendingCb {name, std::move(cb)};
        
        // Check if already negotiated
        if (auto info = di->getConnectedInfo()) {
            std::unique_lock<std::mutex> lkc(info->mutex_);
            if (auto sock = info->socket_) {
                info->cbIds_.emplace(vid);
                lkc.unlock();
                lk.unlock();
                if (sthis->config_->logger)
                    sthis->config_->logger->debug("[device {}] Peer already connected. Add a new channel", deviceId);
                sthis->sendChannelRequest(di, sock, name, vid);
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
            di->executePendingOperations(lk, vid, nullptr);
            return;
        }

        // Note: used when the ice negotiation fails to erase
        // all stored structures.
        auto eraseInfo = [w, diw=std::weak_ptr(di), vid] {
            if (auto di = diw.lock()) {
                std::unique_lock<std::mutex> lk(di->mtx_);
                di->info.erase(vid);
                auto ops = di->extractPendingOperations(vid, nullptr);
                if (di->empty()) {
                    if (auto shared = w.lock())
                        shared->infos_.removeDeviceInfo(di->deviceId);
                }
                lk.unlock();
                for (const auto& op: ops)
                    op.cb(nullptr, di->deviceId);
            }
        };

        // If no socket exists, we need to initiate an ICE connection.
        sthis->getIceOptions([w,
                              deviceId = std::move(deviceId),
                              devicePk = std::move(devicePk),
                              diw=std::weak_ptr(di),
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
            auto info = std::make_shared<ConnectionInfo>();
            auto winfo = std::weak_ptr(info);
            ice_config.tcpEnable = true;
            ice_config.onInitDone = [w,
                                     devicePk = std::move(devicePk),
                                     name = std::move(name),
                                     cert = std::move(cert),
                                     diw,
                                     winfo = std::weak_ptr(info),
                                     vid,
                                     connType,
                                     eraseInfo](bool ok) {
                dht::ThreadPool::io().run([w = std::move(w),
                                           devicePk = std::move(devicePk),
                                           vid,
                                           winfo,
                                           eraseInfo,
                                           connType, ok] {
                    auto sthis = w.lock();
                    if (!ok && sthis && sthis->config_->logger)
                        sthis->config_->logger->error("[device {}] Cannot initialize ICE session.", devicePk->getLongId());
                    if (!sthis || !ok) {
                        eraseInfo();
                        return;
                    }
                    sthis->connectDeviceStartIce(winfo.lock(), devicePk, vid, connType, [=](bool ok) {
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
                     diw,
                     winfo = std::weak_ptr(info),
                     vid,
                     eraseInfo](bool ok) {
                dht::ThreadPool::io().run([w = std::move(w),
                                           deviceId = std::move(deviceId),
                                           name = std::move(name),
                                           cert = std::move(cert),
                                           diw = std::move(diw),
                                           winfo = std::move(winfo),
                                           vid = std::move(vid),
                                           eraseInfo = std::move(eraseInfo),
                                           ok] {
                    auto sthis = w.lock();
                    if (!ok && sthis && sthis->config_->logger)
                        sthis->config_->logger->error("[device {}] ICE negotiation failed.", deviceId);
                    if (!sthis || !ok || !sthis->connectDeviceOnNegoDone(diw, winfo.lock(), deviceId, name, vid, cert))
                        eraseInfo();
                });
            };

            if (auto di = diw.lock()) {
                std::lock_guard<std::mutex> lk(di->mtx_);
                di->info[vid] = info;
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
ConnectionManager::Impl::sendChannelRequest(const std::weak_ptr<DeviceInfo>& dinfo,
                                            const std::shared_ptr<MultiplexedSocket>& sock,
                                            const std::string& name,
                                            const dht::Value::Id& vid)
{
    auto channelSock = sock->addChannel(name);
    channelSock->onShutdown([dinfo, name, vid] {
        if (auto info = dinfo.lock())
            info->executePendingOperations(vid, nullptr);
    });
    channelSock->onReady(
        [dinfo, wSock = std::weak_ptr(channelSock), name, vid](bool accepted) {
            if (auto info = dinfo.lock())
                info->executePendingOperations(vid, accepted ? wSock.lock() : nullptr, accepted);
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
            config_->logger->error("sendChannelRequest failed - error: {}", ec.message());
    }
}

void
ConnectionManager::Impl::onPeerResponse(PeerConnectionRequest&& req)
{
    auto device = req.owner->getLongId();
    if (auto info = infos_.getInfo(device, req.id)) {
        if (config_->logger)
            config_->logger->debug("[device {}] New response received", device);
        std::lock_guard<std::mutex> lk {info->mutex_};
        info->responseReceived_ = true;
        info->response_ = std::move(req);
        info->waitForAnswer_->expires_at(std::chrono::steady_clock::now());
        info->waitForAnswer_->async_wait(std::bind(&ConnectionManager::Impl::onResponse,
                                                   this,
                                                   std::placeholders::_1,
                                                   std::weak_ptr(info),
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
        [w = weak_from_this()](PeerConnectionRequest&& req) {
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
                shared->onPeerResponse(std::move(req));
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
ConnectionManager::Impl::onTlsNegotiationDone(const std::shared_ptr<DeviceInfo>& dinfo, 
                                              const std::shared_ptr<ConnectionInfo>& info,
                                              bool ok,
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
            dinfo->executePendingOperations(vid, nullptr);
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

        // Note: do not remove pending there it's done in sendChannelRequest
        std::unique_lock<std::mutex> lk2 {dinfo->mtx_};
        auto pendingIds = dinfo->getPendingIds();
        lk2.unlock();
        std::unique_lock<std::mutex> lk {info->mutex_};
        addNewMultiplexedSocket(dinfo, deviceId, vid, info);
        // Finally, open the channel and launch pending callbacks
        lk.unlock();
        for (const auto& [id, name]: pendingIds) {
            if (config_->logger)
                config_->logger->debug("[device {}] Send request on TLS socket for channel {}",
                    deviceId, name);
            sendChannelRequest(dinfo, info->socket_, name, id);
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
ConnectionManager::Impl::onRequestStartIce(const std::shared_ptr<ConnectionInfo>& info, const PeerConnectionRequest& req)
{
    if (!info)
        return false;

    auto deviceId = req.owner->getLongId();
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
ConnectionManager::Impl::onRequestOnNegoDone(const std::weak_ptr<DeviceInfo>& dinfo, const std::shared_ptr<ConnectionInfo>& info, const PeerConnectionRequest& req)
{
    if (!info)
        return false;

    auto deviceId = req.owner->getLongId();
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
        [ph, deviceId, w=weak_from_this(), l=config_->logger](const dht::crypto::Certificate& cert) {
            auto shared = w.lock();
            if (!shared)
                return false;
            if (cert.getPublicKey().getId() != ph
             || deviceId != cert.getPublicKey().getLongId()) {
                if (l) l->warn("[device {}] TLS certificate with ID {} doesn't match the DHT request.",
                                        deviceId,
                                        cert.getPublicKey().getLongId());
                return false;
            }
            auto crt = shared->certStore().getCertificate(cert.getLongId().toString());
            if (!crt)
                return false;
            return crt->getPacked() == cert.getPacked();
        });

    info->tls_->setOnReady(
        [w = weak_from_this(), dinfo, winfo=std::weak_ptr(info), deviceId = std::move(deviceId), vid = std::move(req.id)](bool ok) {
            if (auto shared = w.lock())
                shared->onTlsNegotiationDone(dinfo.lock(), winfo.lock(), ok, deviceId, vid);
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
    getIceOptions([w = weak_from_this(), req, deviceId](auto&& ice_config) {
        auto shared = w.lock();
        if (!shared)
            return;

        auto di = shared->infos_.createDeviceInfo(deviceId);
        auto info = std::make_shared<ConnectionInfo>();
        auto wdi = std::weak_ptr(di);
        auto winfo = std::weak_ptr(info);

        // Note: used when the ice negotiation fails to erase
        // all stored structures.
        auto eraseInfo = [w, wdi, id = req.id] {
            auto shared = w.lock();
            if (auto di = wdi.lock()) {
                std::unique_lock<std::mutex> lk(di->mtx_);
                di->info.erase(id);
                auto ops = di->extractPendingOperations(id, nullptr);
                if (di->empty()) {
                    if (shared)
                        shared->infos_.removeDeviceInfo(di->deviceId);
                }
                lk.unlock();
                for (const auto& op: ops)
                    op.cb(nullptr, di->deviceId);
                if (shared && shared->connReadyCb_)
                    shared->connReadyCb_(di->deviceId, "", nullptr);
            }
        };

        ice_config.master = true;
        ice_config.streamsCount = 1;
        ice_config.compCountPerStream = 1; // TCP
        ice_config.tcpEnable = true;
        ice_config.onInitDone = [w, winfo, req, eraseInfo](bool ok) {
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
                [w = std::move(w), winfo = std::move(winfo), req = std::move(req), eraseInfo = std::move(eraseInfo)] {
                    if (auto shared = w.lock()) {
                        if (!shared->onRequestStartIce(winfo.lock(), req))
                            eraseInfo();
                    }
                });
        };

        ice_config.onNegoDone = [w, wdi, winfo, req, eraseInfo](bool ok) {
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
                [w = std::move(w), wdi = std::move(wdi), winfo = std::move(winfo), req = std::move(req), eraseInfo = std::move(eraseInfo)] {
                    if (auto shared = w.lock())
                        if (!shared->onRequestOnNegoDone(wdi.lock(), winfo.lock(), req))
                            eraseInfo();
                });
        };

        // Negotiate a new ICE socket
        {
            std::lock_guard<std::mutex> lk(di->mtx_);
            di->info[req.id] = info;
        }

        if (shared->config_->logger)
            shared->config_->logger->debug("[device {}] Accepting connection", deviceId);
        std::unique_lock<std::mutex> lk {info->mutex_};
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
ConnectionManager::Impl::addNewMultiplexedSocket(const std::weak_ptr<DeviceInfo>& dinfo, const DeviceId& deviceId, const dht::Value::Id& vid, const std::shared_ptr<ConnectionInfo>& info)
{
    info->socket_ = std::make_shared<MultiplexedSocket>(config_->ioContext, deviceId, std::move(info->tls_), config_->logger);
    info->socket_->setOnReady(
        [w = weak_from_this()](const DeviceId& deviceId, const std::shared_ptr<ChannelSocket>& socket) {
            if (auto sthis = w.lock())
                if (sthis->connReadyCb_)
                    sthis->connReadyCb_(deviceId, socket->name(), socket);
        });
    info->socket_->setOnRequest([w = weak_from_this()](const std::shared_ptr<dht::crypto::Certificate>& peer,
                                             const uint16_t&,
                                             const std::string& name) {
        if (auto sthis = w.lock())
            if (sthis->channelReqCb_)
                return sthis->channelReqCb_(peer, name);
        return false;
    });
    info->socket_->onShutdown([dinfo, wi=std::weak_ptr(info), vid]() {
        // Cancel current outgoing connections
        dht::ThreadPool::io().run([dinfo, wi, vid] {
            std::set<dht::Value::Id> ids;
            if (auto info = wi.lock()) {
                std::lock_guard<std::mutex> lk(info->mutex_);
                if (info->socket_) {
                    ids = std::move(info->cbIds_);
                    info->socket_->shutdown();
                }
            }
            if (auto deviceInfo = dinfo.lock()) {
                std::shared_ptr<ConnectionInfo> info;
                std::vector<PendingCb> ops;
                std::unique_lock<std::mutex> lk(deviceInfo->mtx_);
                auto it = deviceInfo->info.find(vid);
                if (it != deviceInfo->info.end()) {
                    info = std::move(it->second);
                    deviceInfo->info.erase(it);
                }
                for (const auto& cbId : ids) {
                    auto po = deviceInfo->extractPendingOperations(cbId, nullptr);
                    ops.insert(ops.end(), po.begin(), po.end());
                }
                lk.unlock();
                for (auto& op : ops)
                    op.cb(nullptr, deviceInfo->deviceId);
            }
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
loadIdList(const std::filesystem::path& path)
{
    std::set<ID, std::less<>> ids;
    std::ifstream file(path);
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
    std::ofstream file(path, std::ios::trunc | std::ios::binary);
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
    treatedMessages_ = loadIdList<std::string>(path.string());
    if (treatedMessages_.empty()) {
        auto messages = loadIdList(path.string());
        for (const auto& m : messages)
            treatedMessages_.emplace(to_hex_string(m));
    }
}

void
ConnectionManager::Impl::saveTreatedMessages() const
{
    dht::ThreadPool::io().run([w = weak_from_this()]() {
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

std::shared_ptr<ConnectionManager::Config>
buildDefaultConfig(dht::crypto::Identity id){
    auto conf = std::make_shared<ConnectionManager::Config>();
    conf->id = std::move(id);
    return conf;
}

ConnectionManager::ConnectionManager(std::shared_ptr<ConnectionManager::Config> config_)
    : pimpl_ {std::make_shared<Impl>(config_)}
{}

ConnectionManager::ConnectionManager(dht::crypto::Identity id)
    : ConnectionManager {buildDefaultConfig(id)}
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
    if (auto dinfo = pimpl_->infos_.getDeviceInfo(deviceId)) {
        std::unique_lock<std::mutex> lk {dinfo->mtx_};
        auto pending = dinfo->getPendingIds();
        lk.unlock();
        return std::find_if(pending.begin(), pending.end(), [&](const auto& p) { return p.second == name; })
               != pending.end();
    }
    return false;
}

void
ConnectionManager::closeConnectionsWith(const std::string& peerUri)
{
    std::vector<std::shared_ptr<DeviceInfo>> dInfos;
    for (const auto& dinfo: pimpl_->infos_.getDeviceInfos()) {
        std::unique_lock<std::mutex> lk(dinfo->mtx_);
        bool isPeer = false;
        for (auto const& [id, cinfo]: dinfo->info) {
            std::lock_guard<std::mutex> lkv {cinfo->mutex_};
            auto tls = cinfo->tls_ ? cinfo->tls_.get() : (cinfo->socket_ ? cinfo->socket_->endpoint() : nullptr);
            auto cert = tls ? tls->peerCertificate() : nullptr;
            if (not cert)
                cert = pimpl_->certStore().getCertificate(dinfo->deviceId.toString());
            if (cert && cert->issuer && peerUri == cert->issuer->getId().toString()) {
                isPeer = true;
                break;
            }
        }
        lk.unlock();
        if (isPeer) {
            dInfos.emplace_back(std::move(dinfo));
        }
    }
    // Stop connections to all peers devices
    for (const auto& dinfo : dInfos) {
        std::unique_lock<std::mutex> lk {dinfo->mtx_};
        auto unused = dinfo->extractUnusedConnections();
        auto pending = dinfo->extractPendingOperations(0, nullptr);
        pimpl_->infos_.removeDeviceInfo(dinfo->deviceId);
        lk.unlock();
        for (auto& op : unused)
            op->shutdown();
        for (auto& op : pending)
            op.cb(nullptr, dinfo->deviceId);
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
    return pimpl_->infos_.getConnectedInfos().size();
}

void
ConnectionManager::monitor() const
{
    auto logger = pimpl_->config_->logger;
    if (!logger)
        return;
    logger->debug("ConnectionManager current status:");
    for (const auto& ci : pimpl_->infos_.getConnectedInfos()) {
        std::lock_guard<std::mutex> lk(ci->mutex_);
        if (ci->socket_)
            ci->socket_->monitor();
    }
    logger->debug("ConnectionManager end status.");
}

void
ConnectionManager::connectivityChanged()
{
    for (const auto& ci : pimpl_->infos_.getConnectedInfos()) {
        std::lock_guard<std::mutex> lk(ci->mutex_);
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
    if (device) {
        if (auto deviceInfo = pimpl_->infos_.getDeviceInfo(device)) {
            connectionsList = deviceInfo->getConnectionList(pimpl_->certStore());
        }
    } else {
        for (const auto& deviceInfo : pimpl_->infos_.getDeviceInfos()) {
            auto cl = deviceInfo->getConnectionList(pimpl_->certStore());
            connectionsList.insert(connectionsList.end(), std::make_move_iterator(cl.begin()), std::make_move_iterator(cl.end()));
        }
    }
    return connectionsList;
}

std::vector<std::map<std::string, std::string>>
ConnectionManager::getChannelList(const std::string& connectionId) const
{
    auto [deviceId, valueId] = parseCallbackId(connectionId);
    if (auto info = pimpl_->infos_.getInfo(deviceId, valueId)) {
        std::lock_guard<std::mutex> lk(info->mutex_);
        if (info->socket_)
            return info->socket_->getChannelList();
    }
    return {};
}

} // namespace dhtnet
