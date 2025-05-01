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
#include "ice_transport.h"
#include "ice_transport_factory.h"
#include "ice_socket.h"
#include "sip_utils.h"
#include "string_utils.h"
#include "upnp/upnp_control.h"
#include "transport/peer_channel.h"
#include "tracepoint/tracepoint.h"

#if __has_include(<fmt/std.h>)
#include <fmt/std.h>
#endif
#include <opendht/logger.h>
#include <opendht/utils.h>

extern "C" {
#include <pjlib.h>
}

#include <map>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <utility>
#include <tuple>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <memory>
#include <cerrno>

#include "pj/limits.h"

#define TRY(ret) \
    do { \
        if ((ret) != PJ_SUCCESS) \
            throw std::runtime_error(#ret " failed"); \
    } while (0)

// Validate that the component ID is within the expected range
#define ASSERT_COMP_ID(compId, compCount) \
    do { \
        if ((compId) == 0 or (compId) > (compCount)) \
            throw std::runtime_error("Invalid component ID " + (std::to_string(compId))); \
    } while (0)

namespace dhtnet {

static constexpr unsigned STUN_MAX_PACKET_SIZE {8192};
static constexpr uint16_t IPV6_HEADER_SIZE = 40; ///< Size in bytes of IPv6 packet header
static constexpr uint16_t IPV4_HEADER_SIZE = 20; ///< Size in bytes of IPv4 packet header
static constexpr int MAX_CANDIDATES {32};
static constexpr int MAX_DESTRUCTION_TIMEOUT {3000};
static constexpr int HANDLE_EVENT_DURATION {500};
static constexpr std::chrono::seconds PORT_MAPPING_TIMEOUT {4};
//==============================================================================

using namespace upnp;

//==============================================================================

class IceLock
{
    pj_grp_lock_t* lk_;

public:
    IceLock(pj_ice_strans* strans)
        : lk_(pj_ice_strans_get_grp_lock(strans))
    {
        lock();
    }

    ~IceLock() { unlock(); }

    void lock() { if (lk_) pj_grp_lock_acquire(lk_); }

    void unlock() { if (lk_) pj_grp_lock_release(lk_); }
};

class IceTransport::Impl
{
public:
    Impl(std::string_view name, const std::shared_ptr<Logger>& logger);
    ~Impl();

    void initIceInstance(const IceTransportOptions& options);

    void onComplete(pj_ice_strans* ice_st, pj_ice_strans_op op, pj_status_t status);

    void onReceiveData(unsigned comp_id, void* pkt, pj_size_t size);

    /**
     * Set/change transport role as initiator.
     * Should be called before start method.
     */
    bool setInitiatorSession();

    /**
     * Set/change transport role as slave.
     * Should be called before start method.
     */
    bool setSlaveSession();
    bool createIceSession(pj_ice_sess_role role);

    void getUFragPwd();

    std::string link() const;

    bool _isInitialized() const;
    bool _isStarted() const;
    bool _isRunning() const;
    bool _isFailed() const;
    bool _waitForInitialization(std::chrono::milliseconds timeout);

    const pj_ice_sess_cand* getSelectedCandidate(unsigned comp_id, bool remote) const;
    IpAddr getLocalAddress(unsigned comp_id) const;
    IpAddr getRemoteAddress(unsigned comp_id) const;
    static const char* getCandidateType(const pj_ice_sess_cand* cand);
    bool isTcpEnabled() const { return config_.protocol == PJ_ICE_TP_TCP; }
    bool addStunConfig(int af);
    void requestUpnpMappings();
    bool hasUpnp() const;
    // Take a list of address pairs (local/public) and add them as
    // reflexive candidates using STUN config.
    void addServerReflexiveCandidates(const std::vector<std::pair<IpAddr, IpAddr>>& addrList);
    // Generate server reflexive candidates using the published (DHT/Account) address
    std::vector<std::pair<IpAddr, IpAddr>> setupGenericReflexiveCandidates();
    // Generate server reflexive candidates using UPnP mappings.
    std::vector<std::pair<IpAddr, IpAddr>> setupUpnpReflexiveCandidates();
    void setDefaultRemoteAddress(unsigned comp_id, const IpAddr& addr);
    IpAddr getDefaultRemoteAddress(unsigned comp_id) const;
    bool handleEvents(unsigned max_msec);
    int flushTimerHeapAndIoQueue();
    int checkEventQueue(int maxEventToPoll);

    std::shared_ptr<dht::log::Logger> logger_ {};
    std::shared_ptr<dhtnet::IceTransportFactory> factory {};

    std::condition_variable_any iceCV_ {};

    std::string sessionName_ {};
    std::unique_ptr<pj_pool_t, decltype(&pj_pool_release)> pool_ {nullptr, pj_pool_release};
    bool isTcp_ {false};
    bool upnpEnabled_ {false};
    IceTransportCompleteCb on_initdone_cb_ {};
    IceTransportCompleteCb on_negodone_cb_ {};
    pj_ice_strans* icest_ {nullptr};
    unsigned streamsCount_ {0};
    unsigned compCountPerStream_ {0};
    unsigned compCount_ {0};
    std::string local_ufrag_ {};
    std::string local_pwd_ {};
    pj_sockaddr remoteAddr_ {};
    pj_ice_strans_cfg config_ {};
    //std::string last_errmsg_ {};

    std::atomic_bool is_stopped_ {false};

    using Packet = std::vector<uint8_t>;

    struct ComponentIO
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<Packet> queue;
        IceRecvCb recvCb;
    };

    // NOTE: Component IDs start from 1, while these three vectors
    // are indexed from 0. Conversion from ID to vector index must
    // be done properly.
    std::vector<ComponentIO> compIO_ {};
    std::vector<PeerChannel> peerChannels_ {};
    std::vector<IpAddr> iceDefaultRemoteAddr_;

    // ICE controlling role. True for controller agents and false for
    // controlled agents
    std::atomic_bool initiatorSession_ {true};

    // Local/Public addresses used by the account owning the ICE instance.
    IpAddr accountLocalAddr_ {};
    IpAddr accountPublicAddr_ {};

    // STUN and TURN servers
    std::vector<StunServerInfo> stunServers_;
    std::vector<TurnServerInfo> turnServers_;

    /**
     * Returns the IP address of each candidate for a given component in the ICE session
     */
    struct LocalCandidate
    {
        IpAddr addr;
        pj_ice_cand_transport transport;
    };


    bool onlyIPv4Private_ {true};

    // IO/Timer events are handled by following thread
    std::thread thread_ {};
    std::atomic_bool threadTerminateFlags_ {false};

    // Wait data on components
    mutable std::mutex sendDataMutex_ {};
    std::condition_variable waitDataCv_ = {};
    pj_size_t lastSentLen_ {0};
    bool destroying_ {false};
    onShutdownCb scb {};

    struct PendingMappingState {
        std::mutex mutex;
        std::condition_variable cv;
        std::map<Mapping::key_t, Mapping::sharedPtr_t> mappings;
        bool failed {false};
    };
    std::mutex upnpMappingsMutex_ {};
    std::shared_ptr<PendingMappingState> pendingState_ {};
    std::shared_ptr<upnp::Controller> upnp_ {};
    std::map<Mapping::key_t, Mapping> upnpMappings_;

    void cancelOperations()
    {
        for (auto& c : peerChannels_)
            c.stop();
        {
            std::lock_guard lk(sendDataMutex_);
            destroying_ = true;
            waitDataCv_.notify_all();
        }
        std::unique_lock lk(upnpMappingsMutex_);
        if (auto p = pendingState_) {
            lk.unlock();
            std::lock_guard lk(p->mutex);
            p->failed = true;
            p->cv.notify_all();
        }
    }
};

//==============================================================================

/**
 * Add STUN/TURN configuration or default host as candidates
 */

static void
add_stun_server(pj_pool_t& pool, pj_ice_strans_cfg& cfg, const StunServerInfo& info, const std::shared_ptr<dht::log::Logger>& logger)
{
    if (cfg.stun_tp_cnt >= PJ_ICE_MAX_STUN)
        throw std::runtime_error("Too many STUN configurations");

    IpAddr ip {info.uri};

    // Given URI is unable to be DNS resolved or not IPv4 or IPv6?
    // This prevents a crash into PJSIP when ip.toString() is called.
    if (ip.getFamily() == AF_UNSPEC) {
        /*JAMI_DBG("[ice (%s)] STUN server '%s' not used, unresolvable address",
                 (cfg.protocol == PJ_ICE_TP_TCP ? "TCP" : "UDP"),
                 info.uri.c_str());*/
        return;
    }

    auto& stun = cfg.stun_tp[cfg.stun_tp_cnt++];
    pj_ice_strans_stun_cfg_default(&stun);
    pj_strdup2_with_null(&pool, &stun.server, ip.toString().c_str());
    stun.af = ip.getFamily();
    if (!(stun.port = ip.getPort()))
        stun.port = PJ_STUN_PORT;
    stun.cfg.max_pkt_size = STUN_MAX_PACKET_SIZE;
    stun.conn_type = cfg.stun.conn_type;
    if (logger)
        logger->debug("Added STUN server '{}', port {}", pj_strbuf(&stun.server), stun.port);
}

static void
add_turn_server(pj_pool_t& pool, pj_ice_strans_cfg& cfg, const TurnServerInfo& info, const std::shared_ptr<dht::log::Logger>& logger)
{
    if (cfg.turn_tp_cnt >= PJ_ICE_MAX_TURN)
        throw std::runtime_error("Too many TURN servers");

    IpAddr ip {info.uri};

    // Same comment as add_stun_server()
    if (ip.getFamily() == AF_UNSPEC) {
        if (logger)
            logger->debug("TURN server '{}' not used, unresolvable address", info.uri);
        return;
    }

    auto& turn = cfg.turn_tp[cfg.turn_tp_cnt++];
    pj_ice_strans_turn_cfg_default(&turn);
    pj_strdup2_with_null(&pool, &turn.server, ip.toString().c_str());
    turn.af = ip.getFamily();
    if (!(turn.port = ip.getPort()))
        turn.port = PJ_STUN_PORT;
    turn.cfg.max_pkt_size = STUN_MAX_PACKET_SIZE;
    turn.conn_type = cfg.turn.conn_type;

    // Authorization (only static plain password supported yet)
    if (not info.password.empty()) {
        turn.auth_cred.type = PJ_STUN_AUTH_CRED_STATIC;
        turn.auth_cred.data.static_cred.data_type = PJ_STUN_PASSWD_PLAIN;
        pj_strset(&turn.auth_cred.data.static_cred.realm,
                  (char*) info.realm.c_str(),
                  info.realm.size());
        pj_strset(&turn.auth_cred.data.static_cred.username,
                  (char*) info.username.c_str(),
                  info.username.size());
        pj_strset(&turn.auth_cred.data.static_cred.data,
                  (char*) info.password.c_str(),
                  info.password.size());
    }
    if (logger)
        logger->debug("Added TURN server '{}', port {}", pj_strbuf(&turn.server), turn.port);
}

//==============================================================================

IceTransport::Impl::Impl(std::string_view name, const std::shared_ptr<Logger>& logger)
    : logger_(logger), sessionName_(name)
{
    if (logger_)
        logger_->debug("[ice:{}] Creating IceTransport session for \"{:s}\"", fmt::ptr(this), sessionName_);
}

IceTransport::Impl::~Impl()
{
    threadTerminateFlags_ = true;

    if (thread_.joinable()) {
        thread_.join();
    }

    if (icest_) {
        pj_ice_strans* strans = nullptr;

        std::swap(strans, icest_);

        // must be done before I/O queue/timer destruction
        if (logger_)
            logger_->debug("[ice:{}] Destroying ice_strans {}", pj_ice_strans_get_user_data(strans), fmt::ptr(strans));

        pj_ice_strans_stop_ice(strans);
        pj_ice_strans_destroy(strans);

        // NOTE: This last timer heap and I/O queue polling is necessary to close
        // TURN socket.
        // Because when destroying the TURN session pjproject creates a pj_timer
        // to postpone the TURN destruction. This timer is only called if we poll
        // the event queue.

        int ret = flushTimerHeapAndIoQueue();

        if (ret < 0) {
            if (logger_)
                logger_->error("[ice:{}] I/O queue polling failed", fmt::ptr(this));
        } else if (ret > 0) {
            if (logger_)
                logger_->warn("[ice:{}] {} timers left in timer heap.", ret, fmt::ptr(this));
        }

        if (checkEventQueue(1) > 0) {
            if (logger_)
                logger_->warn("[ice:{}] Unexpected left events in I/O queue", fmt::ptr(this));
        }

        if (config_.stun_cfg.ioqueue)
            pj_ioqueue_destroy(config_.stun_cfg.ioqueue);

        if (config_.stun_cfg.timer_heap)
            pj_timer_heap_destroy(config_.stun_cfg.timer_heap);
    }

    if (scb)
        scb();
}

void
IceTransport::Impl::initIceInstance(const IceTransportOptions& options)
{
    factory = options.factory;
    isTcp_ = options.tcpEnable;
    upnpEnabled_ = options.upnpEnable;
    on_initdone_cb_ = options.onInitDone;
    on_negodone_cb_ = options.onNegoDone;
    streamsCount_ = options.streamsCount;
    compCountPerStream_ = options.compCountPerStream;
    compCount_ = streamsCount_ * compCountPerStream_;
    compIO_ = std::vector<ComponentIO>(compCount_);
    peerChannels_ = std::vector<PeerChannel>(compCount_);
    iceDefaultRemoteAddr_.resize(compCount_);
    initiatorSession_ = options.master;
    accountLocalAddr_ = std::move(options.accountLocalAddr);
    accountPublicAddr_ = std::move(options.accountPublicAddr);
    stunServers_ = std::move(options.stunServers);
    turnServers_ = std::move(options.turnServers);

    if (logger_)
        logger_->debug("[ice:{}] Initializing the session - comp count {} - as a {}",
             fmt::ptr(this),
             compCount_,
             initiatorSession_ ? "master" : "slave");

    if (upnpEnabled_) {
        if (options.upnpContext) {
            upnp_ = std::make_shared<upnp::Controller>(options.upnpContext);
        } else if (logger_) {
            logger_->error("[ice:{}] UPnP enabled, but no context found", fmt::ptr(this));
        }
    }

    config_ = factory->getIceCfg(); // config copy
    if (isTcp_) {
        config_.protocol = PJ_ICE_TP_TCP;
        config_.stun.conn_type = PJ_STUN_TP_TCP;
        config_.turn.conn_type = PJ_TURN_TP_TCP;
    } else {
        config_.protocol = PJ_ICE_TP_UDP;
        config_.stun.conn_type = PJ_STUN_TP_UDP;
        config_.turn.conn_type = PJ_TURN_TP_UDP;
    }
    if (options.qosType.size() == 1) {
        config_.stun.cfg.qos_type = (pj_qos_type)options.qosType[0];
        config_.turn.cfg.qos_type = (pj_qos_type)options.qosType[0];
    }
    if (options.qosType.size() == compCount_) {
        for (unsigned i = 0; i < compCount_; ++i) {
            config_.comp[i].qos_type = (pj_qos_type)(options.qosType[i]);
        }
    }

    pool_.reset(
        pj_pool_create(factory->getPoolFactory(), "IceTransport.pool", 512, 512, NULL));
    if (not pool_)
        throw std::runtime_error("pj_pool_create() failed");

    // Note: For server reflexive candidates, UPnP mappings will
    // be used if available. Then, the public address learnt during
    // the account registration process will be added only if it
    // differs from the UPnP public address.
    // Also note that UPnP candidates should be added first in order
    // to have a higher priority when performing the connectivity
    // checks.
    // STUN configs layout:
    // - index 0 : host IPv4
    // - index 1 : host IPv6
    // - index 2 : UPnP/generic srflx IPv4
    // - index 3 : generic srflx (if UPnP exists and different)

    config_.stun_tp_cnt = 0;

    // if (logger_)
    //     logger_->debug("[ice:{}] Add host candidates", fmt::ptr(this));
    addStunConfig(pj_AF_INET());
    addStunConfig(pj_AF_INET6());

    std::vector<std::pair<IpAddr, IpAddr>> upnpSrflxCand;
    if (upnp_) {
        requestUpnpMappings();
        upnpSrflxCand = setupUpnpReflexiveCandidates();
        if (not upnpSrflxCand.empty()) {
            addServerReflexiveCandidates(upnpSrflxCand);
            // if (logger_)
            //     logger_->debug("[ice:{}] Added UPnP srflx candidates:", fmt::ptr(this));
        }
    }

    auto genericSrflxCand = setupGenericReflexiveCandidates();

    if (not genericSrflxCand.empty()) {
        // Generic srflx candidates will be added only if different
        // from UPnP candidates.
        if (upnpSrflxCand.empty()
            or (upnpSrflxCand[0].second.toString() != genericSrflxCand[0].second.toString())) {
            addServerReflexiveCandidates(genericSrflxCand);
            // if (logger_)
            //     logger_->debug("[ice:{}] Added generic srflx candidates:", fmt::ptr(this));
        }
    }

    if (upnpSrflxCand.empty() and genericSrflxCand.empty()) {
        if (logger_)
            logger_->warn("[ice:{}] No server reflexive candidates added", fmt::ptr(this));
    }

    pj_ice_strans_cb icecb;
    pj_bzero(&icecb, sizeof(icecb));

    icecb.on_rx_data = [](pj_ice_strans* ice_st,
                          unsigned comp_id,
                          void* pkt,
                          pj_size_t size,
                          const pj_sockaddr_t* /*src_addr*/,
                          unsigned /*src_addr_len*/) {
        if (auto* tr = static_cast<Impl*>(pj_ice_strans_get_user_data(ice_st)))
            tr->onReceiveData(comp_id, pkt, size);
    };

    icecb.on_ice_complete = [](pj_ice_strans* ice_st, pj_ice_strans_op op, pj_status_t status) {
        if (auto* tr = static_cast<Impl*>(pj_ice_strans_get_user_data(ice_st)))
            tr->onComplete(ice_st, op, status);
    };

    if (isTcp_) {
        icecb.on_data_sent = [](pj_ice_strans* ice_st, pj_ssize_t size) {
            if (auto* tr = static_cast<Impl*>(pj_ice_strans_get_user_data(ice_st))) {
                std::lock_guard lk(tr->sendDataMutex_);
                tr->lastSentLen_ += size;
                tr->waitDataCv_.notify_all();
            }
        };
    }

    icecb.on_destroy = [](pj_ice_strans* ice_st) {
        if (auto* tr = static_cast<Impl*>(pj_ice_strans_get_user_data(ice_st)))
            tr->cancelOperations(); // Avoid upper layer to manage this; Stop read operations
    };

    // Add STUN servers
    for (auto& server : stunServers_)
        add_stun_server(*pool_, config_, server, logger_);

    // Add TURN servers
    for (auto& server : turnServers_)
        add_turn_server(*pool_, config_, server, logger_);

    static constexpr auto IOQUEUE_MAX_HANDLES = std::min(PJ_IOQUEUE_MAX_HANDLES, 64);
    TRY(pj_timer_heap_create(pool_.get(), 100, &config_.stun_cfg.timer_heap));
    TRY(pj_ioqueue_create(pool_.get(), IOQUEUE_MAX_HANDLES, &config_.stun_cfg.ioqueue));
    std::ostringstream sessionName {};
    // We use the instance pointer as the PJNATH session name in order
    // to easily identify the logs reported by PJNATH.
    sessionName << this;
    pj_status_t status = pj_ice_strans_create(sessionName.str().c_str(),
                                              &config_,
                                              compCount_,
                                              this,
                                              &icecb,
                                              &icest_);

    if (status != PJ_SUCCESS || icest_ == nullptr) {
        throw std::runtime_error("pj_ice_strans_create() failed");
    }

    // Must be created after any potential failure
    thread_ = std::thread([this] {
        while (not threadTerminateFlags_) {
            // NOTE: handleEvents can return false in this case
            // but here we don't care if there is event or not.
            handleEvents(HANDLE_EVENT_DURATION);
        }
    });
}

bool
IceTransport::Impl::_isInitialized() const
{
    if (auto *icest = icest_) {
        auto state = pj_ice_strans_get_state(icest);
        return state >= PJ_ICE_STRANS_STATE_SESS_READY and state != PJ_ICE_STRANS_STATE_FAILED;
    }
    return false;
}

bool
IceTransport::Impl::_isStarted() const
{
    if (auto *icest = icest_) {
        auto state = pj_ice_strans_get_state(icest);
        return state >= PJ_ICE_STRANS_STATE_NEGO and state != PJ_ICE_STRANS_STATE_FAILED;
    }
    return false;
}

bool
IceTransport::Impl::_isRunning() const
{
    if (auto *icest = icest_) {
        auto state = pj_ice_strans_get_state(icest);
        return state >= PJ_ICE_STRANS_STATE_RUNNING and state != PJ_ICE_STRANS_STATE_FAILED;
    }
    return false;
}

bool
IceTransport::Impl::_isFailed() const
{
    if (auto *icest = icest_)
        return pj_ice_strans_get_state(icest) == PJ_ICE_STRANS_STATE_FAILED;
    return false;
}

bool
IceTransport::Impl::handleEvents(unsigned max_msec)
{
    // By tests, never seen more than two events per 500ms
    static constexpr auto MAX_NET_EVENTS = 2;

    pj_time_val max_timeout = {0, static_cast<long>(max_msec)};
    pj_time_val timeout = {0, 0};
    unsigned net_event_count = 0;

    pj_timer_heap_poll(config_.stun_cfg.timer_heap, &timeout);
    auto hasActiveTimer = timeout.sec != PJ_MAXINT32 || timeout.msec != PJ_MAXINT32;

    // timeout limitation
    if (hasActiveTimer)
        pj_time_val_normalize(&timeout);

    if (PJ_TIME_VAL_GT(timeout, max_timeout)) {
        timeout = max_timeout;
    }

    do {
        auto n_events = pj_ioqueue_poll(config_.stun_cfg.ioqueue, &timeout);

        // timeout
        if (not n_events)
            return hasActiveTimer;

        // error
        if (n_events < 0) {
            const auto err = pj_get_os_error();
            // Kept as debug as some errors are "normal" in regular context
            if (logger_)
                logger_->debug("[ice:{}] I/O queue error {:d}: {:s}", fmt::ptr(this), err, sip_utils::sip_strerror(err));
            std::this_thread::sleep_for(std::chrono::milliseconds(PJ_TIME_VAL_MSEC(timeout)));
            return hasActiveTimer;
        }

        net_event_count += n_events;
        timeout.sec = timeout.msec = 0;
    } while (net_event_count < MAX_NET_EVENTS);
    return hasActiveTimer;
}

int
IceTransport::Impl::flushTimerHeapAndIoQueue()
{
    pj_time_val timerTimeout = {0, 0};
    pj_time_val defaultWaitTime = {0, HANDLE_EVENT_DURATION};
    bool hasActiveTimer = false;
    std::chrono::milliseconds totalWaitTime {0};
    // auto const start = std::chrono::steady_clock::now();
    // We try to process pending events as fast as possible to
    // speed-up the release.
    int maxEventToProcess = 10;

    do {
        if (checkEventQueue(maxEventToProcess) < 0)
            return -1;

        pj_timer_heap_poll(config_.stun_cfg.timer_heap, &timerTimeout);
        hasActiveTimer = !(timerTimeout.sec == PJ_MAXINT32 && timerTimeout.msec == PJ_MAXINT32);

        if (hasActiveTimer) {
            pj_time_val_normalize(&timerTimeout);
            auto waitTime = std::chrono::milliseconds(
                std::min(PJ_TIME_VAL_MSEC(timerTimeout), PJ_TIME_VAL_MSEC(defaultWaitTime)));
            std::this_thread::sleep_for(waitTime);
            totalWaitTime += waitTime;
        }
    } while (hasActiveTimer && totalWaitTime < std::chrono::milliseconds(MAX_DESTRUCTION_TIMEOUT));

    // auto duration = std::chrono::steady_clock::now() - start;
    // if (logger_)
    //     logger_->debug("[ice:{}] Timer heap flushed after {}", fmt::ptr(this), dht::print_duration(duration));

    return static_cast<int>(pj_timer_heap_count(config_.stun_cfg.timer_heap));
}

int
IceTransport::Impl::checkEventQueue(int maxEventToPoll)
{
    pj_time_val timeout = {0, 0};
    int eventCount = 0;
    int events = 0;

    do {
        events = pj_ioqueue_poll(config_.stun_cfg.ioqueue, &timeout);
        if (events < 0) {
            const auto err = pj_get_os_error();
            if (logger_)
                logger_->error("[ice:{}] I/O queue error {:d}: {:s}", fmt::ptr(this), err, sip_utils::sip_strerror(err));
            return events;
        }

        eventCount += events;

    } while (events > 0 && eventCount < maxEventToPoll);

    return eventCount;
}

void
IceTransport::Impl::onComplete(pj_ice_strans*, pj_ice_strans_op op, pj_status_t status)
{
    const char* opname = op == PJ_ICE_STRANS_OP_INIT          ? "initialization"
                         : op == PJ_ICE_STRANS_OP_NEGOTIATION ? "negotiation"
                                                              : "unknown_op";

    const bool done = status == PJ_SUCCESS;
    if (done) {
        if (logger_)
            logger_->debug("[ice:{}] {:s} {:s} success",
                    fmt::ptr(this),
                    (config_.protocol == PJ_ICE_TP_TCP ? "TCP" : "UDP"),
                    opname);
    } else {
        if (logger_)
            logger_->error("[ice:{}] {:s} {:s} failed: {:s}",
                 fmt::ptr(this),
                 (config_.protocol == PJ_ICE_TP_TCP ? "TCP" : "UDP"),
                 opname,
                 sip_utils::sip_strerror(status));
    }

    if (done and op == PJ_ICE_STRANS_OP_INIT) {
        if (initiatorSession_)
            setInitiatorSession();
        else
            setSlaveSession();
    }

    if (op == PJ_ICE_STRANS_OP_INIT and on_initdone_cb_)
        on_initdone_cb_(done);
    else if (op == PJ_ICE_STRANS_OP_NEGOTIATION) {
        if (done) {
            // Dump of connection pairs
            if (logger_)
                logger_->debug("[ice:{}] {:s} connection pairs ([comp id] local [type] ↔ remote [type]):\n{:s}",
                     fmt::ptr(this),
                     (config_.protocol == PJ_ICE_TP_TCP ? "TCP" : "UDP"),
                     link());
        }
        if (on_negodone_cb_)
            on_negodone_cb_(done);
    }

    iceCV_.notify_all();
}

std::string
IceTransport::Impl::link() const
{
    std::ostringstream out;
    for (unsigned strm = 1; strm <= streamsCount_ * compCountPerStream_; strm++) {
        auto absIdx = strm;
        auto comp = (strm + 1) / compCountPerStream_;
        auto laddr = getLocalAddress(absIdx);
        auto raddr = getRemoteAddress(absIdx);

        if (laddr and laddr.getPort() != 0 and raddr and raddr.getPort() != 0) {
            out << " [" << comp << "] " << laddr.toString(true, true) << " ["
                << getCandidateType(getSelectedCandidate(absIdx, false)) << "] "
                << " ↔ " << raddr.toString(true, true) << " ["
                << getCandidateType(getSelectedCandidate(absIdx, true)) << "] " << '\n';
        } else {
            out << " [" << comp << "] disabled\n";
        }
    }
    return out.str();
}

bool
IceTransport::Impl::setInitiatorSession()
{
    if (logger_)
        logger_->debug("[ice:{}] as master", fmt::ptr(this));
    initiatorSession_ = true;
    if (_isInitialized()) {
        auto status = pj_ice_strans_change_role(icest_, PJ_ICE_SESS_ROLE_CONTROLLING);
        if (status != PJ_SUCCESS) {
            if (logger_)
                logger_->error("[ice:{}] Role change failed: {:s}", fmt::ptr(this), sip_utils::sip_strerror(status));
            return false;
        }
        return true;
    }
    return createIceSession(PJ_ICE_SESS_ROLE_CONTROLLING);
}

bool
IceTransport::Impl::setSlaveSession()
{
    if (logger_)
        logger_->debug("[ice:{}] as slave", fmt::ptr(this));
    initiatorSession_ = false;
    if (_isInitialized()) {
        auto status = pj_ice_strans_change_role(icest_, PJ_ICE_SESS_ROLE_CONTROLLED);
        if (status != PJ_SUCCESS) {
            if (logger_)
                logger_->error("[ice:{}] Role change failed: {:s}", fmt::ptr(this), sip_utils::sip_strerror(status));
            return false;
        }
        return true;
    }
    return createIceSession(PJ_ICE_SESS_ROLE_CONTROLLED);
}

const pj_ice_sess_cand*
IceTransport::Impl::getSelectedCandidate(unsigned comp_id, bool remote) const
{
    ASSERT_COMP_ID(comp_id, compCount_);

    // Return the selected candidate pair. Might not be the nominated pair if
    // ICE has not concluded yet, but should be the nominated pair afterwards.
    if (not _isRunning()) {
        if (logger_)
            logger_->error("[ice:{}] ICE transport is not running", fmt::ptr(this));
        return nullptr;
    }

    const auto* sess = pj_ice_strans_get_valid_pair(icest_, comp_id);
    if (sess == nullptr) {
        if (logger_)
            logger_->warn("[ice:{}] Component {} has no valid pair (disabled)", fmt::ptr(this), comp_id);
        return nullptr;
    }

    if (remote)
        return sess->rcand;
    else
        return sess->lcand;
}

IpAddr
IceTransport::Impl::getLocalAddress(unsigned comp_id) const
{
    ASSERT_COMP_ID(comp_id, compCount_);

    if (auto cand = getSelectedCandidate(comp_id, false))
        return cand->addr;

    return {};
}

IpAddr
IceTransport::Impl::getRemoteAddress(unsigned comp_id) const
{
    ASSERT_COMP_ID(comp_id, compCount_);

    if (auto cand = getSelectedCandidate(comp_id, true))
        return cand->addr;

    return {};
}

const char*
IceTransport::Impl::getCandidateType(const pj_ice_sess_cand* cand)
{
    auto name = cand ? pj_ice_get_cand_type_name(cand->type) : nullptr;
    return name ? name : "?";
}

void
IceTransport::Impl::getUFragPwd()
{
    if (icest_) {
        pj_str_t local_ufrag, local_pwd;

        pj_ice_strans_get_ufrag_pwd(icest_, &local_ufrag, &local_pwd, nullptr, nullptr);
        local_ufrag_.assign(local_ufrag.ptr, local_ufrag.slen);
        local_pwd_.assign(local_pwd.ptr, local_pwd.slen);
    }
}

bool
IceTransport::Impl::createIceSession(pj_ice_sess_role role)
{
    if (not icest_) {
        return false;
    }

    if (pj_ice_strans_init_ice(icest_, role, nullptr, nullptr) != PJ_SUCCESS) {
        if (logger_)
            logger_->error("[ice:{}] pj_ice_strans_init_ice() failed", fmt::ptr(this));
        return false;
    }

    // Fetch some information on local configuration
    getUFragPwd();

    if (logger_)
        logger_->debug("[ice:{}] (local) ufrag={}, pwd={}", fmt::ptr(this), local_ufrag_, local_pwd_);

    return true;
}

bool
IceTransport::Impl::addStunConfig(int af)
{
    if (config_.stun_tp_cnt >= PJ_ICE_MAX_STUN) {
        if (logger_)
            logger_->error("Max number of STUN configurations reached ({})", PJ_ICE_MAX_STUN);
        return false;
    }

    if (af != pj_AF_INET() and af != pj_AF_INET6()) {
        if (logger_)
            logger_->error("Invalid address family ({})", af);
        return false;
    }

    auto& stun = config_.stun_tp[config_.stun_tp_cnt++];

    pj_ice_strans_stun_cfg_default(&stun);
    stun.cfg.max_pkt_size = STUN_MAX_PACKET_SIZE;
    stun.af = af;
    stun.conn_type = config_.stun.conn_type;

    // if (logger_)
    //     logger_->debug("[ice:{}] Added host STUN config for {:s} transport",
    //         fmt::ptr(this),
    //         config_.protocol == PJ_ICE_TP_TCP ? "TCP" : "UDP");

    return true;
}

void
IceTransport::Impl::requestUpnpMappings()
{
    if (not upnp_)
        return;
    auto transport = isTcpEnabled() ? PJ_CAND_TCP_PASSIVE : PJ_CAND_UDP;
    auto portType = transport == PJ_CAND_UDP ? PortType::UDP : PortType::TCP;

    // Use a different map instead of upnpMappings_ to store pointers to the mappings
    auto state = std::make_shared<PendingMappingState>();
    {
        std::lock_guard lockMapping(upnpMappingsMutex_);
        pendingState_ = state;
    }

    // Request UPnP mapping for each component.
    for (unsigned id = 1; id <= compCount_; id++) {
        // Set port number to 0 to get any available port.
        Mapping requestedMap(portType);

        requestedMap.setNotifyCallback([state, l=logger_](Mapping::sharedPtr_t mapPtr) {
            // Ignore intermediate states: PENDING, IN_PROGRESS
            // only OPEN and FAILED are considered

            // if the mapping is open check the validity
            std::lock_guard lockMapping(state->mutex);
            if ((mapPtr->getState() == MappingState::OPEN)) {
                if (mapPtr->getMapKey() and mapPtr->hasValidHostAddress()){
                    state->mappings.emplace(mapPtr->getMapKey(), std::move(mapPtr));
                } else {
                    state->failed = true;
                }
            } else if (mapPtr->getState() == MappingState::FAILED) {
                state->failed = true;
                if (l)
                    l->error("UPnP mapping failed: {:s}",
                        mapPtr->toString(true));
            }
            state->cv.notify_all();
        });
        // Request the mapping
        upnp_->reserveMapping(requestedMap);
    }

    std::unique_lock lock(state->mutex);
    state->cv.wait_for(lock, PORT_MAPPING_TIMEOUT, [&] {
        return state->failed || state->mappings.size() == compCount_;
    });
    // Remove the notify callback
    for (auto& map : state->mappings) {
        map.second->setNotifyCallback(nullptr);
    }
    std::lock_guard lockMapping(upnpMappingsMutex_);
    pendingState_.reset();

    // Check the number of mappings
    if (state->failed || state->mappings.size() != compCount_) {
        if (logger_)
            logger_->error("[ice:{}] UPnP mapping failed: expected {:d} mapping(s), got {:d}",
                fmt::ptr(this),
                compCount_,
                state->mappings.size());
        // Release all mappings
        for (auto& map : state->mappings) {
            upnp_->releaseMapping(*map.second);
        }
    } else {
        for (auto& map : state->mappings) {
            if(logger_)
                logger_->debug("[ice:{}] UPnP mapping {:s} successfully allocated\n",
                    fmt::ptr(this),
                    map.second->toString(true));
            upnpMappings_.emplace(map.first, *map.second);
        }
    }
}

bool
IceTransport::Impl::hasUpnp() const
{
    return upnp_ and upnpMappings_.size() == compCount_;
}

void
IceTransport::Impl::addServerReflexiveCandidates(
    const std::vector<std::pair<IpAddr, IpAddr>>& addrList)
{
    if (addrList.size() != compCount_) {
        if (logger_)
            logger_->warn("[ice:{}] Provided addr list size {} does not match component count {}",
                  fmt::ptr(this),
                  addrList.size(),
                  compCount_);
        return;
    }
    if (compCount_ > PJ_ICE_MAX_COMP) {
        if (logger_)
            logger_->error("[ice:{}] Too many components", fmt::ptr(this));
        return;
    }

    // Add config for server reflexive candidates (UPnP or from DHT).
    if (not addStunConfig(pj_AF_INET()))
        return;

    assert(config_.stun_tp_cnt > 0 && config_.stun_tp_cnt < PJ_ICE_MAX_STUN);
    auto& stun = config_.stun_tp[config_.stun_tp_cnt - 1];

    for (unsigned id = 1; id <= compCount_; id++) {
        auto idx = id - 1;
        auto& localAddr = addrList[idx].first;
        auto& publicAddr = addrList[idx].second;

        if (logger_)
            logger_->debug("[ice:{}] Add srflx reflexive candidates [{:s} : {:s}] for comp {:d}",
                 fmt::ptr(this),
                 localAddr.toString(true),
                 publicAddr.toString(true),
                 id);

        pj_sockaddr_cp(&stun.cfg.user_mapping[idx].local_addr, localAddr.pjPtr());
        pj_sockaddr_cp(&stun.cfg.user_mapping[idx].mapped_addr, publicAddr.pjPtr());

        if (isTcpEnabled()) {
            if (publicAddr.getPort() == 9) {
                stun.cfg.user_mapping[idx].tp_type = PJ_CAND_TCP_ACTIVE;
            } else {
                stun.cfg.user_mapping[idx].tp_type = PJ_CAND_TCP_PASSIVE;
            }
        } else {
            stun.cfg.user_mapping[idx].tp_type = PJ_CAND_UDP;
        }
    }

    stun.cfg.user_mapping_cnt = compCount_;
}

std::vector<std::pair<IpAddr, IpAddr>>
IceTransport::Impl::setupGenericReflexiveCandidates()
{
    if (not accountLocalAddr_) {
        if (logger_)
            logger_->warn("[ice:{}] Missing local address, generic srflx candidates unable to be generated!",
                  fmt::ptr(this));
        return {};
    }

    if (not accountPublicAddr_) {
        if (logger_)
            logger_->warn("[ice:{}] Missing public address, generic srflx candidates unable to be generated!",
                  fmt::ptr(this));
        return {};
    }

    std::vector<std::pair<IpAddr, IpAddr>> addrList;
    auto isTcp = isTcpEnabled();

    addrList.reserve(compCount_);
    for (unsigned id = 1; id <= compCount_; id++) {
        // For TCP, the type is set to active, because most likely the incoming
        // connection will be blocked by the NAT.
        // For UDP use random port number.
        uint16_t port = isTcp ? 9
                              : upnp::Controller::generateRandomPort(isTcp ? PortType::TCP
                                                                           : PortType::UDP);

        accountLocalAddr_.setPort(port);
        accountPublicAddr_.setPort(port);
        addrList.emplace_back(accountLocalAddr_, accountPublicAddr_);
    }

    return addrList;
}

std::vector<std::pair<IpAddr, IpAddr>>
IceTransport::Impl::setupUpnpReflexiveCandidates()
{
    // Add UPnP server reflexive candidates if available.
    if (not hasUpnp())
        return {};

    std::lock_guard lock(upnpMappingsMutex_);

    if (upnpMappings_.size() < (size_t)compCount_) {
        if (logger_)
            logger_->warn("[ice:{}] Not enough mappings {:d}. Expected {:d}",
                  fmt::ptr(this),
                  upnpMappings_.size(),
                  compCount_);
        return {};
    }

    std::vector<std::pair<IpAddr, IpAddr>> addrList;

    addrList.reserve(upnpMappings_.size());
    for (auto const& [_, map] : upnpMappings_) {
        assert(map.getMapKey());
        IpAddr localAddr {map.getInternalAddress()};
        localAddr.setPort(map.getInternalPort());
        IpAddr publicAddr {map.getExternalAddress()};
        publicAddr.setPort(map.getExternalPort());
        addrList.emplace_back(localAddr, publicAddr);
    }

    return addrList;
}

void
IceTransport::Impl::setDefaultRemoteAddress(unsigned compId, const IpAddr& addr)
{
    ASSERT_COMP_ID(compId, compCount_);

    iceDefaultRemoteAddr_[compId - 1] = addr;
    // The port does not matter. Set it 0 to avoid confusion.
    iceDefaultRemoteAddr_[compId - 1].setPort(0);
}

IpAddr
IceTransport::Impl::getDefaultRemoteAddress(unsigned compId) const
{
    if (compId > compCount_) {
        if (logger_)
            logger_->error("[ice:{}] Invalid component id {:d}", fmt::ptr(this), compId);
        return {};
    }
    return iceDefaultRemoteAddr_[compId - 1];
}

void
IceTransport::Impl::onReceiveData(unsigned comp_id, void* pkt, pj_size_t size)
{
    ASSERT_COMP_ID(comp_id, compCount_);

    jami_tracepoint_if_enabled(ice_transport_recv,
                               reinterpret_cast<uint64_t>(this),
                               comp_id,
                               size,
                               getRemoteAddress(comp_id).toString().c_str());
    if (size == 0)
        return;

    {
        auto& io = compIO_[comp_id - 1];
        std::lock_guard lk(io.mutex);

        if (io.recvCb) {
            io.recvCb((uint8_t*) pkt, size);
            return;
        }
    }

    std::error_code ec;
    auto err = peerChannels_.at(comp_id - 1).write((const char*) pkt, size, ec);
    if (err < 0) {
        if (logger_)
            logger_->error("[ice:{}] rx: channel is closed", fmt::ptr(this));
    }
}

bool
IceTransport::Impl::_waitForInitialization(std::chrono::milliseconds timeout)
{
    IceLock lk(icest_);

    if (not iceCV_.wait_for(lk, timeout, [this] {
            return threadTerminateFlags_ or _isInitialized() or _isFailed();
        })) {
        if (logger_)
            logger_->warn("[ice:{}] waitForInitialization: timeout", fmt::ptr(this));
        return false;
    }

    return _isInitialized();
}

//==============================================================================

IceTransport::IceTransport(std::string_view name, const std::shared_ptr<dht::log::Logger>& logger)
    : pimpl_ {std::make_unique<Impl>(name, logger)}
{}

IceTransport::~IceTransport()
{
    cancelOperations();
}

const std::shared_ptr<dht::log::Logger>&
IceTransport::logger() const
{
    return pimpl_->logger_;
}

void
IceTransport::initIceInstance(const IceTransportOptions& options)
{
    pimpl_->initIceInstance(options);
    jami_tracepoint(ice_transport_context, reinterpret_cast<uint64_t>(this));
}

bool
IceTransport::isInitialized() const
{
    IceLock lk(pimpl_->icest_);
    return pimpl_->_isInitialized();
}

bool
IceTransport::isStarted() const
{
    IceLock lk(pimpl_->icest_);
    return pimpl_->_isStarted();
}

bool
IceTransport::isRunning() const
{
    if (!pimpl_->icest_)
        return false;
    IceLock lk(pimpl_->icest_);
    return pimpl_->_isRunning();
}

bool
IceTransport::isFailed() const
{
    return pimpl_->_isFailed();
}

unsigned
IceTransport::getComponentCount() const
{
    return pimpl_->compCount_;
}

bool
IceTransport::setSlaveSession()
{
    return pimpl_->setSlaveSession();
}
bool
IceTransport::setInitiatorSession()
{
    return pimpl_->setInitiatorSession();
}

bool
IceTransport::isInitiator() const
{
    if (isInitialized()) {
        return pj_ice_strans_get_role(pimpl_->icest_) == PJ_ICE_SESS_ROLE_CONTROLLING;
    }
    return pimpl_->initiatorSession_;
}

bool
IceTransport::startIce(const Attribute& rem_attrs, std::vector<IceCandidate>&& rem_candidates)
{
    if (not isInitialized()) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] Uninitialized transport", fmt::ptr(pimpl_.get()));
        pimpl_->is_stopped_ = true;
        return false;
    }

    // pj_ice_strans_start_ice crashes if remote candidates array is empty
    if (rem_candidates.empty()) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] Start failed: no remote candidates", fmt::ptr(pimpl_.get()));
        pimpl_->is_stopped_ = true;
        return false;
    }

    auto comp_cnt = std::max(1u, getComponentCount());
    if (rem_candidates.size() / comp_cnt > PJ_ICE_ST_MAX_CAND - 1) {
        std::vector<IceCandidate> rcands;
        rcands.reserve(PJ_ICE_ST_MAX_CAND - 1);
        if (pimpl_->logger_)
            pimpl_->logger_->warn("[ice:{}] Too many candidates detected, trim list.", fmt::ptr(pimpl_.get()));
        // Just trim some candidates. To avoid to only take host candidates, iterate
        // through the whole list and select some host, some turn and peer reflexives
        // It should give at least enough infos to negotiate.
        auto maxHosts = 8;
        auto maxRelays = PJ_ICE_MAX_TURN;
        for (auto& c : rem_candidates) {
            if (c.type == PJ_ICE_CAND_TYPE_HOST) {
                if (maxHosts == 0)
                    continue;
                maxHosts -= 1;
            } else if (c.type == PJ_ICE_CAND_TYPE_RELAYED) {
                if (maxRelays == 0)
                    continue;
                maxRelays -= 1;
            }
            if (rcands.size() == PJ_ICE_ST_MAX_CAND - 1)
                break;
            rcands.emplace_back(std::move(c));
        }
        rem_candidates = std::move(rcands);
    }

    pj_str_t ufrag, pwd;
    if (pimpl_->logger_)
        pimpl_->logger_->debug("[ice:{}] Negotiation starting {:d} remote candidate(s)",
             fmt::ptr(pimpl_),
             rem_candidates.size());

    auto status = pj_ice_strans_start_ice(pimpl_->icest_,
                                          pj_strset(&ufrag,
                                                    (char*) rem_attrs.ufrag.c_str(),
                                                    rem_attrs.ufrag.size()),
                                          pj_strset(&pwd,
                                                    (char*) rem_attrs.pwd.c_str(),
                                                    rem_attrs.pwd.size()),
                                          rem_candidates.size(),
                                          rem_candidates.data());
    if (status != PJ_SUCCESS) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] Start failed: {:s}", fmt::ptr(pimpl_.get()), sip_utils::sip_strerror(status));
        pimpl_->is_stopped_ = true;
        return false;
    }

    return true;
}

bool
IceTransport::startIce(const SDP& sdp)
{
    if (pimpl_->streamsCount_ != 1) {
        if (pimpl_->logger_)
            pimpl_->logger_->error(FMT_STRING("Expected exactly one stream per SDP, found {:d} stream(s)"), pimpl_->streamsCount_);
        return false;
    }

    if (not isInitialized()) {
        if (pimpl_->logger_)
            pimpl_->logger_->error(FMT_STRING("[ice:{}] Uninitialized transport"), fmt::ptr(pimpl_));
        pimpl_->is_stopped_ = true;
        return false;
    }

    for (unsigned id = 1; id <= getComponentCount(); id++) {
        auto candVec = getLocalCandidates(id);
        for (auto const& cand : candVec) {
            if (pimpl_->logger_)
                pimpl_->logger_->debug("[ice:{}] Using local candidate {:s} for comp {:d}",
                     fmt::ptr(pimpl_), cand, id);
        }
    }

    if (pimpl_->logger_)
        pimpl_->logger_->debug("[ice:{}] Negotiation starting {:u} remote candidate(s)",
             fmt::ptr(pimpl_), sdp.candidates.size());
    pj_str_t ufrag, pwd;

    std::vector<IceCandidate> rem_candidates;
    rem_candidates.reserve(sdp.candidates.size());
    IceCandidate cand;
    for (const auto& line : sdp.candidates) {
        if (parseIceAttributeLine(0, line, cand))
            rem_candidates.emplace_back(cand);
    }

    auto status = pj_ice_strans_start_ice(pimpl_->icest_,
                                          pj_strset(&ufrag,
                                                    (char*) sdp.ufrag.c_str(),
                                                    sdp.ufrag.size()),
                                          pj_strset(&pwd, (char*) sdp.pwd.c_str(), sdp.pwd.size()),
                                          rem_candidates.size(),
                                          rem_candidates.data());
    if (status != PJ_SUCCESS) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] Start failed: {:s}", fmt::ptr(pimpl_), sip_utils::sip_strerror(status));
        pimpl_->is_stopped_ = true;
        return false;
    }

    return true;
}

void
IceTransport::cancelOperations()
{
    pimpl_->cancelOperations();
}

IpAddr
IceTransport::getLocalAddress(unsigned comp_id) const
{
    return pimpl_->getLocalAddress(comp_id);
}

IpAddr
IceTransport::getRemoteAddress(unsigned comp_id) const
{
    // Return the default remote address if set.
    // Note that the default remote addresses are the addresses
    // set in the 'c=' and 'a=rtcp' lines of the received SDP.
    // See pj_ice_strans_sendto2() for more details.
    if (auto defaultAddr = pimpl_->getDefaultRemoteAddress(comp_id)) {
        return defaultAddr;
    }

    return pimpl_->getRemoteAddress(comp_id);
}

const IceTransport::Attribute
IceTransport::getLocalAttributes() const
{
    return {pimpl_->local_ufrag_, pimpl_->local_pwd_};
}

std::vector<std::string>
IceTransport::getLocalCandidates(unsigned comp_id) const
{
    ASSERT_COMP_ID(comp_id, getComponentCount());
    std::vector<std::string> res;
    pj_ice_sess_cand cand[MAX_CANDIDATES];
    unsigned cand_cnt = PJ_ARRAY_SIZE(cand);

    if (!isInitialized()) {
        return res;
    }

    if (pj_ice_strans_enum_cands(pimpl_->icest_, comp_id, &cand_cnt, cand) != PJ_SUCCESS) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] pj_ice_strans_enum_cands() failed", fmt::ptr(pimpl_));
        return res;
    }

    res.reserve(cand_cnt);
    for (unsigned i = 0; i < cand_cnt; ++i) {
        /**   Section 4.5, RFC 6544 (https://tools.ietf.org/html/rfc6544)
         *    candidate-attribute   = "candidate" ":" foundation SP component-id
         * SP "TCP" SP priority SP connection-address SP port SP cand-type [SP
         * rel-addr] [SP rel-port] SP tcp-type-ext
         *                             *(SP extension-att-name SP
         *                                  extension-att-value)
         *
         *     tcp-type-ext          = "tcptype" SP tcp-type
         *     tcp-type              = "active" / "passive" / "so"
         */
        char ipaddr[PJ_INET6_ADDRSTRLEN];
        std::string tcp_type;
        if (cand[i].transport != PJ_CAND_UDP) {
            tcp_type += " tcptype";
            switch (cand[i].transport) {
            case PJ_CAND_TCP_ACTIVE:
                tcp_type += " active";
                break;
            case PJ_CAND_TCP_PASSIVE:
                tcp_type += " passive";
                break;
            case PJ_CAND_TCP_SO:
            default:
                tcp_type += " so";
                break;
            }
        }
        res.emplace_back(
            fmt::format("{} {} {} {} {} {} typ {}{}",
                        sip_utils::as_view(cand[i].foundation),
                        cand[i].comp_id,
                        (cand[i].transport == PJ_CAND_UDP ? "UDP" : "TCP"),
                        cand[i].prio,
                        pj_sockaddr_print(&cand[i].addr, ipaddr, sizeof(ipaddr), 0),
                        pj_sockaddr_get_port(&cand[i].addr),
                        pj_ice_get_cand_type_name(cand[i].type),
                        tcp_type));
    }

    return res;
}
std::vector<std::string>
IceTransport::getLocalCandidates(unsigned streamIdx, unsigned compId) const
{
    ASSERT_COMP_ID(compId, getComponentCount());

    std::vector<std::string> res;
    pj_ice_sess_cand cand[MAX_CANDIDATES];
    unsigned cand_cnt = MAX_CANDIDATES;

    if (not isInitialized()) {
        return res;
    }

    // In the implementation, the component IDs are enumerated globally
    // (per SDP: 1, 2, 3, 4, …). This is simpler because we create
    // only one pj_ice_strans instance. However, the component IDs are
    // enumerated per stream in the generated SDP (1, 2, 1, 2, …) in
    // order to be compliant with the spec.

    auto globalCompId = streamIdx * 2 + compId;
    if (pj_ice_strans_enum_cands(pimpl_->icest_, globalCompId, &cand_cnt, cand) != PJ_SUCCESS) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] pj_ice_strans_enum_cands() failed", fmt::ptr(pimpl_));
        return res;
    }

    res.reserve(cand_cnt);
    // Build ICE attributes according to RFC 6544, section 4.5.
    for (unsigned i = 0; i < cand_cnt; ++i) {
        char ipaddr[PJ_INET6_ADDRSTRLEN];
        std::string tcp_type;
        if (cand[i].transport != PJ_CAND_UDP) {
            tcp_type += " tcptype";
            switch (cand[i].transport) {
            case PJ_CAND_TCP_ACTIVE:
                tcp_type += " active";
                break;
            case PJ_CAND_TCP_PASSIVE:
                tcp_type += " passive";
                break;
            case PJ_CAND_TCP_SO:
            default:
                tcp_type += " so";
                break;
            }
        }
        res.emplace_back(
            fmt::format("{} {} {} {} {} {} typ {}{}",
                        sip_utils::as_view(cand[i].foundation),
                        compId,
                        (cand[i].transport == PJ_CAND_UDP ? "UDP" : "TCP"),
                        cand[i].prio,
                        pj_sockaddr_print(&cand[i].addr, ipaddr, sizeof(ipaddr), 0),
                        pj_sockaddr_get_port(&cand[i].addr),
                        pj_ice_get_cand_type_name(cand[i].type),
                        tcp_type));
    }

    return res;
}

bool
IceTransport::parseIceAttributeLine(unsigned streamIdx,
                                    const std::string& line,
                                    IceCandidate& cand) const
{
    // Silently ignore empty lines
    if (line.empty())
        return false;

    if (streamIdx >= pimpl_->streamsCount_) {
        throw std::runtime_error(fmt::format("Stream index {:d} is invalid!", streamIdx));
    }

    int af, cnt;
    char foundation[32], transport[12], ipaddr[80], type[32], tcp_type[32];
    pj_str_t tmpaddr;
    unsigned comp_id, prio, port;
    pj_status_t status;
    pj_bool_t is_tcp = PJ_FALSE;

    // Parse ICE attribute line according to RFC-6544 section 4.5.
    // TODO/WARNING: There is no fail-safe in case of malformed attributes.
    cnt = sscanf(line.c_str(),
                 "%31s %u %11s %u %79s %u typ %31s tcptype %31s\n",
                 foundation,
                 &comp_id,
                 transport,
                 &prio,
                 ipaddr,
                 &port,
                 type,
                 tcp_type);
    if (cnt != 7 && cnt != 8) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] Invalid ICE candidate line: {:s}", fmt::ptr(pimpl_), line);
        return false;
    }

    if (strcmp(transport, "TCP") == 0) {
        is_tcp = PJ_TRUE;
    }

    pj_bzero(&cand, sizeof(IceCandidate));

    if (strcmp(type, "host") == 0)
        cand.type = PJ_ICE_CAND_TYPE_HOST;
    else if (strcmp(type, "srflx") == 0)
        cand.type = PJ_ICE_CAND_TYPE_SRFLX;
    else if (strcmp(type, "prflx") == 0)
        cand.type = PJ_ICE_CAND_TYPE_PRFLX;
    else if (strcmp(type, "relay") == 0)
        cand.type = PJ_ICE_CAND_TYPE_RELAYED;
    else {
        if (pimpl_->logger_)
            pimpl_->logger_->warn("[ice:{}] Invalid remote candidate type '{:s}'", fmt::ptr(pimpl_), type);
        return false;
    }

    if (is_tcp) {
        if (strcmp(tcp_type, "active") == 0)
            cand.transport = PJ_CAND_TCP_ACTIVE;
        else if (strcmp(tcp_type, "passive") == 0)
            cand.transport = PJ_CAND_TCP_PASSIVE;
        else if (strcmp(tcp_type, "so") == 0)
            cand.transport = PJ_CAND_TCP_SO;
        else {
            if (pimpl_->logger_)
                pimpl_->logger_->warn("[ice:{}] Invalid transport type type '{:s}'", fmt::ptr(pimpl_), tcp_type);
            return false;
        }
    } else {
        cand.transport = PJ_CAND_UDP;
    }

    // If the component ID is enumerated relative to media, convert
    // it to absolute enumeration.
    if (comp_id <= pimpl_->compCountPerStream_) {
        comp_id += pimpl_->compCountPerStream_ * streamIdx;
    }
    cand.comp_id = (pj_uint8_t) comp_id;

    cand.prio = prio;

    if (strchr(ipaddr, ':'))
        af = pj_AF_INET6();
    else {
        af = pj_AF_INET();
        pimpl_->onlyIPv4Private_ &= IpAddr(ipaddr).isPrivate();
    }

    tmpaddr = pj_str(ipaddr);
    pj_sockaddr_init(af, &cand.addr, NULL, 0);
    status = pj_sockaddr_set_str_addr(af, &cand.addr, &tmpaddr);
    if (status != PJ_SUCCESS) {
        if (pimpl_->logger_)
            pimpl_->logger_->warn("[ice:{}] Invalid IP address '{:s}'", fmt::ptr(pimpl_), ipaddr);
        return false;
    }

    pj_sockaddr_set_port(&cand.addr, (pj_uint16_t) port);
    pj_strdup2(pimpl_->pool_.get(), &cand.foundation, foundation);

    return true;
}

ssize_t
IceTransport::recv(unsigned compId, unsigned char* buf, size_t len, std::error_code& ec)
{
    ASSERT_COMP_ID(compId, getComponentCount());
    auto& io = pimpl_->compIO_[compId - 1];
    std::lock_guard lk(io.mutex);

    if (io.queue.empty()) {
        ec = std::make_error_code(std::errc::resource_unavailable_try_again);
        return -1;
    }

    auto& packet = io.queue.front();
    const auto count = std::min(len, packet.size());
    std::copy_n(packet.begin(), count, buf);
    if (count == packet.size()) {
        io.queue.pop_front();
    } else {
        packet.erase(packet.begin(), packet.begin() + count);
    }

    ec.clear();
    return count;
}

ssize_t
IceTransport::recvfrom(unsigned compId, char* buf, size_t len, std::error_code& ec)
{
    ASSERT_COMP_ID(compId, getComponentCount());
    return pimpl_->peerChannels_.at(compId - 1).read(buf, len, ec);
}

void
IceTransport::setOnRecv(unsigned compId, IceRecvCb cb)
{
    ASSERT_COMP_ID(compId, getComponentCount());

    auto& io = pimpl_->compIO_[compId - 1];
    std::lock_guard lk(io.mutex);
    io.recvCb = std::move(cb);

    if (io.recvCb) {
        // Flush existing queue using the callback
        for (const auto& packet : io.queue)
            io.recvCb((uint8_t*) packet.data(), packet.size());
        io.queue.clear();
    }
}

void
IceTransport::setOnShutdown(onShutdownCb&& cb)
{
    pimpl_->scb = std::move(cb);
}

ssize_t
IceTransport::send(unsigned compId, const unsigned char* buf, size_t len)
{
    ASSERT_COMP_ID(compId, getComponentCount());

    auto remote = getRemoteAddress(compId);

    if (!remote) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("[ice:{}] Unable to find remote address for component {:d}", fmt::ptr(pimpl_), compId);
        errno = EINVAL;
        return -1;
    }

    std::unique_lock dlk(pimpl_->sendDataMutex_, std::defer_lock);
    if (isTCPEnabled())
        dlk.lock();

    jami_tracepoint(ice_transport_send,
                    reinterpret_cast<uint64_t>(this),
                    compId,
                    len,
                    remote.toString().c_str());

    auto status = pj_ice_strans_sendto2(pimpl_->icest_,
                                        compId,
                                        buf,
                                        len,
                                        remote.pjPtr(),
                                        remote.getLength());

    jami_tracepoint(ice_transport_send_status, status);

    if (status == PJ_EPENDING && isTCPEnabled()) {
        // NOTE; because we are in TCP, the sent size will count the header (2
        // bytes length).
        pimpl_->waitDataCv_.wait(dlk, [&] {
            return pimpl_->lastSentLen_ >= static_cast<pj_size_t>(len) or pimpl_->destroying_;
        });
        pimpl_->lastSentLen_ = 0;
    } else if (status != PJ_SUCCESS && status != PJ_EPENDING) {
        if (status == PJ_EBUSY) {
            errno = EAGAIN;
        } else {
            if (pimpl_->logger_)
                pimpl_->logger_->error("[ice:{}] ICE send failed: {:s}", fmt::ptr(pimpl_), sip_utils::sip_strerror(status));
            errno = EIO;
        }
        return -1;
    }

    return len;
}

bool
IceTransport::waitForInitialization(std::chrono::milliseconds timeout)
{
    return pimpl_->_waitForInitialization(timeout);
}

ssize_t
IceTransport::waitForData(unsigned compId, std::chrono::milliseconds timeout, std::error_code& ec)
{
    ASSERT_COMP_ID(compId, getComponentCount());
    return pimpl_->peerChannels_.at(compId - 1).wait(timeout, ec);
}

bool
IceTransport::isTCPEnabled() const
{
    return pimpl_->isTcpEnabled();
}

ICESDP
IceTransport::parseIceCandidates(std::string_view sdp_msg)
{
    if (pimpl_->streamsCount_ != 1) {
        if (pimpl_->logger_)
            pimpl_->logger_->error("Expected exactly one stream per SDP, found {} stream(s)", pimpl_->streamsCount_);
        return {};
    }

    ICESDP res;
    int nr = 0;
    for (std::string_view line; dhtnet::getline(sdp_msg, line); nr++) {
        if (nr == 0) {
            res.rem_ufrag = line;
        } else if (nr == 1) {
            res.rem_pwd = line;
        } else {
            IceCandidate cand;
            if (parseIceAttributeLine(0, std::string(line), cand)) {
                if (pimpl_->logger_)
                    pimpl_->logger_->debug("[ice:{}] Add remote candidate: {}",
                         fmt::ptr(pimpl_),
                         line);
                res.rem_candidates.emplace_back(cand);
            }
        }
    }
    return res;
}

void
IceTransport::setDefaultRemoteAddress(unsigned comp_id, const IpAddr& addr)
{
    pimpl_->setDefaultRemoteAddress(comp_id, addr);
}

std::string
IceTransport::link() const
{
    return pimpl_->link();
}

//==============================================================================

IceTransportFactory::IceTransportFactory(const std::shared_ptr<Logger>& logger)
    : pjInitLock_()
    // Warning: pj_caching_pool_destroy will segfault if it's called before
    // pj_caching_pool_init. Hence, any member which appears in the initializer
    // list and whose constructor can fail (such as pjInitLock_) must be constructed
    // before cp_ (which means it must be declared before cp_ in the class definition).
    , cp_(new pj_caching_pool(),
          [](pj_caching_pool* p) {
              pj_caching_pool_destroy(p);
              delete p;
          })
    , ice_cfg_()
    , logger_(logger)
{
    pj_caching_pool_init(cp_.get(), NULL, 0);

    pj_ice_strans_cfg_default(&ice_cfg_);
    ice_cfg_.stun_cfg.pf = &cp_->factory;

    // v2.4.5 of PJNATH has a default of 100ms but RFC 5389 since version 14 requires
    // a minimum of 500ms on fixed-line links. Our usual case is wireless links.
    // This solves too long ICE exchange by DHT.
    // Using 500ms with default PJ_STUN_MAX_TRANSMIT_COUNT (7) gives around 33s before timeout.
    ice_cfg_.stun_cfg.rto_msec = 500;

    // See https://tools.ietf.org/html/rfc5245#section-8.1.1.2
    // If enabled, it may help speed-up the connectivity, but may cause
    // the nomination of sub-optimal pairs.
    ice_cfg_.opt.aggressive = PJ_FALSE;
}

IceTransportFactory::~IceTransportFactory() {}

std::shared_ptr<IceTransport>
IceTransportFactory::createTransport(std::string_view name)
{
    return std::make_shared<IceTransport>(name, logger_);
}

std::unique_ptr<IceTransport>
IceTransportFactory::createUTransport(std::string_view name)
{
    return std::make_unique<IceTransport>(name, logger_);
}

//==============================================================================

void
IceSocket::close()
{
    if (ice_transport_)
        ice_transport_->setOnRecv(compId_, {});
    ice_transport_.reset();
}

ssize_t
IceSocket::send(const unsigned char* buf, size_t len)
{
    if (not ice_transport_)
        return -1;
    return ice_transport_->send(compId_, buf, len);
}

ssize_t
IceSocket::waitForData(std::chrono::milliseconds timeout)
{
    if (not ice_transport_)
        return -1;

    std::error_code ec;
    return ice_transport_->waitForData(compId_, timeout, ec);
}

void
IceSocket::setOnRecv(IceRecvCb cb)
{
    if (ice_transport_)
        ice_transport_->setOnRecv(compId_, cb);
}

uint16_t
IceSocket::getTransportOverhead()
{
    if (not ice_transport_)
        return 0;

    return (ice_transport_->getRemoteAddress(compId_).getFamily() == AF_INET) ? IPV4_HEADER_SIZE
                                                                              : IPV6_HEADER_SIZE;
}

void
IceSocket::setDefaultRemoteAddress(const IpAddr& addr)
{
    if (ice_transport_)
        ice_transport_->setDefaultRemoteAddress(compId_, addr);
}

} // namespace dhtnet
