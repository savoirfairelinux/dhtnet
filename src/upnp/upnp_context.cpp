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
#include "upnp/upnp_context.h"
#include "protocol/upnp_protocol.h"

#if HAVE_LIBNATPMP
#include "protocol/natpmp/nat_pmp.h"
#endif
#if HAVE_LIBUPNP
#include "protocol/pupnp/pupnp.h"
#endif
#include <asio.hpp>
#include <asio/steady_timer.hpp>
#if __has_include(<fmt/std.h>)
#include <fmt/std.h>
#else
#include <fmt/ostream.h>
#endif
#include <fmt/chrono.h>

namespace dhtnet {
namespace upnp {

// TODO: figure out what constraints this value needs to satisfy
constexpr static auto MAPPING_RENEWAL_DEBOUNCING_DELAY = std::chrono::seconds(10);
constexpr static int MAX_REQUEST_RETRIES = 20;
constexpr static int MAX_REQUEST_REMOVE_COUNT = 10; // TODO: increase?

constexpr static uint16_t UPNP_TCP_PORT_MIN {10000};
constexpr static uint16_t UPNP_TCP_PORT_MAX {UPNP_TCP_PORT_MIN + 5000};
constexpr static uint16_t UPNP_UDP_PORT_MIN {20000};
constexpr static uint16_t UPNP_UDP_PORT_MAX {UPNP_UDP_PORT_MIN + 5000};

UPnPContext::UPnPContext(const std::shared_ptr<asio::io_context>& ioContext, const std::shared_ptr<dht::log::Logger>& logger)
 : ctx(createIoContext(ioContext, logger))
 , logger_(logger)
 , mappingRenewalTimer_(*ctx)
 , renewalSchedulingTimer_(*ctx)
 , syncTimer_(*ctx)
 , connectivityChangedTimer_(*ctx)
{
    if (logger_) logger_->debug("Creating UPnPContext instance [{}]", fmt::ptr(this));

    // Set port ranges
    portRange_.emplace(PortType::TCP, std::make_pair(UPNP_TCP_PORT_MIN, UPNP_TCP_PORT_MAX));
    portRange_.emplace(PortType::UDP, std::make_pair(UPNP_UDP_PORT_MIN, UPNP_UDP_PORT_MAX));

    ctx->post([this] { init(); });
}

std::shared_ptr<asio::io_context>
UPnPContext::createIoContext(const std::shared_ptr<asio::io_context>& ctx, const std::shared_ptr<dht::log::Logger>& logger) {
    if (ctx) {
        return ctx;
    } else {
        if (logger) logger->debug("UPnPContext: starting dedicated io_context thread");
        auto ioCtx = std::make_shared<asio::io_context>();
        ioContextRunner_ = std::make_unique<std::thread>([ioCtx, l=logger]() {
            try {
                auto work = asio::make_work_guard(*ioCtx);
                ioCtx->run();
            } catch (const std::exception& ex) {
                if (l) l->error("Unexpected io_context thread exception: {}", ex.what());
            }
        });
        return ioCtx;
    }
}

void
UPnPContext::shutdown(std::condition_variable& cv)
{
    if (logger_) logger_->debug("Shutdown UPnPContext instance [{}]", fmt::ptr(this));

    stopUpnp(true);

    for (auto const& [_, proto] : protocolList_) {
        proto->terminate();
    }

    std::lock_guard lock(mappingMutex_);
    mappingList_->clear();
    controllerList_.clear();
    protocolList_.clear();
    shutdownComplete_ = true;
    if (shutdownTimedOut_) {
        // If we timed out in shutdown(), then calling notify_one is not necessary,
        // and doing so anyway can cause bugs, see:
        // https://git.jami.net/savoirfairelinux/dhtnet/-/issues/28
        return;
    }
    cv.notify_one();
}

void
UPnPContext::shutdown()
{
    std::unique_lock lk(mappingMutex_);
    std::condition_variable cv;

    ctx->post([&, this] { shutdown(cv); });

    if (logger_) logger_->debug("Waiting for shutdown ...");

    if (cv.wait_for(lk, std::chrono::seconds(30), [this] { return shutdownComplete_; })) {
        if (logger_) logger_->debug("Shutdown completed");
    } else {
        if (logger_) logger_->error("Shutdown timed out");
        shutdownTimedOut_ = true;
    }
    // NOTE: It's important to unlock mappingMutex_ here, otherwise we get a
    // deadlock when the call to cv.wait_for() above times out before we return
    // from proto->terminate() in shutdown(cv).
    lk.unlock();

    if (ioContextRunner_) {
        if (logger_) logger_->debug("UPnPContext: stopping io_context thread {}", fmt::ptr(this));
        ctx->stop();
        ioContextRunner_->join();
        ioContextRunner_.reset();
        if (logger_) logger_->debug("UPnPContext: stopping io_context thread - finished {}", fmt::ptr(this));
    }
}

UPnPContext::~UPnPContext()
{
    if (logger_) logger_->debug("UPnPContext instance [{}] destroyed", fmt::ptr(this));
}

void
UPnPContext::init()
{
#if HAVE_LIBNATPMP
    auto natPmp = std::make_shared<NatPmp>(ctx, logger_);
    natPmp->setObserver(this);
    protocolList_.emplace(NatProtocolType::NAT_PMP, std::move(natPmp));
#endif

#if HAVE_LIBUPNP
    auto pupnp = std::make_shared<PUPnP>(ctx, logger_);
    pupnp->setObserver(this);
    protocolList_.emplace(NatProtocolType::PUPNP, std::move(pupnp));
#endif
}

void
UPnPContext::startUpnp()
{
    assert(not controllerList_.empty());

    if (logger_) logger_->debug("Starting UPNP context");

    // Request a new IGD search.
    for (auto const& [_, protocol] : protocolList_) {
        ctx->dispatch([p=protocol] { p->searchForIgd(); });
    }

    started_ = true;
}

void
UPnPContext::stopUpnp(bool forceRelease)
{
    if (logger_) logger_->debug("Stopping UPnP context");

    connectivityChangedTimer_.cancel();
    mappingRenewalTimer_.cancel();
    renewalSchedulingTimer_.cancel();
    syncTimer_.cancel();

    // Clear all current mappings

    // Use a temporary list to avoid processing the mappings while holding the lock.
    std::list<Mapping::sharedPtr_t> toRemoveList;
    {
        std::lock_guard lock(mappingMutex_);

        PortType types[2] {PortType::TCP, PortType::UDP};
        for (auto& type : types) {
            auto& mappingList = getMappingList(type);
            for (auto& [_, map] : mappingList) {
                toRemoveList.emplace_back(map);
            }
        }
        // Invalidate the current IGDs.
        preferredIgd_.reset();
        validIgdList_.clear();
    }
    for (auto const& map : toRemoveList) {
        requestRemoveMapping(map);

        if (map->getAutoUpdate() && !forceRelease) {
            map->setState(MappingState::PENDING);
        } else {
            unregisterMapping(map, true);
        }
    }

    // Clear all current IGDs.
    for (auto const& [_, protocol] : protocolList_) {
        ctx->dispatch([p=protocol]{ p->clearIgds(); });
    }

    started_ = false;
}

uint16_t
UPnPContext::generateRandomPort(PortType type)
{
    auto minPort = type == PortType::TCP ? UPNP_TCP_PORT_MIN : UPNP_UDP_PORT_MIN;
    auto maxPort = type == PortType::TCP ? UPNP_TCP_PORT_MAX : UPNP_UDP_PORT_MAX;

    // Seed the generator.
    static std::mt19937 gen(dht::crypto::getSeededRandomEngine());
    // Define the range.
    std::uniform_int_distribution<uint16_t> dist(minPort, maxPort);
    return dist(gen);
}

void
UPnPContext::connectivityChanged()
{
    // Debounce the connectivity change notification.
    connectivityChangedTimer_.expires_after(std::chrono::milliseconds(50));
    connectivityChangedTimer_.async_wait(std::bind(&UPnPContext::_connectivityChanged, this, std::placeholders::_1));
}

void
UPnPContext::_connectivityChanged(const asio::error_code& ec)
{
    if (ec == asio::error::operation_aborted)
        return;

    auto hostAddr = ip_utils::getLocalAddr(AF_INET);

    if (logger_) logger_->debug("Connectivity change check: host address {}", hostAddr.toString());

    auto restartUpnp = false;

    // On reception of "connectivity change" notification, the UPNP search
    // will be restarted if either there is no valid IGD, or the IGD address
    // changed.

    if (not isReady()) {
        restartUpnp = true;
    } else {
        // Check if the host address changed.
        for (auto const& [_, protocol] : protocolList_) {
            if (protocol->isReady() and hostAddr != protocol->getHostAddress()) {
                if (logger_) logger_->warn("Host address changed from {} to {}",
                          protocol->getHostAddress().toString(),
                          hostAddr.toString());
                protocol->clearIgds();
                restartUpnp = true;
                break;
            }
        }
    }

    // We have at least one valid IGD and the host address did
    // not change, so no need to restart.
    if (not restartUpnp) {
        return;
    }

    // No registered controller. A new search will be performed when
    // a controller is registered.
    if (controllerList_.empty())
        return;

    if (logger_) logger_->debug("Connectivity changed. Clear the IGDs and restart");

    stopUpnp();
    startUpnp();
}

void
UPnPContext::setPublicAddress(const IpAddr& addr)
{
    if (not addr)
        return;

    std::lock_guard lock(mappingMutex_);
    if (knownPublicAddress_ != addr) {
        knownPublicAddress_ = std::move(addr);
        if (logger_) logger_->debug("Setting the known public address to {}", addr.toString());
    }
}

bool
UPnPContext::isReady() const
{
    std::lock_guard lock(mappingMutex_);
    return not validIgdList_.empty();
}

IpAddr
UPnPContext::getExternalIP() const
{
    std::lock_guard lock(mappingMutex_);
    // Return the first IGD Ip available.
    if (not validIgdList_.empty()) {
        return (*validIgdList_.begin())->getPublicIp();
    }
    return {};
}

Mapping::sharedPtr_t
UPnPContext::reserveMapping(Mapping& requestedMap)
{
    auto desiredPort = requestedMap.getExternalPort();

    if (desiredPort == 0) {
        if (logger_) logger_->debug("Desired port is not set, will provide the first available port for [{}]",
                requestedMap.getTypeStr());
    } else {
        if (logger_) logger_->debug("Try to find mapping for port {:d} [{}]", desiredPort, requestedMap.getTypeStr());
    }

    Mapping::sharedPtr_t mapRes;

    {
        std::lock_guard lock(mappingMutex_);
        auto& mappingList = getMappingList(requestedMap.getType());

        // We try to provide a mapping in "OPEN" state. If not found,
        // we provide any available mapping. In this case, it's up to
        // the caller to use it or not.
        for (auto const& [_, map] : mappingList) {
            // If the desired port is null, we pick the first available port.
            if (map->isValid() and (desiredPort == 0 or map->getExternalPort() == desiredPort)
                and map->isAvailable()) {
                // Considere the first available mapping regardless of its
                // state. A mapping with OPEN state will be used if found.
                if (not mapRes)
                    mapRes = map;

                if (map->getState() == MappingState::OPEN) {
                    // Found an "OPEN" mapping. We are done.
                    mapRes = map;
                    break;
                }
            }
        }
    }

    // Create a mapping if none was available.
    if (not mapRes) {
        mapRes = registerMapping(requestedMap);
    }

    if (mapRes) {
        // Make the mapping unavailable
        mapRes->setAvailable(false);
        // Copy attributes.
        mapRes->setNotifyCallback(requestedMap.getNotifyCallback());
        mapRes->enableAutoUpdate(requestedMap.getAutoUpdate());
        // Notify the listener.
        if (auto cb = mapRes->getNotifyCallback())
            cb(mapRes);
    }

    enforceAvailableMappingsLimits();

    return mapRes;
}

// TODO: double-check what the expected behavior is when the mapping has auto-update enabled.
void
UPnPContext::releaseMapping(const Mapping& map)
{
    ctx->dispatch([this, map] {
        if (shutdownComplete_)
            return;
        auto mapPtr = getMappingWithKey(map.getMapKey());

        if (not mapPtr) {
            // Might happen if the mapping failed or was never granted.
            if (logger_) logger_->debug("Mapping {} does not exist or was already removed", map.toString());
            return;
        }

        if (mapPtr->isAvailable()) {
            if (logger_) logger_->warn("Trying to release an unused mapping {}", mapPtr->toString());
            return;
        }

        // Remove it.
        requestRemoveMapping(mapPtr);
        unregisterMapping(mapPtr);
        enforceAvailableMappingsLimits();
    });
}

void
UPnPContext::registerController(void* controller)
{
    {
        std::lock_guard lock(mappingMutex_);
        if (shutdownComplete_) {
            if (logger_) logger_->warn("UPnPContext already shut down");
            return;
        }
        auto ret = controllerList_.emplace(controller);
        if (not ret.second) {
            if (logger_) logger_->warn("Controller {} is already registered", fmt::ptr(controller));
            return;
        }
    }

    if (logger_) logger_->debug("Successfully registered controller {}", fmt::ptr(controller));
    if (not started_)
        startUpnp();
}

void
UPnPContext::unregisterController(void* controller)
{
    if (shutdownComplete_)
        return;
    std::unique_lock lock(mappingMutex_);
    if (controllerList_.erase(controller) == 1) {
        if (logger_) logger_->debug("Successfully unregistered controller {}", fmt::ptr(controller));
    } else {
        if (logger_) logger_->debug("Controller {} was already removed", fmt::ptr(controller));
    }

    if (controllerList_.empty()) {
        lock.unlock();
        stopUpnp();
    }
}

std::vector<IGDInfo>
UPnPContext::getIgdsInfo() const
{
    std::vector<IGDInfo> igdInfoList;

    std::lock_guard lk(mappingMutex_);
    for (auto& igd : validIgdList_) {
        auto protocol = protocolList_.at(igd->getProtocol());

        IGDInfo info;
        info.uid = igd->getUID();
        info.localIp = igd->getLocalIp();
        info.publicIp = igd->getPublicIp();
        info.mappingInfoList = protocol->getMappingsInfo(igd);

        igdInfoList.push_back(std::move(info));
    }

    return igdInfoList;
}

// TODO: refactor this function so that it can never fail unless there are literally no ports available
uint16_t
UPnPContext::getAvailablePortNumber(PortType type)
{
    // Only return an available random port. No actual
    // reservation is made here.

    std::lock_guard lock(mappingMutex_);
    auto& mappingList = getMappingList(type);
    int tryCount = 0;
    while (tryCount++ < MAX_REQUEST_RETRIES) {
        uint16_t port = generateRandomPort(type);
        Mapping map(type, port, port);
        if (mappingList.find(map.getMapKey()) == mappingList.end())
            return port;
    }

    // Very unlikely to get here.
    if (logger_) logger_->error("Could not find an available port after %i trials", MAX_REQUEST_RETRIES);
    return 0;
}

void
UPnPContext::requestMapping(const Mapping::sharedPtr_t& map)
{
    assert(map);
    auto const& igd = getPreferredIgd();
    // We must have at least a valid IGD pointer if we get here.
    // Not this method is called only if there were a valid IGD, however,
    // because the processing is asynchronous, it's possible that the IGD
    // was invalidated when the this code executed.
    if (not igd) {
        if (logger_) logger_->debug("Unable to request mapping {}: no valid IGDs available",
                                    map->toString());
        return;
    }

    map->setIgd(igd);

    if (logger_) logger_->debug("Request mapping {} using protocol [{}] IGD [{}]",
            map->toString(),
            igd->getProtocolName(),
            igd->toString());

    updateMappingState(map, MappingState::IN_PROGRESS);

    auto const& protocol = protocolList_.at(igd->getProtocol());
    protocol->requestMappingAdd(*map);
}

void
UPnPContext::provisionNewMappings(PortType type, int portCount)
{
    if (logger_) logger_->debug("Provision {:d} new mappings of type [{}]", portCount, Mapping::getTypeStr(type));

    while (portCount > 0) {
        auto port = getAvailablePortNumber(type);
        if (port > 0) {
            // Found an available port number
            portCount--;
            Mapping map(type, port, port, true);
            registerMapping(map);
        } else {
            // Very unlikely to get here!
            if (logger_) logger_->error("Cannot provision port: no available port number");
        }
    }
}

void
UPnPContext::deleteUnneededMappings(PortType type, int portCount)
{
    if (logger_) logger_->debug("Remove {:d} unneeded mapping of type [{}]", portCount, Mapping::getTypeStr(type));

    std::lock_guard lock(mappingMutex_);
    auto& mappingList = getMappingList(type);

    for (auto it = mappingList.begin(); it != mappingList.end();) {
        auto map = it->second;
        assert(map);

        if (not map->isAvailable()) {
            it++;
            continue;
        }

        if (map->getState() == MappingState::OPEN and portCount > 0) {
            // Close portCount mappings in "OPEN" state.
            requestRemoveMapping(map);
            it = mappingList.erase(it);
            portCount--;
        } else if (map->getState() != MappingState::OPEN) {
            // If this methods is called, it means there are more open
            // mappings than required. So, all mappings in a state other
            // than "OPEN" state (typically in in-progress state) will
            // be deleted as well.
            it = mappingList.erase(it);
        } else {
            it++;
        }
    }
}

void
UPnPContext::updatePreferredIgd()
{
    if (preferredIgd_ and preferredIgd_->isValid())
        return;

    // Reset and search for the best IGD.
    preferredIgd_.reset();

    for (auto const& [_, protocol] : protocolList_) {
        if (protocol->isReady()) {
            auto igdList = protocol->getIgdList();
            assert(not igdList.empty());
            auto const& igd = igdList.front();
            if (not igd->isValid())
                continue;

            // Prefer NAT-PMP over PUPNP.
            if (preferredIgd_ and igd->getProtocol() != NatProtocolType::NAT_PMP)
                continue;

            // Update.
            preferredIgd_ = igd;
        }
    }

    if (preferredIgd_ and preferredIgd_->isValid()) {
        if (logger_) logger_->debug("Preferred IGD updated to [{}] IGD [{} {}] ",
                 preferredIgd_->getProtocolName(),
                 preferredIgd_->getUID(),
                 preferredIgd_->toString());
    }
}

std::shared_ptr<IGD>
UPnPContext::getPreferredIgd() const
{
    return preferredIgd_;
}

// TODO: debounce?
void
UPnPContext::enforceAvailableMappingsLimits()
{
    for (auto type : {PortType::TCP, PortType::UDP}) {
        int pendingCount = 0;
        int inProgressCount = 0;
        int openCount = 0;
        {
            std::lock_guard lock(mappingMutex_);
            const auto& mappingList = getMappingList(type);
            for (const auto& [_, mapping] : mappingList) {
                if (!mapping->isAvailable())
                    continue;
                switch (mapping->getState()) {
                    case MappingState::PENDING:
                        pendingCount++;
                        break;
                    case MappingState::IN_PROGRESS:
                        inProgressCount++;
                        break;
                    case MappingState::OPEN:
                        openCount++;
                        break;
                    default:
                        break;
                }
            }
        }
        int availableCount = openCount + pendingCount + inProgressCount;
        if (logger_) logger_->debug("Number of 'available' {} mappings in the local list: {} ({} open + {} pending + {} in progress)",
                                    Mapping::getTypeStr(type),
                                    availableCount,
                                    openCount,
                                    pendingCount,
                                    inProgressCount);

        int toRequestCount = getMinAvailableMappings(type) - availableCount;
        if (toRequestCount > 0) {
            provisionNewMappings(type, toRequestCount);
            continue;
        }

        int toDeleteCount = openCount - getMaxAvailableMappings(type);
        if (toDeleteCount > 0) {
            deleteUnneededMappings(type, toDeleteCount);
        }
    }
}

void
UPnPContext::renewMappings()
{
    // Skip if no controller registered.
    if (controllerList_.empty())
        return;

    std::shared_ptr<IGD> prefIgd = getPreferredIgd();
    if (not prefIgd) {
        if (logger_) logger_->debug("Cannot renew mappings: no valid IGD available");
        return;
    }

    auto now = sys_clock::now();
    auto nextRenewalTime = sys_clock::time_point::max();

    std::vector<Mapping::sharedPtr_t> toRenew;
    int toRenewLaterCount = 0;

    for (auto type : {PortType::TCP, PortType::UDP}) {
        std::lock_guard lock(mappingMutex_);
        auto mappingList = getMappingList(type);
        for (const auto& [_, map] : mappingList) {
            if (not map->isValid())
                continue;
            if (map->getState() != MappingState::OPEN)
                continue;

            auto mapRenewalTime = map->getRenewalTime();
            if (now >= mapRenewalTime) {
                toRenew.emplace_back(map);
            } else if (mapRenewalTime < sys_clock::time_point::max()) {
                toRenewLaterCount++;
                if (mapRenewalTime < nextRenewalTime)
                    nextRenewalTime = map->getRenewalTime();
            }

        }
    }

    if (!toRenew.empty()) {
        if (logger_) logger_->debug("Sending renewal requests for {} mappings", toRenew.size());
    }
    for (const auto& map : toRenew) {
        const auto& protocol = protocolList_.at(map->getIgd()->getProtocol());
        if (protocol->isReady()) {
            protocol->requestMappingRenew(*map);
        }
    }
    if (toRenewLaterCount > 0) {
        nextRenewalTime += MAPPING_RENEWAL_DEBOUNCING_DELAY;
        if (logger_) logger_->debug("{} mappings didn't need to be renewed (next renewal scheduled for {:%Y-%m-%d %H:%M:%S})",
                                    toRenewLaterCount,
                                    fmt::localtime(sys_clock::to_time_t(nextRenewalTime)));
        mappingRenewalTimer_.expires_at(nextRenewalTime);
        mappingRenewalTimer_.async_wait([this](asio::error_code const& ec) {
            if (ec != asio::error::operation_aborted)
                renewMappings();
        });
    }
}

void
UPnPContext::scheduleMappingsRenewal()
{
    // TODO: explain reason for debouncing this function (what should the delay be?)
    renewalSchedulingTimer_.expires_after(std::chrono::milliseconds(500));
    renewalSchedulingTimer_.async_wait([this](asio::error_code const& ec) {
        if (ec != asio::error::operation_aborted)
            _scheduleMappingsRenewal();
    });
}

void
UPnPContext::_scheduleMappingsRenewal()
{
    // Set timer for next renewal
    // TODO: we should probably ignore mappings which are in the process of being renewed
    sys_clock::time_point nextRenewalTime = sys_clock::time_point::max();
    for (auto type : {PortType::TCP, PortType::UDP}) {
        std::lock_guard lock(mappingMutex_);
        auto mappingList = getMappingList(type);
        for (const auto& [_, map] : mappingList) {
            if (map->getRenewalTime() < nextRenewalTime)
                nextRenewalTime = map->getRenewalTime();
        }
    }
    if (nextRenewalTime == sys_clock::time_point::max())
        return;

    nextRenewalTime += MAPPING_RENEWAL_DEBOUNCING_DELAY;
    if (nextRenewalTime == mappingRenewalTimer_.expiry())
        return;

    if (logger_) logger_->debug("Scheduling next port mapping renewal for {:%Y-%m-%d %H:%M:%S}",
                                 fmt::localtime(sys_clock::to_time_t(nextRenewalTime)));
    mappingRenewalTimer_.expires_at(nextRenewalTime);
    mappingRenewalTimer_.async_wait([this](asio::error_code const& ec) {
        if (ec != asio::error::operation_aborted)
            renewMappings();
    });
}

void
UPnPContext::syncLocalMappingListWithIgd()
{
    std::lock_guard lock(syncMutex_);
    if (syncRequested_)
        return;

    syncRequested_ = true;
    syncTimer_.expires_after(std::chrono::seconds(300));
    syncTimer_.async_wait([this](asio::error_code const& ec) {
        if (ec != asio::error::operation_aborted)
            _syncLocalMappingListWithIgd();
    });
}

void
UPnPContext::_syncLocalMappingListWithIgd()
{
    {
        std::lock_guard lock(syncMutex_);
        syncRequested_ = false;
    }
    const auto& igd = getPreferredIgd();
    if (not igd or igd->getProtocol() != NatProtocolType::PUPNP) {
        return;
    }
    auto protocol = protocolList_.at(NatProtocolType::PUPNP);
    if (!protocol->isReady())
        return;

    if (logger_) logger_->debug("Synchronizing local mapping list with IGD [{}]",
                                igd->toString());
    auto remoteMapList = protocol->getMappingsListByDescr(igd,
                                                          Mapping::UPNP_MAPPING_DESCRIPTION_PREFIX);
    bool requestsInProgress = false;
    // Use a temporary list to avoid processing mappings while holding the lock.
    std::list<Mapping::sharedPtr_t> toRemoveFromLocalList;
    for (auto type: {PortType::TCP, PortType::UDP}) {
        std::lock_guard lock(mappingMutex_);
        for (auto& [_, map] : getMappingList(type)) {
            if (map->getProtocol() != NatProtocolType::PUPNP) {
                continue;
            }
            switch (map->getState()) {
                case MappingState::PENDING:
                case MappingState::IN_PROGRESS:
                    requestsInProgress = true;
                    break;
                case MappingState::OPEN: {
                    auto it = remoteMapList.find(map->getMapKey());
                    if (it == remoteMapList.end()) {
                        if (logger_) logger_->warn("Mapping {} (IGD {}) marked as \"OPEN\" but not found in the "
                                                   "remote list. Removing from local list.",
                                                   map->toString(),
                                                   igd->toString());
                        toRemoveFromLocalList.emplace_back(map);
                    } else {
                        auto oldExpiryTime = map->getExpiryTime();
                        auto newExpiryTime = it->second.getExpiryTime();
                        // The value of newExpiryTime is based on the mapping's "lease duration" that we got from
                        // the IGD, which is supposed to be (according to the UPnP specification) the number of
                        // seconds remaining before the mapping expires. In practice, the duration values returned
                        // by some routers are only precise to the hour (i.e. they're always multiples of 3600). This
                        // means that newExpiryTime can exceed the real expiry time by up to an hour in the worst case.
                        // In order to avoid accidentally scheduling a mapping's renewal too late, we only allow ourselves to
                        // push back its renewal time if newExpiryTime is bigger than oldExpiryTime by a sufficient margin.
                        if (newExpiryTime < oldExpiryTime ||
                            newExpiryTime > oldExpiryTime + std::chrono::seconds(2 * 3600)) {
                            auto newRenewalTime = map->getRenewalTime() + (newExpiryTime - oldExpiryTime) / 2;
                            map->setRenewalTime(newRenewalTime);
                            map->setExpiryTime(newExpiryTime);
                        }
                    }
                    break;
                }
                default:
                    break;
            }
        }
    }
    scheduleMappingsRenewal();

    for (auto const& map : toRemoveFromLocalList) {
        updateMappingState(map, MappingState::FAILED);
        unregisterMapping(map);
    }

    // TODO: add justification for this
    if (requestsInProgress)
        return;
    // Use a temporary list to avoid processing mappings while holding the lock.
    std::list<Mapping> toRemoveFromIgd;
    {
        std::lock_guard lock(mappingMutex_);

        for (auto const& [_, map] : remoteMapList) {
            const auto& mappingList = getMappingList(map.getType());
            auto it = mappingList.find(map.getMapKey());
            if (it == mappingList.end()) {
                // Not present, request mapping remove.
                toRemoveFromIgd.emplace_back(std::move(map));
                // Make only few remove requests at once.
                if (toRemoveFromIgd.size() >= MAX_REQUEST_REMOVE_COUNT)
                    break;
            }
        }
    }

    for (const auto& map : toRemoveFromIgd) {
        protocol->requestMappingRemove(map);
    }

}

void
UPnPContext::pruneMappingsWithInvalidIgds(const std::shared_ptr<IGD>& igd)
{
    // Use temporary list to avoid holding the lock while
    // processing the mapping list.
    std::list<Mapping::sharedPtr_t> toRemoveList;
    {
        std::lock_guard lock(mappingMutex_);

        PortType types[2] {PortType::TCP, PortType::UDP};
        for (auto& type : types) {
            auto& mappingList = getMappingList(type);
            for (auto const& [_, map] : mappingList) {
                if (map->getIgd() == igd)
                    toRemoveList.emplace_back(map);
            }
        }
    }

    for (auto const& map : toRemoveList) {
        if (logger_) logger_->debug("Remove mapping {} (has an invalid IGD {} [{}])",
                 map->toString(),
                 igd->toString(),
                 igd->getProtocolName());
        updateMappingState(map, MappingState::FAILED);
        unregisterMapping(map);
    }
}

void
UPnPContext::processPendingRequests()
{
    // This list holds the mappings to be requested. This is
    // needed to avoid performing the requests while holding
    // the lock.
    std::list<Mapping::sharedPtr_t> requestsList;

    // Populate the list of requests to perform.
    {
        std::lock_guard lock(mappingMutex_);
        PortType typeArray[2] {PortType::TCP, PortType::UDP};

        for (auto type : typeArray) {
            auto& mappingList = getMappingList(type);
            for (auto& [_, map] : mappingList) {
                if (map->getState() == MappingState::PENDING) {
                    if (logger_) logger_->debug("Will attempt to send a request for pending mapping {}",
                                                map->toString());
                    requestsList.emplace_back(map);
                }
            }
        }
    }

    // Process the pending requests.
    for (auto const& map : requestsList) {
        requestMapping(map);
    }
}

void
UPnPContext::onIgdUpdated(const std::shared_ptr<IGD>& igd, UpnpIgdEvent event)
{
    assert(igd);

    char const* IgdState = event == UpnpIgdEvent::ADDED     ? "ADDED"
                           : event == UpnpIgdEvent::REMOVED ? "REMOVED"
                                                            : "INVALID";

    auto const& igdLocalAddr = igd->getLocalIp();
    auto protocolName = igd->getProtocolName();

    if (logger_) logger_->debug("New event for IGD [{} {}] [{}]: [{}]",
             igd->getUID(),
             igd->toString(),
             protocolName,
             IgdState);

    // Check if the IGD has valid addresses.
    if (not igdLocalAddr) {
        if (logger_) logger_->warn("[{}] IGD has an invalid local address", protocolName);
        return;
    }

    if (not igd->getPublicIp()) {
        if (logger_) logger_->warn("[{}] IGD has an invalid public address", protocolName);
        return;
    }

    if (knownPublicAddress_ and igd->getPublicIp() != knownPublicAddress_) {
        if (logger_) logger_->warn("[{}] IGD external address [{}] does not match known public address [{}]."
                  " The mapped addresses might not be reachable",
                  protocolName,
                  igd->getPublicIp().toString(),
                  knownPublicAddress_.toString());
    }

    // Update the IGD list.
    if (event == UpnpIgdEvent::REMOVED or event == UpnpIgdEvent::INVALID_STATE) {
        if (logger_) logger_->warn("State of IGD [{} {}] [{}] changed to [{}]. Pruning the mapping list",
                  igd->getUID(),
                  igd->toString(),
                  protocolName,
                  IgdState);

        pruneMappingsWithInvalidIgds(igd);

        std::lock_guard lock(mappingMutex_);
        validIgdList_.erase(igd);
    } else {
        std::lock_guard lock(mappingMutex_);
        auto ret = validIgdList_.emplace(igd);
        if (ret.second) {
            // TODO: fix potentially misleading comment (pending requests won't be processed if we already had a valid IGD when this one got added)
            if (logger_) logger_->debug("IGD [{}] on address {} was added. Will process any pending requests",
                     protocolName,
                     igdLocalAddr.toString(true, true));
        } else {
            // Already in the list.
            if (logger_) logger_->error("IGD [{}] on address {} already in the list",
                     protocolName,
                     igdLocalAddr.toString(true, true));
            return;
        }
    }

    // TODO: add comments
    updatePreferredIgd();
    processPendingRequests();
    enforceAvailableMappingsLimits();
}

void
UPnPContext::onMappingAdded(const std::shared_ptr<IGD>& igd, const Mapping& mapRes)
{
    // Check if we have a pending request for this response.
    auto map = getMappingWithKey(mapRes.getMapKey());
    if (not map) {
        // We may receive a response for a canceled request. Just ignore it.
        if (logger_) logger_->debug("Response for mapping {} [IGD {}] [{}] does not have a local match",
                 mapRes.toString(),
                 igd->toString(),
                 mapRes.getProtocolName());
        return;
    }

    // The mapping request is new and successful. Update.
    map->setIgd(igd);
    map->setInternalAddress(mapRes.getInternalAddress());
    map->setExternalPort(mapRes.getExternalPort());
    map->setRenewalTime(mapRes.getRenewalTime());
    map->setExpiryTime(mapRes.getExpiryTime());
    scheduleMappingsRenewal();

    // Update the state and report to the owner.
    updateMappingState(map, MappingState::OPEN);

    if (logger_) logger_->debug("Mapping {} (on IGD {} [{}]) successfully performed",
             map->toString(),
             igd->toString(),
             map->getProtocolName());

    // Call setValid() to reset the errors counter. We need
    // to reset the counter on each successful response.
    igd->setValid(true);
    if (igd->getProtocol() == NatProtocolType::PUPNP)
        syncLocalMappingListWithIgd();
}

void
UPnPContext::onMappingRenewed(const std::shared_ptr<IGD>& igd, const Mapping& map)
{
    auto mapPtr = getMappingWithKey(map.getMapKey());

    if (not mapPtr) {
        if (logger_) logger_->warn("Renewed mapping {} from IGD  {} [{}] does not have a match in local list",
                  map.toString(),
                  igd->toString(),
                  map.getProtocolName());
        return;
    }
    if (!mapPtr->isValid() || mapPtr->getState() != MappingState::OPEN) {
        if (logger_) logger_->warn("Renewed mapping {} from IGD {} [{}] is in unexpected state",
                  mapPtr->toString(),
                  igd->toString(),
                  mapPtr->getProtocolName());
        return;
    }

    mapPtr->setRenewalTime(map.getRenewalTime());
    mapPtr->setExpiryTime(map.getExpiryTime());
    scheduleMappingsRenewal();
    if (igd->getProtocol() == NatProtocolType::PUPNP)
        syncLocalMappingListWithIgd();
}

void
UPnPContext::requestRemoveMapping(const Mapping::sharedPtr_t& map)
{
    if (not map or not map->isValid()) {
        // Silently ignore if the mapping is invalid
        return;
    }
    auto protocol = protocolList_.at(map->getIgd()->getProtocol());
    protocol->requestMappingRemove(*map);
}

void
UPnPContext::onMappingRemoved(const std::shared_ptr<IGD>& igd, const Mapping& mapRes)
{
    if (not mapRes.isValid())
        return;

    auto map = getMappingWithKey(mapRes.getMapKey());
    // Notify the listener.
    if (map and map->getNotifyCallback())
        map->getNotifyCallback()(map);
}

Mapping::sharedPtr_t
UPnPContext::registerMapping(Mapping& map)
{
    if (map.getExternalPort() == 0) {
        // JAMI_DBG("Port number not set. Will set a random port number");
        auto port = getAvailablePortNumber(map.getType());
        map.setExternalPort(port);
        map.setInternalPort(port);
    }

    // Newly added mapping must be in pending state by default.
    map.setState(MappingState::PENDING);

    Mapping::sharedPtr_t mapPtr;

    {
        std::lock_guard lock(mappingMutex_);
        auto& mappingList = getMappingList(map.getType());

        auto ret = mappingList.emplace(map.getMapKey(), std::make_shared<Mapping>(map));
        if (not ret.second) {
            if (logger_) logger_->warn("Mapping request for {} already added!", map.toString());
            return {};
        }
        mapPtr = ret.first->second;
        assert(mapPtr);
    }

    // No available IGD. The pending mapping requests will be processed
    // when an IGD becomes available
    // TODO: the IGD may not be available even if isReady() returns true, fix this
    if (not isReady()) {
        if (logger_) logger_->warn("No IGD available. Mapping will be requested when an IGD becomes available");
    } else {
        requestMapping(mapPtr);
    }

    return mapPtr;
}

void
UPnPContext::unregisterMapping(const Mapping::sharedPtr_t& map, bool ignoreAutoUpdate)
{
    if (not map) {
        return;
    }

    if (map->getAutoUpdate() && !ignoreAutoUpdate) {
        if (logger_) logger_->debug("Mapping {} has auto-update enabled, a new mapping will be requested",
                                    map->toString());

        Mapping newMapping(map->getType());
        newMapping.enableAutoUpdate(true);
        newMapping.setNotifyCallback(map->getNotifyCallback());
        reserveMapping(newMapping);

        // TODO: figure out if these lines are actually necessary
        // (See https://review.jami.net/c/jami-daemon/+/16940)
        map->setAvailable(true);
        map->enableAutoUpdate(false);
        map->setNotifyCallback(nullptr);
    }
    auto& mappingList = getMappingList(map->getType());

    if (mappingList.erase(map->getMapKey()) == 1) {
        if (logger_) logger_->debug("Unregistered mapping {}", map->toString());
    } else {
        // The mapping may already be un-registered. Just ignore it.
        if (logger_) logger_->debug("Can't unregister mapping {} [{}] since it doesn't have a local match",
                 map->toString(),
                 map->getProtocolName());
    }
}

std::map<Mapping::key_t, Mapping::sharedPtr_t>&
UPnPContext::getMappingList(PortType type)
{
    unsigned typeIdx = type == PortType::TCP ? 0 : 1;
    return mappingList_[typeIdx];
}

Mapping::sharedPtr_t
UPnPContext::getMappingWithKey(Mapping::key_t key)
{
    std::lock_guard lock(mappingMutex_);
    auto const& mappingList = getMappingList(Mapping::getTypeFromMapKey(key));
    auto it = mappingList.find(key);
    if (it == mappingList.end())
        return nullptr;
    return it->second;
}

void
UPnPContext::onMappingRequestFailed(const Mapping& mapRes)
{
    auto const& map = getMappingWithKey(mapRes.getMapKey());
    if (not map) {
        // We may receive a response for a removed request. Just ignore it.
        if (logger_) logger_->debug("Mapping {} [IGD {}] does not have a local match",
                 mapRes.toString(),
                 mapRes.getProtocolName());
        return;
    }

    auto igd = map->getIgd();
    if (not igd) {
        if (logger_) logger_->error("IGD pointer is null");
        return;
    }

    // TODO: Bug? Do we not need to unregister when igd is null?
    updateMappingState(map, MappingState::FAILED);
    unregisterMapping(map);

    if (logger_) logger_->warn("Mapping request for {} failed on IGD {} [{}]",
              map->toString(),
              igd->toString(),
              igd->getProtocolName());

    enforceAvailableMappingsLimits();
}

void
UPnPContext::updateMappingState(const Mapping::sharedPtr_t& map, MappingState newState, bool notify)
{
    assert(map);

    // Ignore if the state did not change.
    if (newState == map->getState()) {
        return;
    }

    // Update the state.
    map->setState(newState);

    // Notify the listener if set.
    if (notify and map->getNotifyCallback())
        map->getNotifyCallback()(map);
}

} // namespace upnp
} // namespace dhtnet
