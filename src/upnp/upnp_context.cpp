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

#include <asio/steady_timer.hpp>
#if __has_include(<fmt/std.h>)
#include <fmt/std.h>
#else
#include <fmt/ostream.h>
#endif

namespace dhtnet {
namespace upnp {

constexpr static auto MAP_UPDATE_INTERVAL = std::chrono::seconds(30);
constexpr static int MAX_REQUEST_RETRIES = 20;
constexpr static int MAX_REQUEST_REMOVE_COUNT = 5;

constexpr static uint16_t UPNP_TCP_PORT_MIN {10000};
constexpr static uint16_t UPNP_TCP_PORT_MAX {UPNP_TCP_PORT_MIN + 5000};
constexpr static uint16_t UPNP_UDP_PORT_MIN {20000};
constexpr static uint16_t UPNP_UDP_PORT_MAX {UPNP_UDP_PORT_MIN + 5000};

UPnPContext::UPnPContext(const std::shared_ptr<asio::io_context>& ioContext, const std::shared_ptr<dht::log::Logger>& logger)
 : ctx(createIoContext(ioContext, logger))
 , mappingListUpdateTimer_(*ctx)
 , connectivityChangedTimer_(*ctx)
 , logger_(logger)
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

    {
        std::lock_guard<std::mutex> lock(mappingMutex_);
        mappingList_->clear();
        mappingListUpdateTimer_.cancel();
        controllerList_.clear();
        protocolList_.clear();
        shutdownComplete_ = true;
        cv.notify_one();
    }

    if (ioContextRunner_) {
        if (logger_) logger_->debug("UPnPContext: stopping io_context thread");
        ctx->stop();
        ioContextRunner_->join();
        ioContextRunner_.reset();
    }
}

void
UPnPContext::shutdown()
{
    std::unique_lock<std::mutex> lk(mappingMutex_);
    std::condition_variable cv;

    ctx->post([&, this] { shutdown(cv); });
    
    if (logger_) logger_->debug("Waiting for shutdown ...");

    if (cv.wait_for(lk, std::chrono::seconds(30), [this] { return shutdownComplete_; })) {
        if (logger_) logger_->debug("Shutdown completed");
    } else {
        if (logger_) logger_->error("Shutdown timed-out");
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
    /*if (not isValidThread()) {
        ctx->post([this, forceRelease] { stopUpnp(forceRelease); });
        return;
    }*/

    if (logger_) logger_->debug("Stopping UPNP context");

    // Clear all current mappings if any.

    // Use a temporary list to avoid processing the mapping
    // list while holding the lock.
    std::list<Mapping::sharedPtr_t> toRemoveList;
    {
        std::lock_guard<std::mutex> lock(mappingMutex_);

        PortType types[2] {PortType::TCP, PortType::UDP};
        for (auto& type : types) {
            auto& mappingList = getMappingList(type);
            for (auto const& [_, map] : mappingList) {
                toRemoveList.emplace_back(map);
            }
        }
        // Invalidate the current IGDs.
        preferredIgd_.reset();
        validIgdList_.clear();
    }
    for (auto const& map : toRemoveList) {
        requestRemoveMapping(map);

        // Notify is not needed in updateState when
        // shutting down (hence set it to false). NotifyCallback
        // would trigger a new SIP registration and create a
        // false registered state upon program close.
        // It's handled by upper layers.
        updateMappingState(map, MappingState::FAILED, false);
        // We dont remove mappings with auto-update enabled,
        // unless forceRelease is true.
        if (not map->getAutoUpdate() or forceRelease) {
            map->enableAutoUpdate(false);
            unregisterMapping(map);
        }
    }

    // Clear all current IGDs.
    for (auto const& [_, protocol] : protocolList_) {
        ctx->dispatch([p=protocol]{ p->clearIgds(); });
    }

    started_ = false;
}

uint16_t
UPnPContext::generateRandomPort(PortType type, bool mustBeEven)
{
    auto minPort = type == PortType::TCP ? UPNP_TCP_PORT_MIN : UPNP_UDP_PORT_MIN;
    auto maxPort = type == PortType::TCP ? UPNP_TCP_PORT_MAX : UPNP_UDP_PORT_MAX;

    if (minPort >= maxPort) {
        // if (logger_) logger_->error("Max port number ({}) must be greater than min port number ({})", maxPort, minPort);
        // Must be called with valid range.
        assert(false);
    }

    int fact = mustBeEven ? 2 : 1;
    if (mustBeEven) {
        minPort /= fact;
        maxPort /= fact;
    }

    // Seed the generator.
    static std::mt19937 gen(dht::crypto::getSeededRandomEngine());
    // Define the range.
    std::uniform_int_distribution<uint16_t> dist(minPort, maxPort);
    return dist(gen) * fact;
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

    // Mapping with auto update enabled must be processed first.
    processMappingWithAutoUpdate();
}

void
UPnPContext::setPublicAddress(const IpAddr& addr)
{
    if (not addr)
        return;

    std::lock_guard<std::mutex> lock(mappingMutex_);
    if (knownPublicAddress_ != addr) {
        knownPublicAddress_ = std::move(addr);
        if (logger_) logger_->debug("Setting the known public address to {}", addr.toString());
    }
}

bool
UPnPContext::isReady() const
{
    std::lock_guard<std::mutex> lock(mappingMutex_);
    return not validIgdList_.empty();
}

IpAddr
UPnPContext::getExternalIP() const
{
    std::lock_guard<std::mutex> lock(mappingMutex_);
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
        std::lock_guard<std::mutex> lock(mappingMutex_);
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
        // JAMI_WARN("Did not find any available mapping. Will request one now");
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

    updateMappingList(true);

    return mapRes;
}

void
UPnPContext::releaseMapping(const Mapping& map)
{
    ctx->dispatch([this, map] {
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
    });
}

void
UPnPContext::registerController(void* controller)
{
    {
        std::lock_guard<std::mutex> lock(mappingMutex_);
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
    std::unique_lock<std::mutex> lock(mappingMutex_);
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

uint16_t
UPnPContext::getAvailablePortNumber(PortType type)
{
    // Only return an availalable random port. No actual
    // reservation is made here.

    std::lock_guard<std::mutex> lock(mappingMutex_);
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

    /*if (not isValidThread()) {
        ctx->post([this, map] { requestMapping(map); });
        return;
    }*/

    auto const& igd = getPreferredIgd();
    // We must have at least a valid IGD pointer if we get here.
    // Not this method is called only if there were a valid IGD, however,
    // because the processing is asynchronous, it's possible that the IGD
    // was invalidated when the this code executed.
    if (not igd) {
        if (logger_) logger_->debug("No valid IGDs available");
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

bool
UPnPContext::provisionNewMappings(PortType type, int portCount)
{
    if (logger_) logger_->debug("Provision {:d} new mappings of type [{}]", portCount, Mapping::getTypeStr(type));

    assert(portCount > 0);

    while (portCount > 0) {
        auto port = getAvailablePortNumber(type);
        if (port > 0) {
            // Found an available port number
            portCount--;
            Mapping map(type, port, port, true);
            registerMapping(map);
        } else {
            // Very unlikely to get here!
            if (logger_) logger_->error("Can not find any available port to provision!");
            return false;
        }
    }

    return true;
}

bool
UPnPContext::deleteUnneededMappings(PortType type, int portCount)
{
    if (logger_) logger_->debug("Remove {:d} unneeded mapping of type [{}]", portCount, Mapping::getTypeStr(type));

    assert(portCount > 0);

    //CHECK_VALID_THREAD();

    std::lock_guard<std::mutex> lock(mappingMutex_);
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

    return true;
}

void
UPnPContext::updatePreferredIgd()
{
    //CHECK_VALID_THREAD();

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
    //CHECK_VALID_THREAD();

    return preferredIgd_;
}

void
UPnPContext::updateMappingList(bool async)
{
    // Run async if requested.
    if (async) {
        ctx->post([this] { updateMappingList(false); });
        return;
    }

    //CHECK_VALID_THREAD();

    // Update the preferred IGD.
    updatePreferredIgd();

    mappingListUpdateTimer_.cancel();

    // Skip if no controller registered.
    if (controllerList_.empty())
        return;

    // Cancel the current timer (if any) and re-schedule.
    std::shared_ptr<IGD> prefIgd = getPreferredIgd();
    if (not prefIgd) {
        if (logger_) logger_->debug("UPNP/NAT-PMP enabled, but no valid IGDs available");
        // No valid IGD. Nothing to do.
        return;
    }

    mappingListUpdateTimer_.expires_after(MAP_UPDATE_INTERVAL);
    mappingListUpdateTimer_.async_wait([this](asio::error_code const& ec) {
        if (ec != asio::error::operation_aborted)
            updateMappingList(false);
    });

    // Process pending requests if any.
    processPendingRequests(prefIgd);

    // Make new requests for mappings that failed and have
    // the auto-update option enabled.
    processMappingWithAutoUpdate();

    PortType typeArray[2] = {PortType::TCP, PortType::UDP};

    for (auto idx : {0, 1}) {
        auto type = typeArray[idx];

        MappingStatus status;
        getMappingStatus(type, status);

        if (logger_) logger_->debug("Mapping status [{}] - overall {:d}: {:d} open ({:d} ready + {:d} in use), {:d} pending, {:d} "
                "in-progress, {:d} failed",
                Mapping::getTypeStr(type),
                status.sum(),
                status.openCount_,
                status.readyCount_,
                status.openCount_ - status.readyCount_,
                status.pendingCount_,
                status.inProgressCount_,
                status.failedCount_);

        if (status.failedCount_ > 0) {
            std::lock_guard<std::mutex> lock(mappingMutex_);
            auto const& mappingList = getMappingList(type);
            for (auto const& [_, map] : mappingList) {
                if (map->getState() == MappingState::FAILED) {
                    if (logger_) logger_->debug("Mapping status [{}] - Available [{}]",
                            map->toString(true),
                            map->isAvailable() ? "YES" : "NO");
                }
            }
        }

        int toRequestCount = (int) minOpenPortLimit_[idx]
                             - (int) (status.readyCount_ + status.inProgressCount_
                                      + status.pendingCount_);

        // Provision/release mappings accordingly.
        if (toRequestCount > 0) {
            // Take into account the request in-progress when making
            // requests for new mappings.
            provisionNewMappings(type, toRequestCount);
        } else if (status.readyCount_ > maxOpenPortLimit_[idx]) {
            deleteUnneededMappings(type, status.readyCount_ - maxOpenPortLimit_[idx]);
        }
    }

    // Prune the mapping list if needed
    if (protocolList_.at(NatProtocolType::PUPNP)->isReady()) {
#if HAVE_LIBNATPMP
        // Dont perform if NAT-PMP is valid.
        if (not protocolList_.at(NatProtocolType::NAT_PMP)->isReady())
#endif
        {
            pruneMappingList();
        }
    }

#if HAVE_LIBNATPMP
    // Renew nat-pmp allocations
    if (protocolList_.at(NatProtocolType::NAT_PMP)->isReady())
        renewAllocations();
#endif
}

void
UPnPContext::pruneMappingList()
{
    //CHECK_VALID_THREAD();

    MappingStatus status;
    getMappingStatus(status);

    // Do not prune the list if there are pending/in-progress requests.
    if (status.inProgressCount_ != 0 or status.pendingCount_ != 0) {
        return;
    }

    auto const& igd = getPreferredIgd();
    if (not igd or igd->getProtocol() != NatProtocolType::PUPNP) {
        return;
    }
    auto protocol = protocolList_.at(NatProtocolType::PUPNP);

    auto remoteMapList = protocol->getMappingsListByDescr(igd,
                                                          Mapping::UPNP_MAPPING_DESCRIPTION_PREFIX);
    if (remoteMapList.empty()) {
        std::lock_guard<std::mutex> lock(mappingMutex_);
        if (not getMappingList(PortType::TCP).empty() or getMappingList(PortType::TCP).empty()) {
            // JAMI_WARN("We have provisionned mappings but the PUPNP IGD returned an empty list!");
        }
    }

    pruneUnMatchedMappings(igd, remoteMapList);
    pruneUnTrackedMappings(igd, remoteMapList);
}

void
UPnPContext::pruneUnMatchedMappings(const std::shared_ptr<IGD>& igd,
                                    const std::map<Mapping::key_t, Mapping>& remoteMapList)
{
    // Check/synchronize local mapping list with the list
    // returned by the IGD.

    PortType types[2] {PortType::TCP, PortType::UDP};

    for (auto& type : types) {
        // Use a temporary list to avoid processing mappings while holding the lock.
        std::list<Mapping::sharedPtr_t> toRemoveList;
        {
            std::lock_guard<std::mutex> lock(mappingMutex_);
            auto& mappingList = getMappingList(type);
            for (auto const& [_, map] : mappingList) {
                // Only check mappings allocated by UPNP protocol.
                if (map->getProtocol() != NatProtocolType::PUPNP) {
                    continue;
                }
                // Set mapping as failed if not found in the list
                // returned by the IGD.
                if (map->getState() == MappingState::OPEN
                    and remoteMapList.find(map->getMapKey()) == remoteMapList.end()) {
                    toRemoveList.emplace_back(map);

                    if (logger_) logger_->warn("Mapping {} (IGD {}) marked as \"OPEN\" but not found in the "
                              "remote list. Mark as failed!",
                              map->toString(),
                              igd->toString());
                }
            }
        }

        for (auto const& map : toRemoveList) {
            updateMappingState(map, MappingState::FAILED);
            unregisterMapping(map);
        }
    }
}

void
UPnPContext::pruneUnTrackedMappings(const std::shared_ptr<IGD>& igd,
                                    const std::map<Mapping::key_t, Mapping>& remoteMapList)
{
    // Use a temporary list to avoid processing mappings while holding the lock.
    std::list<Mapping> toRemoveList;
    {
        std::lock_guard<std::mutex> lock(mappingMutex_);

        for (auto const& [_, map] : remoteMapList) {
            // Must has valid IGD pointer and use UPNP protocol.
            assert(map.getIgd());
            assert(map.getIgd()->getProtocol() == NatProtocolType::PUPNP);
            auto& mappingList = getMappingList(map.getType());
            auto it = mappingList.find(map.getMapKey());
            if (it == mappingList.end()) {
                // Not present, request mapping remove.
                toRemoveList.emplace_back(std::move(map));
                // Make only few remove requests at once.
                if (toRemoveList.size() >= MAX_REQUEST_REMOVE_COUNT)
                    break;
            }
        }
    }

    // Remove un-tracked mappings.
    auto protocol = protocolList_.at(NatProtocolType::PUPNP);
    for (auto const& map : toRemoveList) {
        protocol->requestMappingRemove(map);
    }
}

void
UPnPContext::pruneMappingsWithInvalidIgds(const std::shared_ptr<IGD>& igd)
{
    //CHECK_VALID_THREAD();

    // Use temporary list to avoid holding the lock while
    // processing the mapping list.
    std::list<Mapping::sharedPtr_t> toRemoveList;
    {
        std::lock_guard<std::mutex> lock(mappingMutex_);

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
        map->updateState(MappingState::FAILED);
        unregisterMapping(map);
    }
}

void
UPnPContext::processPendingRequests(const std::shared_ptr<IGD>& igd)
{
    // This list holds the mappings to be requested. This is
    // needed to avoid performing the requests while holding
    // the lock.
    std::list<Mapping::sharedPtr_t> requestsList;

    // Populate the list of requests to perform.
    {
        std::lock_guard<std::mutex> lock(mappingMutex_);
        PortType typeArray[2] {PortType::TCP, PortType::UDP};

        for (auto type : typeArray) {
            auto& mappingList = getMappingList(type);
            for (auto& [_, map] : mappingList) {
                if (map->getState() == MappingState::PENDING) {
                    if (logger_) logger_->debug("Send pending request for mapping {} to IGD {}",
                             map->toString(),
                             igd->toString());
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
UPnPContext::processMappingWithAutoUpdate()
{
    // This list holds the mappings to be requested. This is
    // needed to avoid performing the requests while holding
    // the lock.
    std::list<Mapping::sharedPtr_t> requestsList;

    // Populate the list of requests for mappings with auto-update enabled.
    {
        std::lock_guard<std::mutex> lock(mappingMutex_);
        PortType typeArray[2] {PortType::TCP, PortType::UDP};

        for (auto type : typeArray) {
            auto& mappingList = getMappingList(type);
            for (auto const& [_, map] : mappingList) {
                if (map->getState() == MappingState::FAILED and map->getAutoUpdate()) {
                    requestsList.emplace_back(map);
                }
            }
        }
    }

    for (auto const& oldMap : requestsList) {
        // Request a new mapping if auto-update is enabled.
        if (logger_) logger_->debug("Mapping {} has auto-update enabled, a new mapping will be requested",
                 oldMap->toString());

        // Reserve a new mapping.
        Mapping newMapping(oldMap->getType());
        newMapping.enableAutoUpdate(true);
        newMapping.setNotifyCallback(oldMap->getNotifyCallback());

        auto const& mapPtr = reserveMapping(newMapping);
        assert(mapPtr);

        // Release the old one.
        oldMap->setAvailable(true);
        oldMap->enableAutoUpdate(false);
        oldMap->setNotifyCallback(nullptr);
        unregisterMapping(oldMap);
    }
}

void
UPnPContext::onIgdUpdated(const std::shared_ptr<IGD>& igd, UpnpIgdEvent event)
{
    assert(igd);

    /*if (not isValidThread()) {
        ctx->post([this, igd, event] { onIgdUpdated(igd, event); });
        return;
    }*/

    // Reset to start search for a new best IGD.
    preferredIgd_.reset();

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

    // The IGD was removed or is invalid.
    if (event == UpnpIgdEvent::REMOVED or event == UpnpIgdEvent::INVALID_STATE) {
        if (logger_) logger_->warn("State of IGD [{} {}] [{}] changed to [{}]. Pruning the mapping list",
                  igd->getUID(),
                  igd->toString(),
                  protocolName,
                  IgdState);

        pruneMappingsWithInvalidIgds(igd);

        std::lock_guard<std::mutex> lock(mappingMutex_);
        validIgdList_.erase(igd);
        return;
    }

    // Update the IGD list.
    {
        std::lock_guard<std::mutex> lock(mappingMutex_);
        auto ret = validIgdList_.emplace(igd);
        if (ret.second) {
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

    // Update the provisionned mappings.
    updateMappingList(false);
}

void
UPnPContext::onMappingAdded(const std::shared_ptr<IGD>& igd, const Mapping& mapRes)
{
    //CHECK_VALID_THREAD();

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

    // Update the state and report to the owner.
    updateMappingState(map, MappingState::OPEN);

    if (logger_) logger_->debug("Mapping {} (on IGD {} [{}]) successfully performed",
             map->toString(),
             igd->toString(),
             map->getProtocolName());

    // Call setValid() to reset the errors counter. We need
    // to reset the counter on each successful response.
    igd->setValid(true);
}

#if HAVE_LIBNATPMP
void
UPnPContext::onMappingRenewed(const std::shared_ptr<IGD>& igd, const Mapping& map)
{
    auto mapPtr = getMappingWithKey(map.getMapKey());

    if (not mapPtr) {
        // We may receive a notification for a canceled request. Ignore it.
        if (logger_) logger_->warn("Renewed mapping {} from IGD  {} [{}] does not have a match in local list",
                  map.toString(),
                  igd->toString(),
                  map.getProtocolName());
        return;
    }
    if (mapPtr->getProtocol() != NatProtocolType::NAT_PMP or not mapPtr->isValid()
        or mapPtr->getState() != MappingState::OPEN) {
        if (logger_) logger_->warn("Renewed mapping {} from IGD {} [{}] is in unexpected state",
                  mapPtr->toString(),
                  igd->toString(),
                  mapPtr->getProtocolName());
        return;
    }

    mapPtr->setRenewalTime(map.getRenewalTime());
}
#endif

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
UPnPContext::deleteAllMappings(PortType type)
{
    /*if (not isValidThread()) {
        ctx->post([this, type] { deleteAllMappings(type); });
        return;
    }*/

    std::lock_guard<std::mutex> lock(mappingMutex_);
    auto& mappingList = getMappingList(type);

    for (auto const& [_, map] : mappingList) {
        requestRemoveMapping(map);
    }
}

void
UPnPContext::onMappingRemoved(const std::shared_ptr<IGD>& igd, const Mapping& mapRes)
{
    if (not mapRes.isValid())
        return;

    /*if (not isValidThread()) {
        ctx->post([this, igd, mapRes] { onMappingRemoved(igd, mapRes); });
        return;
    }*/

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
        std::lock_guard<std::mutex> lock(mappingMutex_);
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
    // when a IGD becomes available (in onIgdAdded() method).
    if (not isReady()) {
        if (logger_) logger_->warn("No IGD available. Mapping will be requested when an IGD becomes available");
    } else {
        requestMapping(mapPtr);
    }

    return mapPtr;
}

void
UPnPContext::unregisterMapping(const Mapping::sharedPtr_t& map)
{
    //CHECK_VALID_THREAD();

    if (not map) {
        // JAMI_ERR("Mapping pointer is null");
        return;
    }

    if (map->getAutoUpdate()) {
        // Dont unregister mappings with auto-update enabled.
        return;
    }
    auto& mappingList = getMappingList(map->getType());

    if (mappingList.erase(map->getMapKey()) == 1) {
        if (logger_) logger_->debug("Unregistered mapping {}", map->toString());
    } else {
        // The mapping may already be un-registered. Just ignore it.
        if (logger_) logger_->debug("Mapping {} [{}] does not have a local match",
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
    std::lock_guard<std::mutex> lock(mappingMutex_);
    auto const& mappingList = getMappingList(Mapping::getTypeFromMapKey(key));
    auto it = mappingList.find(key);
    if (it == mappingList.end())
        return nullptr;
    return it->second;
}

void
UPnPContext::getMappingStatus(PortType type, MappingStatus& status)
{
    std::lock_guard<std::mutex> lock(mappingMutex_);
    auto& mappingList = getMappingList(type);

    for (auto const& [_, map] : mappingList) {
        switch (map->getState()) {
        case MappingState::PENDING: {
            status.pendingCount_++;
            break;
        }
        case MappingState::IN_PROGRESS: {
            status.inProgressCount_++;
            break;
        }
        case MappingState::FAILED: {
            status.failedCount_++;
            break;
        }
        case MappingState::OPEN: {
            status.openCount_++;
            if (map->isAvailable())
                status.readyCount_++;
            break;
        }

        default:
            // Must not get here.
            assert(false);
            break;
        }
    }
}

void
UPnPContext::getMappingStatus(MappingStatus& status)
{
    getMappingStatus(PortType::TCP, status);
    getMappingStatus(PortType::UDP, status);
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

    updateMappingState(map, MappingState::FAILED);
    unregisterMapping(map);

    if (logger_) logger_->warn("Mapping request for {} failed on IGD {} [{}]",
              map->toString(),
              igd->toString(),
              igd->getProtocolName());
}

void
UPnPContext::updateMappingState(const Mapping::sharedPtr_t& map, MappingState newState, bool notify)
{
    // CHECK_VALID_THREAD();

    assert(map);

    // Ignore if the state did not change.
    if (newState == map->getState()) {
        // JAMI_DBG("Mapping %s already in state %s", map->toString().c_str(), map->getStateStr());
        return;
    }

    // Update the state.
    map->setState(newState);

    // Notify the listener if set.
    if (notify and map->getNotifyCallback())
        map->getNotifyCallback()(map);
}

#if HAVE_LIBNATPMP
void
UPnPContext::renewAllocations()
{
    //CHECK_VALID_THREAD();

    // Check if the we have valid PMP IGD.
    auto pmpProto = protocolList_.at(NatProtocolType::NAT_PMP);

    auto now = sys_clock::now();
    std::vector<Mapping::sharedPtr_t> toRenew;

    for (auto type : {PortType::TCP, PortType::UDP}) {
        std::lock_guard<std::mutex> lock(mappingMutex_);
        auto mappingList = getMappingList(type);
        for (auto const& [_, map] : mappingList) {
            if (not map->isValid())
                continue;
            if (map->getProtocol() != NatProtocolType::NAT_PMP)
                continue;
            if (map->getState() != MappingState::OPEN)
                continue;
            if (now < map->getRenewalTime())
                continue;

            toRenew.emplace_back(map);
        }
    }

    // Quit if there are no mapping to renew
    if (toRenew.empty())
        return;

    for (auto const& map : toRenew) {
        pmpProto->requestMappingRenew(*map);
    }
}
#endif

} // namespace upnp
} // namespace dhtnet
