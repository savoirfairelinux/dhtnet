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
#pragma once

#include "../ip_utils.h"

#include "mapping.h"

#include <opendht/rng.h>
#include <opendht/logger.h>
#include <asio/steady_timer.hpp>
#include <asio/system_timer.hpp>

#include <set>
#include <map>
#include <mutex>
#include <memory>
#include <string>
#include <chrono>
#include <random>
#include <atomic>
#include <condition_variable>

#include <cstdlib>

using IgdFoundCallback = std::function<void()>;

namespace dhtnet {
class IpAddr;
}

namespace dhtnet {
namespace upnp {

class UPnPProtocol;
class IGD;

struct IGDInfo
{
    std::string uid;
    IpAddr localIp;
    IpAddr publicIp;
    std::vector<MappingInfo> mappingInfoList;
};

enum class UpnpIgdEvent { ADDED, REMOVED, INVALID_STATE };

// Interface used to report mapping event from the protocol implementations.
// This interface is meant to be implemented only by UPnPContext class. Since
// this class is a singleton, it's assumed that it outlives the protocol
// implementations. In other words, the observer is always assumed to point to a
// valid instance.
class UpnpMappingObserver
{
public:
    UpnpMappingObserver() {};
    virtual ~UpnpMappingObserver() {};

    virtual void onIgdUpdated(const std::shared_ptr<IGD>& igd, UpnpIgdEvent event) = 0;
    virtual void onMappingAdded(const std::shared_ptr<IGD>& igd, const Mapping& map) = 0;
    virtual void onMappingRequestFailed(const Mapping& map) = 0;
    virtual void onMappingRenewed(const std::shared_ptr<IGD>& igd, const Mapping& map) = 0;
    virtual void onMappingRemoved(const std::shared_ptr<IGD>& igd, const Mapping& map) = 0;
};

class UPnPContext : public UpnpMappingObserver
{
public:
    UPnPContext(const std::shared_ptr<asio::io_context>& ctx, const std::shared_ptr<dht::log::Logger>& logger);
    ~UPnPContext();

    std::shared_ptr<asio::io_context> createIoContext(const std::shared_ptr<asio::io_context>& ctx, const std::shared_ptr<dht::log::Logger>& logger);

    // Terminate the instance.
    void shutdown();

    // Set the known public address
    void setPublicAddress(const IpAddr& addr);

    // Check if there is a valid IGD in the IGD list.
    bool isReady() const;

    // Get external Ip of a chosen IGD.
    IpAddr getExternalIP() const;

    // Inform the UPnP context that the network status has changed.
    void connectivityChanged();

    // Returns a shared pointer of the mapping.
    Mapping::sharedPtr_t reserveMapping(Mapping& requestedMap);

    // Release a used mapping (make it available for future use).
    // TODO: The current implementation doesn't seem to do the "make it available for future use" part... fix this.
    void releaseMapping(const Mapping& map);

    // Register a controller
    void registerController(void* controller);
    // Unregister a controller
    void unregisterController(void* controller);

    // Generate random port numbers
    static uint16_t generateRandomPort(PortType type);

    // Return information about the UPnPContext's valid IGDs, including the list
    // of all existing port mappings (for IGDs which support a protocol that allows
    // querying that information -- UPnP does, but NAT-PMP doesn't for example)
    std::vector<IGDInfo> getIgdsInfo() const;

    template <typename T>
    inline void dispatch(T&& f) {
        ctx->dispatch(std::move(f));
    }

    void restart()
    {
        stopUpnp();
        startUpnp();
    }

private:
    // Initialization
    void init();

    /**
     * @brief start the search for IGDs activate the mapping
     * list update.
     *
     */
    void startUpnp();

    /**
     * @brief Clear all IGDs and release/delete current mappings
     *
     * @param forceRelease If true, also delete mappings with enabled
     * auto-update feature.
     *
     */
    void stopUpnp(bool forceRelease = false);

    void shutdown(std::condition_variable& cv);

    // Add a new mapping to the local list and
    // send a request to the IGD to create it.
    Mapping::sharedPtr_t registerMapping(Mapping& map);

    // Remove the given mapping from the local list.
    //
    // If the mapping has auto-update enabled, then a new mapping of the same
    // type will be reserved unless ignoreAutoUpdate is true.
    void unregisterMapping(const Mapping::sharedPtr_t& map, bool ignoreAutoUpdate = false);

    // Perform the request on the provided IGD.
    void requestMapping(const Mapping::sharedPtr_t& map);

    // Request a mapping remove from the IGD.
    void requestRemoveMapping(const Mapping::sharedPtr_t& map);

    // Update the state and notify the listener
    void updateMappingState(const Mapping::sharedPtr_t& map,
                            MappingState newState,
                            bool notify = true);

    // Provision ports.
    uint16_t getAvailablePortNumber(PortType type);

    // Update the current IGD
    void updateCurrentIgd();

    // Get the current IGD
    std::shared_ptr<IGD> getCurrentIgd() const;

    // Send a renewal request to the IGD for each mapping which is past its renewal time.
    void renewMappings();

    // Set a timer so that renewMappings is called when needed
    void scheduleMappingsRenewal();
    void _scheduleMappingsRenewal();

    // Add or remove mappings to maintain the number of available mappings
    // within the limits set by minAvailableMappings_ and maxAvailableMappings_.
    void enforceAvailableMappingsLimits();

    // Provision (pre-allocate) the requested number of mappings.
    void provisionNewMappings(PortType type, int portCount);

    // Close unused mappings.
    void deleteUnneededMappings(PortType type, int portCount);

    void syncLocalMappingListWithIgd();
    void _syncLocalMappingListWithIgd();

    void pruneMappingsWithInvalidIgds(const std::shared_ptr<IGD>& igd);

    /**
     * @brief Get the mapping list
     *
     * @param type transport type (TCP/UDP)
     * @return a reference on the map
     * @warning concurrency protection done by the caller
     */
    std::map<Mapping::key_t, Mapping::sharedPtr_t>& getMappingList(PortType type);

    // Get the mapping from the key.
    Mapping::sharedPtr_t getMappingWithKey(Mapping::key_t key);

    // Process requests with pending status.
    void processPendingRequests();

    // Implementation of UpnpMappingObserver interface.

    // Callback used to report changes in IGD status.
    void onIgdUpdated(const std::shared_ptr<IGD>& igd, UpnpIgdEvent event) override;
    // Callback used to report add request status.
    void onMappingAdded(const std::shared_ptr<IGD>& igd, const Mapping& map) override;
    // Callback invoked when a request fails. Reported on failures for both
    // new requests and renewal requests.
    void onMappingRequestFailed(const Mapping& map) override;

    // Callback used to report renew request status.
    void onMappingRenewed(const std::shared_ptr<IGD>& igd, const Mapping& map) override;

    // Callback used to report remove request status.
    void onMappingRemoved(const std::shared_ptr<IGD>& igd, const Mapping& map) override;

private:
    UPnPContext(const UPnPContext&) = delete;
    UPnPContext(UPnPContext&&) = delete;
    UPnPContext& operator=(UPnPContext&&) = delete;
    UPnPContext& operator=(const UPnPContext&) = delete;

    void _connectivityChanged(const asio::error_code& ec);

    // Thread (io_context), destroyed last
    std::unique_ptr<std::thread> ioContextRunner_ {};

    bool started_ {false};

    // The known public address. The external addresses returned by
    // the IGDs will be checked against this address.
    IpAddr knownPublicAddress_ {};

    // Set of registered controllers
    std::mutex mutable controllerMutex_;
    std::set<void*> controllerList_;

    // Map of available protocols.
    std::map<NatProtocolType, std::shared_ptr<UPnPProtocol>> protocolList_;

    // Port ranges for TCP and UDP (in that order).
    std::map<PortType, std::pair<uint16_t, uint16_t>> portRange_ {};

    // Minimum and maximum limits on the number of available
    // mappings to keep in the list at any given time
    int minAvailableMappings_[2] {4, 8};
    int maxAvailableMappings_[2] {8, 12};
    int getMinAvailableMappings(PortType type) {
        unsigned index = (type == PortType::TCP) ? 0 : 1;
        return minAvailableMappings_[index];
    }
    int getMaxAvailableMappings(PortType type) {
        unsigned index = (type == PortType::TCP) ? 0 : 1;
        return maxAvailableMappings_[index];
    }

    std::shared_ptr<asio::io_context> ctx;
    std::shared_ptr<dht::log::Logger> logger_;
    asio::steady_timer connectivityChangedTimer_;
    asio::system_timer mappingRenewalTimer_;
    asio::steady_timer renewalSchedulingTimer_;
    asio::steady_timer syncTimer_;
    std::mutex syncMutex_;
    bool syncRequested_ {false};

    // This mutex must lock only these two members. All other
    // members must be accessed only from the UPnP context thread.
    // TODO: is this comment up to date?
    std::mutex mutable mappingMutex_;
    // List of mappings.
    std::map<Mapping::key_t, Mapping::sharedPtr_t> mappingList_[2] {};
    // Current IGD. Can be null if there is no valid IGD.
    // TODO: does this needs its own mutex?
    std::shared_ptr<IGD> currentIgd_;

    // Shutdown synchronization
    bool shutdownComplete_ {false};
    bool shutdownTimedOut_ {false};
};

} // namespace upnp
} // namespace dhtnet
