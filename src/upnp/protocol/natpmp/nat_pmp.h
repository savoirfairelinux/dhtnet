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

#include "../upnp_protocol.h"
#include "../igd.h"
#include "pmp_igd.h"
#include "ip_utils.h"

// uncomment to enable native natpmp error messages
//#define ENABLE_STRNATPMPERR 1
#include <natpmp.h>

#include <atomic>
#include <thread>

namespace dhtnet {
class IpAddr;
}

namespace dhtnet {
namespace upnp {

// Requested lifetime in seconds. The actual lifetime might be different.
constexpr static unsigned int MAPPING_ALLOCATION_LIFETIME {7200};
// Max number of IGD search attempts before failure.
constexpr static unsigned int MAX_RESTART_SEARCH_RETRIES {3};
// Base unit for the timeout between two successive IGD search.
constexpr static auto NATPMP_SEARCH_RETRY_UNIT {std::chrono::seconds(10)};

class NatPmp : public UPnPProtocol
{
public:
    NatPmp(const std::shared_ptr<asio::io_context>& ctx, const std::shared_ptr<dht::log::Logger>& logger);
    ~NatPmp();

    // Set the observer.
    void setObserver(UpnpMappingObserver* obs) override;

    // Returns the protocol type.
    NatProtocolType getProtocol() const override { return NatProtocolType::NAT_PMP; }

    // Get protocol type as string.
    char const* getProtocolName() const override { return "NAT-PMP"; }

    // Notifies a change in network.
    void clearIgds() override;

    // Renew pmp_igd.
    void searchForIgd() override;

    // Get the IGD list.
    std::list<std::shared_ptr<IGD>> getIgdList() const override;

    // Return true if it has at least one valid IGD.
    bool isReady() const override;

    // Request a new mapping.
    void requestMappingAdd(const Mapping& mapping) override;

    // Renew an allocated mapping.
    void requestMappingRenew(const Mapping& mapping) override;

    // Removes a mapping.
    void requestMappingRemove(const Mapping& mapping) override;

    // Get the host (local) address.
    const IpAddr getHostAddress() const override;

    // Terminate. Nothing to do here, the clean-up is done when
    // the IGD is cleared.
    void terminate() override;

private:
    NatPmp& operator=(const NatPmp&) = delete;
    NatPmp(const NatPmp&) = delete;

    std::weak_ptr<NatPmp> weak() { return std::static_pointer_cast<NatPmp>(shared_from_this()); }

    void terminate(std::condition_variable& cv);

    void initNatPmp();
    void getIgdPublicAddress();
    void removeAllMappings();
    int readResponse(natpmp_t& handle, natpmpresp_t& response);
    int sendMappingRequest(Mapping& mapping, uint32_t& lifetime);

    // Adds a port mapping.
    int addPortMapping(Mapping& mapping);
    // Removes a port mapping.
    void removePortMapping(Mapping& mapping);

    // True if the error is fatal.
    bool isErrorFatal(int error);
    // Gets NAT-PMP error code string.
    const char* getNatPmpErrorStr(int errorCode) const;
    // Get local getaway.
    std::unique_ptr<IpAddr> getLocalGateway() const;

    // Helpers to process user's callbacks
    void processIgdUpdate(UpnpIgdEvent event);
    void processMappingAdded(const Mapping& map);
    void processMappingRequestFailed(const Mapping& map);
    void processMappingRenewed(const Mapping& map);
    void processMappingRemoved(const Mapping& map);

    // Check if the IGD has a local match
    bool validIgdInstance(const std::shared_ptr<IGD>& igdIn);

    // Increment errors counter.
    void incrementErrorsCounter(const std::shared_ptr<IGD>& igd);

    std::atomic_bool initialized_ {false};

    // Data members
    std::shared_ptr<PMPIGD> igd_;
    natpmp_t natpmpHdl_;
    std::shared_ptr<asio::io_context> ioContext;
    asio::steady_timer searchForIgdTimer_;
    unsigned int igdSearchCounter_ {0};
    UpnpMappingObserver* observer_ {nullptr};
    IpAddr hostAddress_ {};

    // Calls from other threads that does not need synchronous access are
    // rescheduled on the NatPmp private queue. This will avoid the need to
    // protect most of the data members of this class.
    // For some internal members (such as the igd instance and the host
    // address) that need to be synchronously accessed, are protected by
    // this mutex.
    mutable std::mutex natpmpMutex_;

    // Shutdown synchronization
    bool shutdownComplete_ {false};
};

} // namespace upnp
} // namespace dhtnet
