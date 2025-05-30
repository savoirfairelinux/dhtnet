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

#ifdef _WIN32
#define UPNP_USE_MSVCPP
#define UPNP_STATIC_LIB
#endif

#include "../upnp_protocol.h"
#include "../igd.h"
#include "upnp_igd.h"
#include "ip_utils.h"

#include <opendht/thread_pool.h>
#include <upnp/upnp.h>
#include <upnp/upnptools.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include <atomic>
#include <thread>
#include <list>
#include <map>
#include <set>
#include <string>
#include <memory>
#include <future>

namespace dhtnet {
class IpAddr;
}

namespace dhtnet {
namespace upnp {

constexpr static unsigned int MAPPING_LEASE_DURATION {7200};

class PUPnP : public UPnPProtocol
{
public:
    using XMLDocument = std::unique_ptr<IXML_Document, decltype(ixmlDocument_free)&>;

    enum class CtrlAction {
        UNKNOWN,
        ADD_PORT_MAPPING,
        DELETE_PORT_MAPPING,
        GET_GENERIC_PORT_MAPPING_ENTRY,
        GET_STATUS_INFO,
        GET_EXTERNAL_IP_ADDRESS
    };

    PUPnP(const std::shared_ptr<asio::io_context>& ctx, const std::shared_ptr<dht::log::Logger>& logger);
    ~PUPnP();

    // Set the observer
    void setObserver(UpnpMappingObserver* obs) override;

    // Returns the protocol type.
    NatProtocolType getProtocol() const override { return NatProtocolType::PUPNP; }

    // Get protocol type as string.
    char const* getProtocolName() const override { return "PUPNP"; }

    // Notifies a change in network.
    void clearIgds() override;

    // Sends out async search for IGD.
    void searchForIgd() override;

    // Get the IGD list.
    std::list<std::shared_ptr<IGD>> getIgdList() const override;

    // Return true if the it's fully setup.
    bool isReady() const override;

    // Get from the IGD the list of already allocated mappings if any.
    std::map<Mapping::key_t, Mapping> getMappingsListByDescr(
        const std::shared_ptr<IGD>& igd, const std::string& descr) const override;

    // Get information about all existing port mappings on the given IGD
    std::vector<MappingInfo> getMappingsInfo(const std::shared_ptr<IGD>& igd) const override;

    // Request a new mapping.
    void requestMappingAdd(const Mapping& mapping) override;

    // Renew an allocated mapping.
    void requestMappingRenew(const Mapping& mapping) override;

    // Removes a mapping.
    void requestMappingRemove(const Mapping& igdMapping) override;

    // Get the host (local) address.
    const IpAddr getHostAddress() const override;

    // Terminate the instance.
    void terminate() override;

private:
    PUPnP& operator=(const PUPnP&) = delete;
    PUPnP(const PUPnP&) = delete;

    void terminate(std::condition_variable& cv);

    // Init lib-upnp
    void initUpnpLib();

    // Return true if running.
    bool isRunning() const;

    // Register the client
    void registerClient();

    // Unregister the client
    void unregisterClient();

    // Start search for UPnP devices
    void searchForDevices();

    // Start search for UPnP device in a different thread
    void searchForDeviceAsync(const std::string& deviceType);

    // Return true if it has at least one valid IGD.
    bool hasValidIgd() const;

    // Update the host (local) address.
    void updateHostAddress();

    // Check the host (local) address.
    // Returns true if the address is valid.
    bool hasValidHostAddress();

    // Delete mappings matching the description
    void deleteMappingsByDescription(const std::shared_ptr<IGD>& igd,
                                     const std::string& description);

    // Search for the IGD in the local list of known IGDs.
    std::shared_ptr<UPnPIGD> findMatchingIgd(const std::string& ctrlURL) const;

    // Process the reception of an add mapping action answer.
    void processAddMapAction(const Mapping& map);

    // Called after a successful mapping renewal
    void processMappingRenewed(const Mapping& map);

    // Process the a mapping request failure.
    void processRequestMappingFailure(const Mapping& map);

    // Process the reception of a remove mapping action answer.
    void processRemoveMapAction(const Mapping& map);

    // Increment IGD errors counter.
    void incrementErrorsCounter(const std::shared_ptr<IGD>& igd);

    // Download XML document.
    void downLoadIgdDescription(const std::string& url);

    // Validate IGD from the xml document received from the router.
    bool validateIgd(const std::string& location, IXML_Document* doc_container_ptr);

    // Returns control point action callback based on xml node.
    static CtrlAction getAction(const char* xmlNode);

    // Control point callback.
    static int ctrlPtCallback(Upnp_EventType event_type, const void* event, void* user_data);
#if UPNP_VERSION < 10800
    static inline int ctrlPtCallback(Upnp_EventType event_type, void* event, void* user_data)
    {
        return ctrlPtCallback(event_type, (const void*) event, user_data);
    };
#endif
    // Process IGD responses.
    void processDiscoverySearchResult(const std::string& deviceId,
                                      const std::string& igdUrl,
                                      const IpAddr& dstAddr);
    void processDiscoveryAdvertisementByebye(const std::string& deviceId);
    void processDiscoverySubscriptionExpired(Upnp_EventType event_type,
                                             const std::string& eventSubUrl);

    // Callback event handler function for the UPnP client (control point).
    int handleCtrlPtUPnPEvents(Upnp_EventType event_type, const void* event);

    // Subscription event callback.
    static int subEventCallback(Upnp_EventType event_type, const void* event, void* user_data);
#if UPNP_VERSION < 10800
    static inline int subEventCallback(Upnp_EventType event_type, void* event, void* user_data)
    {
        return subEventCallback(event_type, (const void*) event, user_data);
    };
#endif

    // Callback subscription event function for handling subscription request.
    int handleSubscriptionUPnPEvent(Upnp_EventType event_type, const void* event);

    // Parses the IGD candidate.
    std::unique_ptr<UPnPIGD> parseIgd(IXML_Document* doc, std::string locationUrl);

    // These functions directly create UPnP actions and make synchronous UPnP
    // control point calls. Must be run on the PUPNP internal execution queue.
    bool actionIsIgdConnected(const UPnPIGD& igd);
    IpAddr actionGetExternalIP(const UPnPIGD& igd);
    bool actionAddPortMapping(const Mapping& mapping);
    bool actionDeletePortMapping(const Mapping& mapping);

    // Event type to string
    static const char* eventTypeToString(Upnp_EventType eventType);

    std::weak_ptr<PUPnP> weak() { return std::static_pointer_cast<PUPnP>(shared_from_this()); }

    // Initialization status.
    std::atomic_bool initialized_ {false};
    // Client registration status.
    std::atomic_bool clientRegistered_ {false};

    std::shared_ptr<asio::io_context> ioContext;
    asio::steady_timer searchForIgdTimer_;
    unsigned int igdSearchCounter_ {0};

    // List of discovered IGDs.
    std::set<std::string> discoveredIgdList_;

    // Control point handle.
    UpnpClient_Handle ctrlptHandle_ {-1};

    // Observer to report the results.
    UpnpMappingObserver* observer_ {nullptr};

    // List of valid IGDs.
    std::list<std::shared_ptr<IGD>> validIgdList_;

    // Current host address.
    IpAddr hostAddress_ {};

    // Calls from other threads that does not need synchronous access are
    // rescheduled on the UPnP private queue. This will avoid the need to
    // protect most of the data members of this class.
    // For some internal members (namely the validIgdList and the hostAddress)
    // that need to be synchronously accessed, are protected by this mutex.
    mutable std::mutex pupnpMutex_;

    // Shutdown synchronization
    bool shutdownComplete_ {false};

    // Count ongoing operations
    std::mutex ongoingOpsMtx_;
    int ongoingOps_ {0};
    bool destroying_ {false};
    dht::ThreadPool ongoingOpsThreadPool_;
};

} // namespace upnp
} // namespace dhtnet
