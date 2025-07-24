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

#include "./igd.h"
#include "upnp/upnp_context.h"
#include "upnp/mapping.h"
#include "ip_utils.h"

#include <map>
#include <string>
#include <chrono>
#include <functional>
#include <condition_variable>
#include <list>

namespace dhtnet {
namespace upnp {

// UPnP device descriptions.
constexpr static const char* UPNP_ROOT_DEVICE = "upnp:rootdevice";
constexpr static const char* UPNP_IGD_DEVICE
    = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
constexpr static const char* UPNP_WAN_DEVICE = "urn:schemas-upnp-org:device:WANDevice:1";
constexpr static const char* UPNP_WANCON_DEVICE
    = "urn:schemas-upnp-org:device:WANConnectionDevice:1";
constexpr static const char* UPNP_WANIP_SERVICE = "urn:schemas-upnp-org:service:WANIPConnection:1";
constexpr static const char* UPNP_WANPPP_SERVICE
    = "urn:schemas-upnp-org:service:WANPPPConnection:1";


// Pure virtual interface class that UPnPContext uses to call protocol functions.
class UPnPProtocol : public std::enable_shared_from_this<UPnPProtocol>//, protected UpnpThreadUtil
{
public:
    enum class UpnpError : int { INVALID_ERR = -1, ERROR_OK, CONFLICT_IN_MAPPING };

    UPnPProtocol(const std::shared_ptr<dht::log::Logger>& logger) : logger_(logger) {};
    virtual ~UPnPProtocol() {};

    // Get protocol type.
    virtual NatProtocolType getProtocol() const = 0;

    // Get protocol type as string.
    virtual char const* getProtocolName() const = 0;

    // Clear all known IGDs.
    virtual void clearIgds() = 0;

    // Search for IGD.
    virtual void searchForIgd() = 0;

    // Get the IGD instance.
    virtual std::list<std::shared_ptr<IGD>> getIgdList() const = 0;

    // Return true if it has at least one valid IGD.
    virtual bool isReady() const = 0;

    // Get the list of already allocated mappings if any.
    virtual std::map<Mapping::key_t, Mapping> getMappingsListByDescr(const std::shared_ptr<IGD>&,
                                                                     const std::string&) const
    {
        return {};
    }

    // Get information about all existing port mappings on the given IGD
    virtual std::vector<MappingInfo> getMappingsInfo(const std::shared_ptr<IGD>& igd) const
    {
        return {};
    }

    // Sends a request to add a mapping.
    virtual void requestMappingAdd(const Mapping& map) = 0;

    // Renew an allocated mapping.
    virtual void requestMappingRenew(const Mapping& mapping) = 0;

    // Sends a request to remove a mapping.
    virtual void requestMappingRemove(const Mapping& igdMapping) = 0;

    // Set the user callbacks.
    virtual void setObserver(UpnpMappingObserver* obs) = 0;

    // Get the current host (local) address
    virtual const IpAddr getHostAddress() const = 0;

    // Terminate
    virtual void terminate() = 0;

    std::shared_ptr<dht::log::Logger> logger_;
};

} // namespace upnp
} // namespace dhtnet
