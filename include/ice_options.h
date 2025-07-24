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

#include "ip_utils.h"

#include <functional>
#include <vector>
#include <string>
#include <memory>

namespace dhtnet {

namespace upnp {
class UPnPContext;
}

class IceTransportFactory;
using IceTransportCompleteCb = std::function<void(bool)>;

struct StunServerInfo
{
    inline StunServerInfo& setUri(const std::string& args) {
        uri = args;
        return *this;
    }

    std::string uri; // server URI, mandatory
};

struct TurnServerInfo
{
    inline TurnServerInfo& setUri(const std::string& args) {
        uri = args;
        return *this;
    }
    inline TurnServerInfo& setUsername(const std::string& args) {
        username = args;
        return *this;
    }
    inline TurnServerInfo& setPassword(const std::string& args) {
        password = args;
        return *this;
    }
    inline TurnServerInfo& setRealm(const std::string& args) {
        realm = args;
        return *this;
    }

    std::string uri;      // server URI, mandatory
    std::string username; // credentials username (optional, empty if not used)
    std::string password; // credentials password (optional, empty if not used)
    std::string realm;    // credentials realm (optional, empty if not used)
};

/** Maps PJSIP QOS types */
enum class QosType
{
    BEST_EFFORT,    /**< Best effort traffic (default value).
                         Any QoS function calls with specifying
                         this value are effectively no-op   */
    BACKGROUND,     /**< Background traffic.                */
    VIDEO,          /**< Video traffic.                     */
    VOICE,          /**< Voice traffic.                     */
    CONTROL,        /**< Control traffic.                   */
    SIGNALLING      /**< Signalling traffic.                */
};

struct IceTransportOptions
{
    std::shared_ptr<IceTransportFactory> factory {};
    bool master {true};
    unsigned streamsCount {1};
    unsigned compCountPerStream {1};
    bool upnpEnable {false};
    IceTransportCompleteCb onInitDone {};
    IceTransportCompleteCb onNegoDone {};
    std::vector<StunServerInfo> stunServers;
    std::vector<TurnServerInfo> turnServers;
    bool tcpEnable {false};
    // Addresses used by the account owning the transport instance.
    IpAddr accountLocalAddr {};
    IpAddr accountPublicAddr {};
    std::shared_ptr<upnp::UPnPContext> upnpContext {};
    /** Per component QoS Type. */
    std::vector<QosType> qosType {};
};

}
