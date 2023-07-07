#pragma once

#include <functional>
#include <vector>
#include <string>

#include "ip_utils.h"

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

struct IceTransportOptions
{
    IceTransportFactory* factory {nullptr};
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
};

}
