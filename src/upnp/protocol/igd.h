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

#include <mutex>
#include <atomic>

#include "ip_utils.h"
#include "upnp/mapping.h"

#ifdef _MSC_VER
typedef uint16_t in_port_t;
#endif

namespace dhtnet {
namespace upnp {

enum class NatProtocolType { UNKNOWN, PUPNP, NAT_PMP };

class IGD
{
public:
    // Max error before moving the IGD to invalid state.
    constexpr static int MAX_ERRORS_COUNT = 10;

    IGD(NatProtocolType prot);
    virtual ~IGD() = default;
    bool operator==(IGD& other) const;

    NatProtocolType getProtocol() const { return protocol_; }

    char const* getProtocolName() const
    {
        return protocol_ == NatProtocolType::NAT_PMP ? "NAT-PMP" : "UPNP";
    };

    IpAddr getLocalIp() const
    {
        std::lock_guard lock(mutex_);
        return localIp_;
    }
    IpAddr getPublicIp() const
    {
        std::lock_guard lock(mutex_);
        return publicIp_;
    }
    void setLocalIp(const IpAddr& addr)
    {
        std::lock_guard lock(mutex_);
        localIp_ = addr;
    }
    void setPublicIp(const IpAddr& addr)
    {
        std::lock_guard lock(mutex_);
        publicIp_ = addr;
    }
    void setUID(const std::string& uid)
    {
        std::lock_guard lock(mutex_);
        uid_ = uid;
    }
    std::string getUID() const
    {
        std::lock_guard lock(mutex_);
        return uid_;
    }

    void setValid(bool valid);
    bool isValid() const { return valid_; }
    bool incrementErrorsCounter();
    int getErrorsCount() const;

    virtual const std::string toString() const = 0;

protected:
    const NatProtocolType protocol_ {NatProtocolType::UNKNOWN};
    std::atomic_bool valid_ {false};
    std::atomic<int> errorsCounter_ {0};

    mutable std::mutex mutex_;
    IpAddr localIp_ {};  // Local IP of the IGD (typically the same as the gateway).
    IpAddr publicIp_ {}; // External/public IP of IGD.
    std::string uid_ {};

private:
    IGD(IGD&& other) = delete;
    IGD(IGD& other) = delete;
    IGD& operator=(IGD&& other) = delete;
    IGD& operator=(IGD& other) = delete;
};

} // namespace upnp
} // namespace dhtnet
