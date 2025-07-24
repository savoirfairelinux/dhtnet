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

#include "upnp/mapping.h"
#include "igd.h"

namespace dhtnet {
namespace upnp {

using namespace std::literals;

Mapping::Mapping(PortType type, uint16_t portExternal, uint16_t portInternal, bool available)
    : type_(type)
    , externalPort_(portExternal)
    , internalPort_(portInternal)
    , internalAddr_()
    , igd_()
    , available_(available)
    , state_(MappingState::PENDING)
    , notifyCb_(nullptr)
    , autoUpdate_(false)
    , renewalTime_(sys_clock::time_point::max())
{}

Mapping::Mapping(const Mapping& other)
{
    std::lock_guard lock(other.mutex_);

    internalAddr_ = other.internalAddr_;
    internalPort_ = other.internalPort_;
    externalPort_ = other.externalPort_;
    type_ = other.type_;
    igd_ = other.igd_;
    available_ = other.available_;
    state_ = other.state_;
    notifyCb_ = other.notifyCb_;
    lastNotifiedState_ = other.lastNotifiedState_;
    autoUpdate_ = other.autoUpdate_;
    renewalTime_ = other.renewalTime_;
    expiryTime_ = other.expiryTime_;
}

void
Mapping::updateFrom(const Mapping::sharedPtr_t& other)
{
    updateFrom(*other);
}

void
Mapping::updateFrom(const Mapping& other)
{
    if (type_ != other.type_) {
        return;
    }

    internalAddr_ = std::move(other.internalAddr_);
    internalPort_ = other.internalPort_;
    externalPort_ = other.externalPort_;
    igd_ = other.igd_;
    state_ = other.state_;
}

void
Mapping::setAvailable(bool val)
{
    std::lock_guard lock(mutex_);
    available_ = val;
}

void
Mapping::setState(const MappingState& state)
{
    std::lock_guard lock(mutex_);
    state_ = state;
}

const char*
Mapping::getStateStr() const
{
    std::lock_guard lock(mutex_);
    return getStateStr(state_);
}

std::string
Mapping::toString(bool extraInfo) const
{
    std::lock_guard lock(mutex_);
    std::ostringstream descr;
    descr << UPNP_MAPPING_DESCRIPTION_PREFIX << "-" << getTypeStr(type_);
    descr << ":" << std::to_string(internalPort_);

    if (extraInfo) {
        descr << " (state=" << getStateStr(state_)
              << ", auto-update=" << (autoUpdate_ ? "YES" : "NO") << ")";
    }

    return descr.str();
}

bool
Mapping::isValid() const
{
    std::lock_guard lock(mutex_);
    if (state_ == MappingState::FAILED)
        return false;
    if (internalPort_ == 0)
        return false;
    if (externalPort_ == 0)
        return false;
    if (not igd_ or not igd_->isValid())
        return false;
    IpAddr intAddr(internalAddr_);
    return intAddr and not intAddr.isLoopback();
}

bool
Mapping::hasValidHostAddress() const
{
    std::lock_guard lock(mutex_);

    IpAddr intAddr(internalAddr_);
    return intAddr and not intAddr.isLoopback();
}

bool
Mapping::hasPublicAddress() const
{
    std::lock_guard lock(mutex_);

    return igd_ and igd_->getPublicIp() and not igd_->getPublicIp().isPrivate();
}

Mapping::key_t
Mapping::getMapKey() const
{
    std::lock_guard lock(mutex_);

    key_t mapKey = internalPort_;
    if (type_ == PortType::UDP)
        mapKey |= 1 << (sizeof(uint16_t) * 8);
    return mapKey;
}

PortType
Mapping::getTypeFromMapKey(key_t key)
{
    return (key >> (sizeof(uint16_t) * 8)) ? PortType::UDP : PortType::TCP;
}

std::string
Mapping::getExternalAddress() const
{
    std::lock_guard lock(mutex_);
    if (igd_)
        return igd_->getPublicIp().toString();
    return {};
}

void
Mapping::setExternalPort(uint16_t port)
{
    std::lock_guard lock(mutex_);
    externalPort_ = port;
}

uint16_t
Mapping::getExternalPort() const
{
    std::lock_guard lock(mutex_);
    return externalPort_;
}

std::string
Mapping::getExternalPortStr() const
{
    std::lock_guard lock(mutex_);
    return std::to_string(externalPort_);
}

void
Mapping::setInternalAddress(const std::string& addr)
{
    std::lock_guard lock(mutex_);
    internalAddr_ = addr;
}

std::string
Mapping::getInternalAddress() const
{
    std::lock_guard lock(mutex_);
    return internalAddr_;
}

void
Mapping::setInternalPort(uint16_t port)
{
    std::lock_guard lock(mutex_);
    internalPort_ = port;
}

uint16_t
Mapping::getInternalPort() const
{
    std::lock_guard lock(mutex_);
    return internalPort_;
}

std::string
Mapping::getInternalPortStr() const
{
    std::lock_guard lock(mutex_);
    return std::to_string(internalPort_);
}

PortType
Mapping::getType() const
{
    std::lock_guard lock(mutex_);
    return type_;
}

const char*
Mapping::getTypeStr() const
{
    std::lock_guard lock(mutex_);
    return getTypeStr(type_);
}

bool
Mapping::isAvailable() const
{
    std::lock_guard lock(mutex_);
    return available_;
}

std::shared_ptr<IGD>
Mapping::getIgd() const
{
    std::lock_guard lock(mutex_);
    return igd_;
}

NatProtocolType
Mapping::getProtocol() const
{
    std::lock_guard lock(mutex_);
    if (igd_)
        return igd_->getProtocol();
    return NatProtocolType::UNKNOWN;
}

std::string_view
Mapping::getProtocolName() const
{
    switch(getProtocol()) {
    case NatProtocolType::NAT_PMP:
        return "NAT-PMP"sv;
    case NatProtocolType::PUPNP:
        return "PUPNP"sv;
    default:
        return "UNKNOWN"sv;
    }
}

void
Mapping::setIgd(const std::shared_ptr<IGD>& igd)
{
    std::lock_guard lock(mutex_);
    igd_ = igd;
}

MappingState
Mapping::getState() const
{
    std::lock_guard lock(mutex_);
    return state_;
}

void
Mapping::notify(sharedPtr_t mapping)
{
    if (!mapping)
        return;

    NotifyCallback cb;
    {
        std::lock_guard lock(mapping->mutex_);
        if (!mapping->notifyCb_)
            return;
        if (mapping->state_ != mapping->lastNotifiedState_) {
            mapping->lastNotifiedState_ = mapping->state_;
            cb = mapping->notifyCb_;
        }
    }
    if (cb)
        cb(mapping);
}

Mapping::NotifyCallback
Mapping::getNotifyCallback() const
{
    std::lock_guard lock(mutex_);
    return notifyCb_;
}

void
Mapping::setNotifyCallback(NotifyCallback cb)
{
    std::lock_guard lock(mutex_);
    notifyCb_ = std::move(cb);
    if (!notifyCb_) {
        // When a mapping is released by a controller, its NotifyCallback is set
        // to null (see UPnPContext::releaseMapping). We need to reset
        // lastNotifiedState_ when this happens to make sure the mapping isn't
        // in a incorrect state if it's later reused by a different controller.
        lastNotifiedState_ = std::nullopt;
    }
}

void
Mapping::enableAutoUpdate(bool enable)
{
    std::lock_guard lock(mutex_);
    autoUpdate_ = enable;
}

bool
Mapping::getAutoUpdate() const
{
    std::lock_guard lock(mutex_);
    return autoUpdate_;
}

sys_clock::time_point
Mapping::getRenewalTime() const
{
    std::lock_guard lock(mutex_);
    return renewalTime_;
}

void
Mapping::setRenewalTime(sys_clock::time_point time)
{
    std::lock_guard lock(mutex_);
    renewalTime_ = time;
}

sys_clock::time_point
Mapping::getExpiryTime() const
{
    std::lock_guard lock(mutex_);
    return expiryTime_;
}

void
Mapping::setExpiryTime(sys_clock::time_point time)
{
    std::lock_guard lock(mutex_);
    expiryTime_ = time;
}

void
Mapping::setAddedInfo(const Mapping& other)
{
    std::lock_guard lock(mutex_);
    if (other.igd_) {
        igd_ = other.igd_;
    }
    internalAddr_ = other.internalAddr_;
    externalPort_ = other.externalPort_;
    renewalTime_ = other.renewalTime_;
    expiryTime_ = other.expiryTime_;
}

} // namespace upnp
} // namespace dhtnet
