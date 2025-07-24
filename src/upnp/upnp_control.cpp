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
#include "upnp/upnp_control.h"
#include "upnp/upnp_context.h"

namespace dhtnet {
namespace upnp {

Controller::Controller(const std::shared_ptr<UPnPContext>& ctx)
 : upnpContext_(ctx)
{
    upnpContext_->dispatch([c=upnpContext_, this]{
        c->registerController(this);
    });
}

Controller::~Controller()
{
    releaseAllMappings();
    upnpContext_->dispatch([c=upnpContext_, this]{
        c->unregisterController(this);
    });
}

void
Controller::setPublicAddress(const IpAddr& addr)
{
    assert(upnpContext_);

    if (addr and addr.getFamily() == AF_INET) {
        upnpContext_->setPublicAddress(addr);
    }
}

bool
Controller::isReady() const
{
    assert(upnpContext_);
    return upnpContext_->isReady();
}

IpAddr
Controller::getExternalIP() const
{
    assert(upnpContext_);
    if (upnpContext_->isReady()) {
        return upnpContext_->getExternalIP();
    }
    return {};
}

Mapping::sharedPtr_t
Controller::reserveMapping(uint16_t port, PortType type)
{
    Mapping map(type, port, port);
    return reserveMapping(map);
}

Mapping::sharedPtr_t
Controller::reserveMapping(Mapping& requestedMap)
{
    assert(upnpContext_);

    // Try to get a provisioned port
    auto mapRes = upnpContext_->reserveMapping(requestedMap);
    if (mapRes)
        addLocalMap(*mapRes);
    return mapRes;
}

void
Controller::releaseMapping(const Mapping& map)
{
    assert(upnpContext_);

    removeLocalMap(map);
    return upnpContext_->releaseMapping(map);
}

void
Controller::releaseAllMappings()
{
    assert(upnpContext_);

    std::lock_guard lk(mapListMutex_);
    for (auto const& [_, map] : mappingList_) {
        upnpContext_->releaseMapping(map);
    }
    mappingList_.clear();
}

void
Controller::addLocalMap(const Mapping& map)
{
    if (map.getMapKey()) {
        std::lock_guard lock(mapListMutex_);
        auto ret = mappingList_.emplace(map.getMapKey(), map);
    }
}

bool
Controller::removeLocalMap(const Mapping& map)
{
    assert(upnpContext_);

    std::lock_guard lk(mapListMutex_);
    return mappingList_.erase(map.getMapKey()) == 1;
}

uint16_t
Controller::generateRandomPort(PortType type)
{
    return UPnPContext::generateRandomPort(type);
}

} // namespace upnp
} // namespace dhtnet
