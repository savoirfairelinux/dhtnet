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
#include "nat_pmp.h"

#if HAVE_LIBNATPMP
#ifdef _WIN32
// On Windows we assume WSAStartup is called during DHT initialization
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#endif

#ifdef _WIN32
#define _poll(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)
#else
#define _poll(fds, nfds, timeout) poll(fds, nfds, timeout)
#endif

namespace dhtnet {
namespace upnp {

NatPmp::NatPmp(const std::shared_ptr<asio::io_context>& ctx, const std::shared_ptr<dht::log::Logger>& logger)
 : UPnPProtocol(logger), ioContext(ctx), searchForIgdTimer_(*ctx)
{
    // JAMI_DBG("NAT-PMP: Instance [%p] created", this);
    ioContext->dispatch([this] {
        igd_ = std::make_shared<PMPIGD>();
    });
}

NatPmp::~NatPmp()
{
    // JAMI_DBG("NAT-PMP: Instance [%p] destroyed", this);
}

void
NatPmp::initNatPmp()
{
    initialized_ = false;

    {
        std::lock_guard lock(natpmpMutex_);
        hostAddress_ = ip_utils::getLocalAddr(AF_INET);
    }

    // Local address must be valid.
    if (not getHostAddress() or getHostAddress().isLoopback()) {
        if (logger_) logger_->warn("NAT-PMP: Does not have a valid local address!");
        return;
    }

    assert(igd_);
    if (igd_->isValid()) {
        igd_->setValid(false);
        processIgdUpdate(UpnpIgdEvent::REMOVED);
    }

    igd_->setLocalIp(IpAddr());
    igd_->setPublicIp(IpAddr());
    igd_->setUID("");

    if (logger_) logger_->debug("NAT-PMP: Trying to initialize IGD");

    int err = initnatpmp(&natpmpHdl_, 0, 0);

    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Initializing IGD using default gateway failed!");
        const auto& localGw = ip_utils::getLocalGateway();
        if (not localGw) {
            if (logger_) logger_->warn("NAT-PMP: Couldn't find valid gateway on local host");
            err = NATPMP_ERR_CANNOTGETGATEWAY;
        } else {
            if (logger_) logger_->warn("NAT-PMP: Trying to initialize using detected gateway {}",
                      localGw.toString());
            struct in_addr inaddr;
            inet_pton(AF_INET, localGw.toString().c_str(), &inaddr);
            err = initnatpmp(&natpmpHdl_, 1, inaddr.s_addr);
        }
    }

    if (err < 0) {
        if (logger_) logger_->error("NAT-PMP: Can't initialize libnatpmp -> {}", getNatPmpErrorStr(err));
        return;
    }

    char addrbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &natpmpHdl_.gateway, addrbuf, sizeof(addrbuf));
    IpAddr igdAddr(addrbuf);
    if (logger_) logger_->debug("NAT-PMP: Initialized on gateway {}", igdAddr.toString());

    // Set the local (gateway) address.
    igd_->setLocalIp(igdAddr);
    // NAT-PMP protocol does not have UID, but we will set generic
    // one debugging purposes.
    igd_->setUID("NAT-PMP Gateway");

    // Search and set the public address.
    getIgdPublicAddress();

    // Update and notify.
    if (igd_->isValid()) {
        initialized_ = true;
        processIgdUpdate(UpnpIgdEvent::ADDED);
    };
}

void
NatPmp::setObserver(UpnpMappingObserver* obs)
{
    observer_ = obs;
}

void
NatPmp::terminate(std::condition_variable& cv)
{
    if (logger_) logger_->debug("NAT-PMP: Terminate instance {}", fmt::ptr(this));

    initialized_ = false;
    observer_ = nullptr;

    std::lock_guard lock(natpmpMutex_);
    shutdownComplete_ = true;
    cv.notify_one();
}

void
NatPmp::terminate()
{
    std::condition_variable cv {};

    ioContext->dispatch([&] {
        terminate(cv);
    });

    std::unique_lock lk(natpmpMutex_);
    if (cv.wait_for(lk, std::chrono::seconds(10), [this] { return shutdownComplete_; })) {
        if (logger_) logger_->debug("NAT-PMP: Shutdown completed");
    } else {
        if (logger_) logger_->error("NAT-PMP: Shutdown timed-out");
    }
}

const IpAddr
NatPmp::getHostAddress() const
{
    std::lock_guard lock(natpmpMutex_);
    return hostAddress_;
}

void
NatPmp::clearIgds()
{
    bool do_close = false;

    if (igd_) {
        if (igd_->isValid()) {
            do_close = true;
        }
        igd_->setValid(false);
    }

    initialized_ = false;
    searchForIgdTimer_.cancel();

    igdSearchCounter_ = 0;

    if (do_close) {
        closenatpmp(&natpmpHdl_);
        memset(&natpmpHdl_, 0, sizeof(natpmpHdl_));
    }
}

void
NatPmp::searchForIgd()
{
    if (not initialized_) {
        observer_->onIgdDiscoveryStarted();
        initNatPmp();
    }

    // Schedule a retry in case init failed.
    if (not initialized_) {
        if (igdSearchCounter_++ < MAX_RESTART_SEARCH_RETRIES) {
            if (logger_) logger_->debug("NAT-PMP: Start search for IGDs. Attempt {}", igdSearchCounter_);
            // Cancel the current timer (if any) and re-schedule.
            searchForIgdTimer_.expires_after(NATPMP_SEARCH_RETRY_UNIT * igdSearchCounter_);
            searchForIgdTimer_.async_wait([w=weak()](const asio::error_code& ec) {
                if (!ec) {
                    if (auto shared = w.lock())
                        shared->searchForIgd();
                }
            });
        } else {
            if (logger_) logger_->warn("NAT-PMP: Setup failed after {} trials. NAT-PMP will be disabled!",
                       MAX_RESTART_SEARCH_RETRIES);
        }
    }
}

std::list<std::shared_ptr<IGD>>
NatPmp::getIgdList() const
{
    std::lock_guard lock(natpmpMutex_);
    std::list<std::shared_ptr<IGD>> igdList;
    if (igd_->isValid())
        igdList.emplace_back(igd_);
    return igdList;
}

bool
NatPmp::isReady() const
{
    if (observer_ == nullptr) {
        if (logger_) logger_->error("NAT-PMP: the observer is not set!");
        return false;
    }

    // Must at least have a valid local address.
    if (not getHostAddress() or getHostAddress().isLoopback())
        return false;

    return igd_ and igd_->isValid();
}

void
NatPmp::incrementErrorsCounter(const std::shared_ptr<IGD>& igdIn)
{
    if (not validIgdInstance(igdIn)) {
        return;
    }

    if (not igd_->isValid()) {
        // Already invalid. Nothing to do.
        return;
    }

    if (not igd_->incrementErrorsCounter()) {
        // Disable this IGD.
        igd_->setValid(false);
        // Notify the listener.
        if (logger_) logger_->warn("NAT-PMP: No more valid IGD!");

        processIgdUpdate(UpnpIgdEvent::INVALID_STATE);
    }
}

void
NatPmp::requestMappingAdd(const Mapping& mapping)
{
    Mapping map(mapping);
    assert(map.getIgd());
    auto err = addPortMapping(map);
    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Request for mapping {} on {} failed with error {:d}: {}",
                  map.toString(),
                  igd_->toString(),
                  err,
                  getNatPmpErrorStr(err));

        if (isErrorFatal(err)) {
            // Fatal error, increment the counter.
            incrementErrorsCounter(igd_);
        }
        // Notify the listener.
        processMappingRequestFailed(std::move(map));
    } else {
        if (logger_) logger_->debug("NAT-PMP: Request for mapping {:s} on {:s} succeeded",
                 map.toString(),
                 igd_->toString());
        // Notify the listener.
        processMappingAdded(std::move(map));
    }
}

void
NatPmp::requestMappingRenew(const Mapping& mapping)
{
    Mapping map(mapping);
    auto err = addPortMapping(map);
    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Renewal request for mapping {} on {} failed with error {:d}: {}",
                  map.toString(),
                  igd_->toString(),
                  err,
                  getNatPmpErrorStr(err));
        // Notify the listener.
        processMappingRequestFailed(std::move(map));

        if (isErrorFatal(err)) {
            // Fatal error, increment the counter.
            incrementErrorsCounter(igd_);
        }
    } else {
        if (logger_) logger_->debug("NAT-PMP: Renewal request for mapping {} on {} succeeded",
                 map.toString(),
                 igd_->toString());
        // Notify the listener.
        processMappingRenewed(map);
    }
}

int
NatPmp::readResponse(natpmp_t& handle, natpmpresp_t& response)
{
    int err = 0;
    unsigned readRetriesCounter = 0;

    while (true) {
        if (readRetriesCounter++ > MAX_READ_RETRIES) {
            err = NATPMP_ERR_SOCKETERROR;
            break;
        }

        struct pollfd fds;
        fds.fd = handle.s;
        fds.events = POLLIN;
        struct timeval timeout;
        err = getnatpmprequesttimeout(&handle, &timeout);
        int millis = (timeout.tv_sec * 1000) + (timeout.tv_usec / 1000);
        // Note, getnatpmprequesttimeout can be negative if previous deadline is passed.
        if (err != 0 || millis < 0)
            millis = 50;

        // Wait for data.
        if (_poll(&fds, 1, millis) == -1) {
            err = NATPMP_ERR_SOCKETERROR;
            break;
        }

        // Read the data.
        err = readnatpmpresponseorretry(&handle, &response);

        if (err == NATPMP_TRYAGAIN) {
            std::this_thread::sleep_for(std::chrono::milliseconds(TIMEOUT_BEFORE_READ_RETRY));
        } else {
            break;
        }
    }

    return err;
}

int
NatPmp::sendMappingRequest(Mapping& mapping, uint32_t& lifetime)
{
    int err = sendnewportmappingrequest(&natpmpHdl_,
                                        mapping.getType() == PortType::UDP ? NATPMP_PROTOCOL_UDP
                                                                           : NATPMP_PROTOCOL_TCP,
                                        mapping.getInternalPort(),
                                        mapping.getExternalPort(),
                                        lifetime);

    if (err < 0) {
        if (logger_) logger_->error("NAT-PMP: Send mapping request failed with error {} {:d}",
                 getNatPmpErrorStr(err),
                 errno);
        return err;
    }

    unsigned readRetriesCounter = 0;

    while (readRetriesCounter++ < MAX_READ_RETRIES) {
        // Read the response
        natpmpresp_t response;
        err = readResponse(natpmpHdl_, response);

        if (err < 0) {
            if (logger_) logger_->warn("NAT-PMP: Read response on IGD {} failed with error {}",
                      igd_->toString(),
                      getNatPmpErrorStr(err));
        } else if (response.type != NATPMP_RESPTYPE_TCPPORTMAPPING
                   and response.type != NATPMP_RESPTYPE_UDPPORTMAPPING) {
            if (logger_) logger_->error("NAT-PMP: Unexpected response type ({:d}) for mapping {} from IGD {}.",
                     response.type,
                     mapping.toString(),
                     igd_->toString());
            // Try to read again.
            continue;
        }

        uint16_t newExternalPort = response.pnu.newportmapping.mappedpublicport;
        uint32_t newLifetime = response.pnu.newportmapping.lifetime;
        if (lifetime > 0) {
            // We requested the creation/renewal of a mapping and didn't get an error, so at this point
            // newExternalPort and newLifetime should both be nonzero. However, that's not always the case
            // in practice (presumably because some routers don't implement NAT-PMP correctly).
            if (newExternalPort == 0 || newLifetime == 0) {
                if (logger_) logger_->warn("NAT-PMP: mapping request returned without error but the response"
                                           " contains invalid data (external port: {}, lifetime: {})",
                                           newExternalPort,
                                           newLifetime);
                err = NATPMP_ERR_INVALIDARGS;
            } else {
                lifetime = newLifetime;
                mapping.setExternalPort(newExternalPort);
            }
        }
       break;
    }

    return err;
}

int
NatPmp::addPortMapping(Mapping& mapping)
{
    auto const& igdIn = mapping.getIgd();
    assert(igdIn);
    assert(igdIn->getProtocol() == NatProtocolType::NAT_PMP);

    if (not igdIn->isValid() or not validIgdInstance(igdIn)) {
        mapping.setState(MappingState::FAILED);
        return NATPMP_ERR_INVALIDARGS;
    }

    mapping.setInternalAddress(getHostAddress().toString());

    uint32_t lifetime = MAPPING_ALLOCATION_LIFETIME;
    int err = sendMappingRequest(mapping, lifetime);

    if (err < 0) {
        mapping.setState(MappingState::FAILED);
        return err;
    }

    // Set the renewal time and update.
    mapping.setRenewalTime(sys_clock::now() + std::chrono::seconds(lifetime / 2));
    mapping.setState(MappingState::OPEN);

    return 0;
}

void
NatPmp::requestMappingRemove(const Mapping& mapping)
{
    ioContext->dispatch([w = weak(), mapping] {
        if (auto pmpThis = w.lock()) {
            Mapping map {mapping};
            pmpThis->removePortMapping(map);
        }
    });
}

void
NatPmp::removePortMapping(Mapping& mapping)
{
    auto igdIn = mapping.getIgd();
    assert(igdIn);
    if (not igdIn->isValid()) {
        return;
    }

    if (not validIgdInstance(igdIn)) {
        return;
    }

    Mapping mapToRemove(mapping);

    uint32_t lifetime = 0;
    int err = sendMappingRequest(mapping, lifetime);

    if (err < 0) {
        // Nothing to do if the request fails, just log the error.
        if (logger_) logger_->warn("NAT-PMP: Send remove request failed with error {}. Ignoring",
                  getNatPmpErrorStr(err));
    }

    // Update and notify the listener.
    mapToRemove.setState(MappingState::FAILED);
    processMappingRemoved(std::move(mapToRemove));
}

void
NatPmp::getIgdPublicAddress()
{
    // Set the public address for this IGD if it does not
    // have one already.
    if (igd_->getPublicIp()) {
        if (logger_) logger_->warn("NAT-PMP: IGD {} already have a public address ({})",
                  igd_->toString(),
                  igd_->getPublicIp().toString());
        return;
    }
    assert(igd_->getProtocol() == NatProtocolType::NAT_PMP);

    int err = sendpublicaddressrequest(&natpmpHdl_);

    if (err < 0) {
        if (logger_) logger_->error("NAT-PMP: send public address request on IGD {} failed with error: {}",
                 igd_->toString(),
                 getNatPmpErrorStr(err));

        if (isErrorFatal(err)) {
            // Fatal error, increment the counter.
            incrementErrorsCounter(igd_);
        }
        return;
    }

    natpmpresp_t response;
    err = readResponse(natpmpHdl_, response);

    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Read response on IGD {} failed - {}",
                  igd_->toString(),
                  getNatPmpErrorStr(err));
        return;
    }

    if (response.type != NATPMP_RESPTYPE_PUBLICADDRESS) {
        if (logger_) logger_->error("NAT-PMP: Unexpected response type ({:d}) for public address request from IGD {}.",
                 response.type,
                 igd_->toString());
        return;
    }

    IpAddr publicAddr(response.pnu.publicaddress.addr);

    if (not publicAddr) {
        if (logger_) logger_->error("NAT-PMP: IGD {} returned an invalid public address {}",
                 igd_->toString(),
                 publicAddr.toString());
    }

    // Update.
    igd_->setPublicIp(publicAddr);
    igd_->setValid(true);

    if (logger_) logger_->debug("NAT-PMP: Setting IGD {} public address to {}",
             igd_->toString(),
             igd_->getPublicIp().toString());
}

void
NatPmp::removeAllMappings()
{
    if (logger_) logger_->warn("NAT-PMP: Send request to close all existing mappings to IGD {}",
              igd_->toString().c_str());

    int err = sendnewportmappingrequest(&natpmpHdl_, NATPMP_PROTOCOL_TCP, 0, 0, 0);
    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Send close all TCP mappings request failed with error {}",
                  getNatPmpErrorStr(err));
    }
    err = sendnewportmappingrequest(&natpmpHdl_, NATPMP_PROTOCOL_UDP, 0, 0, 0);
    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Send close all UDP mappings request failed with error {}",
                  getNatPmpErrorStr(err));
    }
}

const char*
NatPmp::getNatPmpErrorStr(int errorCode) const
{
#ifdef ENABLE_STRNATPMPERR
    return strnatpmperr(errorCode);
#else
    switch (errorCode) {
    case NATPMP_ERR_INVALIDARGS:
        return "INVALIDARGS";
        break;
    case NATPMP_ERR_SOCKETERROR:
        return "SOCKETERROR";
        break;
    case NATPMP_ERR_CANNOTGETGATEWAY:
        return "CANNOTGETGATEWAY";
        break;
    case NATPMP_ERR_CLOSEERR:
        return "CLOSEERR";
        break;
    case NATPMP_ERR_RECVFROM:
        return "RECVFROM";
        break;
    case NATPMP_ERR_NOPENDINGREQ:
        return "NOPENDINGREQ";
        break;
    case NATPMP_ERR_NOGATEWAYSUPPORT:
        return "NOGATEWAYSUPPORT";
        break;
    case NATPMP_ERR_CONNECTERR:
        return "CONNECTERR";
        break;
    case NATPMP_ERR_WRONGPACKETSOURCE:
        return "WRONGPACKETSOURCE";
        break;
    case NATPMP_ERR_SENDERR:
        return "SENDERR";
        break;
    case NATPMP_ERR_FCNTLERROR:
        return "FCNTLERROR";
        break;
    case NATPMP_ERR_GETTIMEOFDAYERR:
        return "GETTIMEOFDAYERR";
        break;
    case NATPMP_ERR_UNSUPPORTEDVERSION:
        return "UNSUPPORTEDVERSION";
        break;
    case NATPMP_ERR_UNSUPPORTEDOPCODE:
        return "UNSUPPORTEDOPCODE";
        break;
    case NATPMP_ERR_UNDEFINEDERROR:
        return "UNDEFINEDERROR";
        break;
    case NATPMP_ERR_NOTAUTHORIZED:
        return "NOTAUTHORIZED";
        break;
    case NATPMP_ERR_NETWORKFAILURE:
        return "NETWORKFAILURE";
        break;
    case NATPMP_ERR_OUTOFRESOURCES:
        return "OUTOFRESOURCES";
        break;
    case NATPMP_TRYAGAIN:
        return "TRYAGAIN";
        break;
    default:
        return "UNKNOWNERR";
        break;
    }
#endif
}

bool
NatPmp::isErrorFatal(int error)
{
    switch (error) {
    case NATPMP_ERR_INVALIDARGS:
    case NATPMP_ERR_SOCKETERROR:
    case NATPMP_ERR_CANNOTGETGATEWAY:
    case NATPMP_ERR_CLOSEERR:
    case NATPMP_ERR_RECVFROM:
    case NATPMP_ERR_NOGATEWAYSUPPORT:
    case NATPMP_ERR_CONNECTERR:
    case NATPMP_ERR_SENDERR:
    case NATPMP_ERR_UNDEFINEDERROR:
    case NATPMP_ERR_UNSUPPORTEDVERSION:
    case NATPMP_ERR_UNSUPPORTEDOPCODE:
    case NATPMP_ERR_NOTAUTHORIZED:
    case NATPMP_ERR_NETWORKFAILURE:
    case NATPMP_ERR_OUTOFRESOURCES:
        return true;
    default:
        return false;
    }
}

bool
NatPmp::validIgdInstance(const std::shared_ptr<IGD>& igdIn)
{
    if (igd_.get() != igdIn.get()) {
        if (logger_) logger_->error("NAT-PMP: IGD ({}) does not match local instance ({})",
                 igdIn->toString(),
                 igd_->toString());
        return false;
    }

    return true;
}

void
NatPmp::processIgdUpdate(UpnpIgdEvent event)
{
    if (igd_->isValid()) {
        // Remove all current mappings if any.
        removeAllMappings();
    }

    if (observer_ == nullptr)
        return;
    // Process the response on the context thread.
    ioContext->post([w = weak(), event] {
        if (auto shared = w.lock()) {
            if (!shared->shutdownComplete_) {
                shared->observer_->onIgdUpdated(shared->igd_, event);
            }
        }
    });
}

void
NatPmp::processMappingAdded(const Mapping& map)
{
    if (observer_ == nullptr)
        return;

    // Process the response on the context thread.
    ioContext->post([w=weak(), map] {
        if (auto shared = w.lock()) {
            if (!shared->shutdownComplete_) {
                shared->observer_->onMappingAdded(shared->igd_, map);
            }
        }
    });
}

void
NatPmp::processMappingRequestFailed(const Mapping& map)
{
    if (observer_ == nullptr)
        return;

    // Process the response on the context thread.
    ioContext->post([w=weak(), map] {
        if (auto shared = w.lock()) {
            if (!shared->shutdownComplete_) {
                shared->observer_->onMappingRequestFailed(map);
            }
        }
    });
}

void
NatPmp::processMappingRenewed(const Mapping& map)
{
    if (observer_ == nullptr)
        return;

    // Process the response on the context thread.
    ioContext->post([w=weak(), map] {
        if (auto shared = w.lock()) {
            if (!shared->shutdownComplete_) {
                shared->observer_->onMappingRenewed(shared->igd_, map);
            }
        }
    });
}

void
NatPmp::processMappingRemoved(const Mapping& map)
{
    if (observer_ == nullptr)
        return;

    // Process the response on the context thread.
    ioContext->post([w=weak(), map] {
        if (auto shared = w.lock()) {
            if (!shared->shutdownComplete_) {
                shared->observer_->onMappingRemoved(shared->igd_, map);
            }
        }
    });
}

} // namespace upnp
} // namespace dhtnet

#endif //-- #if HAVE_LIBNATPMP
