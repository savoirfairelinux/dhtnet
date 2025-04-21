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

#include <asio/post.hpp>

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
    asio::dispatch(*ioContext, [this] {
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
        if (logger_) logger_->warn("NAT-PMP: No valid local address!");
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

    if (logger_) logger_->debug("NAT-PMP: Attempting to initialize IGD");

    int err = initnatpmp(&natpmpHdl_, 0, 0);

    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Initializing IGD using default gateway failed!");
        const auto& localGw = ip_utils::getLocalGateway();
        if (not localGw) {
            if (logger_) logger_->warn("NAT-PMP: Unable to find valid gateway on local host");
            err = NATPMP_ERR_CANNOTGETGATEWAY;
        } else {
            if (logger_) logger_->warn("NAT-PMP: Attempting to initialize using detected gateway {}",
                      localGw.toString());
            struct in_addr inaddr;
            inet_pton(AF_INET, localGw.toString().c_str(), &inaddr);
            err = initnatpmp(&natpmpHdl_, 1, inaddr.s_addr);
        }
    }

    if (err < 0) {
        if (logger_) logger_->error("NAT-PMP: Unable to initialize libnatpmp → {}", getNatPmpErrorStr(err));
        return;
    }

    char addrbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &natpmpHdl_.gateway, addrbuf, sizeof(addrbuf));
    IpAddr igdAddr(addrbuf);
    if (logger_) logger_->debug("NAT-PMP: Initialized on gateway {}", igdAddr.toString());

    // Set the local (gateway) address.
    igd_->setLocalIp(igdAddr);
    // NAT-PMP protocol does not have UID, setting genetic one
    // for debugging purposes.
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

    asio::dispatch(*ioContext, [&] {
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
            if (logger_) logger_->warn("NAT-PMP: Setup failed after {} attempts. NAT-PMP will be disabled!",
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
        if (logger_) logger_->error("NAT-PMP: The observer is not set!");
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
    // libnatpmp isn't thread-safe, so we use Asio here to make
    // sure that all requests are sent from the same thread.
    asio::post(*ioContext, [w = weak(), mapping] {
        auto sthis = w.lock();
        if (!sthis)
            return;
        Mapping map(mapping);
        assert(map.getIgd());
        auto err = sthis->addPortMapping(map);
        if (err < 0) {
            if (sthis->logger_)
                sthis->logger_->warn("NAT-PMP: Request for mapping {} on {} failed with error {:d}: {}",
                                     map.toString(),
                                     sthis->igd_->toString(),
                                     err,
                                     sthis->getNatPmpErrorStr(err));

            if (sthis->isErrorFatal(err)) {
                // Fatal error, increment the counter.
                sthis->incrementErrorsCounter(sthis->igd_);
            }
            // Notify the listener.
            sthis->processMappingRequestFailed(std::move(map));
        } else {
            if (sthis->logger_)
                sthis->logger_->debug("NAT-PMP: Request for mapping {:s} on {:s} succeeded",
                                      map.toString(),
                                      sthis->igd_->toString());
            // Notify the listener.
            sthis->processMappingAdded(std::move(map));
        }
    });
}

void
NatPmp::requestMappingRenew(const Mapping& mapping)
{
    // libnatpmp isn't thread-safe, so we use Asio here to make
    // sure that all requests are sent from the same thread.
    asio::post(*ioContext, [w = weak(), mapping] {
        auto sthis = w.lock();
        if (!sthis)
            return;
        Mapping map(mapping);
        auto err = sthis->addPortMapping(map);
        if (err < 0) {
            if (sthis->logger_)
                sthis->logger_->warn("NAT-PMP: Renewal request for mapping {} on {} failed with error {:d}: {}",
                                     map.toString(),
                                     sthis->igd_->toString(),
                                     err,
                                     sthis->getNatPmpErrorStr(err));
            // Notify the listener.
            sthis->processMappingRequestFailed(std::move(map));

            if (sthis->isErrorFatal(err)) {
                // Fatal error, increment the counter.
                sthis->incrementErrorsCounter(sthis->igd_);
            }
        } else {
            if (sthis->logger_)
                sthis->logger_->debug("NAT-PMP: Renewal request for mapping {} on {} succeeded",
                                      map.toString(),
                                      sthis->igd_->toString());
            // Notify the listener.
            sthis->processMappingRenewed(map);
        }
    });
}

int
NatPmp::readResponse(natpmp_t& handle, natpmpresp_t& response)
{
    int err = 0;

    // Following libnatpmp's documentation, we call readnatpmpresponseorretry as long
    // as it returns NATPMP_TRYAGAIN. The maximum number of retries is determined by
    // libnatpmp's NATPMP_MAX_RETRIES macro, whose default value is 9, in accordance
    // with RFC 6886 (https://datatracker.ietf.org/doc/html/rfc6886#section-3.1).
    do {
        struct pollfd fds;
        fds.fd = handle.s;
        fds.events = POLLIN;
        struct timeval timeout;
        err = getnatpmprequesttimeout(&handle, &timeout);
        if (err < 0) {
            // getnatpmprequesttimeout should never fail. If it does,
            // then there's a bug in our code or in libnatpmp's.
            if (logger_)
                logger_->error("NAT-PMP: Unexpected error in getnatpmprequesttimeout: {}", err);
            break;
        }

        // Compute the value of the timeout in milliseconds (rounded up because rounding down would lead to
        // spinning in the cases where tv_sec is 0 and tv_usec is positive but less than 1000). If it's negative,
        // then we're already past the previous deadline, so we can set the timeout to zero in that case.
        int millis = (timeout.tv_sec * 1000) + ((timeout.tv_usec + 999) / 1000);
        if (millis < 0)
            millis = 0;

        // Wait for data.
        if (_poll(&fds, 1, millis) == -1) {
            err = NATPMP_ERR_SOCKETERROR;
            break;
        }

        // Read the data.
        err = readnatpmpresponseorretry(&handle, &response);
    } while(err == NATPMP_TRYAGAIN);

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

    // Read the response
    natpmpresp_t response;
    err = readResponse(natpmpHdl_, response);
    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Read response on IGD {} failed with error {}",
                  igd_->toString(),
                  getNatPmpErrorStr(err));
        return err;
    }

    // Even if readResponse returned without error, there is no guarantee that the
    // response we read is for the mapping we just requested. libnatpmp expects that
    // after each call to sendnewportmappingrequest, readnatpmpresponseorretry will
    // be called "as long as it returns NATPMP_TRYAGAIN". Failure to do so (for example
    // because of a bug as in https://git.jami.net/savoirfairelinux/dhtnet/-/issues/33)
    // can result in us reading the response to a previous request.
    bool responseValid = true;

    if (response.type == NATPMP_RESPTYPE_PUBLICADDRESS) {
        responseValid = false;
        if (logger_)
            logger_->error("NAT-PMP: Unexpected response to request for mapping {} from IGD {} [type: PUBLICADDRESS]",
                           mapping.toString(),
                           igd_->toString());
    } else {
        // There are only three possible response types in libnatpmp. If it's not
        // PUBLICADDRESS, then it's either UDPPORTMAPPING or TCPPORTMAPPING.
        uint16_t expectedType = mapping.getType() == PortType::UDP ? NATPMP_RESPTYPE_UDPPORTMAPPING
                                                                   : NATPMP_RESPTYPE_TCPPORTMAPPING;
        uint16_t expectedPrivatePort = mapping.getInternalPort();
        // If the response we got was actually for the mapping we requested, then both the
        // type and the internal port (called "private port" by libnatpmp) should match.
        // The other parameters, including the external port, are allowed to differ (see
        // section 3.3 of the NAT-PMP RFC: https://datatracker.ietf.org/doc/html/rfc6886).
        if (response.type != expectedType ||
            response.pnu.newportmapping.privateport != expectedPrivatePort) {
            responseValid = false;
            if (logger_)
                logger_->error("NAT-PMP: Unexpected response to request for mapping {} from IGD {}"
                               " [type={}, resultcode={}, privateport={}, mappedpublicport={}, lifetime={}]",
                               mapping.toString(),
                               igd_->toString(),
                               response.type == NATPMP_RESPTYPE_UDPPORTMAPPING ? "UDP" : "TCP",
                               response.resultcode,
                               response.pnu.newportmapping.privateport,
                               response.pnu.newportmapping.mappedpublicport,
                               response.pnu.newportmapping.lifetime);
        }
    }

    if (!responseValid) {
        // Unfortunately, libnatpmp only allows reading one response per request sent; calling
        // readResponse again at this point would result in a NATPMP_ERR_NOPENDINGREQ error.
        // Since it is unable to known whether the mapping was actually created or not, we return an
        // error to ensure the caller is unable to attempt to use a port mapping that doesn't exist.
        return NATPMP_ERR_INVALIDARGS;
    }

    uint16_t newExternalPort = response.pnu.newportmapping.mappedpublicport;
    uint32_t newLifetime = response.pnu.newportmapping.lifetime;
    if (lifetime > 0) {
        // We requested the creation/renewal of a mapping and didn't get an error, so at this point
        // newExternalPort and newLifetime should both be nonzero.
        if (newExternalPort == 0 || newLifetime == 0) {
            if (logger_) logger_->error("NAT-PMP: Response from IGD {} to request for mapping {} "
                                        "indicates that the mapping was deleted [external port: {}, lifetime: {}]",
                                        igd_->toString(),
                                        mapping.toString(),
                                        newExternalPort,
                                        newLifetime);
            return NATPMP_ERR_INVALIDARGS;
        }
    }

    // We need to set the mapping's lifetime and external port here because NAT-PMP
    // doesn't guarantee that the values returned by the IGD are those we requested.
    lifetime = newLifetime;
    mapping.setExternalPort(newExternalPort);
    return 0;
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
    asio::dispatch(*ioContext, [w = weak(), mapping] {
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
        if (logger_) logger_->error("NAT-PMP: Send public address request on IGD {} failed with error: {}",
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
    if (logger_) logger_->debug("NAT-PMP: Send request to close all existing mappings to IGD {}",
              igd_->toString().c_str());

    // NOTE: libnatpmp assumes that the response to each request will be read (see
    // https://git.jami.net/savoirfairelinux/dhtnet/-/issues/33 for more details), so
    // it's important that we call readResponse after each call to sendnewportmappingrequest
    // below, even if we don't actually look at the content of the responses.
    natpmpresp_t response;
    int err = sendnewportmappingrequest(&natpmpHdl_, NATPMP_PROTOCOL_TCP, 0, 0, 0);
    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Send close all TCP mappings request failed with error {}",
                  getNatPmpErrorStr(err));
    } else {
        err = readResponse(natpmpHdl_, response);
        if (err < 0 && logger_)
            logger_->warn("NAT-PMP: Failed to read response to TCP mappings deletion request: {}",
                          getNatPmpErrorStr(err));
    }
    err = sendnewportmappingrequest(&natpmpHdl_, NATPMP_PROTOCOL_UDP, 0, 0, 0);
    if (err < 0) {
        if (logger_) logger_->warn("NAT-PMP: Send close all UDP mappings request failed with error {}",
                  getNatPmpErrorStr(err));
    } else {
        err = readResponse(natpmpHdl_, response);
        if (err < 0 && logger_)
            logger_->warn("NAT-PMP: Failed to read response to UDP mappings deletion request: {}",
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
    case NATPMP_ERR_NOPENDINGREQ:
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

    if (observer_ && !shutdownComplete_) {
        observer_->onIgdUpdated(igd_, event);
    }
}

void
NatPmp::processMappingAdded(const Mapping& map)
{
    if (observer_ && !shutdownComplete_) {
        observer_->onMappingAdded(igd_, map);
    }
}

void
NatPmp::processMappingRequestFailed(const Mapping& map)
{
    if (observer_ && !shutdownComplete_) {
        observer_->onMappingRequestFailed(map);
    }
}

void
NatPmp::processMappingRenewed(const Mapping& map)
{
    if (observer_ && !shutdownComplete_) {
        observer_->onMappingRenewed(igd_, map);
    }
}

void
NatPmp::processMappingRemoved(const Mapping& map)
{
    if (observer_ && !shutdownComplete_) {
        observer_->onMappingRemoved(igd_, map);
    }
}

} // namespace upnp
} // namespace dhtnet

#endif //-- #if HAVE_LIBNATPMP
