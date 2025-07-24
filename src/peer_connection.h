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
#include "certstore.h"
#include "opendht/crypto.h"
#include "ice_transport.h"
#include "tls_session.h"

#include <functional>
#include <future>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace dht {
namespace crypto {
struct PrivateKey;
struct Certificate;
} // namespace crypto
} // namespace dht

namespace dhtnet {
namespace tls {
class DhParams;
}

using OnStateChangeCb = std::function<bool(tls::TlsSessionState state)>;
using OnReadyCb = std::function<void(bool ok)>;
using onShutdownCb = std::function<void(void)>;

static constexpr int ICE_COMP_ID_SIP_TRANSPORT {1};

//==============================================================================

class IceSocketEndpoint : public GenericSocket<uint8_t>
{
public:
    using SocketType = GenericSocket<uint8_t>;
    explicit IceSocketEndpoint(std::shared_ptr<IceTransport> ice, bool isSender);
    ~IceSocketEndpoint();

    void shutdown() override;
    bool isReliable() const override { return ice_ ? ice_->isTCPEnabled() : false; }
    bool isInitiator() const override { return ice_ ? ice_->isInitiator() : true; }
    int maxPayload() const override
    {
        return 65536 /* The max for a RTP packet used to wrap data here */;
    }
    int waitForData(std::chrono::milliseconds timeout, std::error_code& ec) const override;
    std::size_t read(ValueType* buf, std::size_t len, std::error_code& ec) override;
    std::size_t write(const ValueType* buf, std::size_t len, std::error_code& ec) override;

    std::shared_ptr<IceTransport> underlyingICE() const { return ice_; }

    void setOnRecv(RecvCb&& cb) override
    {
        if (ice_)
            ice_->setOnRecv(compId_, cb);
    }

private:
    std::shared_ptr<IceTransport> ice_ {nullptr};
    std::atomic_bool iceStopped {false};
    std::atomic_bool iceIsSender {false};
    uint8_t compId_ {1};
};

//==============================================================================

/// Implement a TLS session IO over a system socket
class TlsSocketEndpoint : public GenericSocket<uint8_t>
{
public:
    using SocketType = GenericSocket<uint8_t>;
    using Identity = std::pair<std::shared_ptr<dht::crypto::PrivateKey>,
                               std::shared_ptr<dht::crypto::Certificate>>;

    TlsSocketEndpoint(std::unique_ptr<IceSocketEndpoint>&& tr,
                      tls::CertificateStore& certStore,
                      const std::shared_ptr<asio::io_context>& ioContext,
                      const Identity& local_identity,
                      const std::shared_future<tls::DhParams>& dh_params,
                      const dht::crypto::Certificate& peer_cert);
    TlsSocketEndpoint(std::unique_ptr<IceSocketEndpoint>&& tr,
                      tls::CertificateStore& certStore,
                      const std::shared_ptr<asio::io_context>& ioContext,
                      const Identity& local_identity,
                      const std::shared_future<tls::DhParams>& dh_params,
                      std::function<bool(const dht::crypto::Certificate&)>&& cert_check);
    ~TlsSocketEndpoint();

    bool isReliable() const override { return true; }
    bool isInitiator() const override;
    int maxPayload() const override;
    void shutdown() override;
    std::size_t read(ValueType* buf, std::size_t len, std::error_code& ec) override;
    std::size_t write(const ValueType* buf, std::size_t len, std::error_code& ec) override;

    std::shared_ptr<dht::crypto::Certificate> peerCertificate() const;

    void setOnRecv(RecvCb&&) override
    {
        throw std::logic_error("TlsSocketEndpoint::setOnRecv not implemented");
    }
    int waitForData(std::chrono::milliseconds timeout, std::error_code&) const override;

    void setOnStateChange(OnStateChangeCb&& cb);
    void setOnReady(OnReadyCb&& cb);

    IpAddr getLocalAddress() const;
    IpAddr getRemoteAddress() const;

    void monitor() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl_;
};

} // namespace dhtnet
