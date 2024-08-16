/*
 *  Copyright (C) 2023 Savoir-faire Linux Inc.
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
#include "connectionmanager.h"
#include "multiplexed_socket.h"
#include "ice_transport_factory.h"
#include "certstore.h"

#include <asio.hpp>

namespace dhtnet {

/*
    Both the client and the server have a TUN interface.
    The server creates a a TUN interface for each client.
    The client needs to know the server TUN address (peer address in the TUN configuration).
    The server send its TUN addresses to the client in the first packet.
    Two states are used to handle this:
    - METADATA: the first packet is sent by the server and contains its TUN address
    - DATA: the actual data
*/

struct MetaData
{
    std::string addrClient;
    std::string addrServer;
    std::string addrClientIpv6;
    std::string addrServerIpv6;
    MSGPACK_DEFINE_MAP(addrClient, addrServer, addrClientIpv6, addrServerIpv6);
};

class Dvpn
{
public:
    Dvpn(dht::crypto::Identity identity,
         const std::string& bootstrap,
         const std::string& turn_host,
         const std::string& turn_user,
         const std::string& turn_pass,
         const std::string& turn_realm,
         const std::string& configuration_file);
    ~Dvpn();
    void run();

    std::unique_ptr<ConnectionManager> connectionManager;
    std::shared_ptr<Logger> logger;
    std::shared_ptr<tls::CertificateStore> certStore;
    std::shared_ptr<IceTransportFactory> iceFactory;
    std::shared_ptr<asio::io_context> ioContext;
    enum class CommunicationState { METADATA, DATA };
    std::shared_ptr<tls::TrustStore> trustStore;
};

class DvpnServer : public Dvpn
{
public:
    // Build a server
    DvpnServer(dht::crypto::Identity identity,
               const std::string& bootstrap,
               const std::string& turn_host,
               const std::string& turn_user,
               const std::string& turn_pass,
               const std::string& turn_realm,
               const std::string& configuration_file,
               bool anonymous);
};

class DvpnClient : public Dvpn
{
public:
    // Build a client
    DvpnClient(dht::InfoHash peer_id,
               dht::crypto::Identity identity,
               const std::string& bootstrap,
               const std::string& turn_host,
               const std::string& turn_user,
               const std::string& turn_pass,
               const std::string& turn_realm,
               const std::string& configuration_file);

private:
    msgpack::unpacker pac_ {};
    CommunicationState connection_state = CommunicationState::METADATA;
    int tun_fd;
    char tun_device[IFNAMSIZ] = {0}; // IFNAMSIZ is typically the maximum size for interface names
    std::shared_ptr<asio::posix::stream_descriptor> tun_stream;
};

} // namespace dhtnet