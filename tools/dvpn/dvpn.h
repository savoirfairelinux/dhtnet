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
#include "connectionmanager.h"
#include "multiplexed_socket.h"
#include "ice_transport_factory.h"
#include "certstore.h"

#include <asio.hpp>

namespace dhtnet {

class Dvpn
{
public:
    // Build a server
    Dvpn(const std::filesystem::path& path,
         dht::crypto::Identity identity,
         const std::string& bootstrap,
         const std::string& turn_host,
         const std::string& turn_user,
         const std::string& turn_pass,
         const std::string& turn_realm);
    // Build a client
    Dvpn(const std::filesystem::path& path,
         dht::crypto::Identity identity,
         const std::string& bootstrap,
         dht::InfoHash peer_id,
         const std::string& turn_host,
         const std::string& turn_user,
         const std::string& turn_pass,
         const std::string& turn_realm);
    ~Dvpn();
    void run();

private:
    std::unique_ptr<ConnectionManager> connectionManager;
    std::shared_ptr<Logger> logger;
    std::shared_ptr<tls::CertificateStore> certStore;
    std::shared_ptr<IceTransportFactory> iceFactory;
    std::shared_ptr<asio::io_context> ioContext;
    std::thread ioContextRunner;
};

} // namespace dhtnet
