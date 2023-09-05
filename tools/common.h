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
#include <opendht/crypto.h>
#include "connectionmanager.h"
#include "multiplexed_socket.h"
#include "ice_transport_factory.h"
#include "certstore.h"

namespace dhtnet {

using Buffer = std::shared_ptr<std::vector<uint8_t>>;
constexpr size_t BUFFER_SIZE = 64 * 1024;

/**
 * Attempt to retrieve the identity from the .ssh directory, and if none is found, generate a new
 * certification.
 * @return dht::crypto::Identity
 */
dht::crypto::Identity loadIdentity(const std::filesystem::path& path);
// add certstore to the config
std::unique_ptr<ConnectionManager::Config> connectionManagerConfig(
    const std::filesystem::path& path,
    dht::crypto::Identity identity,
    const std::string& bootstrap,
    std::shared_ptr<Logger> logger,
    tls::CertificateStore& certStore,
    std::shared_ptr<asio::io_context> ioContext,
    IceTransportFactory& iceFactory,
    const std::string& turn_host ="",
    const std::string& turn_user="",
    const std::string& turn_pass="",
    const std::string& turn_realm="");
// add ioContext to readFromStdin

template<typename T>
void readFromPipe(std::shared_ptr<ChannelSocket> socket, T input, Buffer buffer);

} // namespace dhtnet