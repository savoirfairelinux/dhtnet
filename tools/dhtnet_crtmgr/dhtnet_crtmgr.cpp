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

#include "dhtnet_crtmgr.h"
#include "fileutils.h"

#include <opendht/crypto.h>


namespace dhtnet {

dht::crypto::Identity
loadIdentity(const std::filesystem::path& path_pkey, const std::filesystem::path& path_cert)
{
    // check files exists
    if (!std::filesystem::exists(path_pkey) or !std::filesystem::exists(path_cert))
    {
        fmt::print(stderr, "Error: missing identity files\n");
        return {};
    }

    // Load identity
    auto privateKey = std::make_unique<dht::crypto::PrivateKey>(fileutils::loadFile(path_pkey));
    auto certificate = std::make_unique<dht::crypto::Certificate>(fileutils::loadFile(path_cert));
    return dht::crypto::Identity(std::move(privateKey), std::move(certificate));
}

// generate a new certification Authority
void generateCA(const std::filesystem::path& path_ca)
{
    auto ca = dht::crypto::generateIdentity("dhtnet-ca");
    if (!std::filesystem::exists(path_ca))
        std::filesystem::create_directories(path_ca);
    dht::crypto::saveIdentity(ca, path_ca/ "dhtnet-ca");
}

// generate a new identity
void generatePeerIdentity(const std::filesystem::path& path_id, const dht::crypto::Identity& idCA)
{
    auto identity = dht::crypto::generateIdentity("identity", idCA);
    if (!std::filesystem::exists(path_id))
        std::filesystem::create_directories(path_id);
    dht::crypto::saveIdentity(identity, path_id/ "idPeer");
}
} // namespace dhtnet