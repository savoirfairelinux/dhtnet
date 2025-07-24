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

#include "dhtnet_crtmgr.h"
#include "fileutils.h"

#include <opendht/crypto.h>


namespace dhtnet {

dht::crypto::Identity
loadIdentity(const std::filesystem::path& privatekey, const std::filesystem::path& cert)
{
    // check files exists
    if (!std::filesystem::exists(privatekey) or !std::filesystem::exists(cert))
    {
        fmt::print(stderr, "Error: missing identity files\n");
        return {};
    }

    // Load identity
    auto privateKey = std::make_unique<dht::crypto::PrivateKey>(fileutils::loadFile(privatekey));
    auto certificate = std::make_unique<dht::crypto::Certificate>(fileutils::loadFile(cert));
    return dht::crypto::Identity(std::move(privateKey), std::move(certificate));
}

// generate a new identity
dht::crypto::Identity generateIdentity(const std::filesystem::path& path_id, const std::string& name, const dht::crypto::Identity& ca)
{
    auto identity = dht::crypto::generateIdentity(name, ca);
    std::error_code ec;
    std::filesystem::create_directories(path_id, ec);
    if (ec) {
        fmt::print(stderr, "Error: failed to create directory {}\n", path_id.string());
        return {};
    }
    // catch error
    try{
        dht::crypto::saveIdentity(identity, path_id / name);
    } catch (const std::exception& e) {
        fmt::print(stderr, "Error: failed to save identity: {}\n", e.what());
        return {};
    }
    return identity;
}
} // namespace dhtnet
