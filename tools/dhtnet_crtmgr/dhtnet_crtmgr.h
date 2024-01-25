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
#include "fileutils.h"

namespace dhtnet {

/**
 * Get the private key and certificate from the given paths.
 * @return dht::crypto::Identity
 */
dht::crypto::Identity loadIdentity(const std::filesystem::path& path_id, const std::filesystem::path& path_ca);

/**
 * Generate a new certification Authority.
 */

void generateCA(const std::filesystem::path& path_ca);

/**
 * Generate a new identity.
 */
void generateIdentity(const std::filesystem::path& path_id, const std::filesystem::path& path_cert);
}