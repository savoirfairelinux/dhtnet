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

#include <utility>
#include <string>
#include <vector>
#include <cstring> // strcmp
#include <memory>

extern "C" {
#include <pjlib.h>
}

namespace dhtnet {
namespace sip_utils {

using namespace std::literals;

std::string_view sip_strerror(pj_status_t code);

// Helper function that return a constant pj_str_t from an array of any types
// that may be statically casted into char pointer.
// Per convention, the input array is supposed to be null terminated.
template<typename T, std::size_t N>
constexpr const pj_str_t
CONST_PJ_STR(T (&a)[N]) noexcept
{
    return {const_cast<char*>(a), N - 1};
}

inline const pj_str_t
CONST_PJ_STR(const std::string& str) noexcept
{
    return {const_cast<char*>(str.c_str()), (pj_ssize_t) str.size()};
}

inline constexpr pj_str_t
CONST_PJ_STR(const std::string_view& str) noexcept
{
    return {const_cast<char*>(str.data()), (pj_ssize_t) str.size()};
}

inline constexpr std::string_view
as_view(const pj_str_t& str) noexcept
{
    return {str.ptr, (size_t) str.slen};
}

} // namespace sip_utils
} // namespace dhtnet
