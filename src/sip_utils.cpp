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
#include "sip_utils.h"

namespace dhtnet {

namespace sip_utils {
std::string_view
sip_strerror(pj_status_t code)
{
    thread_local char err_msg[PJ_ERR_MSG_SIZE];
    return sip_utils::as_view(pj_strerror(code, err_msg, sizeof err_msg));
}
}
} // namespace dhtnet