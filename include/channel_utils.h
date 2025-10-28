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
#include "channel_socket.h"

#include <msgpack.hpp>


namespace dhtnet {

template<typename T>
ChannelSocket::RecvCb
buildMsgpackReader(std::function<void(T&&)> userCb)
{
    return [
        cb = std::move(userCb),
        unpacker = std::make_shared<msgpack::unpacker>()
    ](const uint8_t* buf, std::size_t len) -> ssize_t {
        unpacker->reserve_buffer(len);
        std::memcpy(unpacker->buffer(), buf, len);
        unpacker->buffer_consumed(len);

        try {
            // Catch msgpack errors to avoid terminating the reader thread
            msgpack::unpacked result;
            while (unpacker->next(result)) {
                cb(result.get().as<T>());
            }
        } catch (const msgpack::parse_error& e) {
            return -1;
        } catch (const std::bad_cast& e) {
            return -1;
        }
        return static_cast<ssize_t>(len);
    };
}

} // namespace dhtnet
