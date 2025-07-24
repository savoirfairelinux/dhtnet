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

#include "../ip_utils.h"

#include <map>
#include <string>
#include <chrono>
#include <functional>
#include <mutex>
#include <memory>
#include <optional>

namespace dhtnet {
namespace upnp {

using sys_clock = std::chrono::system_clock;

enum class PortType { TCP, UDP };

/**
 * State Machine:
 *
 * - PENDING: Initial state when a mapping is requested by the client.
 * - IN_PROGRESS: Intermediate state while the mapping is being requested from an IGD.
 * - OPEN: State when the mapping is successfully established.
 * - FAILED: State when the mapping fails or is invalidated.
 *
 * State Transitions:
 *
 * - PENDING -> IN_PROGRESS: When the mapping request is sent to the IGD.
 * - PENDING -> FAILED: When there is no valid IGD and it's not during the IGD discovery phase.
 * - IN_PROGRESS -> OPEN: When the mapping is successfully established.
 * - IN_PROGRESS -> FAILED: When the mapping fails.
 * - OPEN -> FAILED: When the IGD becomes invalid or the mapping is removed.
 * - FAILED -> PENDING: When auto-update is enabled and there is no valid IGD.
 * - FAILED -> unregistered: When auto-update is disabled.
 *
 * If auto-update is enabled but there is a valid IGD, the mapping will be unregistered and a new mapping of the same type will be requested.
 */
enum class MappingState { PENDING, IN_PROGRESS, FAILED, OPEN };

enum class NatProtocolType;
class IGD;

class Mapping
{
    friend class UPnPContext;
    friend class NatPmp;
    friend class PUPnP;

public:
    using key_t = uint64_t;
    using sharedPtr_t = std::shared_ptr<Mapping>;
    using NotifyCallback = std::function<void(sharedPtr_t)>;

    static constexpr char const* MAPPING_STATE_STR[4] {"PENDING", "IN_PROGRESS", "FAILED", "OPEN"};
    static constexpr char const* UPNP_MAPPING_DESCRIPTION_PREFIX {"JAMI"};

    Mapping(PortType type,
            uint16_t portExternal = 0,
            uint16_t portInternal = 0,
            bool available = true);
    Mapping(const Mapping& other);
    Mapping(Mapping&& other) = delete;
    ~Mapping() = default;

    // Delete operators with confusing semantic.
    Mapping& operator=(Mapping&& other) = delete;
    bool operator==(const Mapping& other) = delete;
    bool operator!=(const Mapping& other) = delete;
    bool operator<(const Mapping& other) = delete;
    bool operator>(const Mapping& other) = delete;
    bool operator<=(const Mapping& other) = delete;
    bool operator>=(const Mapping& other) = delete;

    inline explicit operator bool() const { return isValid(); }

    void updateFrom(const Mapping& other);
    void updateFrom(const Mapping::sharedPtr_t& other);
    std::string getExternalAddress() const;
    uint16_t getExternalPort() const;
    std::string getExternalPortStr() const;
    std::string getInternalAddress() const;
    uint16_t getInternalPort() const;
    std::string getInternalPortStr() const;
    PortType getType() const;
    const char* getTypeStr() const;
    static const char* getTypeStr(PortType type) { return type == PortType::UDP ? "UDP" : "TCP"; }
    std::shared_ptr<IGD> getIgd() const;
    NatProtocolType getProtocol() const;
    std::string_view getProtocolName() const;
    bool isAvailable() const;
    MappingState getState() const;
    const char* getStateStr() const;
    static const char* getStateStr(MappingState state)
    {
        return MAPPING_STATE_STR[static_cast<int>(state)];
    }
    std::string toString(bool extraInfo = false) const;
    bool isValid() const;
    bool hasValidHostAddress() const;
    bool hasPublicAddress() const;
    void setNotifyCallback(NotifyCallback cb);
    void enableAutoUpdate(bool enable);
    bool getAutoUpdate() const;
    key_t getMapKey() const;
    static PortType getTypeFromMapKey(key_t key);
    sys_clock::time_point getRenewalTime() const;
    sys_clock::time_point getExpiryTime() const;

private:
    // Call the mapping's NotifyCallback (notifyCb_) if it has never been called before
    // or if the state of the mapping has changed since the last time it was called.
    static void notify(sharedPtr_t mapping);
    NotifyCallback getNotifyCallback() const;
    void setInternalAddress(const std::string& addr);
    void setExternalPort(uint16_t port);
    void setInternalPort(uint16_t port);

    void setIgd(const std::shared_ptr<IGD>& igd);
    void setAvailable(bool val);
    void setState(const MappingState& state);
    void setRenewalTime(sys_clock::time_point time);
    void setExpiryTime(sys_clock::time_point time);

    mutable std::mutex mutex_;
    PortType type_ {PortType::UDP};
    uint16_t externalPort_ {0};
    uint16_t internalPort_ {0};
    std::string internalAddr_;
    // Protocol and
    std::shared_ptr<IGD> igd_;
    // Track if the mapping is available to use.
    bool available_;

    // Track the state of the mapping
    MappingState state_;
    // Callback used to notify the user when the state of the mapping changes.
    NotifyCallback notifyCb_;
    // State of the mapping the last time its NotifyCallback was called.
    // Used by the `notify` function to avoid calling the NotifyCallback
    // twice for the same mapping state.
    std::optional<MappingState> lastNotifiedState_ {std::nullopt};

    // If true, a new mapping will be requested on behalf of the mapping
    // owner when the mapping state changes from "OPEN" to "FAILED".
    bool autoUpdate_;
    sys_clock::time_point renewalTime_;
    sys_clock::time_point expiryTime_;
};

struct MappingInfo
{
    std::string remoteHost;
    std::string protocol;
    std::string internalClient;
    std::string enabled;
    std::string description;
    uint16_t externalPort;
    uint16_t internalPort;
    uint32_t leaseDuration;
};

} // namespace upnp
} // namespace dhtnet
