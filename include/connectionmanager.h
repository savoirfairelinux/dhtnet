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
#pragma once

#include "ice_options.h"
#include "multiplexed_socket.h"
#include "ice_transport_factory.h"
#include "turn_cache.h"

#include <opendht/dhtrunner.h>
#include <opendht/infohash.h>
#include <opendht/value.h>
#include <opendht/default_types.h>
#include <opendht/sockaddr.h>
#include <opendht/logger.h>

#include <memory>
#include <vector>
#include <string>

namespace dhtnet {

class ChannelSocket;
class ConnectionManager;
namespace upnp {
class Controller;
}
namespace tls {
class CertificateStore;
}
enum class ConnectionStatus : int { Connected, TLS, ICE, Connecting, Waiting };

/**
 * A PeerConnectionRequest is a request which ask for an initial connection
 * It contains the ICE request an ID and if it's an answer
 * Transmitted via the UDP DHT
 */
struct PeerConnectionRequest : public dht::EncryptedValue<PeerConnectionRequest>
{
    static const constexpr dht::ValueType& TYPE = dht::ValueType::USER_DATA;
    static constexpr const char* key_prefix = "peer:"; ///< base to compute the DHT listen key
    dht::Value::Id id = dht::Value::INVALID_ID;
    std::string ice_msg {};
    bool isAnswer {false};
    std::string connType {}; // Used for push notifications to know why we open a new connection
    MSGPACK_DEFINE_MAP(id, ice_msg, isAnswer, connType)
};

/**
 * Used to accept or not an incoming ICE connection (default accept)
 */
using onICERequestCallback = std::function<bool(const DeviceId&)>;
/**
 * Used to accept or decline an incoming channel request
 */
using ChannelRequestCallback = std::function<bool(const std::shared_ptr<dht::crypto::Certificate>&,
                                                  const std::string& /* name */)>;
/**
 * Used by connectDevice, when the socket is ready
 */
using ConnectCallback = std::function<void(const std::shared_ptr<ChannelSocket>&, const DeviceId&)>;
using ConnectCallbackLegacy = std::function<void(const std::shared_ptr<ChannelSocket>&, const dht::InfoHash&)>;

/**
 * Used when an incoming connection is ready
 */
using ConnectionReadyCallback = std::function<
    void(const DeviceId&, const std::string& /* channel_name */, std::shared_ptr<ChannelSocket>)>;

using iOSConnectedCallback
    = std::function<bool(const std::string& /* connType */, dht::InfoHash /* peer_h */)>;

/**
 * Manages connections to other devices
 * @note the account MUST be valid if ConnectionManager lives
 */
class ConnectionManager
{
public:
    struct Config;

    ConnectionManager(std::shared_ptr<Config> config_);
    ~ConnectionManager();

    /**
     * Open a new channel between the account's device and another device
     * This method will send a message on the account's DHT, wait a reply
     * and then, create a Tls socket with remote peer.
     * @param deviceId       Remote device
     * @param name           Name of the channel
     * @param cb             Callback called when socket is ready ready
     * @param noNewSocket    Do not negotiate a new socket if there is none
     * @param forceNewSocket Negotiate a new socket even if there is one // todo group with previous
     * (enum)
     * @param connType       Type of the connection
     */
    void connectDevice(const DeviceId& deviceId,
                       const std::string& name,
                       ConnectCallback cb,
                       bool noNewSocket = false,
                       bool forceNewSocket = false,
                       const std::string& connType = "");
    void connectDevice(const dht::InfoHash& deviceId,
                       const std::string& name,
                       ConnectCallbackLegacy cb,
                       bool noNewSocket = false,
                       bool forceNewSocket = false,
                       const std::string& connType = "");

    void connectDevice(const std::shared_ptr<dht::crypto::Certificate>& cert,
                       const std::string& name,
                       ConnectCallback cb,
                       bool noNewSocket = false,
                       bool forceNewSocket = false,
                       const std::string& connType = "");

    /**
     * Check if we are already connecting to a device with a specific name
     * @param deviceId      Remote device
     * @param name          Name of the channel
     * @return if connecting
     * @note isConnecting is not true just after connectDevice() as connectDevice is full async
     */
    bool isConnecting(const DeviceId& deviceId, const std::string& name) const;

    /**
     * Close all connections with a current device
     * @param peerUri      Peer URI
     */
    void closeConnectionsWith(const std::string& peerUri);

    /**
     * Method to call to listen to incoming requests
     * @param deviceId      Account's device
     */
    void onDhtConnected(const dht::crypto::PublicKey& devicePk);

    /**
     * Add a callback to decline or accept incoming ICE connections
     * @param cb    Callback to trigger
     */
    void onICERequest(onICERequestCallback&& cb);

    /**
     * Trigger cb on incoming peer channel
     * @param cb    Callback to trigger
     * @note        The callback is used to validate
     * if the incoming request is accepted or not.
     */
    void onChannelRequest(ChannelRequestCallback&& cb);

    /**
     * Trigger cb when connection with peer is ready
     * @param cb    Callback to trigger
     */
    void onConnectionReady(ConnectionReadyCallback&& cb);

    /**
     * Trigger cb when connection with peer is ready for iOS devices
     * @param cb    Callback to trigger
     */
    void oniOSConnected(iOSConnectedCallback&& cb);

    /**
     * @return the number of active sockets
     */
    std::size_t activeSockets() const;

    /**
     * Log informations for all sockets
     */
    void monitor() const;

    /**
     * Send beacon on peers supporting it
     */
    void connectivityChanged();

    /**
     * Create and return ICE options.
     */
    void getIceOptions(std::function<void(IceTransportOptions&&)> cb) noexcept;
    IceTransportOptions getIceOptions() const noexcept;

    /**
     * Get the published IP address, fallbacks to NAT if family is unspecified
     * Prefers the usage of IPv4 if possible.
     */
    IpAddr getPublishedIpAddress(uint16_t family = PF_UNSPEC) const;

    /**
     * Set published IP address according to given family
     */
    void setPublishedAddress(const IpAddr& ip_addr);

    /**
     * Store the local/public addresses used to register
     */
    void storeActiveIpAddress(std::function<void()>&& cb = {});

    /**
     * Retrieve the list of connections.
     *
     * @param device The device ID to filter the connections (optional).
     * @return The list of connections as a vector of maps, where each map represents a connection.
     *
     * Note: The connections are represented as maps with string keys and string values. The map
     *       contains the following key-value pairs:
     *       - "id": The unique identifier of the connection.
     *       - "userUri": The user URI associated with the connection (if available).
     *       - "status": The status of the connection, represented as an integer:
     *                   - 0: ConnectionStatus::Connected
     *                   - 1: ConnectionStatus::TLS
     *                   - 2: ConnectionStatus::ICE
     *                   - 3: ConnectionStatus::Connecting (for pending operations)
     *                   - 4: ConnectionStatus::Waiting (for pending operations)
     *       - "remoteAddress": The remote IP address of the connection (if available).
     *       - "remotePort": The remote port of the connection (if available).
     *
     *       If a specific device ID is provided, the returned list will only include connections
     *       associated with that device. Otherwise, connections from all devices will be included.
    */
    std::vector<std::map<std::string, std::string>> getConnectionList(
        const DeviceId& device = {}) const;

    /**
      * Retrieve the list of channels associated with a connection.
    *
    * @param connectionId The ID of the connection to fetch the channels from.
    * @return The list of channels as a vector of maps, where each map represents a channel
    *         and contains key-value pairs of channel ID and channel name.
    *
    *       If the specified connection ID is valid and associated with a connection,
    *       the method returns the list of channels associated with that connection.
    *       Otherwise, an empty vector is returned.
    */
    std::vector<std::map<std::string, std::string>> getChannelList(
        const std::string& connectionId) const;


    std::shared_ptr<Config> getConfig();

private:
    ConnectionManager() = delete;
    class Impl;
    std::shared_ptr<Impl> pimpl_;
};

struct ConnectionManager::Config
{
    /**
     * Determine if STUN public address resolution is required to register this account. In this
     * case a STUN server hostname must be specified.
     */
    bool stunEnabled {false};

    /**
     * The STUN server hostname (optional), used to provide the public IP address in case the
     * softphone stay behind a NAT.
     */
    std::string stunServer {};

    /**
     * Determine if TURN public address resolution is required to register this account. In this
     * case a TURN server hostname must be specified.
     */
    bool turnEnabled {false};

    /**
     * The TURN server hostname (optional), used to provide the public IP address in case the
     * softphone stay behind a NAT.
     */
    std::string turnServer;
    std::string turnServerUserName;
    std::string turnServerPwd;
    std::string turnServerRealm;

    std::shared_ptr<TurnCache> turnCache;

    std::string cachePath {};

    std::shared_ptr<asio::io_context> ioContext;
    std::shared_ptr<dht::DhtRunner> dht;
    dht::crypto::Identity id;

    tls::CertificateStore* certStore;

    dhtnet::IceTransportFactory* factory;

    /**
     * UPnP IGD controller and the mutex to access it
     */
    bool upnpEnabled;
    std::shared_ptr<dhtnet::upnp::Controller> upnpCtrl;

    std::shared_ptr<dht::log::Logger> logger;

    /**
     * returns whether or not UPnP is enabled and active
     * ie: if it is able to make port mappings
     */
    bool getUPnPActive() const;

};

} // namespace dhtnet