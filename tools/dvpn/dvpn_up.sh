#!/bin/sh

# Peer-to-peer address
PEER_ADDRESS="10.66.78.0"

# TUN interface name second argument
TUN=$2

# VPN server address
SERVER=$3

# Wait for the TUN interface to become available
while ! ip link show dev $TUN >/dev/null 2>&1; do
    sleep 1
done

tun_num=$(echo $TUN | sed 's/tun//')
IP_ADDRESS_PREFIX="10.66.77."

IP_ADDRESS="${IP_ADDRESS_PREFIX}${tun_num}"
echo "Configuring IP address: $IP_ADDRESS"

# configure TUN interface ip address, mask, and peer-to-peer address
ifconfig $TUN $IP_ADDRESS netmask "255.255.255.0" pointopoint $PEER_ADDRESS

# Bring up the TUN interface
ifconfig $TUN up

# Check if the TUN interface is up
if [ $? -eq 0 ]; then
    echo "TUN interface $TUN is up"
else
    echo "Error: Failed to bring up TUN interface $TUN"
    exit 1
fi

# For client: retrieve default gateway and add routes
if [ "$1" = "client" ]; then
    # retrieve default gateway
    GW=$(ip route show default | awk '/default/ {print $3}')

    # add route to VPN server via default gateway
    ip route add $SERVER via $GW

    # add default route via TUN interface
    ip route add default dev $TUN
else
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    # Detect public interface
    PUBLIC_INTERFACE=$(ip route | grep default | awk '{print $5}')

    iptables -t nat -A POSTROUTING -o $PUBLIC_INTERFACE -j MASQUERADE --random

    # Allow traffic from the private network to the public network
    iptables -A FORWARD -i $TUN -o $PUBLIC_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $PUBLIC_INTERFACE -o $TUN -j ACCEPT
fi
