#!/bin/sh

# TUN interface name
tun="$2"

# VPN server address (remote peer public address)
server="$3"

# Extract the TUN interface number
tun_num=$(echo "$tun" | sed 's/tun//')

# Define the IP address prefix for the TUN interface
ip_address_prefix="10.66.77."
ip_peer_address_prefix="10.66.78."

# Generate the IP address and peer-to-peer address for the TUN interface
ip_address="${ip_address_prefix}${tun_num}"
ip_peer_address="${ip_peer_address_prefix}${tun_num}"

# Configure TUN interface IP address, mask, and peer-to-peer address
ifconfig "$tun" "$ip_address" netmask "255.255.255.0" pointopoint "$ip_peer_address"

# Bring up the TUN interface
ifconfig "$tun" up

# Check if the TUN interface is up
if ip link show dev "$tun" | grep -q "UP"; then
    echo "TUN interface $tun is up"
else
    echo "Error: Failed to bring up TUN interface $tun"
    exit 1
fi

# For client: retrieve default gateway and add routes
if [ "$1" = "client" ]; then
    # Retrieve default gateway
    gw=$(ip route show default | awk '/default/ {print $3}')

    # Add route to VPN server via default gateway
    ip route add "$server" via "$gw"

    # Add default route via TUN interface
    ip route add default dev "$tun"
else
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # Detect public interface
    public_interface=$(ip route | grep default | awk '{print $5}')

    # Configure NAT
    iptables -t nat -A POSTROUTING -o "$public_interface" -j MASQUERADE --random

    # Allow traffic from the private network to the public network
    iptables -A FORWARD -i "$tun" -o "$public_interface" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$public_interface" -o "$tun" -j ACCEPT
fi
