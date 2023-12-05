#!/bin/sh

ip_address="$1"
# peer-to-peer address
ptp_address="$1"
# TUN interface address
tun_address="$2"
# TUN interface mask
tun_mask="$3"
# TUN interface name
tun="$4"
# VPN server address (remote peer public address)
server="$5"


# Configure TUN interface IP address, mask, and peer-to-peer address
ifconfig "$tun" "$ip_address" netmask "$tun_mask" pointopoint "$ptp_address"

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
if [ "$6" = "true" ]; then
    # Retrieve default gateway
    gw=$(ip route show default | awk '/default/ {print $3}')
=-;
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
