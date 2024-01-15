#!/bin/sh

# peer-to-peer tun address
ptp_address="$1"
# TUN interface address
tun_address="$2"
# TUN interface name
tun="$3"
# VPN server address (remote peer public address)
server="$4"
# Check if the peer is a vpn client
[ "$5" = "true" ] && is_client=true || is_client=false
# TUN interface address ipv6
tun_address_ipv6="$6"
# peer-to-peer tun address ipv6
ptp_address_ipv6="$7"

# Function to set up routes
setup_route() {
    # Get the gateway address of the default route
    gw=$(ip route show default | awk '/default/ {print $3; exit}')

    existing_route=$(ip route show "$server" | awk '/via/ { print $3 }')
    echo "existing_route "$existing_route""

    if [ "$existing_route" = "$gw" ]; then
        echo "Route to $server via $gw already exists."
    else
        ip route del "$server" &> /dev/null
        ip route add "$server" via "$gw" metric 50 || echo "Failed to add route to $server via $gw."
        echo "Route to $server via $gw added."
    fi

    ip route add default dev "$tun" metric 50
    ip -6 route add default dev "$tun" metric 50
}


# Function to set up NAT
setup_nat() {
    sysctl -w net.ipv4.ip_forward=1
    # enable ipv6 forwarding
    sysctl -w net.ipv6.conf.all.forwarding=1
    public_interface=$(ip route | awk '/default/{print $5}')

    # Check if the NAT rule already exists
    iptables -C -t nat -A POSTROUTING -o "$public_interface" -j MASQUERADE || iptables -t nat -A POSTROUTING -o "$public_interface" -j MASQUERADE

    # Allow traffic from the private network to the public network
    iptables -A FORWARD -i "$tun" -o "$public_interface" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$public_interface" -o "$tun" -j ACCEPT

    public_interface_ipv6=$(ip -6 route | awk '/default/{print $5}')

    # Check if the default interface ipv6 is the same as the default interface ipv4
    if [ -n "$public_interface_ipv6" ] && [ "$public_interface" != "$public_interface_ipv6" ]; then
        # Check if the NAT rule already exists
        iptables -C -t nat -A POSTROUTING -o "$public_interface_ipv6" -j MASQUERADE || iptables -t nat -A POSTROUTING -o "$public_interface_ipv6" -j MASQUERADE

        # Allow traffic from the private network to the public network
        iptables -A FORWARD -i "$tun" -o "$public_interface_ipv6" -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -i "$public_interface_ipv6" -o "$tun" -j ACCEPT
    fi
}

# Configure TUN interface IP address, mask, and peer-to-peer address
ip -6 addr add "$tun_address_ipv6" remote "$ptp_address_ipv6" dev "$tun"
ip addr add "$tun_address" remote "$ptp_address" dev "$tun"

# Bring up the TUN interface
ip link set dev "$tun" up
# Check if TUN interface is up
if ip addr show "$tun"; then
    echo "TUN interface $tun is up."
else
    echo "TUN interface $tun is not up."
fi
if $is_client; then
    # For client: set up routes
    setup_route
else
    # For server: set up NAT
    setup_nat
fi