#!/bin/sh

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

# Check if the peer is a vpn client
[ "$6" = "true" ] && is_client=true || is_client=false

# Function to set up routes
setup_routes() {
    gw=$(ip route show default | awk '/default/ {print $3}')
    existing_route=$(ip route show "$server" | awk '/via/ { print $3 }')

    if [ "$existing_route" = "$gw" ]; then
        echo "Route to $server via $gw already exists."
    else
        ip route del "$server" &> /dev/null
        ip route add "$server" via "$gw"
        echo "Route to $server via $gw added."
    fi

    ip route add default dev "$tun"
}

# Function to set up NAT
setup_nat() {
    sysctl -w net.ipv4.ip_forward=1

    public_interface=$(ip route | awk '/default/{print $5}')

    # Check if the NAT rule already exists
    iptables -C -t nat -A POSTROUTING -o "$public_interface" -j MASQUERADE || iptables -t nat -A POSTROUTING -o "$public_interface" -j MASQUERADE

    # Allow traffic from the private network to the public network
    iptables -A FORWARD -i "$tun" -o "$public_interface" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$public_interface" -o "$tun" -j ACCEPT
}

# # Function to clean up routing table
# cleanup_routes() {
#     ip route del "$server"
#     ip route del default dev "$tun"
# }

# Configure TUN interface IP address, mask, and peer-to-peer address
ip address add "$tun_address" peer "$ptp_address" dev "$tun"

# Bring up the TUN interface
ip link set dev "$tun" up

# Check if TUN interface is up
if ip link show "$tun"; then
    echo "TUN interface $tun is up."
else
    echo "TUN interface $tun is not up."
fi

if $is_client; then
    # For client: set up routes
    setup_routes
else
    # For server: set up NAT
    setup_nat
fi

# Call cleanup_routes function when the script exits
# trap cleanup_routes EXIT