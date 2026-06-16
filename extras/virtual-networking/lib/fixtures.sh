#!/usr/bin/env bash

if [[ -n "${DHTNET_VNET_FIXTURES_SH:-}" ]]; then
    return 0
fi
DHTNET_VNET_FIXTURES_SH=1

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/netns.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/topology.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/upnp.sh"

vnet_fixture_apply_topology() {
    local topology_file="$1"
    vnet_topology_apply "${topology_file}"
}

vnet_fixture_delete_topology_namespaces() {
    local topology_file="$1"
    local -a topology_namespaces=()
    vnet_topology_read_namespaces "${topology_file}" topology_namespaces
    vnet_delete_namespaces "${topology_namespaces[@]}"
}

vnet_fixture_wait_for_udp_listener() {
    local namespace="$1"
    local port="$2"
    local timeout_s="${3:-10}"
    local attempt

    for ((attempt = 1; attempt <= timeout_s; attempt++)); do
        if ip netns exec "${namespace}" ss -lun 2>/dev/null | grep -Eq ":${port}([[:space:]]|$)"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

vnet_fixture_start_local_bootstrap() {
    local namespace="$1"
    local bind_ip="$2"
    local port="$3"
    local pidfile="$4"
    local logfile="$5"
    local timeout_s="${6:-10}"
    local bootstrap_script="$7"

    ip netns exec "${namespace}" python3 "${bootstrap_script}" \
        --bind "${bind_ip}" \
        --port "${port}" \
        > "${logfile}" 2>&1 &
    echo $! > "${pidfile}"
    vnet_fixture_wait_for_udp_listener "${namespace}" "${port}" "${timeout_s}"
}

vnet_fixture_start_miniupnpd_instance() {
    local namespace="$1"
    local config_file="$2"
    local pidfile="$3"
    local logfile="$4"
    local ext_iface="$5"
    local listen_iface="$6"
    local uuid="$7"
    local friendly_name="$8"
    local ext_ip="$9"

    vnet_write_miniupnpd_config \
        "${config_file}" \
        "${ext_iface}" \
        "${listen_iface}" \
        "${uuid}" \
        "${friendly_name}" \
        "${ext_ip}"
    vnet_start_miniupnpd "${namespace}" "${config_file}" "${pidfile}" "${logfile}"
}

vnet_fixture_wait_for_discovery() {
    local namespace="$1"
    local output_file="$2"
    local timeout_s="${3:-10}"

    vnet_wait_for_upnpc "${namespace}" "${timeout_s}" "${output_file}" || true
}

vnet_fixture_stop_pidfile() {
    local pidfile="$1"
    vnet_kill_pidfile "${pidfile}"
}
