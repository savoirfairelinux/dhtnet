#!/usr/bin/env bash

if [[ -n "${DHTNET_VNET_UPNP_SH:-}" ]]; then
    return 0
fi
DHTNET_VNET_UPNP_SH=1

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

vnet_write_miniupnpd_config() {
    local destination="$1"
    local ext_ifname="$2"
    local listening_ip="$3"
    local uuid="$4"
    local friendly_name="$5"
    local ext_ip="$6"

    cat > "${destination}" <<CFG
ext_ifname=${ext_ifname}
listening_ip=${listening_ip}
enable_upnp=yes
secure_mode=no
system_uptime=yes
uuid=${uuid}
friendly_name=${friendly_name}
ext_ip=${ext_ip}
CFG
}

vnet_start_miniupnpd() {
    local namespace="$1"
    local config_file="$2"
    local pidfile="$3"
    local logfile="$4"
    local launcher_pid
    local daemon_pid
    local attempt

    ip netns exec "${namespace}" miniupnpd -d -f "${config_file}" -P "${pidfile}" \
        > "${logfile}" 2>&1 &
    launcher_pid=$!

    for ((attempt = 1; attempt <= 10; attempt++)); do
        if [[ -s "${pidfile}" ]]; then
            daemon_pid="$(<"${pidfile}")"
            if [[ "${daemon_pid}" =~ ^[0-9]+$ ]] && kill -0 "${daemon_pid}" 2>/dev/null; then
                return 0
            fi
        fi

        if ! kill -0 "${launcher_pid}" 2>/dev/null; then
            wait "${launcher_pid}" 2>/dev/null
            return 1
        fi
        sleep 0.1
    done

    if [[ ! -s "${pidfile}" ]] && kill -0 "${launcher_pid}" 2>/dev/null; then
        printf '%s\n' "${launcher_pid}" > "${pidfile}"
        return 0
    fi

    return 1
}

vnet_wait_for_upnpc() {
    local namespace="$1"
    local timeout_s="${2:-10}"
    local output_file="${3:-}"
    local expected_external_ip="${4:-}"
    local bind_ip="${5:-}"
    local probe_output
    local cleanup_output=0
    local attempt
    local escaped_external_ip

    if [[ -n "${output_file}" ]]; then
        probe_output="${output_file}"
    else
        probe_output="$(mktemp "${VNET_STATE_ROOT}/upnpc.XXXXXX")"
        cleanup_output=1
    fi

    escaped_external_ip="${expected_external_ip//./\\.}"

    for ((attempt = 1; attempt <= timeout_s; attempt++)); do
        local -a command=(ip netns exec "${namespace}" upnpc)
        if [[ -n "${bind_ip}" ]]; then
            command+=(-m "${bind_ip}")
        fi
        command+=(-s)

        if "${command[@]}" > "${probe_output}" 2>&1; then
            if grep -q "Found valid IGD" "${probe_output}" &&
                {
                    [[ -z "${expected_external_ip}" ]] ||
                        grep -Eq "ExternalIPAddress[[:space:]]*=[[:space:]]*${escaped_external_ip}([[:space:]]|$)" "${probe_output}"
                }; then
                if ((cleanup_output)); then
                    rm -f "${probe_output}"
                fi
                return 0
            fi
        fi
        sleep 1
    done

    if ((cleanup_output)); then
        rm -f "${probe_output}"
    fi
    return 1
}
