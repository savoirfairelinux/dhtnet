#!/usr/bin/env bash

if [[ -n "${DHTNET_VNET_TOPOLOGY_SH:-}" ]]; then
    return 0
fi
DHTNET_VNET_TOPOLOGY_SH=1

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/netns.sh"

VNET_TOPOLOGY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VNET_TOPOLOGY_ROOT="$(cd "${VNET_TOPOLOGY_LIB_DIR}/../.." && pwd)"

vnet_connect_namespaces_with_veth() {
    local ns_a="$1"
    local iface_a="$2"
    local ns_b="$3"
    local iface_b="$4"
    local tmp_a
    local tmp_b

    tmp_a="$(printf 'v%05x%04x' "$$" "${RANDOM}")"
    tmp_b="$(printf 'v%05x%04x' "$$" "${RANDOM}")"
    ip link add "${tmp_a}" type veth peer name "${tmp_b}" || return $?
    ip link set "${tmp_a}" netns "${ns_a}" || return $?
    ip link set "${tmp_b}" netns "${ns_b}" || return $?
    ip -n "${ns_a}" link set "${tmp_a}" name "${iface_a}" || return $?
    ip -n "${ns_b}" link set "${tmp_b}" name "${iface_b}" || return $?
}

vnet_set_loopbacks_up() {
    local ns
    for ns in "$@"; do
        ip -n "${ns}" link set lo up || return $?
    done
}

vnet_configure_ipv4_interface() {
    local ns="$1"
    local iface="$2"
    local cidr="$3"

    ip -n "${ns}" addr add "${cidr}" dev "${iface}" || return $?
    ip -n "${ns}" link set "${iface}" up || return $?
}

vnet_configure_ipv6_interface() {
    local ns="$1"
    local iface="$2"
    local cidr="$3"

    ip -n "${ns}" -6 addr add "${cidr}" dev "${iface}" nodad || return $?
    ip -n "${ns}" link set "${iface}" up || return $?
}

vnet_add_default_route() {
    local ns="$1"
    local via="$2"
    local dev="${3:-}"
    local metric="${4:-}"

    local cmd=(ip -n "${ns}" route add default via "${via}")
    if [[ -n "${dev}" ]]; then
        cmd+=(dev "${dev}")
    fi
    if [[ -n "${metric}" ]]; then
        cmd+=(metric "${metric}")
    fi
    "${cmd[@]}" || return $?
}

vnet_add_ipv6_default_route() {
    local ns="$1"
    local via="$2"
    local dev="${3:-}"
    local metric="${4:-}"

    local cmd=(ip -n "${ns}" -6 route add default via "${via}")
    if [[ -n "${dev}" ]]; then
        cmd+=(dev "${dev}")
    fi
    if [[ -n "${metric}" ]]; then
        cmd+=(metric "${metric}")
    fi
    "${cmd[@]}" || return $?
}

vnet_add_device_route() {
    local ns="$1"
    local destination="$2"
    local dev="$3"
    local metric="${4:-}"

    local cmd=(ip -n "${ns}" route add "${destination}" dev "${dev}")
    if [[ -n "${metric}" ]]; then
        cmd+=(metric "${metric}")
    fi
    "${cmd[@]}" || return $?
}

vnet_add_ipv6_route() {
    local ns="$1"
    local destination="$2"
    local via="${3:-}"
    local dev="${4:-}"
    local metric="${5:-}"

    local cmd=(ip -n "${ns}" -6 route add "${destination}")
    if [[ -n "${via}" ]]; then
        cmd+=(via "${via}")
    fi
    if [[ -n "${dev}" ]]; then
        cmd+=(dev "${dev}")
    fi
    if [[ -n "${metric}" ]]; then
        cmd+=(metric "${metric}")
    fi
    "${cmd[@]}" || return $?
}

vnet_enable_ipv4_forwarding() {
    local ns="$1"
    ip netns exec "${ns}" sysctl -w net.ipv4.ip_forward=1 >/dev/null || return $?
}

vnet_enable_ipv6_forwarding() {
    local ns="$1"
    ip netns exec "${ns}" sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null || return $?
}

vnet_setup_basic_nat_router() {
    local ns="$1"
    local lan_iface="$2"
    local wan_iface="$3"

    vnet_enable_ipv4_forwarding "${ns}" || return $?
    ip netns exec "${ns}" iptables -t nat -A POSTROUTING -o "${wan_iface}" -j MASQUERADE || return $?
    ip netns exec "${ns}" iptables -A FORWARD -i "${wan_iface}" -o "${lan_iface}" \
        -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return $?
    ip netns exec "${ns}" iptables -A FORWARD -i "${lan_iface}" -o "${wan_iface}" -j ACCEPT || return $?
}

vnet_setup_basic_ipv4_router() {
    local ns="$1"

    vnet_enable_ipv4_forwarding "${ns}" || return $?
    ip netns exec "${ns}" iptables -P FORWARD ACCEPT || return $?
}

vnet_setup_basic_ipv6_router() {
    local ns="$1"

    vnet_enable_ipv6_forwarding "${ns}" || return $?
}

vnet_topology_require_file() {
    local topology_file="$1"
    if [[ ! -f "${topology_file}" ]]; then
        echo "Error: topology file not found: ${topology_file}" >&2
        return 1
    fi
}

vnet_topology_json_cli() {
    local action="$1"
    local topology_file="$2"
    local topology_dir

    vnet_require_commands python3
    vnet_topology_require_file "${topology_file}" || return 1
    topology_dir="$(cd "$(dirname "${topology_file}")" && pwd)"
    topology_file="${topology_dir}/$(basename "${topology_file}")"
    (
        cd "${VNET_TOPOLOGY_ROOT}" &&
        python3 -m lib.tools.topology_json "${action}" "${topology_file}"
    )
}

vnet_topology_load_defaults() {
    local topology_file="$1"
    local output
    local key
    local value

    output="$(vnet_topology_json_cli defaults "${topology_file}")" || return 1
    while IFS=$'\t' read -r key value; do
        [[ -n "${key}" ]] || continue
        if [[ ! -v "${key}" || -z "${!key-}" ]]; then
            printf -v "${key}" '%s' "${value}"
        fi
    done <<< "${output}"
}

vnet_topology_resolve_value() {
    local template="$1"
    local resolved=""
    local remainder="${template}"

    while [[ "${remainder}" =~ ^([^{}]*)\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)$ ]]; do
        local prefix="${BASH_REMATCH[1]}"
        local variable_name="${BASH_REMATCH[2]}"
        local suffix="${BASH_REMATCH[3]}"

        if [[ ! -v "${variable_name}" ]]; then
            echo "Error: topology placeholder {${variable_name}} is not defined" >&2
            return 1
        fi

        resolved+="${prefix}${!variable_name}"
        remainder="${suffix}"
    done

    if [[ "${remainder}" == *"{"* || "${remainder}" == *"}"* ]]; then
        echo "Error: invalid topology placeholder syntax in ${template}" >&2
        return 1
    fi

    printf '%s\n' "${resolved}${remainder}"
}

vnet_topology_namespaces() {
    local topology_file="$1"
    local output
    local namespace

    vnet_topology_load_defaults "${topology_file}" || return 1
    output="$(vnet_topology_json_cli namespaces "${topology_file}")" || return 1
    while IFS= read -r namespace; do
        [[ -n "${namespace}" ]] || continue
        vnet_topology_resolve_value "${namespace}" || return 1
    done <<< "${output}"
}

vnet_topology_read_namespaces() {
    local topology_file="$1"
    local -n namespaces_ref="$2"
    local output

    namespaces_ref=()
    output="$(vnet_topology_namespaces "${topology_file}")" || return 1
    if [[ -n "${output}" ]]; then
        mapfile -t namespaces_ref <<< "${output}"
    fi
}

vnet_topology_apply() {
    local topology_file="$1"
    local -a topology_namespaces=()
    local output
    local line

    vnet_topology_read_namespaces "${topology_file}" topology_namespaces || return 1
    vnet_create_namespaces "${topology_namespaces[@]}" || return $?
    vnet_topology_load_defaults "${topology_file}" || return 1
    output="$(vnet_topology_json_cli operations "${topology_file}")" || return 1
    while IFS= read -r line; do
        local -a fields=()
        local -a resolved=()
        local index
        local resolved_value

        [[ -n "${line}" ]] || continue
        IFS=$'\t' read -r -a fields <<< "${line}"
        for ((index = 1; index < ${#fields[@]}; index++)); do
            resolved_value="$(vnet_topology_resolve_value "${fields[index]}")" || return $?
            resolved+=("${resolved_value}")
        done

        case "${fields[0]}" in
            set-loopbacks-up)
                vnet_set_loopbacks_up "${resolved[@]}" || return $?
                ;;
            connect-veth)
                vnet_connect_namespaces_with_veth "${resolved[0]}" "${resolved[1]}" "${resolved[2]}" "${resolved[3]}" || return $?
                ;;
            configure-ipv4-interface)
                vnet_configure_ipv4_interface "${resolved[0]}" "${resolved[1]}" "${resolved[2]}" || return $?
                ;;
            configure-ipv6-interface)
                vnet_configure_ipv6_interface "${resolved[0]}" "${resolved[1]}" "${resolved[2]}" || return $?
                ;;
            add-default-route)
                vnet_add_default_route "${resolved[0]}" "${resolved[1]}" "${resolved[2]:-}" "${resolved[3]:-}" || return $?
                ;;
            add-ipv6-default-route)
                vnet_add_ipv6_default_route "${resolved[0]}" "${resolved[1]}" "${resolved[2]:-}" "${resolved[3]:-}" || return $?
                ;;
            add-device-route)
                vnet_add_device_route "${resolved[0]}" "${resolved[1]}" "${resolved[2]}" "${resolved[3]:-}" || return $?
                ;;
            add-ipv6-route)
                vnet_add_ipv6_route "${resolved[0]}" "${resolved[1]}" "${resolved[2]:-}" "${resolved[3]:-}" "${resolved[4]:-}" || return $?
                ;;
            setup-basic-nat-router)
                vnet_setup_basic_nat_router "${resolved[0]}" "${resolved[1]}" "${resolved[2]}" || return $?
                ;;
            setup-basic-ipv4-router)
                vnet_setup_basic_ipv4_router "${resolved[0]}" || return $?
                ;;
            setup-basic-ipv6-router)
                vnet_setup_basic_ipv6_router "${resolved[0]}" || return $?
                ;;
            *)
                echo "Error: unsupported topology operation ${fields[0]}" >&2
                return 1
                ;;
        esac
    done <<< "${output}"
}
