#!/usr/bin/env bash

if [[ -n "${DHTNET_VNET_TOPOLOGY_SH:-}" ]]; then
    return 0
fi
DHTNET_VNET_TOPOLOGY_SH=1

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/netns.sh"

VNET_TOPOLOGY_JSON_CLI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/topology_json.py"

vnet_connect_namespaces_with_veth() {
    local ns_a="$1"
    local iface_a="$2"
    local ns_b="$3"
    local iface_b="$4"

    ip link add "${iface_a}" type veth peer name "${iface_b}"
    ip link set "${iface_a}" netns "${ns_a}"
    ip link set "${iface_b}" netns "${ns_b}"
}

vnet_set_loopbacks_up() {
    local ns
    for ns in "$@"; do
        ip -n "${ns}" link set lo up
    done
}

vnet_configure_ipv4_interface() {
    local ns="$1"
    local iface="$2"
    local cidr="$3"

    ip -n "${ns}" addr add "${cidr}" dev "${iface}"
    ip -n "${ns}" link set "${iface}" up
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
    "${cmd[@]}"
}

vnet_replace_default_route() {
    local ns="$1"
    local via="$2"
    local dev="${3:-}"
    local metric="${4:-}"

    local cmd=(ip -n "${ns}" route replace default via "${via}")
    if [[ -n "${dev}" ]]; then
        cmd+=(dev "${dev}")
    fi
    if [[ -n "${metric}" ]]; then
        cmd+=(metric "${metric}")
    fi
    "${cmd[@]}"
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
    "${cmd[@]}"
}

vnet_enable_ipv4_forwarding() {
    local ns="$1"
    ip netns exec "${ns}" sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

vnet_setup_basic_nat_router() {
    local ns="$1"
    local lan_iface="$2"
    local wan_iface="$3"

    vnet_enable_ipv4_forwarding "${ns}"
    ip netns exec "${ns}" iptables -t nat -A POSTROUTING -o "${wan_iface}" -j MASQUERADE
    ip netns exec "${ns}" iptables -A FORWARD -i "${wan_iface}" -o "${lan_iface}" \
        -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip netns exec "${ns}" iptables -A FORWARD -i "${lan_iface}" -o "${wan_iface}" -j ACCEPT
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

    vnet_require_commands python3
    vnet_topology_require_file "${topology_file}" || return 1
    python3 "${VNET_TOPOLOGY_JSON_CLI}" "${action}" "${topology_file}"
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

vnet_topology_roles() {
    local topology_file="$1"
    local output
    local role
    local namespace
    local capabilities

    vnet_topology_load_defaults "${topology_file}" || return 1
    output="$(vnet_topology_json_cli roles "${topology_file}")" || return 1
    while IFS=$'\t' read -r role namespace capabilities; do
        [[ -n "${role}" ]] || continue
        namespace="$(vnet_topology_resolve_value "${namespace}")" || return 1
        printf '%s\t%s\t%s\n' "${role}" "${namespace}" "${capabilities}"
    done <<< "${output}"
}

vnet_topology_state_vars() {
    local topology_file="$1"
    vnet_topology_json_cli state-vars "${topology_file}"
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

vnet_topology_read_state_vars() {
    local topology_file="$1"
    local -n state_vars_ref="$2"
    local output

    state_vars_ref=()
    output="$(vnet_topology_state_vars "${topology_file}")" || return 1
    if [[ -n "${output}" ]]; then
        mapfile -t state_vars_ref <<< "${output}"
    fi
}

vnet_topology_apply() {
    local topology_file="$1"
    local output
    local line

    vnet_topology_load_defaults "${topology_file}" || return 1
    output="$(vnet_topology_json_cli operations "${topology_file}")" || return 1
    while IFS= read -r line; do
        local -a fields=()
        local -a resolved=()
        local index

        [[ -n "${line}" ]] || continue
        IFS=$'\t' read -r -a fields <<< "${line}"
        for ((index = 1; index < ${#fields[@]}; index++)); do
            resolved+=("$(vnet_topology_resolve_value "${fields[index]}")") || return 1
        done

        case "${fields[0]}" in
            create-namespaces)
                vnet_create_namespaces "${resolved[@]}"
                ;;
            set-loopbacks-up)
                vnet_set_loopbacks_up "${resolved[@]}"
                ;;
            connect-veth)
                vnet_connect_namespaces_with_veth "${resolved[0]}" "${resolved[1]}" "${resolved[2]}" "${resolved[3]}"
                ;;
            configure-ipv4-interface)
                vnet_configure_ipv4_interface "${resolved[0]}" "${resolved[1]}" "${resolved[2]}"
                ;;
            add-default-route)
                vnet_add_default_route "${resolved[0]}" "${resolved[1]}" "${resolved[2]:-}" "${resolved[3]:-}"
                ;;
            add-device-route)
                vnet_add_device_route "${resolved[0]}" "${resolved[1]}" "${resolved[2]}" "${resolved[3]:-}"
                ;;
            setup-basic-nat-router)
                vnet_setup_basic_nat_router "${resolved[0]}" "${resolved[1]}" "${resolved[2]}"
                ;;
            *)
                echo "Error: unsupported topology operation ${fields[0]}" >&2
                return 1
                ;;
        esac
    done <<< "${output}"
}
