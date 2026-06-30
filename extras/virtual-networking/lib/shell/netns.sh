#!/usr/bin/env bash

if [[ -n "${DHTNET_VNET_NETNS_SH:-}" ]]; then
    return 0
fi
DHTNET_VNET_NETNS_SH=1

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

vnet_create_namespaces() {
    local ns
    for ns in "$@"; do
        ip netns add "${ns}" || return $?
    done
}

vnet_delete_namespace() {
    ip netns del "$1" 2>/dev/null || true
}

vnet_delete_namespaces() {
    local ns
    for ns in "$@"; do
        vnet_delete_namespace "${ns}"
    done
}
