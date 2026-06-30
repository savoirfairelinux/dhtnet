#!/usr/bin/env bash

if [[ -n "${DHTNET_VNET_COMMON_SH:-}" ]]; then
    return 0
fi
DHTNET_VNET_COMMON_SH=1

VNET_COMMON_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Provides access to VNET_STATE_ROOT
# shellcheck disable=SC2034
VNET_COMMON_ROOT="$(cd "${VNET_COMMON_LIB_DIR}/../.." && pwd)"
: "${VNET_STATE_ROOT:=/tmp/dhtnet-virtual-networking}"

vnet_require_commands() {
    local missing=()
    local cmd
    for cmd in "$@"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing+=("${cmd}")
        fi
    done

    if ((${#missing[@]} > 0)); then
        echo "Error: missing required commands: ${missing[*]}" >&2
        exit 1
    fi
}

vnet_kill_pidfile() {
    local pidfile="$1"
    if [[ ! -f "${pidfile}" ]]; then
        return 0
    fi

    local pid
    pid="$(<"${pidfile}")"
    if [[ "${pid}" =~ ^[0-9]+$ ]]; then
        kill "${pid}" 2>/dev/null || true
    fi
}
