#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/shell/fixtures.sh"

cleanup_on_error() {
    if [[ -n "${VNET_FIXTURE_PIDFILE:-}" && -s "${VNET_FIXTURE_PIDFILE}" ]]; then
        vnet_fixture_stop_pidfile "${VNET_FIXTURE_PIDFILE}" || true
    fi
}
trap cleanup_on_error ERR

vnet_fixture_start_miniupnpd_instance \
    "${VNET_FIXTURE_NAMESPACE:?missing VNET_FIXTURE_NAMESPACE}" \
    "${VNET_FIXTURE_CONFIGFILE:?missing VNET_FIXTURE_CONFIGFILE}" \
    "${VNET_FIXTURE_PIDFILE:?missing VNET_FIXTURE_PIDFILE}" \
    "${VNET_FIXTURE_LOGFILE:?missing VNET_FIXTURE_LOGFILE}" \
    "${VNET_FIXTURE_EXT_IFACE:?missing VNET_FIXTURE_EXT_IFACE}" \
    "${VNET_FIXTURE_LISTEN_IFACE:?missing VNET_FIXTURE_LISTEN_IFACE}" \
    "${VNET_FIXTURE_UUID:?missing VNET_FIXTURE_UUID}" \
    "${VNET_FIXTURE_FRIENDLY_NAME:?missing VNET_FIXTURE_FRIENDLY_NAME}" \
    "${VNET_FIXTURE_EXT_IP:?missing VNET_FIXTURE_EXT_IP}"

python3 - "${VNET_FIXTURE_OUTPUT_FILE:?missing VNET_FIXTURE_OUTPUT_FILE}" <<'PY'
import json
import os
import sys

payload = {
    "external_ip": os.environ["VNET_FIXTURE_EXT_IP"],
    "pidfile": os.environ["VNET_FIXTURE_PIDFILE"],
    "logfile": os.environ["VNET_FIXTURE_LOGFILE"],
    "configfile": os.environ["VNET_FIXTURE_CONFIGFILE"],
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
PY
trap - ERR
