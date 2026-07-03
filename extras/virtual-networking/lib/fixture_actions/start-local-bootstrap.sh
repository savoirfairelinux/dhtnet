#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/shell/fixtures.sh"

cleanup_on_error() {
    if [[ -n "${VNET_FIXTURE_PIDFILE:-}" && -s "${VNET_FIXTURE_PIDFILE}" ]]; then
        vnet_fixture_stop_pidfile "${VNET_FIXTURE_PIDFILE}" || true
    fi
}
trap cleanup_on_error ERR

json_output() {
    local output_file="$1"
    python3 - "$output_file" <<'PY'
import json
import os
import sys

host = os.environ["VNET_FIXTURE_BIND_IP"].split("/", 1)[0]
port = int(os.environ["VNET_FIXTURE_PORT"])
endpoint_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
payload = {
    "bootstrap_host": host,
    "bootstrap_port": port,
    "bootstrap_endpoint": f"{endpoint_host}:{port}",
    "pidfile": os.environ["VNET_FIXTURE_PIDFILE"],
    "logfile": os.environ["VNET_FIXTURE_LOGFILE"],
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
PY
}

bind_ip="${VNET_FIXTURE_BIND_IP:?missing VNET_FIXTURE_BIND_IP}"
bind_ip="${bind_ip%%/*}"

vnet_fixture_start_local_bootstrap \
    "${VNET_FIXTURE_NAMESPACE:?missing VNET_FIXTURE_NAMESPACE}" \
    "${bind_ip}" \
    "${VNET_FIXTURE_PORT:?missing VNET_FIXTURE_PORT}" \
    "${VNET_FIXTURE_PIDFILE:?missing VNET_FIXTURE_PIDFILE}" \
    "${VNET_FIXTURE_LOGFILE:?missing VNET_FIXTURE_LOGFILE}" \
    "${VNET_FIXTURE_TIMEOUT_S:-10}" \
    "${VNET_FIXTURE_BOOTSTRAP_SCRIPT:?missing VNET_FIXTURE_BOOTSTRAP_SCRIPT}"

export VNET_FIXTURE_BIND_IP="${bind_ip}"
json_output "${VNET_FIXTURE_OUTPUT_FILE:?missing VNET_FIXTURE_OUTPUT_FILE}"
trap - ERR
