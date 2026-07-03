#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/shell/fixtures.sh"

bind_ip="${VNET_FIXTURE_DISCOVERY_BIND_IP:-}"
bind_ip="${bind_ip%%/*}"

if ! vnet_fixture_wait_for_discovery \
    "${VNET_FIXTURE_NAMESPACE:?missing VNET_FIXTURE_NAMESPACE}" \
    "${VNET_FIXTURE_DISCOVERY_LOG:?missing VNET_FIXTURE_DISCOVERY_LOG}" \
    "${VNET_FIXTURE_DISCOVERY_TIMEOUT_S:-10}" \
    "${VNET_FIXTURE_DISCOVERY_EXPECTED_EXTERNAL_IP:?missing VNET_FIXTURE_DISCOVERY_EXPECTED_EXTERNAL_IP}" \
    "${bind_ip}"; then
    printf 'UPnP discovery failed; last probe output follows:\n' >&2
    if [[ -s "${VNET_FIXTURE_DISCOVERY_LOG}" ]]; then
        sed 's/^/  /' "${VNET_FIXTURE_DISCOVERY_LOG}" >&2
    else
        printf '  no UPnP probe output was captured\n' >&2
    fi
    exit 1
fi

VNET_FIXTURE_DISCOVERY_BIND_IP="${bind_ip}" python3 - "${VNET_FIXTURE_OUTPUT_FILE:?missing VNET_FIXTURE_OUTPUT_FILE}" <<'PY'
import json
import os
import sys

payload = {
    "discovery_role": os.environ["VNET_FIXTURE_ROLE"],
    "discovery_namespace": os.environ["VNET_FIXTURE_NAMESPACE"],
    "discovery_expected_external_ip": os.environ["VNET_FIXTURE_DISCOVERY_EXPECTED_EXTERNAL_IP"],
    "discovery_log": os.environ["VNET_FIXTURE_DISCOVERY_LOG"],
}
bind_ip = os.environ.get("VNET_FIXTURE_DISCOVERY_BIND_IP")
if bind_ip:
    payload["discovery_bind_ip"] = bind_ip
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True)
PY
