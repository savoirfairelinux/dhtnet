#!/usr/bin/env bash
# Verify that a real dhtnet WAN-side session can be established and that the
# router creates UPnP mappings while that session is active.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VNET_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${VNET_ROOT}/lib/common.sh"
source "${VNET_ROOT}/lib/netns.sh"
source "${VNET_ROOT}/lib/result-recording.sh"
source "${VNET_ROOT}/actors/dhtnet-tooling.sh"

usage() {
    echo "Usage: sudo bash $0 [--run-id ID] [--artifact-root DIR] --actor-log PATH"
    echo "  --run-id ID         Override the generated result run identifier"
    echo "  --artifact-root DIR Override the artifact root (default: extras/virtual-networking/artifacts)"
    echo "  --actor-log PATH    Path to the orchestrator actor log so the probe can extract the peer ID"
    exit 1
}

LAB_NAME="fake-upnp-network"
STATE_FILE="$(vnet_state_file_path "${LAB_NAME}")"
RTR_EXT_IP="11.0.0.2"
RTR_NS="rtr"
WAN_NS="wan"
LAN_NS="lan"
RUN_ID=""
ACTOR_LOG=""
PROBE_EXIT_CODE=0
PROBE_OVERALL_STATUS="passed"
PROBE_SUMMARY_FINALIZED=0
WAN_BOOTSTRAP_IP=""
BOOTSTRAP_PORT=4222
REPO_ROOT="${VNET_REPO_ROOT:-$(cd "${VNET_ROOT}/../.." && pwd)}"
BUILD_DIR="${DHTNET_BUILD_DIR:-}"
CLIENT_DIR=""
CLIENT_CERT=""
CLIENT_KEY=""
CLIENT_FIFO=""
CLIENT_OUTPUT=""
CLIENT_LAUNCHER=""
KEEPALIVE_PID=""
CLIENT_PID=""
ROUNDTRIP_TOKEN=""

while (($# > 0)); do
    case "$1" in
        --artifact-root)
            shift
            [[ $# -gt 0 ]] || usage
            VNET_ARTIFACT_ROOT="$1"
            ;;
        --run-id)
            shift
            [[ $# -gt 0 ]] || usage
            RUN_ID="$1"
            ;;
        --actor-log)
            shift
            [[ $# -gt 0 ]] || usage
            ACTOR_LOG="$1"
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            ;;
    esac
    shift
done

vnet_require_root
vnet_require_commands bash grep ip mktemp nft python3 sed sort ss tail

load_lab_state() {
    if vnet_load_env_file "${STATE_FILE}"; then
        RTR_EXT_IP="${RTR_TO_WAN_IP:-${RTR_EXT_IP}}"
        WAN_BOOTSTRAP_IP="${WAN_BOOTSTRAP_IP:-${WAN_IP_CIDR%%/*}}"
        BOOTSTRAP_PORT="${BOOTSTRAP_PORT:-4222}"
    fi
}

append_text_capture() {
    local label="$1"
    local kind="$2"
    local filename="$3"
    local content="$4"

    printf '%s\n' "${content}" > "${VNET_RESULT_CAPTURES_DIR}/${filename}"
    vnet_results_capture "${label}" "${kind}" "captures/${filename}"
}

mark_failed() {
    PROBE_OVERALL_STATUS="failed"
    PROBE_EXIT_CODE=1
}

cleanup_probe() {
    if [[ -n "${CLIENT_PID}" ]]; then
        kill "${CLIENT_PID}" 2>/dev/null || true
        wait "${CLIENT_PID}" 2>/dev/null || true
    fi
    if [[ -n "${KEEPALIVE_PID}" ]]; then
        kill "${KEEPALIVE_PID}" 2>/dev/null || true
        wait "${KEEPALIVE_PID}" 2>/dev/null || true
    fi
    if [[ -n "${CLIENT_FIFO}" ]]; then
        rm -f "${CLIENT_FIFO}" 2>/dev/null || true
    fi
    if [[ -n "${CLIENT_DIR}" ]]; then
        rm -rf "${CLIENT_DIR}" 2>/dev/null || true
    fi
}

record_assertion() {
    local name="$1"
    local status="$2"
    local started_ms="$3"
    local details="$4"
    local ended_ms
    ended_ms="$(vnet_now_ms)"
    vnet_results_assert "${name}" "${status}" "$((ended_ms - started_ms))" "${details}"
}

finalize_summary() {
    local trap_rc="${1:-$?}"

    if [[ "${PROBE_SUMMARY_FINALIZED}" -eq 1 ]] || [[ -z "${VNET_RESULT_DIR:-}" ]]; then
        return
    fi

    if [[ "${PROBE_OVERALL_STATUS}" == "passed" && "${trap_rc}" -ne 0 ]]; then
        PROBE_OVERALL_STATUS="error"
        PROBE_EXIT_CODE="${trap_rc}"
    fi

    vnet_results_note "script_exit_code=${PROBE_EXIT_CODE:-${trap_rc}}"
    vnet_results_event "run_finished" "${PROBE_OVERALL_STATUS}" \
        "Probe finished with status ${PROBE_OVERALL_STATUS}"
    vnet_results_finalize "${PROBE_OVERALL_STATUS}"
    PROBE_SUMMARY_FINALIZED=1

    echo
    echo "[SUMMARY] ${VNET_RESULT_DIR}/summary.txt"
    cat "${VNET_RESULT_DIR}/summary.txt"
}

on_exit() {
    local trap_rc=$?
    cleanup_probe
    finalize_summary "${trap_rc}"
}

trap on_exit EXIT

load_lab_state
WAN_BOOTSTRAP_IP="${WAN_BOOTSTRAP_IP:-11.0.0.1}"
BOOTSTRAP_PORT="${BOOTSTRAP_PORT:-4222}"
vnet_results_init "probe-dht-from-wan" "${RUN_ID}"
vnet_results_field "lab" "${LAB_NAME}"
vnet_results_field "topology" "single-router"
vnet_results_note "router_external_ip=${RTR_EXT_IP}"
vnet_results_note "bootstrap_ip=${WAN_BOOTSTRAP_IP}:${BOOTSTRAP_PORT}"

vnet_results_capture_command "namespace list" "state-dump" "netns-list.txt" ip netns list || true

start_ms="$(vnet_now_ms)"
if vnet_assert_namespaces_exist "${RTR_NS}" "${WAN_NS}" "${LAN_NS}"; then
    record_assertion "namespaces_exist" "passed" "${start_ms}" \
        "Namespaces ${RTR_NS}, ${WAN_NS}, and ${LAN_NS} are present."
else
    record_assertion "namespaces_exist" "failed" "${start_ms}" \
        "Run setup-fake-upnp-network.sh first."
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

if [[ -z "${ACTOR_LOG}" || ! -f "${ACTOR_LOG}" ]]; then
    start_ms="$(vnet_now_ms)"
    record_assertion "actor_log_present" "failed" "${start_ms}" \
        "Actor log path is missing or unreadable: ${ACTOR_LOG:-<unset>}"
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi
cp "${ACTOR_LOG}" "${VNET_RESULT_CAPTURES_DIR}/actor.log"
vnet_results_capture "Actor log" "log" "captures/actor.log"

actor_peer_id="$(sed -n 's/^ACTOR_PEER_ID=//p' "${ACTOR_LOG}" | tail -n 1)"
start_ms="$(vnet_now_ms)"
if [[ -n "${actor_peer_id}" ]]; then
    record_assertion "actor_peer_id_present" "passed" "${start_ms}" \
        "Extracted actor peer ID ${actor_peer_id} from the actor log."
    vnet_results_note "actor_peer_id=${actor_peer_id}"
else
    record_assertion "actor_peer_id_present" "failed" "${start_ms}" \
        "Could not extract ACTOR_PEER_ID from the actor log."
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

DSH_BIN="$(vnet_resolve_dhtnet_tool dsh DHTNET_DSH_BIN)"
CRTMGR_BIN="$(vnet_resolve_dhtnet_tool dhtnet-crtmgr DHTNET_CRTMGR_BIN)"

mapped_ports() {
    ip netns exec "${RTR_NS}" nft list chain ip miniupnpd prerouting 2>/dev/null \
        | grep -oP 'udp dport \K[0-9]+' | sort -u
}

wait_for_pattern() {
    local file="$1"
    local pattern="$2"
    local timeout_s="${3:-15}"
    local attempt

    for ((attempt = 1; attempt <= timeout_s; attempt++)); do
        if [[ -f "${file}" ]] && grep -Fq "${pattern}" "${file}"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_mapped_ports() {
    local timeout_s="${1:-15}"
    local ports=""
    local attempt

    for ((attempt = 1; attempt <= timeout_s; attempt++)); do
        ports="$(mapped_ports || true)"
        if [[ -n "${ports}" ]]; then
            printf '%s\n' "${ports}"
            return 0
        fi
        sleep 1
    done
    return 1
}

prepare_client_identity() {
    CLIENT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dhtnet-probe-client.XXXXXX")"
    "${CRTMGR_BIN}" --setup -o "${CLIENT_DIR}" >/dev/null
    CLIENT_CERT="${CLIENT_DIR}/id/id-server.crt"
    CLIENT_KEY="${CLIENT_DIR}/id/id-server.pem"
}

start_wan_roundtrip_client() {
    local peer_id="$1"

    CLIENT_FIFO="$(mktemp -u "${TMPDIR:-/tmp}/dhtnet-probe-client-stdin.XXXXXX")"
    mkfifo "${CLIENT_FIFO}"
    CLIENT_OUTPUT="${VNET_RESULT_CAPTURES_DIR}/wan-dsh-client.txt"
    CLIENT_LAUNCHER="${CLIENT_DIR}/run-dsh-client.sh"
    ROUNDTRIP_TOKEN="dhtnet-vnet-$(date +%s%N)"

    cat > "${CLIENT_LAUNCHER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cat "${CLIENT_FIFO}" | "${DSH_BIN}" -b "${WAN_BOOTSTRAP_IP}" -c "${CLIENT_CERT}" -p "${CLIENT_KEY}" -s /bin/cat "${peer_id}"
EOF
    chmod +x "${CLIENT_LAUNCHER}"

    tail -f /dev/null > "${CLIENT_FIFO}" &
    KEEPALIVE_PID="$!"

    ip netns exec "${WAN_NS}" "${CLIENT_LAUNCHER}" > "${CLIENT_OUTPUT}" 2>&1 &
    CLIENT_PID="$!"

    sleep 2
    printf '%s\n' "${ROUNDTRIP_TOKEN}" > "${CLIENT_FIFO}"
}

prepare_client_identity
start_wan_roundtrip_client "${actor_peer_id}"
vnet_results_capture "WAN dsh client output" "command-output" "captures/wan-dsh-client.txt"

echo "=== dhtnet WAN Roundtrip Analysis ==="
echo

start_ms="$(vnet_now_ms)"
if wait_for_pattern "${CLIENT_OUTPUT}" "${ROUNDTRIP_TOKEN}" 20; then
    record_assertion "wan_dsh_roundtrip" "passed" "${start_ms}" \
        "WAN namespace dsh client connected to the actor and echoed token ${ROUNDTRIP_TOKEN}."
else
    record_assertion "wan_dsh_roundtrip" "failed" "${start_ms}" \
        "WAN namespace dsh client did not echo token ${ROUNDTRIP_TOKEN}. Capture: captures/wan-dsh-client.txt"
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

vnet_results_capture_command "router miniupnpd prerouting" "state-dump" \
    "router-nft-prerouting.txt" ip netns exec "${RTR_NS}" nft list chain ip miniupnpd prerouting || true
vnet_results_capture_command "lan udp sockets" "state-dump" \
    "lan-udp-sockets.txt" ip netns exec "${LAN_NS}" ss -ulnp || true

start_ms="$(vnet_now_ms)"
if mapped="$(wait_for_mapped_ports 20)"; then
    append_text_capture "mapped UDP ports" "command-output" "mapped-ports.txt" "${mapped}"
    record_assertion "upnp_mapped_ports_present" "passed" "${start_ms}" \
        "At least one UPnP-mapped UDP port exists while the WAN dhtnet session is active."
    vnet_results_metric "mapped_port_count" "$(printf '%s\n' "${mapped}" | grep -c .)"
else
    append_text_capture "mapped UDP ports" "command-output" "mapped-ports.txt" ""
    record_assertion "upnp_mapped_ports_present" "failed" "${start_ms}" \
        "No UPnP-mapped UDP ports were observed while the WAN dhtnet session was active."
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

exit "${PROBE_EXIT_CODE}"
