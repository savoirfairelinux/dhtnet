#!/usr/bin/env bash
# Verify that a real dhtnet WAN-side session can be established and that the
# router creates UPnP mappings while that session is active.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VNET_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${VNET_ROOT}/lib/common.sh"
source "${VNET_ROOT}/lib/netns.sh"
source "${VNET_ROOT}/actors/dhtnet-tooling.sh"

: "${VNET_ARTIFACT_ROOT:=${VNET_ROOT}/artifacts}"

usage() {
    cat <<'EOF'
Usage: sudo bash probe-dht-from-wan.sh [--run-id ID] [--artifact-root DIR]
    [--result-dir DIR]
    --lab NAME
    --topology NAME
    --client-namespace NS
    --router-namespace NS
    --actor-namespace NS
    (--actor-output PATH | --actor-peer-id HEX)
    --bootstrap-host HOST
    --bootstrap-port PORT
    [--router-external-ip IP]
EOF
    exit 1
}

LAB_NAME=""
TOPOLOGY_NAME=""
CLIENT_NS=""
ROUTER_NS=""
ACTOR_NS=""
ACTOR_OUTPUT=""
ACTOR_PEER_ID=""
BOOTSTRAP_HOST=""
BOOTSTRAP_PORT=""
BOOTSTRAP_TARGET=""
RTR_EXT_IP=""
RUN_ID=""
RESULT_DIR=""
PROBE_EXIT_CODE=0
PROBE_OVERALL_STATUS="passed"
PROBE_SUMMARY_FINALIZED=0
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
        --result-dir)
            shift
            [[ $# -gt 0 ]] || usage
            RESULT_DIR="$1"
            ;;
        --lab)
            shift
            [[ $# -gt 0 ]] || usage
            LAB_NAME="$1"
            ;;
        --topology)
            shift
            [[ $# -gt 0 ]] || usage
            TOPOLOGY_NAME="$1"
            ;;
        --client-namespace)
            shift
            [[ $# -gt 0 ]] || usage
            CLIENT_NS="$1"
            ;;
        --router-namespace)
            shift
            [[ $# -gt 0 ]] || usage
            ROUTER_NS="$1"
            ;;
        --actor-namespace)
            shift
            [[ $# -gt 0 ]] || usage
            ACTOR_NS="$1"
            ;;
        --actor-output)
            shift
            [[ $# -gt 0 ]] || usage
            ACTOR_OUTPUT="$1"
            ;;
        --actor-peer-id)
            shift
            [[ $# -gt 0 ]] || usage
            ACTOR_PEER_ID="$1"
            ;;
        --bootstrap-host)
            shift
            [[ $# -gt 0 ]] || usage
            BOOTSTRAP_HOST="$1"
            ;;
        --bootstrap-port)
            shift
            [[ $# -gt 0 ]] || usage
            BOOTSTRAP_PORT="$1"
            ;;
        --router-external-ip)
            shift
            [[ $# -gt 0 ]] || usage
            RTR_EXT_IP="$1"
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

if [[ -z "${LAB_NAME}" || -z "${TOPOLOGY_NAME}" || -z "${CLIENT_NS}" || -z "${ROUTER_NS}" || -z "${ACTOR_NS}" || -z "${BOOTSTRAP_HOST}" || -z "${BOOTSTRAP_PORT}" ]]; then
    usage
fi
if [[ -z "${ACTOR_OUTPUT}" && -z "${ACTOR_PEER_ID}" ]]; then
    usage
fi

if [[ "${BOOTSTRAP_PORT}" == "4222" ]]; then
    BOOTSTRAP_TARGET="${BOOTSTRAP_HOST}"
else
    BOOTSTRAP_TARGET="${BOOTSTRAP_HOST}:${BOOTSTRAP_PORT}"
fi

if [[ -n "${RESULT_DIR}" ]]; then
    VNET_RESULT_DIR="${RESULT_DIR}"
    VNET_RESULT_META_DIR="${RESULT_DIR}/.meta"
    VNET_RESULT_CAPTURES_DIR="${RESULT_DIR}"
    export VNET_RESULT_DIR VNET_RESULT_META_DIR VNET_RESULT_CAPTURES_DIR
fi

vnet_results_cli() {
    (
        cd "${VNET_ROOT}" &&
        python3 -m lib.result_recorder_cli "$@"
    )
}

vnet_results_default_run_id() {
    local scenario="${1:-scenario}"
    vnet_results_cli default-run-id "${scenario}"
}

vnet_results_init() {
    local scenario="$1"
    local run_id="${2:-$(vnet_results_default_run_id "${scenario}")}"
    local init_exports
    local -a init_args=(
        init-shell
        --artifact-root "${VNET_ARTIFACT_ROOT}"
        --scenario "${scenario}"
        --run-id "${run_id}"
    )

    if [[ -n "${VNET_RESULT_DIR:-}" ]]; then
        init_args+=(--result-dir "${VNET_RESULT_DIR}")
    fi
    if [[ -n "${VNET_RESULT_META_DIR:-}" ]]; then
        init_args+=(--meta-dir "${VNET_RESULT_META_DIR}")
    fi
    if [[ -n "${VNET_RESULT_CAPTURES_DIR:-}" ]]; then
        init_args+=(--captures-dir "${VNET_RESULT_CAPTURES_DIR}")
    fi

    init_exports="$(vnet_results_cli "${init_args[@]}")" || return 1
    eval "${init_exports}"

    vnet_results_event "run_started" "info" "Scenario '${VNET_RESULT_SCENARIO}' started"
}

vnet_results_event() {
    local event="$1"
    local status="${2:-info}"
    local message="${3:-}"

    vnet_results_cli event \
        --event "${event}" \
        --status "${status}" \
        --message "${message}"
}

vnet_results_field() {
    local key="$1"
    local value="$2"

    vnet_results_cli field \
        --key "${key}" \
        --value "${value}"
}

vnet_results_assert() {
    local name="$1"
    local status="$2"
    local duration_ms="$3"
    local details="${4:-}"

    vnet_results_cli assertion \
        --name "${name}" \
        --status "${status}" \
        --duration-ms "${duration_ms}" \
        --details "${details}"
}

vnet_results_metric() {
    local key="$1"
    local value="$2"

    vnet_results_cli metric \
        --key "${key}" \
        --value "${value}"
}

vnet_results_note() {
    local note="$1"

    vnet_results_cli note \
        --note "${note}"
}

vnet_results_capture() {
    local label="$1"
    local kind="$2"
    local path="$3"

    vnet_results_cli capture \
        --label "${label}" \
        --kind "${kind}" \
        --path "${path}"
}

vnet_results_capture_command() {
    local label="$1"
    local kind="$2"
    local filename="$3"
    shift 3

    local destination="${VNET_RESULT_CAPTURES_DIR}/${filename}"
    local rc=0
    if "$@" > "${destination}" 2>&1; then
        rc=0
    else
        rc=$?
    fi

    vnet_results_capture "${label}" "${kind}" "captures/${filename}"
    return "${rc}"
}

vnet_results_finalize() {
    local status="$1"

    vnet_results_cli finalize \
        --status "${status}"
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

resolve_actor_peer_id() {
    if [[ -n "${ACTOR_PEER_ID}" ]]; then
        printf '%s\n' "${ACTOR_PEER_ID}"
        return 0
    fi

    python3 "${VNET_ROOT}/lib/actor_output.py" peer-id "${ACTOR_OUTPUT}"
}

vnet_results_init "probe-dht-from-wan" "${RUN_ID}"
vnet_results_field "lab" "${LAB_NAME}"
vnet_results_field "topology" "${TOPOLOGY_NAME}"
vnet_results_note "bootstrap_target=${BOOTSTRAP_TARGET}"
if [[ -n "${RTR_EXT_IP}" ]]; then
    vnet_results_note "router_external_ip=${RTR_EXT_IP}"
fi

vnet_results_capture_command "namespace list" "state-dump" "netns-list.txt" ip netns list || true

start_ms="$(vnet_now_ms)"
if vnet_assert_namespaces_exist "${ROUTER_NS}" "${CLIENT_NS}" "${ACTOR_NS}"; then
    record_assertion "namespaces_exist" "passed" "${start_ms}" \
        "Namespaces ${ROUTER_NS}, ${CLIENT_NS}, and ${ACTOR_NS} are present."
else
    record_assertion "namespaces_exist" "failed" "${start_ms}" \
        "Required namespaces are missing."
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

if [[ -n "${ACTOR_OUTPUT}" ]]; then
    start_ms="$(vnet_now_ms)"
    if [[ -f "${ACTOR_OUTPUT}" ]]; then
        cp "${ACTOR_OUTPUT}" "${VNET_RESULT_CAPTURES_DIR}/actor-output.json"
        vnet_results_capture "Actor output" "state-dump" "captures/actor-output.json"
        record_assertion "actor_output_present" "passed" "${start_ms}" \
            "Actor output file is present at ${ACTOR_OUTPUT}."
    else
        record_assertion "actor_output_present" "failed" "${start_ms}" \
            "Actor output path is missing or unreadable: ${ACTOR_OUTPUT}"
        mark_failed
        exit "${PROBE_EXIT_CODE}"
    fi
fi

actor_peer_id="$(resolve_actor_peer_id || true)"
start_ms="$(vnet_now_ms)"
if [[ -n "${actor_peer_id}" ]]; then
    record_assertion "actor_peer_id_present" "passed" "${start_ms}" \
        "Resolved actor peer ID ${actor_peer_id}."
    vnet_results_note "actor_peer_id=${actor_peer_id}"
else
    record_assertion "actor_peer_id_present" "failed" "${start_ms}" \
        "Could not determine actor peer ID."
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

DSH_BIN="$(vnet_resolve_dhtnet_tool dsh DHTNET_DSH_BIN)"
CRTMGR_BIN="$(vnet_resolve_dhtnet_tool dhtnet-crtmgr DHTNET_CRTMGR_BIN)"

mapped_ports() {
    ip netns exec "${ROUTER_NS}" nft list chain ip miniupnpd prerouting 2>/dev/null \
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

start_roundtrip_client() {
    local peer_id="$1"

    CLIENT_FIFO="$(mktemp -u "${TMPDIR:-/tmp}/dhtnet-probe-client-stdin.XXXXXX")"
    mkfifo "${CLIENT_FIFO}"
    CLIENT_OUTPUT="${VNET_RESULT_CAPTURES_DIR}/wan-dsh-client.txt"
    CLIENT_LAUNCHER="${CLIENT_DIR}/run-dsh-client.sh"
    ROUNDTRIP_TOKEN="dhtnet-vnet-$(date +%s%N)"

    cat > "${CLIENT_LAUNCHER}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cat "${CLIENT_FIFO}" | "${DSH_BIN}" -b "${BOOTSTRAP_TARGET}" -c "${CLIENT_CERT}" -p "${CLIENT_KEY}" -s /bin/cat "${peer_id}"
EOF
    chmod +x "${CLIENT_LAUNCHER}"

    tail -f /dev/null > "${CLIENT_FIFO}" &
    KEEPALIVE_PID="$!"

    ip netns exec "${CLIENT_NS}" "${CLIENT_LAUNCHER}" > "${CLIENT_OUTPUT}" 2>&1 &
    CLIENT_PID="$!"

    sleep 2
    printf '%s\n' "${ROUNDTRIP_TOKEN}" > "${CLIENT_FIFO}"
}

prepare_client_identity
start_roundtrip_client "${actor_peer_id}"
vnet_results_capture "WAN dsh client output" "command-output" "captures/wan-dsh-client.txt"

echo "=== dhtnet WAN Roundtrip Analysis ==="
echo

start_ms="$(vnet_now_ms)"
if wait_for_pattern "${CLIENT_OUTPUT}" "${ROUNDTRIP_TOKEN}" 20; then
    record_assertion "wan_dsh_roundtrip" "passed" "${start_ms}" \
        "Client namespace dsh session connected to the actor and echoed token ${ROUNDTRIP_TOKEN}."
else
    record_assertion "wan_dsh_roundtrip" "failed" "${start_ms}" \
        "Client namespace dsh session did not echo token ${ROUNDTRIP_TOKEN}. Capture: captures/wan-dsh-client.txt"
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

vnet_results_capture_command "router miniupnpd prerouting" "state-dump" \
    "router-nft-prerouting.txt" ip netns exec "${ROUTER_NS}" nft list chain ip miniupnpd prerouting || true
vnet_results_capture_command "actor udp sockets" "state-dump" \
    "actor-udp-sockets.txt" ip netns exec "${ACTOR_NS}" ss -ulnp || true

start_ms="$(vnet_now_ms)"
if mapped="$(wait_for_mapped_ports 20)"; then
    append_text_capture "mapped UDP ports" "command-output" "mapped-ports.txt" "${mapped}"
    record_assertion "upnp_mapped_ports_present" "passed" "${start_ms}" \
        "At least one UPnP-mapped UDP port exists while the dhtnet session is active."
    vnet_results_metric "mapped_port_count" "$(printf '%s\n' "${mapped}" | grep -c .)"
else
    append_text_capture "mapped UDP ports" "command-output" "mapped-ports.txt" ""
    record_assertion "upnp_mapped_ports_present" "failed" "${start_ms}" \
        "No UPnP-mapped UDP ports were observed while the dhtnet session was active."
    mark_failed
    exit "${PROBE_EXIT_CODE}"
fi

exit "${PROBE_EXIT_CODE}"
