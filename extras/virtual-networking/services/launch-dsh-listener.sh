#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VNET_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${VNET_ROOT}/lib/shell/common.sh"
source "${SCRIPT_DIR}/dhtnet-tooling.sh"

usage() {
    cat <<'EOF'
Usage: launch-dsh-listener.sh [--build-dir DIR] [--bootstrap HOST]

Launch a dhtnet `dsh` listener suitable for the virtual-networking baseline
scenario. The helper expects prebuilt `dsh` / `dhtnet-crtmgr` binaries,
generates a temporary identity, emits the service peer ID, starts `dsh -l -a`,
and signals readiness after the identity is announced.
EOF
    exit 0
}

REPO_ROOT="${VNET_REPO_ROOT:-$(cd "${VNET_ROOT}/../.." && pwd)}"
BUILD_DIR="${DHTNET_BUILD_DIR:-}"
BOOTSTRAP="${DHTNET_BOOTSTRAP:-bootstrap.sfl.io}"

while (($# > 0)); do
    case "$1" in
        --build-dir)
            shift
            [[ $# -gt 0 ]] || usage
            BUILD_DIR="$1"
            ;;
        --bootstrap)
            shift
            [[ $# -gt 0 ]] || usage
            BOOTSTRAP="$1"
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

vnet_require_commands grep mktemp python3 tail

DSH_BIN="$(vnet_resolve_dhtnet_tool dsh DHTNET_DSH_BIN)"
CRTMGR_BIN="$(vnet_resolve_dhtnet_tool dhtnet-crtmgr DHTNET_CRTMGR_BIN)"
SERVICE_OUTPUT_CLI="${VNET_ROOT}/lib/tools/service_output.py"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/dhtnet-service-dsh.XXXXXX")"
dsh_pid=""
tail_pid=""
DHTNET_LOG="${WORKDIR}/dsh.log"
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -n "${dsh_pid}" ]] && kill -0 "${dsh_pid}" 2>/dev/null; then
        kill "${dsh_pid}" 2>/dev/null || true
        wait "${dsh_pid}" 2>/dev/null || true
    fi
    if [[ -n "${tail_pid}" ]] && kill -0 "${tail_pid}" 2>/dev/null; then
        kill "${tail_pid}" 2>/dev/null || true
        wait "${tail_pid}" 2>/dev/null || true
    fi
    rm -rf "${WORKDIR}"
    exit "${rc}"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

umask 077
export DHTNET_CACHE_DIR="${WORKDIR}/cache"
mkdir -p "${DHTNET_CACHE_DIR}"

"${CRTMGR_BIN}" --setup -o "${WORKDIR}" >/dev/null
CERT_PATH="${WORKDIR}/id/id-server.crt"
KEY_PATH="${WORKDIR}/id/id-server.pem"
peer_id="$(python3 "${SERVICE_OUTPUT_CLI}" long-id "${CERT_PATH}")"
if [[ -z "${peer_id}" ]]; then
    echo "Error: unable to extract dsh service identity information" >&2
    exit 1
fi

echo "[SERVICE] workspace: ${WORKDIR}"
echo "[SERVICE] cache dir: ${DHTNET_CACHE_DIR}"
echo "[SERVICE] bootstrap: ${BOOTSTRAP}"
echo "SERVICE_PEER_ID=${peer_id}"
echo "[SERVICE] launching: ${DSH_BIN} -l -a -b ${BOOTSTRAP} -c ${CERT_PATH} -p ${KEY_PATH}"

if [[ -n "${VNET_SERVICE_OUTPUT_FILE:-}" ]]; then
    mkdir -p "$(dirname "${VNET_SERVICE_OUTPUT_FILE}")"
    python3 "${SERVICE_OUTPUT_CLI}" write \
        "${VNET_SERVICE_OUTPUT_FILE}" \
        "${peer_id}" \
        "${BOOTSTRAP}" \
        "${CERT_PATH}" \
        "${KEY_PATH}"
fi

touch "${DHTNET_LOG}"
tail -n +1 -F "${DHTNET_LOG}" &
tail_pid=$!

"${DSH_BIN}" -l -a -b "${BOOTSTRAP}" -c "${CERT_PATH}" -p "${KEY_PATH}" >"${DHTNET_LOG}" 2>&1 &
dsh_pid=$!

if [[ -n "${VNET_SERVICE_READY_FILE:-}" ]]; then
    ready_timeout_s="${VNET_SERVICE_READY_TIMEOUT_S:-60}"
    if [[ ! "${ready_timeout_s}" =~ ^[0-9]+$ ]]; then
        echo "Error: VNET_SERVICE_READY_TIMEOUT_S must be a non-negative integer" >&2
        exit 1
    fi
    deadline=$((SECONDS + ready_timeout_s))
    while (( SECONDS <= deadline )); do
        if grep -Fq "Identity announced true" "${DHTNET_LOG}"; then
            printf 'ready\n' > "${VNET_SERVICE_READY_FILE}"
            break
        fi
        if ! kill -0 "${dsh_pid}" 2>/dev/null; then
            wait "${dsh_pid}"
            exit $?
        fi
        sleep 0.25
    done
    if [[ ! -e "${VNET_SERVICE_READY_FILE}" ]]; then
        echo "Error: dsh listener did not announce identity within ${ready_timeout_s}s" >&2
        exit 1
    fi
fi

wait "${dsh_pid}"
