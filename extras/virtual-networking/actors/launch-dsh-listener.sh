#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VNET_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${VNET_ROOT}/lib/common.sh"
source "${SCRIPT_DIR}/dhtnet-tooling.sh"

usage() {
    cat <<'EOF'
Usage: launch-dsh-listener.sh [--build-dir DIR] [--bootstrap HOST]

Launch a dhtnet `dsh` listener suitable for the virtual-networking baseline
scenario. The helper expects prebuilt `dsh` / `dhtnet-crtmgr` binaries,
generates a temporary identity, emits the actor peer ID, and then execs
`dsh -l -a`.
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

vnet_require_commands mktemp python3

DSH_BIN="$(vnet_resolve_dhtnet_tool dsh DHTNET_DSH_BIN)"
CRTMGR_BIN="$(vnet_resolve_dhtnet_tool dhtnet-crtmgr DHTNET_CRTMGR_BIN)"
ACTOR_OUTPUT_CLI="${VNET_ROOT}/lib/actor_output.py"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/dhtnet-actor-dsh.XXXXXX")"
cleanup() {
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

umask 077
export DHTNET_CACHE_DIR="${WORKDIR}/cache"
mkdir -p "${DHTNET_CACHE_DIR}"

"${CRTMGR_BIN}" --setup -o "${WORKDIR}" >/dev/null
CERT_PATH="${WORKDIR}/id/id-server.crt"
KEY_PATH="${WORKDIR}/id/id-server.pem"
peer_id="$(python3 "${ACTOR_OUTPUT_CLI}" long-id "${CERT_PATH}")"
if [[ -z "${peer_id}" ]]; then
    echo "Error: unable to extract dsh actor identity information" >&2
    exit 1
fi

echo "[ACTOR] workspace: ${WORKDIR}"
echo "[ACTOR] cache dir: ${DHTNET_CACHE_DIR}"
echo "[ACTOR] bootstrap: ${BOOTSTRAP}"
echo "ACTOR_PEER_ID=${peer_id}"
echo "[ACTOR] launching: ${DSH_BIN} -l -a -b ${BOOTSTRAP} -c ${CERT_PATH} -p ${KEY_PATH}"

if [[ -n "${VNET_ACTOR_OUTPUT_FILE:-}" ]]; then
    mkdir -p "$(dirname "${VNET_ACTOR_OUTPUT_FILE}")"
    python3 "${ACTOR_OUTPUT_CLI}" write \
        "${VNET_ACTOR_OUTPUT_FILE}" \
        "${peer_id}" \
        "${BOOTSTRAP}" \
        "${CERT_PATH}" \
        "${KEY_PATH}"
fi

if [[ -n "${VNET_ACTOR_READY_FILE:-}" ]]; then
    printf 'ready\n' > "${VNET_ACTOR_READY_FILE}"
fi

exec "${DSH_BIN}" -l -a -b "${BOOTSTRAP}" -c "${CERT_PATH}" -p "${KEY_PATH}"
