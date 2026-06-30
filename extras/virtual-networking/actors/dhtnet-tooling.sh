#!/usr/bin/env bash

if [[ -n "${DHTNET_VNET_TOOLING_SH:-}" ]]; then
    return 0
fi
DHTNET_VNET_TOOLING_SH=1

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib/shell/common.sh"

if [[ -n "${VNET_REPO_ROOT:-}" ]]; then
    REPO_ROOT="${VNET_REPO_ROOT}"
elif [[ -n "${VNET_COMMON_ROOT:-}" ]]; then
    REPO_ROOT="$(cd "${VNET_COMMON_ROOT}/../.." && pwd)"
else
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
fi
BUILD_DIR="${BUILD_DIR:-${DHTNET_BUILD_DIR:-}}"

declare -a VNET_DHTNET_BUILD_DIR_CANDIDATES=()

vnet_append_build_dir_candidate() {
    local candidate="$1"
    local normalized
    local existing

    [[ -d "${candidate}" ]] || return 0
    normalized="$(cd "${candidate}" && pwd)"
    for existing in "${VNET_DHTNET_BUILD_DIR_CANDIDATES[@]:-}"; do
        [[ "${existing}" == "${normalized}" ]] && return 0
    done
    VNET_DHTNET_BUILD_DIR_CANDIDATES+=("${normalized}")
}

vnet_collect_build_dir_candidates() {
    local candidate

    VNET_DHTNET_BUILD_DIR_CANDIDATES=()
    if [[ -n "${BUILD_DIR:-}" ]]; then
        vnet_append_build_dir_candidate "${BUILD_DIR}"
    fi
    vnet_append_build_dir_candidate "${REPO_ROOT}/build"
    for candidate in "${REPO_ROOT}"/build-* "${REPO_ROOT}"/cmake-build*; do
        vnet_append_build_dir_candidate "${candidate}"
    done
}

vnet_find_tool_in_build_dir() {
    local build_dir="$1"
    local binary_name="$2"
    local candidate
    local found

    for candidate in \
        "${build_dir}/${binary_name}" \
        "${build_dir}/bin/${binary_name}" \
        "${build_dir}/Debug/${binary_name}" \
        "${build_dir}/Release/${binary_name}" \
        "${build_dir}/RelWithDebInfo/${binary_name}" \
        "${build_dir}/MinSizeRel/${binary_name}"; do
        if [[ -x "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    found="$(find "${build_dir}" -maxdepth 4 -type f -name "${binary_name}" -perm -111 -print -quit 2>/dev/null || true)"
    if [[ -n "${found}" ]]; then
        printf '%s\n' "${found}"
        return 0
    fi
}

vnet_resolve_dhtnet_tool() {
    local binary_name="$1"
    local env_var_name="$2"
    local env_value="${!env_var_name:-}"
    local build_dir
    local found_path

    if [[ -n "${env_value}" ]]; then
        if [[ ! -x "${env_value}" ]]; then
            echo "Error: ${env_var_name} points to a non-executable path: ${env_value}" >&2
            return 1
        fi
        printf '%s\n' "${env_value}"
        return 0
    fi

    vnet_collect_build_dir_candidates
    for build_dir in "${VNET_DHTNET_BUILD_DIR_CANDIDATES[@]:-}"; do
        found_path="$(vnet_find_tool_in_build_dir "${build_dir}" "${binary_name}" || true)"
        if [[ -n "${found_path}" ]]; then
            printf '%s\n' "${found_path}"
            return 0
        fi
    done

    if command -v "${binary_name}" >/dev/null 2>&1; then
        command -v "${binary_name}"
        return 0
    fi

    echo "Error: could not find ${binary_name}. Build dhtnet first as described in BUILD.md, then set ${env_var_name}, DHTNET_BUILD_DIR, or place the binary under ${REPO_ROOT}/build." >&2
    return 1
}
