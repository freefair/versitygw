#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LAB_DIR="${PROJECT_ROOT}/tests/lab"
LAB_LOCAL_DIR="${LAB_DIR}/.local"
readonly SCRIPT_DIR PROJECT_ROOT LAB_DIR LAB_LOCAL_DIR
export PROJECT_ROOT LAB_DIR LAB_LOCAL_DIR

lab_die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

lab_require_command() {
    command -v "$1" >/dev/null 2>&1 || lab_die "required command not found: $1"
}

lab_load_env_file() {
    local env_file="$1"
    local line
    local name
    local value

    [[ -f "${env_file}" ]] || return 0

    while IFS= read -r line || [[ -n "${line}" ]]; do
        [[ -z "${line}" || "${line}" == \#* ]] && continue
        [[ "${line}" == [A-Za-z_]*=* ]] || lab_die "invalid environment entry in ${env_file}"
        name="${line%%=*}"
        value="${line#*=}"
        [[ "${name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || lab_die "invalid variable name in ${env_file}"
        export "${name}=${value}"
    done <"${env_file}"
}

lab_profile_path() {
    local profile="$1"
    local candidate

    for candidate in \
        "${LAB_DIR}/environments/${profile}.env" \
        "${HOME}/.config/versitygw-lab/${profile}.env"; do
        if [[ -f "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    lab_die "environment profile not found: ${profile}"
}

lab_load_environment() {
    local profile="${1:-${VERSITYGW_LAB_ENV:-}}"
    local explicit_file="${2:-}"
    local names=()
    local values=()
    local name

    while IFS='=' read -r name _; do
        case "${name}" in
            PROXMOX_TOKEN | PROXMOX_VE_* | TF_VAR_* | ANSIBLE_* | VERSITYGW_LAB_*)
                names+=("${name}")
                values+=("${!name}")
                ;;
        esac
    done < <(env)

    lab_load_env_file "${HOME}/.config/versitygw-lab.env"
    lab_load_env_file "${PROJECT_ROOT}/.env.local"

    if [[ -n "${profile}" ]]; then
        lab_load_env_file "$(lab_profile_path "${profile}")"
    fi
    if [[ -n "${explicit_file}" ]]; then
        lab_load_env_file "${explicit_file}"
    fi

    local index
    for ((index = 0; index < ${#names[@]}; index++)); do
        export "${names[index]}=${values[index]}"
    done
}

lab_require_variable() {
    local name="$1"
    [[ -n "${!name:-}" ]] || lab_die "required environment variable is unset: ${name}"
}
