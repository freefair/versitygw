#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

readonly ANSIBLE_DIR="${LAB_DIR}/ansible"
readonly INVENTORY_FILE="${LAB_LOCAL_DIR}/inventory.yml"
readonly LOCKPROBE_FILE="${LAB_LOCAL_DIR}/bin/versitygw-lockprobe"

usage() {
    cat <<'EOF'
Usage: scripts/ansible.sh [--env NAME | --env-file PATH] COMMAND

Commands:
  inventory  Generate the ignored local inventory.
  syntax     Generate inventory and run syntax checks.
  configure  Configure NFS, iSCSI, and ScoutFS on the provisioned VMs.
  verify     Verify mounts, services, and shared filesystem visibility.
EOF
}

require_inventory_configuration() {
    local name
    local node_ips

    for name in TF_VAR_storage_ip TF_VAR_node_ips TF_VAR_ssh_username VERSITYGW_LAB_CLIENT_CIDR; do
        lab_require_variable "${name}"
    done
    [[ -f "${LAB_LOCAL_DIR}/ssh/id_ed25519" ]] || \
        lab_die "lab SSH private key not found: ${LAB_LOCAL_DIR}/ssh/id_ed25519"
    node_ips="${TF_VAR_node_ips:-}"
    jq -e 'length == 3 and (all(.[]; type == "string"))' \
        <<<"${node_ips}" >/dev/null || lab_die "TF_VAR_node_ips must contain three strings"
}

generate_inventory() {
    local node_a
    local node_b
    local node_c
    local inventory_tmp
    local node_ips="${TF_VAR_node_ips:-}"
    local ssh_username="${TF_VAR_ssh_username:-}"
    local storage_ip="${TF_VAR_storage_ip:-}"
    local client_cidr="${VERSITYGW_LAB_CLIENT_CIDR:-}"

    require_inventory_configuration
    node_a="$(jq -r '.[0]' <<<"${node_ips}")"
    node_b="$(jq -r '.[1]' <<<"${node_ips}")"
    node_c="$(jq -r '.[2]' <<<"${node_ips}")"
    mkdir -p "${LAB_LOCAL_DIR}"
    inventory_tmp="${INVENTORY_FILE}.tmp"

    sed \
        -e "s|@@SSH_USER@@|${ssh_username}|g" \
        -e "s|@@SSH_KEY@@|${LAB_LOCAL_DIR}/ssh/id_ed25519|g" \
        -e "s|@@KNOWN_HOSTS@@|${LAB_LOCAL_DIR}/known_hosts|g" \
        -e "s|@@LOCKPROBE@@|${LOCKPROBE_FILE}|g" \
        -e "s|@@STORAGE_IP@@|${storage_ip}|g" \
        -e "s|@@CLIENT_CIDR@@|${client_cidr}|g" \
        -e "s|@@NODE_A_IP@@|${node_a}|g" \
        -e "s|@@NODE_B_IP@@|${node_b}|g" \
        -e "s|@@NODE_C_IP@@|${node_c}|g" \
        "${ANSIBLE_DIR}/inventory.yml.template" >"${inventory_tmp}"
    mv "${inventory_tmp}" "${INVENTORY_FILE}"
    chmod 600 "${INVENTORY_FILE}"
    printf '%s\n' "${INVENTORY_FILE}"
}

run_playbook() {
    local playbook="$1"
    shift

    ANSIBLE_CONFIG="${ANSIBLE_DIR}/ansible.cfg" \
        ansible-playbook -i "${INVENTORY_FILE}" "${ANSIBLE_DIR}/${playbook}" "$@"
}

build_lockprobe() {
    lab_require_command go
    mkdir -p "$(dirname "${LOCKPROBE_FILE}")"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -o "${LOCKPROBE_FILE}" ./tests/lab/lockprobe
}

main() {
    local profile=""
    local env_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --env) profile="${2:?missing profile name}"; shift 2 ;;
            --env-file) env_file="${2:?missing environment file}"; shift 2 ;;
            -h | --help) usage; return 0 ;;
            *) break ;;
        esac
    done

    [[ $# -eq 1 ]] || { usage >&2; return 2; }
    lab_require_command ansible-playbook
    lab_require_command jq
    lab_load_environment "${profile}" "${env_file}"

    case "$1" in
        inventory) generate_inventory ;;
        syntax)
            generate_inventory >/dev/null
            run_playbook site.yml --syntax-check
            run_playbook verify.yml --syntax-check
            ;;
        configure)
            generate_inventory >/dev/null
            build_lockprobe
            run_playbook site.yml
            ;;
        verify) generate_inventory >/dev/null; run_playbook verify.yml ;;
        *) usage >&2; return 2 ;;
    esac
}

main "$@"
