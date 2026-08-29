#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=scripts/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

readonly TERRAFORM_DIR="${LAB_DIR}/terraform"
readonly PLAN_FILE="${LAB_LOCAL_DIR}/create.tfplan"

usage() {
    cat <<'EOF'
Usage: scripts/terraform.sh [--env NAME | --env-file PATH] COMMAND

Commands:
  init      Initialize the pinned provider.
  validate  Check formatting and validate the configuration.
  plan      Write a local create plan and require exactly four VM creates.
  apply     Apply the previously verified local create plan.
  output    Print Terraform outputs as JSON.

The wrapper intentionally has no destroy command. Destruction is a separate,
explicitly approved operation. Environment precedence is global config,
project .env.local, selected profile, then the caller's existing environment.
EOF
}

run_terraform() {
    local ssh_public_key="${TF_VAR_ssh_public_key:-}"

    if [[ -z "${ssh_public_key}" && -f "${LAB_LOCAL_DIR}/ssh/id_ed25519.pub" ]]; then
        ssh_public_key="$(<"${LAB_LOCAL_DIR}/ssh/id_ed25519.pub")"
    fi

    PROXMOX_VE_API_TOKEN="${PROXMOX_TOKEN:-}" \
        TF_VAR_ssh_public_key="${ssh_public_key}" \
        terraform -chdir="${TERRAFORM_DIR}" "$@"
}

require_runtime_configuration() {
    local name
    for name in PROXMOX_TOKEN TF_VAR_proxmox_endpoint TF_VAR_network_bridge TF_VAR_vlan_id \
        TF_VAR_network_prefix_length TF_VAR_gateway TF_VAR_storage_ip TF_VAR_node_ips \
        TF_VAR_storage_vm_id TF_VAR_node_vm_ids VERSITYGW_LAB_SUBNET_PREFIX; do
        lab_require_variable "${name}"
    done
    [[ -f "${LAB_LOCAL_DIR}/ssh/id_ed25519.pub" || -n "${TF_VAR_ssh_public_key:-}" ]] || \
        lab_die "create the lab SSH key first: ${LAB_LOCAL_DIR}/ssh/id_ed25519"
}

verify_create_plan() {
    local plan_json
    local actual_scope
    local creates
    local updates
    local deletes
    local expected_scope

    plan_json="$(run_terraform show -json "${PLAN_FILE}")"
    creates="$(jq '[.resource_changes[]? | select(.change.actions == ["create"])] | length' <<<"${plan_json}")"
    updates="$(jq '[.resource_changes[]? | select(.change.actions | index("update"))] | length' <<<"${plan_json}")"
    deletes="$(jq '[.resource_changes[]? | select(.change.actions | index("delete"))] | length' <<<"${plan_json}")"

    if [[ "${creates}" != "4" || "${updates}" != "0" || "${deletes}" != "0" ]]; then
        lab_die "refusing plan: expected 4 creates, 0 updates, 0 deletes; got ${creates}/${updates}/${deletes}"
    fi

    [[ "${TF_VAR_vlan_id:-}" =~ ^[0-9]+$ ]] || lab_die "refusing plan: TF_VAR_vlan_id must be numeric"
    [[ "${TF_VAR_network_prefix_length:-}" =~ ^[0-9]+$ ]] || lab_die "refusing plan: TF_VAR_network_prefix_length must be numeric"
    jq -e 'length == 3 and (all(.[]; type == "number"))' <<<"${TF_VAR_node_vm_ids:-}" >/dev/null || \
        lab_die "TF_VAR_node_vm_ids must contain three VM IDs"
    jq -e 'length == 3 and (all(.[]; type == "string"))' <<<"${TF_VAR_node_ips:-}" >/dev/null || \
        lab_die "TF_VAR_node_ips must contain three addresses"

    expected_scope="$(jq -cn \
        --arg storage_ip "${TF_VAR_storage_ip:-}" \
        --argjson storage_vm_id "${TF_VAR_storage_vm_id:-null}" \
        --argjson node_ips "${TF_VAR_node_ips:-null}" \
        --argjson node_vm_ids "${TF_VAR_node_vm_ids:-null}" \
        --arg gateway "${TF_VAR_gateway:-}" \
        --arg bridge "${TF_VAR_network_bridge:-}" \
        --argjson vlan_id "${TF_VAR_vlan_id:-null}" \
        --arg prefix_length "${TF_VAR_network_prefix_length:-}" \
        '[
          {name:"node-a", vm_id:$node_vm_ids[0], address:($node_ips[0] + "/" + $prefix_length), gateway:$gateway, bridge:$bridge, vlan_id:$vlan_id},
          {name:"node-b", vm_id:$node_vm_ids[1], address:($node_ips[1] + "/" + $prefix_length), gateway:$gateway, bridge:$bridge, vlan_id:$vlan_id},
          {name:"node-c", vm_id:$node_vm_ids[2], address:($node_ips[2] + "/" + $prefix_length), gateway:$gateway, bridge:$bridge, vlan_id:$vlan_id},
          {name:"storage", vm_id:$storage_vm_id, address:($storage_ip + "/" + $prefix_length), gateway:$gateway, bridge:$bridge, vlan_id:$vlan_id}
        ] | sort_by(.name)')"
    actual_scope="$(jq -c '
        [.resource_changes[]
          | select(.type == "proxmox_virtual_environment_vm" and .name == "lab")
          | {
              name: (.address | capture("\\[\\\"(?<name>[^\\\"]+)\\\"\\]").name),
              vm_id: .change.after.vm_id,
              address: .change.after.initialization[0].ip_config[0].ipv4[0].address,
              gateway: .change.after.initialization[0].ip_config[0].ipv4[0].gateway,
              bridge: .change.after.network_device[0].bridge,
              vlan_id: .change.after.network_device[0].vlan_id
            }
        ] | sort_by(.name)' <<<"${plan_json}")"
    [[ "${actual_scope}" == "${expected_scope}" ]] || lab_die "refusing plan: VM IDs or network scope differ from the approved lab variables"

    local subnet_regex="^${VERSITYGW_LAB_SUBNET_PREFIX//./\\.}\\.([0-9]{1,3})$"
    while IFS= read -r address; do
        [[ "${address}" =~ ${subnet_regex} ]] || lab_die "refusing plan: address outside ${VERSITYGW_LAB_SUBNET_PREFIX}.0/24: ${address}"
        (( BASH_REMATCH[1] >= 1 && BASH_REMATCH[1] <= 254 )) || lab_die "refusing plan: unusable lab address ${address}"
    done < <(jq -r --arg prefix_length "${TF_VAR_network_prefix_length}" '.[].address | sub("/\($prefix_length)$"; "")' <<<"${actual_scope}")

    printf 'verified plan: 4 creates, 0 updates, 0 deletes; %s/VLAN %s; addresses limited to %s.0/24\n' \
        "${TF_VAR_network_bridge}" "${TF_VAR_vlan_id}" "${VERSITYGW_LAB_SUBNET_PREFIX}"
}

ensure_ssh_key() {
    local key_directory="${LAB_LOCAL_DIR}/ssh"
    local private_key="${key_directory}/id_ed25519"
    local public_key="${private_key}.pub"

    if [[ -f "${private_key}" && -f "${public_key}" ]]; then
        return 0
    fi
    if [[ -e "${private_key}" || -e "${public_key}" ]]; then
        lab_die "incomplete lab SSH key pair under ${key_directory}; preserve or repair it explicitly"
    fi
    lab_require_command ssh-keygen
    mkdir -p "${key_directory}"
    chmod 700 "${key_directory}"
    ssh-keygen -q -t ed25519 -N "" -C "versitygw-dev-lab" -f "${private_key}"
    chmod 600 "${private_key}"
    chmod 644 "${public_key}"
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
    lab_require_command terraform
    lab_require_command jq
    lab_load_environment "${profile}" "${env_file}"
    mkdir -p "${LAB_LOCAL_DIR}"

    case "$1" in
        init) run_terraform init -input=false ;;
        validate)
            run_terraform fmt -check -diff -recursive
            run_terraform init -backend=false -input=false
            run_terraform validate
            ;;
        plan)
            ensure_ssh_key
            require_runtime_configuration
            run_terraform init -input=false
            run_terraform plan -input=false -out="${PLAN_FILE}"
            verify_create_plan
            ;;
        apply)
            require_runtime_configuration
            [[ -f "${PLAN_FILE}" ]] || lab_die "no verified plan exists: run plan first"
            verify_create_plan
            run_terraform apply -input=false "${PLAN_FILE}"
            ;;
        output) require_runtime_configuration; run_terraform output -json ;;
        *) usage >&2; return 2 ;;
    esac
}

main "$@"
