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
    lab_require_variable PROXMOX_TOKEN
    lab_require_variable TF_VAR_proxmox_endpoint
    [[ -f "${LAB_LOCAL_DIR}/ssh/id_ed25519.pub" || -n "${TF_VAR_ssh_public_key:-}" ]] || \
        lab_die "create the lab SSH key first: ${LAB_LOCAL_DIR}/ssh/id_ed25519"
}

verify_create_plan() {
    local plan_json
    local creates
    local updates
    local deletes

    plan_json="$(run_terraform show -json "${PLAN_FILE}")"
    creates="$(jq '[.resource_changes[]? | select(.change.actions == ["create"])] | length' <<<"${plan_json}")"
    updates="$(jq '[.resource_changes[]? | select(.change.actions | index("update"))] | length' <<<"${plan_json}")"
    deletes="$(jq '[.resource_changes[]? | select(.change.actions | index("delete"))] | length' <<<"${plan_json}")"

    if [[ "${creates}" != "4" || "${updates}" != "0" || "${deletes}" != "0" ]]; then
        lab_die "refusing plan: expected 4 creates, 0 updates, 0 deletes; got ${creates}/${updates}/${deletes}"
    fi
    printf 'verified plan: 4 creates, 0 updates, 0 deletes\n'
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
