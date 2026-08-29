#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

usage() {
    cat <<'EOF'
Usage: scripts/run.sh [--env NAME | --env-file PATH] COMMAND

Commands:
  create     Generate the project SSH key and write a reviewed create plan.
  apply      Apply that exact plan, configure the four VMs, then verify.
  configure  Rebuild artifacts and apply the lab Ansible configuration.
  verify     Query the running NFS and ScoutFS gateways with the live probe.

There is intentionally no destroy command. Removing the temporary lab requires
separate, explicit approval and a reviewed Terraform destroy plan.
EOF
}

main() {
    local environment_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --env | --env-file)
                environment_args+=("$1" "${2:?missing value for $1}")
                shift 2
                ;;
            -h | --help)
                usage
                return 0
                ;;
            *) break ;;
        esac
    done

    [[ $# -eq 1 ]] || { usage >&2; return 2; }
    case "$1" in
        create)
            "${SCRIPT_DIR}/terraform.sh" "${environment_args[@]}" plan
            printf 'plan ready; review it, then run: scripts/run.sh apply\n'
            ;;
        apply)
            "${SCRIPT_DIR}/terraform.sh" "${environment_args[@]}" apply
            "${SCRIPT_DIR}/ansible.sh" "${environment_args[@]}" configure
            "${SCRIPT_DIR}/ansible.sh" "${environment_args[@]}" verify
            ;;
        configure) "${SCRIPT_DIR}/ansible.sh" "${environment_args[@]}" configure ;;
        verify) "${SCRIPT_DIR}/ansible.sh" "${environment_args[@]}" verify ;;
        *) usage >&2; return 2 ;;
    esac
}

main "$@"
