#!/usr/bin/env bats

setup() {
    export TEST_ROOT="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${TEST_ROOT}/scripts" "${TEST_ROOT}/tests/lab/terraform" \
        "${TEST_ROOT}/tests/lab/.local/ssh" "${TEST_ROOT}/bin" "${TEST_ROOT}/home/.config"
    cp "${BATS_TEST_DIRNAME}/../../../scripts/lib.sh" "${TEST_ROOT}/scripts/lib.sh"
    cp "${BATS_TEST_DIRNAME}/../../../scripts/terraform.sh" "${TEST_ROOT}/scripts/terraform.sh"
    export HOME="${TEST_ROOT}/home"
    export PATH="${TEST_ROOT}/bin:${PATH}"
    export FAKE_TERRAFORM_LOG="${TEST_ROOT}/terraform.log"
    export TF_VAR_network_bridge="vmbr0"
    export TF_VAR_vlan_id="100"
    export TF_VAR_network_prefix_length="24"
    export TF_VAR_gateway="10.100.0.1"
    export TF_VAR_storage_ip="10.100.0.10"
    export TF_VAR_node_ips='["10.100.0.11","10.100.0.12","10.100.0.13"]'
    export TF_VAR_storage_vm_id="900"
    export TF_VAR_node_vm_ids='[901,902,903]'
    export VERSITYGW_LAB_SUBNET_PREFIX="10.100.0"
    export TF_VAR_ssh_public_key="ssh-ed25519 test-key"

    cat >"${TEST_ROOT}/bin/ssh-keygen" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-f" ]]; then
        key_path="$2"
        break
    fi
    shift
done
touch "${key_path}"
printf 'ssh-ed25519 test-key\n' >"${key_path}.pub"
EOF
    chmod +x "${TEST_ROOT}/bin/ssh-keygen"
}

write_fake_terraform() {
    cat >"${TEST_ROOT}/bin/terraform" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_TERRAFORM_LOG}"
if [[ "$*" == *"show -json"* ]]; then
    printf '%s\n' "${FAKE_PLAN_JSON}"
elif [[ "$*" == *"plan "* ]]; then
    touch "${TEST_ROOT}/tests/lab/.local/create.tfplan"
fi
EOF
    chmod +x "${TEST_ROOT}/bin/terraform"
}

@test "caller environment overrides project local environment" {
    write_fake_terraform
    printf 'TF_VAR_proxmox_endpoint=https://from-file.invalid\n' >"${TEST_ROOT}/.env.local"
    export TF_VAR_proxmox_endpoint="https://from-caller.invalid"
    export PROXMOX_TOKEN="test-token"

    run "${TEST_ROOT}/scripts/terraform.sh" output

    [ "$status" -eq 0 ]
}

@test "plan gate accepts exactly four creates" {
    write_fake_terraform
    export TF_VAR_proxmox_endpoint="https://example.invalid"
    export PROXMOX_TOKEN="test-token"
    export FAKE_PLAN_JSON='{"resource_changes":[
      {"address":"proxmox_virtual_environment_vm.lab[\"node-a\"]","type":"proxmox_virtual_environment_vm","name":"lab","change":{"actions":["create"],"after":{"vm_id":901,"network_device":[{"bridge":"vmbr0","vlan_id":100}],"initialization":[{"ip_config":[{"ipv4":[{"address":"10.100.0.11/24","gateway":"10.100.0.1"}]}]}]}}},
      {"address":"proxmox_virtual_environment_vm.lab[\"node-b\"]","type":"proxmox_virtual_environment_vm","name":"lab","change":{"actions":["create"],"after":{"vm_id":902,"network_device":[{"bridge":"vmbr0","vlan_id":100}],"initialization":[{"ip_config":[{"ipv4":[{"address":"10.100.0.12/24","gateway":"10.100.0.1"}]}]}]}}},
      {"address":"proxmox_virtual_environment_vm.lab[\"node-c\"]","type":"proxmox_virtual_environment_vm","name":"lab","change":{"actions":["create"],"after":{"vm_id":903,"network_device":[{"bridge":"vmbr0","vlan_id":100}],"initialization":[{"ip_config":[{"ipv4":[{"address":"10.100.0.13/24","gateway":"10.100.0.1"}]}]}]}}},
      {"address":"proxmox_virtual_environment_vm.lab[\"storage\"]","type":"proxmox_virtual_environment_vm","name":"lab","change":{"actions":["create"],"after":{"vm_id":900,"network_device":[{"bridge":"vmbr0","vlan_id":100}],"initialization":[{"ip_config":[{"ipv4":[{"address":"10.100.0.10/24","gateway":"10.100.0.1"}]}]}]}}}
    ]}'

    run "${TEST_ROOT}/scripts/terraform.sh" plan

    [ "$status" -eq 0 ]
    [[ "$output" == *"verified plan: 4 creates, 0 updates, 0 deletes"* ]]
    [ -f "${TEST_ROOT}/tests/lab/.local/ssh/id_ed25519" ]
    [ -f "${TEST_ROOT}/tests/lab/.local/ssh/id_ed25519.pub" ]
}

@test "plan gate rejects any deletion" {
    write_fake_terraform
    export TF_VAR_proxmox_endpoint="https://example.invalid"
    export PROXMOX_TOKEN="test-token"
    export FAKE_PLAN_JSON='{"resource_changes":[{"change":{"actions":["create"]}},{"change":{"actions":["create"]}},{"change":{"actions":["create"]}},{"change":{"actions":["create"]}},{"change":{"actions":["delete"]}}]}'

    run "${TEST_ROOT}/scripts/terraform.sh" plan

    [ "$status" -eq 1 ]
    [[ "$output" == *"refusing plan"* ]]
}

@test "plan gate rejects a network outside the approved lab scope" {
    write_fake_terraform
    export TF_VAR_proxmox_endpoint="https://example.invalid"
    export PROXMOX_TOKEN="test-token"
    export TF_VAR_vlan_id="not-a-vlan"
    export FAKE_PLAN_JSON='{"resource_changes":[]}'

    run "${TEST_ROOT}/scripts/terraform.sh" plan

    [ "$status" -eq 1 ]
    [[ "$output" == *"refusing plan"* ]]
}
