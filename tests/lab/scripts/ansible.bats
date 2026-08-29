#!/usr/bin/env bats

setup() {
    export TEST_ROOT="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${TEST_ROOT}/scripts" "${TEST_ROOT}/tests/lab/.local/ssh" \
        "${TEST_ROOT}/tests/lab/ansible" "${TEST_ROOT}/bin" "${TEST_ROOT}/home"
    cp "${BATS_TEST_DIRNAME}/../../../scripts/lib.sh" "${TEST_ROOT}/scripts/lib.sh"
    cp "${BATS_TEST_DIRNAME}/../../../scripts/ansible.sh" "${TEST_ROOT}/scripts/ansible.sh"
    cp "${BATS_TEST_DIRNAME}/../ansible/inventory.yml.template" \
        "${TEST_ROOT}/tests/lab/ansible/inventory.yml.template"
    touch "${TEST_ROOT}/tests/lab/.local/ssh/id_ed25519"
    export HOME="${TEST_ROOT}/home"
    export PATH="${TEST_ROOT}/bin:${PATH}"
    export TF_VAR_storage_ip="192.0.2.10"
    export TF_VAR_node_ips='["192.0.2.11","192.0.2.12","192.0.2.13"]'
    export TF_VAR_ssh_username="rocky"
    export VERSITYGW_LAB_CLIENT_CIDR="192.0.2.0/24"
}

@test "inventory generation keeps environment-specific values local" {
    run "${TEST_ROOT}/scripts/ansible.sh" inventory

    [ "$status" -eq 0 ]
    [ -f "${TEST_ROOT}/tests/lab/.local/inventory.yml" ]
    grep -q 'ansible_host: "192.0.2.10"' "${TEST_ROOT}/tests/lab/.local/inventory.yml"
    grep -q 'scoutfs_quorum_slot: 2' "${TEST_ROOT}/tests/lab/.local/inventory.yml"
    grep -q 'versitygw_local_binary_path:.*tests/lab/.local/bin/versitygw' \
        "${TEST_ROOT}/tests/lab/.local/inventory.yml"
}

@test "inventory generation rejects an incomplete node list" {
    export TF_VAR_node_ips='["192.0.2.11"]'

    run "${TEST_ROOT}/scripts/ansible.sh" inventory

    [ "$status" -eq 1 ]
    [[ "$output" == *"TF_VAR_node_ips must contain three strings"* ]]
}
