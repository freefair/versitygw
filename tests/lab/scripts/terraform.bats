#!/usr/bin/env bats

setup() {
    export TEST_ROOT="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${TEST_ROOT}/scripts" "${TEST_ROOT}/tests/lab/terraform" \
        "${TEST_ROOT}/tests/lab/.local/ssh" "${TEST_ROOT}/bin" "${TEST_ROOT}/home/.config"
    cp "${BATS_TEST_DIRNAME}/../../../scripts/lib.sh" "${TEST_ROOT}/scripts/lib.sh"
    cp "${BATS_TEST_DIRNAME}/../../../scripts/terraform.sh" "${TEST_ROOT}/scripts/terraform.sh"
    printf 'ssh-ed25519 test-key\n' >"${TEST_ROOT}/tests/lab/.local/ssh/id_ed25519.pub"
    export HOME="${TEST_ROOT}/home"
    export PATH="${TEST_ROOT}/bin:${PATH}"
    export FAKE_TERRAFORM_LOG="${TEST_ROOT}/terraform.log"
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
    export FAKE_PLAN_JSON='{"resource_changes":[{"change":{"actions":["create"]}},{"change":{"actions":["create"]}},{"change":{"actions":["create"]}},{"change":{"actions":["create"]}}]}'

    run "${TEST_ROOT}/scripts/terraform.sh" plan

    [ "$status" -eq 0 ]
    [[ "$output" == *"verified plan: 4 creates, 0 updates, 0 deletes"* ]]
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
