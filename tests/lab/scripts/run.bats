#!/usr/bin/env bats

setup() {
    export TEST_ROOT="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${TEST_ROOT}/scripts"
    cp "${BATS_TEST_DIRNAME}/../../../scripts/run.sh" "${TEST_ROOT}/scripts/run.sh"
    export RUN_LOG="${TEST_ROOT}/run.log"

    cat >"${TEST_ROOT}/scripts/terraform.sh" <<'EOF'
#!/usr/bin/env bash
printf 'terraform %s\n' "$*" >>"${RUN_LOG}"
EOF
    cat >"${TEST_ROOT}/scripts/ansible.sh" <<'EOF'
#!/usr/bin/env bash
printf 'ansible %s\n' "$*" >>"${RUN_LOG}"
EOF
    chmod +x "${TEST_ROOT}/scripts/terraform.sh" "${TEST_ROOT}/scripts/ansible.sh"
}

@test "create stops after producing a plan" {
    run "${TEST_ROOT}/scripts/run.sh" create

    [ "$status" -eq 0 ]
    [ "$(<"${RUN_LOG}")" = "terraform plan" ]
    [[ "$output" == *"review it"* ]]
}

@test "apply uses the reviewed plan before configuration and verification" {
    run "${TEST_ROOT}/scripts/run.sh" apply

    [ "$status" -eq 0 ]
    [ "$(<"${RUN_LOG}")" = $'terraform apply\nansible configure\nansible verify' ]
}
