# NFS and ScoutFS Lifecycle Lab

- [Topology](#topology)
- [Prerequisites](#prerequisites)
- [Run](#run)
- [Safety and teardown](#safety-and-teardown)

This disposable development lab verifies behavior that cannot be represented
faithfully in a single-container CI job: NFSv4.2 record-lock coordination,
ScoutFS cross-node atomic-file contention, and leader-owned Lifecycle execution
with native release/stage. It is not a runtime dependency and is not part of
the normal CI suite.

## Topology

Terraform creates exactly four Rocky Linux VMs with local state:

- one NFS and iSCSI storage VM;
- three NFS clients, ScoutFS mounts, and gateway nodes.

The checked plan is accepted only when it contains four creates, zero updates,
and zero deletes. The wrapper intentionally exposes no destroy command.

## Prerequisites

- Terraform, Ansible, `jq`, Go, Bats, and ShellCheck on the workstation;
- a Rocky Linux 9 cloud-init template in Proxmox;
- an API token in `PROXMOX_TOKEN` using the provider format
  `user@realm!token=secret`;
- the non-secret `TF_VAR_*` values declared in
  [`variables.tf`](terraform/variables.tf).

Keep secrets in the ignored project `.env.local`, the caller environment, or an
explicit ignored env file. Scripts never print the token and never invoke
1Password. Plans, generated inventory, SSH keys, gateway credentials, and
encryption keys remain under the ignored `tests/lab/.local/` directory.
Terraform's ignored local state remains at
`tests/lab/terraform/terraform.tfstate`.

## Run

Generate the project-local SSH key and a create-only Terraform plan:

```bash
scripts/run.sh create
```

Review the Terraform output and saved plan. Apply that exact plan, configure,
and verify only in a second explicit step:

```bash
scripts/run.sh apply
```

Rebuild and redeploy the current source to existing VMs:

```bash
scripts/run.sh configure
```

Query the already running gateways without changing infrastructure:

```bash
scripts/run.sh verify
```

The verification playbook checks mounts and services, measured NFS record-lock
behavior, ScoutFS `O_EXCL` contention across nodes, Lifecycle CRUD, automatic
interval-driven expiration, retention of the newest
noncurrent version, local SSE-S3/KMS/DSSE round trips, range reads, encrypted
copy and multipart upload, physical ciphertext, POSIX archive stubs, and
ScoutFS offline extents with transparent S3 restore.

The cross-node NFS record-lock test runs with both gateway instances active.
The NFS behavior probe then pauses the peer Lifecycle executor in an Ansible
`block` and restores it in `always`. This isolates the probe's deliberate
post-upload `mtime` aging from NFS cross-client attribute writeback; naturally
aged production objects do not undergo that artificial timestamp mutation.
ScoutFS behavior remains exercised with all three gateway instances active.

## Safety and teardown

Review Terraform output and the local plan before applying. The scripts never
modify SSH client configuration and always use the generated project-local key
with `IdentitiesOnly=yes`.

VM removal is intentionally outside the wrapper. It requires explicit approval
and a separately reviewed Terraform destroy plan so unrelated cluster VMs
cannot be removed accidentally.
