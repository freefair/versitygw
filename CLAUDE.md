# Project Guidance

## Rules

- Preserve Amazon S3 wire behavior while keeping storage mechanisms backend-owned.
- Keep Lifecycle evaluation transport-independent and mutations conditional and backend-atomic.
- Keep encryption keys out of command-line arguments, YAML, logs, metrics, and object metadata.
- Keep the entire `.claude/` directory (rules mirrors, task notes) untracked and gitignored.
- Report unrelated upstream defects without mixing them into feature changes.

## Current State

Lifecycle and Encryption have repository inventories and approved implementation plans. The temporary filesystem lab under `tests/lab/` validates NFS and ScoutFS coordination without becoming a CI dependency.

## Documentation

- [Lifecycle and Encryption inventory](docs/impl/s3-lifecycle-encryption-inventory.md)
- [Lifecycle implementation plan](docs/impl/s3-lifecycle.md)
- [Encryption implementation plan](docs/impl/s3-encryption.md)
