# Project Guidance

## Rules

- Preserve Amazon S3 wire behavior while keeping storage mechanisms backend-owned.
- Keep Lifecycle evaluation transport-independent and mutations conditional and backend-atomic.
- Keep encryption keys out of command-line arguments, YAML, logs, metrics, and object metadata.
- Treat generated `.claude/rules/` files as ignored local mirrors; task notes remain tracked.
- Report unrelated upstream defects without mixing them into feature changes.

## Current State

Lifecycle and Encryption are implemented for POSIX, ScoutFS, Azure, and S3Proxy according to each backend's capability boundary. The temporary filesystem lab under `tests/lab/` validates NFS and ScoutFS coordination without becoming a CI dependency.

## Documentation

- [Lifecycle and Encryption inventory](docs/impl/s3-lifecycle-encryption-inventory.md)
- [Lifecycle implementation plan](docs/impl/s3-lifecycle.md)
- [Encryption implementation plan](docs/impl/s3-encryption.md)
- [Lifecycle operation guide](docs/s3-lifecycle.md)
- [Encryption operation guide](docs/s3-encryption.md)
- [NFS and ScoutFS verification lab](tests/lab/README.md)
