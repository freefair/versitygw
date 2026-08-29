# S3 Lifecycle

- [Supported behavior](#supported-behavior)
- [Backend matrix](#backend-matrix)
- [POSIX archive tiers](#posix-archive-tiers)
- [Multi-instance requirements](#multi-instance-requirements)
- [Operations](#operations)

VersityGW implements Amazon S3 Lifecycle configuration CRUD and automatic rule
execution. The gateway evaluates rules at startup and on the interval selected
with `--lifecycle-interval`. `--lifecycle-dry-run` records eligible work without
mutating objects.

## Supported behavior

- Current-object expiration for unversioned, versioning-enabled, and
  versioning-suspended buckets.
- Noncurrent-version expiration and transition.
- `NewerNoncurrentVersions` retention from 1 through the Amazon S3 maximum of
  100, combined with the configured noncurrent-age threshold.
- Expired delete-marker removal.
- Incomplete multipart upload abortion.
- Prefix, tag, object-size, and `And` filters.
- Date and day eligibility aligned with Amazon S3 midnight-UTC behavior.
- Object Lock protection, conditional mutations, startup catch-up, metrics,
  audit records, and background removal events.
- Monotonic S3 transition-waterfall enforcement and lower-cost selection when
  multiple eligible transition rules overlap.

The bucket API is `PUT`, `GET`, and `DELETE /<bucket>?lifecycle`. A configuration
contains at most 1,000 rules. Unsupported transition targets are rejected when
the configuration is written, before destructive background execution begins.

## Backend matrix

| Backend | Configuration | Expiration and retention | Transitions | Coordination |
| --- | --- | --- | --- | --- |
| POSIX | Bucket metadata | Gateway executor | Configured archive roots | Per-bucket `fcntl` record lock |
| ScoutFS | Bucket metadata | Gateway executor | Configured archive root plus native release/stage for `GLACIER` | ScoutFS leader check plus cross-node atomic lock files |
| Azure | Container metadata | Gateway executor | Rejected until an exact S3-to-Azure tier mapping is enabled | Renewable Azure container lease |
| S3Proxy | Native upstream API | Upstream service | Upstream service | Upstream service |

S3Proxy does not run a second local coordinator. Azure accepts expiration,
retention, and multipart cleanup rules but rejects transition rules because it
does not currently advertise transition capabilities.

## POSIX archive tiers

Configure each accepted transition class with a repeatable backend option:

```bash
versitygw --lifecycle-interval 1h posix \
  --versioning-dir /srv/versitygw/versions \
  --lifecycle-archive-tier GLACIER=/archive/glacier \
  --lifecycle-archive-tier DEEP_ARCHIVE=/archive/deep \
  /srv/versitygw/data
```

Each archive root must already exist, be writable, resolve without symlinks,
and not overlap the data, version, sidecar, key, or another archive root.
Placing it on a separate mount moves stored bytes to a separate tier; placing it
on the same filesystem changes representation but not the physical storage
tier.

A generic POSIX transition writes a version-aware manifest and leaves a
zero-length namespace stub.
S3 `HEAD` and listings keep the plaintext size, ETag, checksums, version ID,
encryption result, and storage class.
`GET` returns `InvalidObjectState` until an explicit `RestoreObject` request has
staged the archived bytes; the restore itself publishes data atomically.
Direct POSIX readers must not treat an archive stub as object data; use the S3
interface for archived objects.

ScoutFS `GLACIER` transitions preserve the inode's logical size and release its
hot extents after the recovery copy is durable.
A restore stages the native file.
Archive manifests are reconciled after interrupted transition or restore
operations.

## Multi-instance requirements

Generic POSIX execution requires working process-scoped `fcntl` byte-range
locks on the shared filesystem. A contention self-test runs before the first
lease is used; failure refuses execution instead of falling back to best effort.
This contract is verified by the repository lab on NFSv4.2.

ScoutFS v1.33 does not provide the required cross-node `fcntl` coordination.
Only the node whose matching ScoutFS sysfs state reports `is_leader=1` executes
Lifecycle work. Leadership is checked before acquiring a lease and before every
mutation, including native release callbacks, deletion, multipart abortion,
archive reconciliation, and recovery-manifest updates. Missing, ambiguous, or
lost leadership refuses the mutation.

ScoutFS bucket leases and object mutations use lock files created with
`O_CREAT|O_EXCL`. Their owner record contains hostname, Linux boot ID, PID, and
a random nonce. A lock is recovered automatically only when it belongs to this
host and boot and its PID is demonstrably absent. Remote, malformed, or
boot-ambiguous locks are never stolen by timeout; they remain fail-closed for
operator inspection. Release verifies ownership before atomically renaming and
removing the lock. This mechanism is self-contained and has no Redis or other
external coordination dependency.

## Operations

Start with dry-run enabled and inspect `lifecycle` audit records and metrics.
Removing a Lifecycle configuration prevents future eligibility but does not
reverse completed actions. Back up data roots, version roots, archive roots,
and encryption key rings as one recovery set when encryption is enabled.

The disposable live validation environment is documented in
[the NFS and ScoutFS lab guide](../tests/lab/README.md).
