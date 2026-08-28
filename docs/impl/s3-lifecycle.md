# Amazon S3-Compatible Lifecycle Implementation Plan

## Table of Contents

- [Goal](#goal)
- [Compatibility Scope](#compatibility-scope)
- [Required Behavior](#required-behavior)
- [Options Considered](#options-considered)
- [Architecture](#architecture)
- [Lifecycle Configuration Model](#lifecycle-configuration-model)
- [Validation Rules](#validation-rules)
- [Execution Model](#execution-model)
- [Version Retention and Expiration](#version-retention-and-expiration)
- [POSIX Archive Tiers](#posix-archive-tiers)
- [Backend Strategies](#backend-strategies)
- [Multi-Instance Coordination](#multi-instance-coordination)
- [Observability and Events](#observability-and-events)
- [Implementation Sequence](#implementation-sequence)
- [Planned File Map](#planned-file-map)
- [Test Plan](#test-plan)
- [Rollout and Migration](#rollout-and-migration)
- [Acceptance Criteria](#acceptance-criteria)
- [Risks and Explicit Trade-Offs](#risks-and-explicit-trade-offs)
- [Sources](#sources)

## Goal

Implement the Amazon S3 Lifecycle API and execute enabled rules against existing and future objects.

The implementation is complete only when configuration CRUD, rule validation, eligibility evaluation, expiration, version retention, multipart cleanup, supported transitions, restart recovery, and multi-instance safety work together.

Persisting XML without executing it is not a Lifecycle implementation.

## Compatibility Scope

The target is Amazon S3 general purpose buckets.

The following public operations are required:

- `PutBucketLifecycleConfiguration`.
- `GetBucketLifecycleConfiguration`.
- `DeleteBucketLifecycle`.

The following actions are required:

- `Expiration` by age or date.
- `ExpiredObjectDeleteMarker` cleanup.
- `NoncurrentVersionExpiration` with `NoncurrentDays` and optional `NewerNoncurrentVersions`.
- `AbortIncompleteMultipartUpload`.
- `Transition` for current versions when the backend supports the target class.
- `NoncurrentVersionTransition` when the backend supports the target class.

S3 Express directory buckets, replication-aware suppression, S3 billing changes, S3 Batch Operations, and AWS account-level analytics are outside the scope.

The absence of replication support must be documented because Amazon S3 suppresses Lifecycle actions for versions with pending or failed replication status.

## Required Behavior

| Bucket state | Action | Required result |
| --- | --- | --- |
| Never versioned | Current expiration | Permanently delete the object |
| Versioning enabled | Current expiration | Create a new delete marker and make the prior version noncurrent |
| Versioning suspended | Current expiration | Create or replace the null-version delete marker according to S3 semantics |
| Versioning enabled or suspended | Noncurrent expiration | Permanently delete only eligible noncurrent versions |
| Any state | Expired delete marker | Remove a current delete marker only when no noncurrent versions remain |
| Any state | Multipart abort | Abort eligible incomplete uploads without affecting completed objects |
| Supported backend | Transition | Move the selected version to the requested storage class without changing its version ID |

Existing objects are evaluated immediately after a rule becomes active.

Rule execution is asynchronous and restart-safe.

Eligibility uses UTC and rounds age-based dates up to the next midnight UTC, matching Amazon S3.

An object or version receives at most one effective Lifecycle action per evaluation day.

Permanent deletion takes precedence over transition.

Transition takes precedence over creation of a delete marker.

## Options Considered

| Decision | Option | Advantages | Costs | Result |
| --- | --- | --- | --- | --- |
| Rule execution | One generic gateway executor | One implementation of AWS rule semantics | Cannot make atomic storage decisions or native transitions for every backend | Rejected |
| Rule execution | Backend-owned executor | Maximum backend freedom | Duplicates evaluation and scheduling logic | Rejected |
| Rule execution | Shared evaluator and coordinator with backend mutation capabilities | One S3 rule engine with backend-atomic execution | Requires focused backend interfaces | Chosen |
| POSIX archive representation | Rename versions through a filename convention | Simple initial layout | Exposes internal state in bucket paths and couples version identity to filenames | Rejected |
| POSIX archive representation | Metadata-only shadow files | Keeps visible names stable | Does not move payload bytes to another tier | Rejected as the sole mechanism |
| POSIX archive representation | Hidden manifest/stub plus configured tier roots | Preserves S3 version IDs and supports separate mounts | Direct POSIX reads no longer work for offline objects | Chosen for generic POSIX |
| POSIX archive representation | Filesystem-native HSM | Transparent POSIX namespace and real offline state | Available only on supporting filesystems | Chosen when a backend such as ScoutFS exposes it |

The chosen split keeps AWS rule semantics in one testable package while leaving data placement and atomic mutation with the backend that owns the storage.

## Architecture

The feature is divided into a transport-independent rule package, backend capabilities, and a long-running coordinator.

```text
PUT/GET/DELETE ?lifecycle
  -> controller parses and validates AWS XML
  -> LifecycleConfigurationStore persists canonical configuration

LifecycleCoordinator
  -> acquires per-bucket backend lease
  -> loads canonical configuration
  -> asks backend for stable candidate snapshots
  -> LifecycleEvaluator selects one effective action per version
  -> backend conditionally applies the action
  -> metrics, audit record, and optional event are emitted
```

The proposed feature package is `internal/lifecycle`.

It contains domain types, XML conversion, validation, rule matching, conflict resolution, scheduling, and a clock interface.

The package must not depend on Fiber, filesystem APIs, Azure SDK types, or AWS service clients.

The S3 controller remains responsible for transport behavior and authorization.

The backend remains responsible for atomic persistence, candidate enumeration, leases, and physical transitions.

### Capability Interfaces

The implementation should introduce focused interfaces instead of adding unrelated methods directly to every operation group.

```go
type LifecycleConfigurationStore interface {
    PutLifecycleConfiguration(context.Context, string, lifecycle.Configuration) error
    GetLifecycleConfiguration(context.Context, string) (lifecycle.Configuration, error)
    DeleteLifecycleConfiguration(context.Context, string) error
}

type LifecycleExecutorBackend interface {
    LifecycleConfigurationStore
    AcquireLifecycleLease(context.Context, string, string) (LifecycleLease, error)
    ListLifecycleCandidates(context.Context, LifecycleCursor) (LifecyclePage, error)
    ApplyLifecycleAction(context.Context, LifecycleAction) error
    LifecycleCapabilities() LifecycleCapabilities
}
```

`LifecycleAction` includes bucket, key, version ID, observed state token, action type, target storage class, and rule ID.

The observed state token prevents deleting or transitioning an object that changed after evaluation.

Backends that delegate Lifecycle execution expose `LifecycleConfigurationStore` but do not start the gateway coordinator.

Backends that cannot provide a required capability reject the configuration at PUT time with an S3-compatible error.

## Lifecycle Configuration Model

Canonical configuration stores semantic values rather than raw XML only.

The canonical model contains:

- Up to 1,000 rules.
- A unique optional rule ID of at most 255 characters.
- Enabled or disabled status.
- Legacy prefix or current filter representation.
- Prefix, tag, object-size, and logical-AND predicates.
- Current expiration and transition actions.
- Noncurrent expiration and transition actions.
- Incomplete multipart upload expiry.
- The `x-amz-transition-default-minimum-object-size` setting.

The original XML namespace and element ordering are transport details and are not part of rule identity.

GET serializes canonical state into AWS-compatible XML.

PUT replaces the complete prior configuration atomically.

DELETE removes the configuration atomically and is idempotent.

GET without a stored configuration returns `NoSuchLifecycleConfiguration` with HTTP 404.

## Validation Rules

Validation happens before persistence and before backend capability checks.

The validator must cover at least the following rules:

- The configuration contains between 1 and 1,000 rules.
- Rule IDs are unique and no longer than 255 characters.
- Status is exactly `Enabled` or `Disabled`.
- Every rule contains at least one action.
- A filter contains exactly one top-level predicate unless it uses `And`.
- Tag keys within an `And` filter are unique.
- `ObjectSizeGreaterThan` is strictly less than `ObjectSizeLessThan` when both exist.
- Size bounds are exclusive.
- `Expiration.Days`, `NoncurrentDays`, and multipart days satisfy the AWS positive-value constraints.
- Transition days allow zero where Amazon S3 allows zero.
- Date actions use midnight UTC ISO 8601 values.
- `ExpiredObjectDeleteMarker` is not combined with expiration days or date.
- Tag filters are rejected for `AbortIncompleteMultipartUpload` and `ExpiredObjectDeleteMarker` rules.
- `NewerNoncurrentVersions` is between 1 and 100.
- `NewerNoncurrentVersions` requires `NoncurrentDays` and a `Filter` element.
- Transition storage classes are valid Amazon S3 transition targets.
- The active backend can perform every enabled transition requested by the configuration.

Malformed XML returns `MalformedXML`.

Semantically invalid combinations return the same error class Amazon S3 uses for that combination, normally `InvalidRequest` or `InvalidArgument`.

The controller must use the existing request-checksum middleware for `Content-MD5` and SDK checksum headers.

## Execution Model

### Scheduling

The coordinator starts after the backend and event/metrics services are ready.

It performs a catch-up evaluation at startup and then evaluates on a configurable interval.

The initial recommended interval is one hour, while all eligibility timestamps remain aligned to midnight UTC.

Tests use an injected clock and never wait for wall-clock time.

Shutdown cancels scans, stops accepting new work, waits for in-flight atomic actions, releases leases, and then returns from backend shutdown.

### Candidate Enumeration

Candidate enumeration is paginated and bounded.

The backend returns current objects, noncurrent versions, delete markers, and incomplete multipart uploads through stable cursors.

Each candidate exposes key, version ID, current/noncurrent state, size, last-modified time, successor time, tags on demand, storage class, delete-marker state, and Object Lock state.

Prefix and size filters are applied before tag reads to avoid unnecessary metadata operations.

Disabled rules are never evaluated.

### Conditional Mutation

Evaluation and mutation are separated so rule logic can be tested without storage.

Every mutation includes the candidate state token observed during enumeration.

If the object, version graph, retention state, or upload changed, the backend returns a precondition conflict and the coordinator defers the candidate to the next pass.

Lifecycle actions are idempotent.

Repeated expiration of an already removed version, repeated multipart abort, and repeated transition to the current storage class complete without corrupting state.

### Object Lock

Lifecycle never bypasses Object Lock.

Governance or compliance retention and legal holds prevent permanent deletion of the protected version.

Current-version expiration may create a delete marker without deleting the retained version, matching normal versioned-bucket behavior.

Blocked actions are recorded as skipped rather than repeatedly logged as failures.

## Version Retention and Expiration

`NewerNoncurrentVersions` is a per-rule Amazon S3 value, not a global server setting.

The accepted range is fixed at 1 through 100.

The implementation must not introduce a value above 100 because that would create a non-S3 XML contract.

For each key, the evaluator orders noncurrent versions from newest to oldest.

The current version is not included in the retained count.

Delete markers are evaluated through delete-marker rules and do not count as retained data versions.

A noncurrent version is eligible for expiration only when both conditions hold:

1. More than `NewerNoncurrentVersions` newer noncurrent data versions exist.
2. Its noncurrent age exceeds `NoncurrentDays`.

Noncurrent age starts when the successor version is created, not at the older version's original creation time.

For example, with a current `v7`, noncurrent `v6` through `v1`, retention count three, and age 30 days, `v6`, `v5`, and `v4` remain protected by count.

Versions `v3` through `v1` are deleted only after each also exceeds the 30-day noncurrent age.

The implementation must test overwrites, explicit version deletion, current delete markers, suspended versioning, null versions, and Object Lock combinations.

## POSIX Archive Tiers

### Configuration

POSIX exposes an optional mapping from supported S3 storage classes to archive roots.

Non-secret configuration may use a YAML profile or CLI/environment selection consistent with the existing gateway configuration model.

Example conceptual mapping:

```yaml
lifecycle:
  tiers:
    STANDARD_IA:
      root: /srv/versitygw/warm
    GLACIER:
      root: /srv/versitygw/archive
    DEEP_ARCHIVE:
      root: /srv/versitygw/deep-archive
```

A root on the same filesystem provides protocol emulation but not physical tiering.

A root on a distinct mount provides actual data movement to another tier.

The configuration and user documentation must state which case applies.

### Layout

Archive payloads live outside visible bucket namespaces.

The logical layout is:

```text
<tier-root>/<escaped-bucket>/<escaped-key>/<version-id>/data
<tier-root>/<escaped-bucket>/<escaped-key>/<version-id>/manifest
```

Escaping must be collision-free and must prevent path traversal.

The manifest records format version, source identity, storage class, plaintext size, ETag, checksums, transition time, archive location, encryption metadata reference, and restore state.

The existing S3 version ID remains authoritative.

### Transition Protocol

The backend acquires an object-version mutation lock before transition.

For a same-filesystem target, it uses an atomic rename after writing the manifest.

For a cross-filesystem target, it copies into a temporary destination, flushes data and directory metadata, verifies size and checksum, atomically renames the destination, atomically publishes the source stub metadata, and only then removes the hot payload.

A crash before source removal leaves a recoverable duplicate, never a missing object.

A reconciliation pass removes verified temporary duplicates and repairs incomplete manifests.

The source path becomes a backend-recognized stub so xattr metadata remains addressable.

GET on an offline version returns `InvalidObjectState`.

HEAD and listing return the transitioned storage class and restore status.

Restore stages a temporary hot copy and keeps the archive copy until the restore expiry is processed.

Hardlinks and reflinks are not archive mechanisms because they do not independently create a lower storage tier or reliable offline state.

### Direct POSIX Access

Archive stubs are not transparent plaintext files.

Transparent direct POSIX access and S3 offline/restore semantics can coexist only when the filesystem supplies an HSM capability.

ScoutFS uses its native release/stage behavior for that case and does not use generic stub files for `GLACIER`.

## Backend Strategies

| Backend | Configuration ownership | Execution ownership | Transition strategy |
| --- | --- | --- | --- |
| POSIX | Bucket metadata | Gateway coordinator | Configured tier roots and stubs |
| ScoutFS | Bucket metadata | Gateway coordinator | Native release/stage for `GLACIER`, configured roots for any additional class |
| Azure | Container metadata | Gateway coordinator initially | Azure tier operation only after exact semantics are validated; otherwise reject unsupported transitions |
| S3Proxy | Native upstream API | Upstream S3 service | Native upstream Lifecycle transitions |

S3Proxy must not run the gateway coordinator when it successfully delegates configuration to the upstream service.

If an upstream S3-compatible service rejects part of the configuration, VersityGW returns the translated upstream error and does not retain a divergent local copy.

Azure must not claim an S3 storage class merely by changing metadata.

An unsupported transition is rejected when the configuration is written, not discovered days later by the executor.

## Multi-Instance Coordination

Only one gateway instance may evaluate a bucket at a time.

The coordinator assigns each process a random instance ID and obtains a per-bucket backend lease.

POSIX and ScoutFS use a lock file on the shared backend filesystem and document the filesystem locking requirement.

Azure uses Blob leases.

S3Proxy delegates execution and therefore does not need a gateway Lifecycle lease.

Lease loss cancels new mutations immediately.

Every mutation remains conditionally idempotent so a process crash between action completion and progress recording is safe.

Progress cursors are optimization state only.

A complete rescan can reconstruct all required work after progress loss.

## Observability and Events

Add structured metrics for scan duration, candidates evaluated, actions applied, actions skipped, conflicts, failures, lease contention, bytes transitioned, versions expired, and multipart uploads aborted.

Metrics are labeled by backend, action, storage class, and outcome, but never by bucket or key to avoid unbounded cardinality.

Logs include bucket, rule ID, action, and a safely encoded object identifier at debug level.

Logs never include tags, user metadata, encryption context, or key material.

Lifecycle actions need an event-sender path that is independent of Fiber request contexts.

Expiration emits the corresponding S3 object-removal event with a service identity rather than a requester identity.

The audit record distinguishes user-initiated deletion from Lifecycle deletion.

## Implementation Sequence

### Phase 1: Contract Tests and Domain Model

1. Create failing protocol tests in a temporary test harness for AWS XML round trips, invalid configurations, errors, and response headers.
2. Add `internal/lifecycle/types.go`, `xml.go`, and `validate.go` with unit tests.
3. Add missing errors to `s3err/s3err.go` with error serialization tests.
4. Verify the model against the pinned AWS SDK types without using SDK types inside the evaluator.

### Phase 2: Configuration API

1. Add Lifecycle capability interfaces and unsupported defaults under `backend/`.
2. Add `s3api/controllers/bucket-lifecycle.go` and controller tests.
3. Replace the three router stubs in `s3api/router.go` with the new handlers and checksum middleware.
4. Implement configuration persistence in POSIX, ScoutFS, Azure, and S3Proxy.
5. Extend generated backend mocks and update controller test fixtures.
6. Replace the three `NotImplemented` integration tests with real CRUD and validation tests.

### Phase 3: Pure Evaluator

1. Add filter matching, UTC eligibility calculations, noncurrent ordering, and conflict precedence under `internal/lifecycle`.
2. Add table-driven tests for every versioning state and action combination.
3. Add an injected clock and deterministic candidate identifiers.
4. Prove through mutation tests that count retention cannot delete any of the protected newest versions.

### Phase 4: POSIX Candidate and Mutation Primitives

1. Add stable current/version/delete-marker/multipart candidate enumeration to `backend/posix`.
2. Add conditional expiration and multipart-abort operations.
3. Reuse backend Object Lock checks for permanent deletion.
4. Add per-bucket lease files and shutdown cancellation.
5. Add unit tests using temporary POSIX and sidecar metadata roots.

### Phase 5: Coordinator

1. Add `internal/lifecycle/coordinator.go` with bounded concurrency and paginated scans.
2. Wire the coordinator through `embedgw` and gateway startup/shutdown.
3. Add metrics and audit callbacks.
4. Test startup catch-up, cancellation, lease contention, crash replay, and state conflicts.

### Phase 6: POSIX and ScoutFS Transitions

1. Add archive configuration to the shared POSIX/ScoutFS CLI option path.
2. Implement the versioned archive manifest and stub format.
3. Implement same-filesystem and cross-filesystem transition protocols.
4. Integrate ScoutFS native release/stage for `GLACIER`.
5. Add restore-expiry processing and reconciliation of interrupted transitions.

### Phase 7: Azure and S3Proxy

1. Forward Lifecycle CRUD natively in S3Proxy and disable local execution for that backend.
2. Implement Azure candidate enumeration, leases, expiration, and multipart cleanup.
3. Validate each proposed Azure access-tier mapping against Azure behavior before enabling its S3 transition class.
4. Reject any transition whose semantics cannot be preserved.

### Phase 8: Documentation and Compatibility Matrix

1. Update the README and user documentation with supported actions per backend.
2. Document archive roots, restore behavior, direct POSIX consequences, scan configuration, and failure recovery.
3. Add upgrade guidance and operational verification commands.

## Planned File Map

The exact split may be refined during the failing-test prototype, but these ownership boundaries are part of the plan.

| Area | Planned files or directories | Change |
| --- | --- | --- |
| Domain | `internal/lifecycle/types.go`, `xml.go`, `validate.go`, `evaluate.go` | Canonical model, AWS XML conversion, validation, and pure evaluation |
| Coordinator | `internal/lifecycle/coordinator.go`, `clock.go`, `metrics.go` | Scheduling, leases, pagination, conflict handling, and instrumentation |
| Backend contract | `backend/lifecycle.go`, `backend/backend.go` | Focused configuration/execution capabilities and unsupported defaults |
| S3 transport | `s3api/controllers/bucket-lifecycle.go`, `s3api/router.go` | CRUD handlers, checksums, authorization, and responses |
| Errors | `s3err/s3err.go` and tests | Missing Lifecycle error codes and XML serialization |
| POSIX | `backend/posix/` | Configuration storage, candidate enumeration, leases, conditional actions, archive manifests, and reconciliation |
| ScoutFS | `backend/scoutfs/` | Native release/stage transition integration |
| Azure | `backend/azure/` | Configuration metadata, leases, expiration, and validated tier mappings |
| S3Proxy | `backend/s3proxy/` | Native Lifecycle API delegation and executor suppression |
| Startup | `embedgw/` and command option packages | Coordinator lifecycle and non-secret tier-root configuration |
| Tests | `internal/lifecycle/*_test.go`, backend tests, `s3api/controllers/*_test.go`, `tests/integration/` | Unit, fault, concurrency, backend, and protocol coverage |
| Documentation | `README.md`, `docs/` | Compatibility matrix, operation, recovery, and migration guidance |

## Test Plan

### Unit Tests

- XML decode and encode with namespaces and all supported elements.
- Every validation constraint and exact S3 error.
- Prefix, tag, size, and `And` filters.
- Midnight UTC rounding and injected-time boundaries.
- Current expiration for every versioning state.
- `NewerNoncurrentVersions` values 1, 100, 0, and 101.
- Combined age and count eligibility.
- Successor-based noncurrent age.
- Delete-marker cleanup.
- Rule conflict precedence.
- Object Lock skip behavior.
- Backend capability rejection.
- Lease acquisition, loss, and cancellation.
- Archive transition failure at every atomic step.

### Integration Tests

- Lifecycle CRUD through the AWS SDK.
- Existing-object catch-up after configuration PUT.
- Automatic permanent deletion in an unversioned bucket.
- Delete-marker creation in versioning-enabled and suspended buckets.
- Retain the newest noncurrent versions and delete only older eligible versions.
- Locked versions survive while unlocked eligible versions are removed.
- Incomplete multipart uploads are aborted after eligibility.
- Transition, `InvalidObjectState`, restore, and restore expiry.
- Restart during a scan and restart during transition.
- Two gateway instances contend for the same bucket without duplicate action.
- S3Proxy delegates without running a second executor.

### Differential Tests

Run the same configuration and object timeline against Amazon S3 and VersityGW where AWS credentials are explicitly supplied for an integration environment.

Normalize only asynchronous execution time and provider-specific request IDs.

Compare configuration XML, error codes, version graphs, delete markers, storage-class headers, and expiration headers.

### Final Verification

Run focused package tests first, then `make test`, static analysis available in the project toolchain, integration suites for each backend, and the repository code-review workflow.

## Rollout and Migration

Lifecycle configuration is absent by default, so enabling the code does not mutate existing buckets until a rule is stored.

The coordinator must support a dry-run mode during rollout that records eligible actions without mutating data.

Dry-run is an operator feature and does not alter the S3 API contract.

Before enabling execution, validate that archive roots are distinct from bucket roots, writable, persistent, and included in backup policy.

The first active scan may process a large backlog because Lifecycle applies to existing objects.

Rate and concurrency limits must protect foreground S3 traffic.

Deleting a Lifecycle configuration stops future eligibility but does not roll back completed actions.

## Acceptance Criteria

- All three bucket Lifecycle APIs match Amazon S3 general-purpose-bucket request, response, and error behavior.
- Configuration replacement is atomic and supports up to 1,000 rules.
- Unversioned expiration permanently deletes eligible objects.
- Versioned expiration creates the correct delete marker.
- Noncurrent expiration retains exactly the configured 1–100 newest noncurrent versions and also applies the configured age threshold.
- Object Lock prevents permanent Lifecycle deletion.
- Expired delete markers and incomplete multipart uploads are cleaned correctly.
- Supported transitions move data without changing key, version ID, ETag, checksum, or plaintext size.
- Unsupported transitions are rejected at configuration time.
- Restart and multi-instance execution cannot lose or duplicate destructive actions.
- Existing objects become eligible after a configuration is added.
- Metrics and audit records distinguish every action and outcome without exposing object data.
- The full test suite and backend integration matrix pass.

## Risks and Explicit Trade-Offs

Generic POSIX archive stubs break transparent direct reads for transitioned objects.

Using an archive root on the same filesystem provides S3 state emulation but no storage-cost or capacity benefit.

Lifecycle scans are proportional to object and version count unless a future backend supplies an indexed candidate feed.

Tag filters may require one metadata read per prefix/size-matched candidate.

Multi-instance correctness depends on backend lock semantics and must be verified on every supported shared filesystem.

Transition and Encryption must compose without decrypting and re-encrypting merely to move an archived POSIX payload.

## Sources

- [Amazon S3 Lifecycle configuration elements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html)
- [Amazon S3 object expiration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html)
- [Amazon S3 PutBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html)
- [Amazon S3 GetBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html)
- [Amazon S3 DeleteBucketLifecycle](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html)
