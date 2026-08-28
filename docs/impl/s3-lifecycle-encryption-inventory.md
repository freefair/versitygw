# S3 Lifecycle and Encryption Repository Inventory

## Table of Contents

- [Purpose and Scope](#purpose-and-scope)
- [Executive Summary](#executive-summary)
- [Request Architecture](#request-architecture)
- [Repository Map](#repository-map)
- [Lifecycle Inventory](#lifecycle-inventory)
- [Encryption Inventory](#encryption-inventory)
- [Backend Capability Matrix](#backend-capability-matrix)
- [Persistence and Versioning](#persistence-and-versioning)
- [Testing Inventory](#testing-inventory)
- [Cross-Cutting Constraints](#cross-cutting-constraints)
- [Accepted Planning Decisions](#accepted-planning-decisions)
- [Sources](#sources)

## Purpose and Scope

This document records the repository state that the Lifecycle and Encryption implementation plans build upon.

The compatibility target is the Amazon S3 contract for general purpose buckets.

S3 Express directory buckets are outside the scope because VersityGW does not currently implement the directory-bucket endpoint, naming, session, or authorization model.

The corresponding implementation plans are [S3 Lifecycle](./s3-lifecycle.md) and [S3 Encryption](./s3-encryption.md).

## Executive Summary

Lifecycle and bucket Encryption already have routes, IAM actions, authorization middleware, and metrics names.

All six bucket operations currently terminate in a shared `NotImplemented` handler.

The central `backend.Backend` interface has no Lifecycle or bucket Encryption methods.

The local S3 request path does not parse or enforce object encryption headers, even though the AWS SDK input and response types used by the repository already contain most required fields.

No Lifecycle scheduler, distributed lease, rule evaluator, transition abstraction, or execution state exists.

POSIX has the strongest existing building blocks for both features: durable bucket/object metadata, object version storage, object-lock enforcement, multipart metadata, and bounded filesystem concurrency.

ScoutFS extends POSIX and already exposes an offline/restore model that can implement a real `GLACIER` transition.

S3Proxy can delegate both features to an upstream S3 service, while Azure requires explicit translation or a gateway-owned implementation.

## Request Architecture

The current S3 request flow is:

```text
Fiber route
  -> authentication and authorization middleware
  -> S3ApiController
  -> backend.Backend
  -> POSIX, ScoutFS, Azure, S3Proxy, or plugin implementation
  -> controllers.ProcessHandlers serializes the S3 response
```

Controllers own HTTP concerns, AWS XML parsing, response headers, and IAM checks.

Backends own persistence and data operations.

Several AWS SDK types cross the controller/backend boundary directly, while repository-specific operations use types from `s3response`.

Each shipped backend embeds `backend.BackendUnsupported`, which supplies `NotImplemented` defaults for methods the backend does not override.

This pattern allows new optional feature interfaces to remain explicit without forcing silent fallback behavior.

## Repository Map

| Area | Current responsibility | Relevance |
| --- | --- | --- |
| `s3api/router.go` | S3 operation dispatch and middleware chains | Lifecycle and Encryption routes already exist as stubs |
| `s3api/controllers/` | Request parsing, access checks, response construction | Missing Lifecycle and bucket Encryption handlers and object SSE parsing |
| `s3api/utils/` | Shared S3 validation and parsing | Natural location for transport-level SSE and Lifecycle helpers |
| `backend/backend.go` | Main storage contract and unsupported defaults | Missing Lifecycle and Encryption capabilities |
| `backend/posix/` | POSIX objects, versions, multipart uploads, metadata, Object Lock | Needs Lifecycle execution, archive storage, and local encryption |
| `backend/scoutfs/` | POSIX extension with offline file handling | Can map real offline extents to `GLACIER` |
| `backend/azure/` | Azure Blob adapter | Needs an explicit Lifecycle and Encryption strategy |
| `backend/s3proxy/` | Upstream S3 adapter plus gateway metadata bucket | Can forward native S3 Lifecycle and Encryption requests |
| `backend/meta/` | xattr, sidecar, and no-metadata stores | Can persist bucket configuration and encrypted-object manifests |
| `auth/` | IAM actions, bucket policies, Object Lock checks | Encryption condition keys are currently omitted |
| `s3response/` | Repository-specific S3 input/output structures | Already contains multiple SSE fields but local controllers do not populate them |
| `s3event/` | Global object event delivery | Needs Lifecycle-originated event support without a Fiber request context |
| `metrics/` | Per-operation metrics catalogue | Bucket Lifecycle and Encryption metric names already exist |
| `tests/integration/` | AWS SDK integration tests | Currently asserts `NotImplemented` for both features |
| `tests/` | REST, AWS CLI, s3cmd, and multi-backend suites | Needs new feature-specific suites and backend matrix coverage |

## Lifecycle Inventory

### Public API

| Operation | Route | IAM action | Current result |
| --- | --- | --- | --- |
| `PutBucketLifecycleConfiguration` | `PUT /?lifecycle` | `s3:PutLifecycleConfiguration` | `NotImplemented` |
| `GetBucketLifecycleConfiguration` | `GET /?lifecycle` | `s3:GetLifecycleConfiguration` | `NotImplemented` |
| `DeleteBucketLifecycle` | `DELETE /?lifecycle` | `s3:PutLifecycleConfiguration` | `NotImplemented` |

The router already applies bucket-name validation, SigV4 verification, public-bucket authorization, and ACL parsing.

The routes do not yet attach the complete checksum validation required by configuration PUT requests.

No controller parses, validates, stores, retrieves, or deletes Lifecycle XML.

No `NoSuchLifecycleConfiguration` error exists in the repository error catalogue.

### Execution

There is no process that evaluates stored rules against existing or newly written objects.

There is no restart catch-up, injected clock, daily eligibility calculation, per-bucket lease, or idempotency record.

There is no central representation of an object version becoming noncurrent.

POSIX can infer that time from the creation time of the successor version, which matches the Amazon S3 definition.

Object deletion and version deletion already enforce Object Lock inside the backend and can be reused through a Lifecycle-specific conditional operation.

### Storage Classes

POSIX reports `STANDARD` for ordinary objects and versions.

It does not persist a storage class or implement a transition.

ScoutFS can report `GLACIER` for offline files and implements `RestoreObject` by staging offline data.

S3Proxy already forwards storage-class fields for ordinary upstream object operations.

Azure currently reports `STANDARD` and does not expose Azure access-tier state as an S3 storage class.

### Existing Test Defect

`PutBucketLifecycleConfiguration_not_implemented` calls `PutBucketAnalyticsConfiguration` instead of the Lifecycle API.

This is a test defect within the feature scope and must be corrected when the stub tests are replaced.

## Encryption Inventory

### Bucket API

| Operation | Route | IAM action | Current result |
| --- | --- | --- | --- |
| `PutBucketEncryption` | `PUT /?encryption` | `s3:PutEncryptionConfiguration` | `NotImplemented` |
| `GetBucketEncryption` | `GET /?encryption` | `s3:GetEncryptionConfiguration` | `NotImplemented` |
| `DeleteBucketEncryption` | `DELETE /?encryption` | `s3:PutEncryptionConfiguration` | `NotImplemented` |

No backend stores the default encryption configuration.

Bucket creation does not establish an SSE-S3 default.

Bucket deletion does not clean up an encryption configuration because no such configuration exists yet.

### Object Write Path

`s3response.PutObjectInput`, `CreateMultipartUploadInput`, and `CopyObjectInput` contain SSE-related fields.

`PutObject`, `POSTObject`, `CopyObject`, and `CreateMultipartUpload` do not populate those fields from request headers or form fields.

`UploadPart` and `UploadPartCopy` do not forward SSE-C headers.

The S3Proxy implementation already maps many SSE fields to the upstream AWS SDK, but the local controller path does not supply them.

### Object Read Path

The AWS SDK `GetObjectInput` and `HeadObjectInput` support SSE-C request fields.

The controllers do not parse those headers.

The backend outputs and `s3response` models contain encryption response fields, but GET, HEAD, PUT, POST, Copy, and multipart responses do not emit the corresponding S3 headers.

### Security and Policy Handling

The debug logger already redacts SSE-C customer key headers and has tests for both destination and copy-source keys.

Bucket-policy validation explicitly omits `s3:x-amz-server-side-encryption` because the runtime does not currently read the header.

There is no key-provider interface, local key ring, AWS KMS client, encrypted-object format, or key-rotation procedure.

There is no validation that rejects SSE-C over an insecure transport.

## Backend Capability Matrix

| Capability | POSIX | ScoutFS | Azure | S3Proxy |
| --- | --- | --- | --- | --- |
| Bucket metadata | xattr or sidecar | POSIX metadata | Container metadata | Native API or meta-bucket object |
| Object versions | Gateway version directory | Gateway version directory | Incomplete S3 version semantics | Native upstream versions |
| Object Lock | Implemented | Inherited from POSIX | Implemented through metadata | Native or gateway-limited |
| Lifecycle configuration | Missing | Missing | Missing | Not forwarded |
| Lifecycle executor | Missing | Missing | Missing | Upstream can own execution |
| Physical archive transition | Missing | Offline extents support `GLACIER` | Azure access tiers exist but are not mapped | Native upstream storage classes |
| Default bucket encryption | Missing | Missing | Missing | Not forwarded through bucket API |
| SSE-S3 | Missing | Missing | Missing | Upstream fields partly wired |
| SSE-C | Redaction only | Redaction only | Missing | Upstream fields partly wired |
| SSE-KMS and DSSE-KMS | Missing | Missing | Missing | Upstream fields partly wired |

## Persistence and Versioning

POSIX stores bucket configuration as metadata attributes on the bucket directory.

The metadata abstraction supports atomic replacement through temporary files in sidecar mode and native xattr replacement in xattr mode.

The `NoMeta` implementation intentionally discards metadata and cannot safely support either feature.

An encryption-capable or Lifecycle-capable local backend must reject `NoMeta` at startup rather than claim support.

POSIX stores noncurrent versions under a separate configured versioning directory.

Lifecycle must operate on that existing version graph instead of creating a second naming scheme for S3 versions.

Archive-tier payloads may use a separate hidden storage layout, but their manifests must continue to reference the original S3 version IDs.

## Testing Inventory

The repository contains Go unit tests, AWS SDK integration tests, direct REST tests, BATS suites, and multi-backend test modes.

`make test` runs `go test ./...`.

The controller mock is generated from the complete `backend.Backend` interface and will need regeneration or replacement when the contract changes.

The integration group catalogue currently registers three Encryption and three Lifecycle `NotImplemented` tests.

No golden AWS response fixtures, clock-driven Lifecycle tests, crash-recovery tests, encrypted range tests, or key-rotation tests exist.

## Cross-Cutting Constraints

Lifecycle operations execute as the storage service and must not be blocked by bucket-policy denies, matching Amazon S3 behavior.

Lifecycle must still obey Object Lock and must condition every mutation on the version and state that were evaluated.

Backend plugins are compiled Go plugins, so changing the backend contract requires rebuilding plugins even when source compatibility is retained through an unsupported default.

Application-level POSIX encryption makes encrypted object files opaque to direct filesystem readers.

POSIX archive stubs likewise cannot provide both S3 `InvalidObjectState` behavior and transparent direct file reads without filesystem-level HSM support.

The feature documentation and rollout must state these consequences before either capability is enabled.

## Accepted Planning Decisions

- General purpose buckets define the compatibility scope.
- Lifecycle includes configuration CRUD and actual asynchronous execution.
- Automatic expiration is required for unversioned, versioning-enabled, and versioning-suspended buckets.
- `NewerNoncurrentVersions` is configurable per rule from 1 through 100, with the Amazon S3 maximum fixed at 100.
- POSIX archive tiers use configurable roots and a stub plus archive manifest when no native HSM capability exists.
- Encryption storage is backend-owned through explicit capabilities.
- S3Proxy uses native upstream encryption where available.
- POSIX uses local envelope encryption and can additionally use AWS KMS.
- The cloud-independent provider uses operator-supplied local key material and no external key-management service.
- Secret key material is never placed in YAML, command-line arguments, logs, or object metadata.

## Sources

- [Amazon S3 Lifecycle configuration elements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html)
- [Amazon S3 PutBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html)
- [Amazon S3 GetBucketLifecycleConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html)
- [Amazon S3 server-side encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html)
- [Amazon S3 PutBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html)
- [Amazon S3 GetBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html)
- [Amazon S3 DeleteBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html)
