# Amazon S3-Compatible Encryption Implementation Plan

## Table of Contents

- [Goal](#goal)
- [Compatibility Scope](#compatibility-scope)
- [Design Principles](#design-principles)
- [Options Considered](#options-considered)
- [Architecture](#architecture)
- [Bucket Encryption Configuration](#bucket-encryption-configuration)
- [Encryption Modes](#encryption-modes)
- [Key Provider Model](#key-provider-model)
- [Cloud-Independent Local Key Provider](#cloud-independent-local-key-provider)
- [POSIX Encrypted Object Format](#posix-encrypted-object-format)
- [S3 Operation Coverage](#s3-operation-coverage)
- [Backend Strategies](#backend-strategies)
- [Lifecycle and Versioning Interaction](#lifecycle-and-versioning-interaction)
- [Implementation Sequence](#implementation-sequence)
- [Planned File Map](#planned-file-map)
- [Test Plan](#test-plan)
- [Security Requirements](#security-requirements)
- [Rollout and Migration](#rollout-and-migration)
- [Acceptance Criteria](#acceptance-criteria)
- [Risks and Explicit Trade-Offs](#risks-and-explicit-trade-offs)
- [Sources](#sources)

## Goal

Implement Amazon S3-compatible server-side encryption while allowing each backend to choose the correct storage mechanism.

The S3 layer validates and resolves encryption intent.

The backend performs encryption, native delegation, key wrapping, persistence, range handling, copy behavior, and decryption.

The implementation must work with AWS KMS and with a completely local key provider that requires no cloud or third-party service.

## Compatibility Scope

The target is Amazon S3 general purpose buckets.

The required bucket operations are:

- `PutBucketEncryption`.
- `GetBucketEncryption`.
- `DeleteBucketEncryption`.

The required encryption modes are:

- SSE-S3 using `AES256`.
- SSE-KMS using `aws:kms`.
- DSSE-KMS using `aws:kms:dsse`.
- SSE-C using the customer-provided AES-256 key headers.

The April 2026 Amazon S3 behavior that allows bucket-level blocking of SSE-C through `BlockedEncryptionTypes` is part of the target contract.

The source is the AWS [Default SSE-C setting for new buckets FAQ](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-s3-c-encryption-setting-faq.html), retrieved 2026-08-28: “automatically disables server-side encryption with customer-provided keys (SSE-C) for all new general purpose buckets.”

New general purpose buckets therefore block new SSE-C writes by default, while existing SSE-C objects remain readable with the correct key.

S3 Express directory-bucket restrictions, AWS CloudTrail, S3 Inventory, S3 Storage Lens, replication, annotations, and AWS-managed `aws/s3` key creation are outside the scope.

VersityGW supplies its own managed local SSE-S3 key rather than pretending to own an AWS account-managed `aws/s3` key.

## Design Principles

- The gateway never treats encryption as a boolean.
- The S3 transport layer produces an explicit, validated encryption intent.
- A backend advertises supported algorithms and mechanisms before accepting a bucket configuration or object write.
- A backend never silently downgrades, ignores, or substitutes an encryption request.
- Key material never appears in logs, errors, metrics, command-line arguments, YAML, or stored object metadata.
- Payload checksums, object size, and range semantics are defined over plaintext.
- S3-visible ETags follow the operation and encryption mode and are never derived from ciphertext; the implementation must not assume that every ETag is a plaintext MD5 digest.
- Encrypted data formats are versioned and independently recoverable when software is upgraded.
- Key rotation never requires immediate rewriting of every existing object.
- Losing all copies of a wrapping key makes affected objects unrecoverable and is treated as an operationally fatal condition.

## Options Considered

| Decision | Option | Advantages | Costs | Result |
| --- | --- | --- | --- | --- |
| Encryption ownership | Gateway encrypts every backend stream | One cipher implementation | Prevents native S3/KMS use and creates unnecessary double encryption | Rejected |
| Encryption ownership | Backend receives only a boolean | Small interface | Cannot express SSE-C, KMS key IDs, DSSE, Bucket Keys, or downgrade errors | Rejected |
| Encryption ownership | Gateway validates an explicit intent and backend implements it | Preserves one S3 contract and native backend mechanisms | Requires capability negotiation and richer results | Chosen |
| Local root key | Asymmetric wrapping key pair | Decryption can be isolated from an encryption-only process | Adds key-format and rotation complexity without a separate process boundary | Deferred |
| Local root key | Symmetric 256-bit key ring | Small auditable implementation and efficient rewrap | Every gateway that writes also holds decryption capability | Chosen for the local provider |
| POSIX protection | Filesystem encryption only | Transparent direct filesystem access | Cannot provide per-request SSE-C or per-object KMS semantics | Rejected as the S3 implementation |
| POSIX protection | Chunked authenticated object container | Supports authenticated ranges, versions, and per-object envelope keys | Adds format and I/O overhead and removes transparent direct reads | Chosen |

The chosen boundary means the gateway says exactly how an object must be protected, while POSIX, S3Proxy, ScoutFS, and Azure remain responsible for the physical mechanism.

## Architecture

```text
S3 request
  -> parse encryption headers or POST fields
  -> load bucket default and SSE-C block state
  -> evaluate bucket-policy encryption condition keys
  -> validate combinations and transport security
  -> produce EncryptionIntent
  -> backend implementation
       -> native upstream SSE, or
       -> local/AWS envelope encryption
  -> EncryptionResult
  -> S3 response headers
```

The shared feature package is `internal/encryption`.

It defines transport-independent algorithms, intent/result types, key-provider contracts, metadata envelopes, and validation helpers.

Backend-specific cipher I/O remains within the backend implementation.

### Capability Contract

```go
type EncryptionCapabilities struct {
    SSES3             bool
    SSEC              bool
    SSEKMS            bool
    DSSEKMS           bool
    BucketKeys        bool
    NativePassthrough bool
}

type EncryptionIntent struct {
    Mode               Mode
    KMSKeyID           string
    KMSContext         []byte
    BucketKeyEnabled   bool
    CustomerKey        SensitiveBytes
    CustomerKeyMD5     [16]byte
}

type EncryptionResult struct {
    Mode               Mode
    KMSKeyID           string
    CustomerKeyMD5     string
    BucketKeyEnabled   bool
}
```

The exact Go representation may change during the test-first prototype, but the separation of concerns is fixed.

Customer keys are request-scoped and are cleared from reusable buffers on completion as a best-effort defense.

The main backend contract composes a focused `BucketEncryptionStore` and exposes object encryption through the existing object methods.

## Bucket Encryption Configuration

Every encryption-capable bucket has an effective default of SSE-S3 once encryption is enabled for its backend.

`GetBucketEncryption` behavior is capability- and rollout-aware:

| Backend state | HTTP and S3 result | Body |
| --- | --- | --- |
| Encryption capability absent | HTTP 501 `NotImplemented` | Standard S3 error XML; no encryption configuration XML |
| Audit mode, writes still plaintext | HTTP 501 `NotImplemented` | Standard S3 error XML; the gateway must not claim `AES256` |
| Encryption enabled | HTTP 200 | Canonical `ServerSideEncryptionConfiguration` XML containing the persisted rule or effective default |

The exact default response for a newly created, encryption-enabled general purpose bucket is:

```xml
<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Rule>
    <ApplyServerSideEncryptionByDefault>
      <SSEAlgorithm>AES256</SSEAlgorithm>
    </ApplyServerSideEncryptionByDefault>
    <BlockedEncryptionTypes>
      <EncryptionType>SSE-C</EncryptionType>
    </BlockedEncryptionTypes>
  </Rule>
</ServerSideEncryptionConfiguration>
```

A missing bucket still returns `NoSuchBucket`; capability handling occurs only after bucket resolution.

`PutBucketEncryption` atomically replaces the complete configuration.

`DeleteBucketEncryption` resets the effective default to SSE-S3 rather than disabling encryption.

The canonical configuration contains:

- Default algorithm.
- Optional KMS key ID.
- Optional S3 Bucket Key flag.
- Optional blocked encryption types.

The validator enforces:

- Exactly one `ServerSideEncryptionRule` for a general purpose bucket.
- Exactly the supported rule shape for a general purpose bucket.
- An omitted `ApplyServerSideEncryptionByDefault` is accepted when the request only changes `BlockedEncryptionTypes` and normalizes to the effective SSE-S3 default.
- `AES256`, `aws:kms`, or `aws:kms:dsse` as the default algorithm.
- A KMS key ID only with `aws:kms` or `aws:kms:dsse`.
- No KMS key ID with `AES256`.
- Bucket Keys with `aws:kms` require provider support and implement bucket-level key reuse.
- `BucketKeyEnabled=true` with `AES256` is accepted, persisted, and returned, matching the official AWS example; it has no cryptographic effect because S3 Bucket Keys reduce only SSE-KMS calls.
- Bucket Keys with `aws:kms:dsse` are rejected because Amazon S3 does not support that combination.
- Exactly one `BlockedEncryptionTypes.EncryptionType` value when the element is present.
- `SSE-C` means blocked and `NONE` means explicitly unblocked; mixtures, duplicates, and unknown values are rejected.
- Backend capability before persistence.

Changing a bucket default affects future writes only.

For `AES256` plus `BucketKeyEnabled=true`, `PutBucketEncryption` returns HTTP 200 with an empty success body. A subsequent `GetBucketEncryption` includes `<BucketKeyEnabled>true</BucketKeyEnabled>` in the rule even though object encryption remains ordinary SSE-S3.

Existing objects retain the encryption metadata and key wrapping used when they were written.

## Encryption Modes

### SSE-S3

The backend creates a random 256-bit data-encryption key for every object version.

The payload is encrypted with AES-256-GCM.

The data key is wrapped by the backend's active managed key.

The client receives `x-amz-server-side-encryption: AES256` and never sees a key ID.

### SSE-KMS

The backend obtains or generates a data key through the selected key provider.

The wrapped data key, provider name, provider key ID, and authenticated encryption context are stored in the encrypted-object manifest.

AWS KMS key IDs are handled by the AWS provider.

Local key IDs are handled by the local provider.

The response exposes the requested KMS key ID according to S3 response rules.

### DSSE-KMS

DSSE uses two independent AES-256-GCM layers and independent data keys.

AWS documents the first layer as a unique DEK generated by AWS KMS and the second as a separate AES-256 key managed by Amazon S3. VersityGW preserves that division of responsibility rather than deriving both layers from one KMS key.

For an encrypted POSIX or ScoutFS backend with AWS KMS explicitly selected, the first layer uses AWS KMS and the second layer uses the gateway-managed local SSE-S3 key ring. Recovery of those objects therefore requires both AWS KMS access and a backup of the local key ring.

For the local provider, both layers use local key material with distinct wrapping-key IDs or key rings in addition to independent data keys and nonces. AWS KMS is not contacted, configured implicitly, or required unless the operator explicitly selects the AWS KMS provider.

For S3Proxy native delegation, the upstream S3 service owns both layers; VersityGW does not add a local layer or require its local key ring.

The implementation does not reuse a nonce, data key, or wrapped-key record between layers.

### SSE-C

SSE-C is accepted only over a transport that the gateway can authenticate as TLS.

Direct TLS is accepted from the request connection. TLS termination at a reverse proxy is supported only through an explicit trusted-proxy configuration containing CIDR prefixes. The resolver trusts `X-Forwarded-Proto: https` only when the immediate peer address is inside that list, the header contains exactly one value, and that value is `https` case-insensitively. The trusted CIDR list is empty by default; an untrusted peer cannot make plaintext HTTP acceptable by spoofing `X-Forwarded-Proto` or `Forwarded`.

Malformed, repeated, or comma-separated forwarded-protocol values fail closed. The resolver uses only the immediate peer, not an arbitrary address supplied in `X-Forwarded-For`.

The algorithm must be `AES256`.

The supplied key must decode to exactly 256 bits and match `x-amz-server-side-encryption-customer-key-MD5`.

The raw customer key is never persisted.

The backend generates a random object data key and derives a wrapping key from the customer key with HKDF-SHA-256, a per-object random salt, and object identity as context.

The derived key wraps the data key with AES-256-GCM and a random wrapping nonce.

The manifest stores the salt, wrapping nonce, wrapped data key, customer-key MD5, and non-secret algorithm data.

Authenticated unwrap failure rejects a wrong customer key, so no additional password-style verifier is stored.

GET, HEAD, Copy source, and UploadPartCopy require the matching customer key headers.

Bucket-level SSE-C blocking rejects PUT, POST, Copy destination, multipart initiation, multipart parts, and other new SSE-C writes while preserving reads of existing SSE-C objects.

## Key Provider Model

```go
type KeyProvider interface {
    Name() string
    GenerateDataKey(context.Context, KeyRequest) (PlaintextDataKey, WrappedDataKey, error)
    WrapKey(context.Context, KeyRequest, PlaintextDataKey) (WrappedDataKey, error)
    UnwrapKey(context.Context, KeyRequest, WrappedDataKey) (PlaintextDataKey, error)
    ValidateKeyReference(string) error
}
```

The interface accepts a key ID and authenticated encryption context.

`ValidateKeyReference` validates syntax and provider routing without contacting AWS KMS or unwrapping key material.

Provider errors are translated into S3 errors without returning sensitive provider details to the client.

The implementation includes `LocalKeyProvider` and `AWSKMSKeyProvider`.

### AWS KMS Provider

The AWS provider uses the official AWS SDK for Go v2 KMS client.

It uses `GenerateDataKey` for writes and `Decrypt` for reads.

It passes the normalized S3 encryption context and records the exact context required for future decrypt operations.

For general purpose buckets, `PutBucketEncryption` does not call AWS KMS to validate the supplied key ID because Amazon S3 deliberately defers that failure to object use.

An omitted KMS key ID selects the provider's explicitly configured default, which is `aws/s3` for AWS KMS and the active local KMS key for the local provider.

AWS credentials come from the standard AWS SDK credential chain or an explicitly configured non-secret profile selection.

Credentials are never duplicated into gateway YAML.

KMS authorization failures remain distinguishable in internal logs while clients receive the appropriate S3 error.

Provider timeouts and retry limits are bounded so a KMS outage cannot hold an object request indefinitely.

### Bucket Keys

Bucket Keys require a separate cached bucket-level wrapping-key design.

They are implemented only after SSE-KMS behavior is complete and differential tests pass.

The cache is bounded, keyed by bucket and KMS key ID, expires entries, clears plaintext keys on eviction as a best effort, and never persists plaintext key material.

If exact Bucket Key semantics cannot be guaranteed for a provider, that provider reports `BucketKeys: false` and bucket configuration requesting the feature is rejected.

DSSE-KMS always reports `BucketKeys: false` because Amazon S3 does not support Bucket Keys for DSSE-KMS.

## Cloud-Independent Local Key Provider

### Key Ring

The local provider uses symmetric 256-bit key-encryption keys.

Symmetric wrapping is preferred over an asymmetric key pair because both encryption and decryption occur in the trusted gateway process and asymmetric wrapping would add complexity without creating a separate trust boundary.

The design can add an RSA-OAEP wrapping provider later without changing the S3 or backend contracts.

The operator provisions a persistent key directory outside object storage.

Example layout:

```text
/run/secrets/versitygw-kms/
├── 2026-01.key
├── 2026-08.key
└── active
```

Each `.key` file contains exactly 32 random bytes.

`active` contains only the non-secret active key ID and may alternatively be supplied through an environment variable.

The key directory path and active key ID are non-secret configuration.

The key bytes themselves are supplied through protected files or a container-orchestrator secret mount.

The gateway refuses to read key bytes from CLI arguments or YAML.

### Startup Validation

The local provider validates that:

- The active key exists and has the required length.
- Key IDs use a restricted filename-safe syntax.
- Key files are regular files and not symlinks.
- POSIX permissions do not grant group or world access.
- Duplicate key IDs do not exist.
- The key directory is outside bucket and archive roots.
- Every locally referenced bucket key remains available.

The last check is performed by a bounded metadata audit or maintained key-reference index.

Startup fails when the active key is invalid.

Missing historical keys mark affected objects unavailable and emit a high-severity health error rather than silently corrupting data.

### Rotation

Rotation adds a new key file and atomically changes the active key ID.

New objects use the new key immediately.

Existing objects continue to decrypt with their recorded key ID.

An optional rewrap operation replaces only wrapped data keys and manifests, not object ciphertext.

The plan does not remove an old key until a verified reference scan reports zero dependent objects and versions.

Key backup and restore are mandatory operational documentation.

## POSIX Encrypted Object Format

### Container Requirements

POSIX stores encrypted object payloads in a versioned binary container.

The container supports streaming writes, authenticated chunk reads, byte ranges, multipart completion, format migration, and corruption detection.

The V1 format contains:

- Magic bytes and format version.
- Algorithm and layer count.
- Plaintext size.
- Fixed chunk-size identifier.
- Random object ID and base nonce material.
- Wrapped data-key records and provider key IDs.
- Authenticated manifest hash.
- Independently authenticated ciphertext chunks.

The concrete chunk size is an on-disk format constant selected after benchmark and range-amplification tests.

It is not an operator setting because changing it must not reinterpret existing files.

Each chunk uses a unique nonce derived without collision from object nonce material and chunk index.

Additional authenticated data binds format version, bucket identity, key, version ID, plaintext length, chunk index, and encryption mode.

### Atomic Writes

The backend streams plaintext through checksum calculation and encryption into a temporary file.

It flushes ciphertext and metadata before atomically publishing the object version.

An interrupted write never replaces the prior current version.

S3 checksums and content length remain plaintext properties.

ETag generation follows the S3 operation and encryption mode and never hashes stored ciphertext.

### Ranges

A range request maps the plaintext range to the minimum set of encrypted chunks.

Every fetched chunk is authenticated before any bytes from that chunk are returned.

The response slices the authenticated plaintext to the requested byte range.

The implementation never returns unauthenticated plaintext for streaming convenience.

### Multipart Uploads

Multipart parts must be encrypted at rest before completion.

Each multipart upload receives an upload-scoped data key and unique per-part nonce domain.

Completion streams authenticated part plaintext into the final object container and atomically publishes it.

This adds I/O but avoids nonce reuse, ambiguous concatenation, and dependence on final part offsets at initiation time.

Abort removes encrypted parts and wrapped upload keys.

UploadPart requires the same SSE-C headers used at initiation when the upload uses SSE-C.

## S3 Operation Coverage

| Operation | Required encryption behavior |
| --- | --- |
| `CreateBucket` | Establish effective SSE-S3 default and default SSE-C block state |
| `PutBucketEncryption` | Validate and atomically replace default/block configuration |
| `GetBucketEncryption` | Return effective default, Bucket Key state, and blocked types |
| `DeleteBucketEncryption` | Reset to SSE-S3 |
| `PutObject` | Resolve explicit headers over bucket default, encrypt, and return SSE headers |
| `POSTObject` | Parse form fields, enforce POST policy conditions, and encrypt |
| `CreateMultipartUpload` | Resolve encryption once and persist upload encryption state |
| `UploadPart` | Enforce matching SSE-C headers and encrypt the part at rest |
| `UploadPartCopy` | Decrypt source as required and enforce destination upload encryption |
| `CompleteMultipartUpload` | Build and publish one encrypted object version |
| `AbortMultipartUpload` | Remove encrypted part data and key metadata |
| `CopyObject` | Independently resolve source decryption and destination encryption |
| `GetObject` | Validate SSE-C headers, unwrap keys, authenticate chunks, and decrypt ranges |
| `HeadObject` | Validate SSE-C headers and return encryption metadata without payload decryption |
| `GetObjectAttributes` | Return plaintext size/checksums without exposing encryption internals |
| `DeleteObject` and `DeleteObjects` | Delete ciphertext and wrapped-key metadata together |
| `ListObjects` and versions | Return plaintext size and storage class without encryption internals |

Copying an object to itself with a changed encryption configuration is a valid metadata-changing copy.

Copying without destination SSE headers applies the destination bucket default.

Copy-source SSE-C and destination SSE-C headers are distinct and must never be interchanged.

## Backend Strategies

| Backend | Strategy |
| --- | --- |
| POSIX | Local container encryption using Local KMS or AWS KMS providers |
| ScoutFS | Inherit POSIX encryption so offline extents contain ciphertext and restore does not expose unverified bytes |
| S3Proxy | Forward native bucket and object SSE fields to the upstream S3 API and return translated results |
| Azure | Implement backend-owned envelope encryption for modes Azure cannot map exactly; enable native Azure encryption only after semantic equivalence is verified |

S3Proxy must not decrypt and re-encrypt data that the upstream service can protect natively.

Azure must not translate an AWS KMS key ID into an unrelated Azure key identifier or report SSE-KMS when exact semantics are absent.

Every backend advertises its effective capability set through diagnostics and documentation.

## Lifecycle and Versioning Interaction

Every object version carries its own immutable encryption manifest reference.

Overwriting an object creates a new encrypted version and leaves the older version decryptable with its original key ID.

Lifecycle expiration removes ciphertext, the manifest, tags, Object Lock metadata when permitted, and any archive reference as one logical operation.

Lifecycle transition moves ciphertext and its manifest as opaque authenticated data.

Transition does not decrypt or re-encrypt the object.

Restore moves or stages the same encrypted representation and authenticates it during GET.

Key-reference scans include current, noncurrent, archived, and multipart objects before permitting key deletion.

## Implementation Sequence

### Phase 1: Protocol Tests and Domain Types

1. Build a temporary failing test harness for bucket XML, object header combinations, SSE-C transport checks, and response headers.
2. Add `internal/encryption/types.go`, `validate.go`, and `xml.go` with unit tests.
3. Add missing S3 errors and exact response tests in `s3err`.
4. Add encryption condition keys and runtime values to bucket-policy evaluation with tests.

### Phase 2: Backend Capability and Bucket API

1. Add `backend/encryption.go` with focused capability and configuration-store interfaces.
2. Add unsupported defaults without silent success.
3. Add `s3api/controllers/bucket-encryption.go` and controller tests.
4. Replace the three encryption router stubs and attach checksum validation.
5. Implement configuration persistence or native delegation for every shipped backend.
6. Replace the three `NotImplemented` integration tests with real tests.

### Phase 3: Request and Response Coverage

1. Add shared encryption-header parsing that never logs raw keys.
2. Extend `PutObject`, `POSTObject`, Copy, multipart, GET, HEAD, and attributes paths with `EncryptionIntent`.
3. Add all required response headers from `EncryptionResult`.
4. Ensure POST policies and bucket policies receive normalized encryption condition values.
5. Regenerate backend mocks and update controller fixtures.

### Phase 4: Local Key Provider

1. Add failing tests for key loading, invalid permissions, rotation, missing historical keys, and rewrap.
2. Implement `internal/encryption/local_provider.go` using Go cryptographic primitives.
3. Add key-directory and active-key configuration shared by POSIX and ScoutFS commands.
4. Add a health check that reports active and missing referenced key IDs without exposing paths or bytes.
5. Write key-generation, backup, restore, and rotation documentation using a safe project-provided command.

### Phase 5: POSIX SSE-S3 and SSE-C

1. Prototype and test the container format outside production paths.
2. Implement streaming encrypted writes and authenticated full reads.
3. Add range reads, conditionals, checksums, ETags, and version moves.
4. Add SSE-C key validation and copy-source behavior.
5. Implement encrypted multipart storage and completion.
6. Verify xattr and sidecar metadata modes on supported platforms.

### Phase 6: AWS KMS and DSSE-KMS

1. Add the pinned AWS KMS SDK dependency through the existing Go module workflow.
2. Implement bounded AWS KMS GenerateDataKey, Encrypt, and Decrypt operations.
3. Add local and AWS provider routing by key ID/provider configuration.
4. Implement SSE-KMS and then the independent second DSSE layer.
5. Add provider outage, timeout, permission, context mismatch, and rotation tests.

### Phase 7: S3Proxy and Azure

1. Complete native bucket/object SSE forwarding in S3Proxy.
2. Add differential tests against Amazon S3 for all supported modes.
3. Implement Azure-owned envelope encryption where exact native mapping is unavailable.
4. Validate Azure range, copy, block upload, metadata size, and access-tier interaction.

### Phase 8: Bucket Keys, Migration, and Documentation

1. Implement Bucket Keys only for providers that can preserve their semantics.
2. Add an inventory tool that reports plaintext legacy, encrypted, missing-key, and format-version counts without reading object contents.
3. Add an explicit re-encryption workflow for legacy objects.
4. Update README, operational documentation, backend compatibility matrix, and disaster-recovery procedures.

## Planned File Map

The exact split may be refined during the failing-test prototype, but the interface and secret-handling boundaries are fixed.

| Area | Planned files or directories | Change |
| --- | --- | --- |
| Domain | `internal/encryption/types.go`, `validate.go`, `xml.go` | Intent/result model, bucket configuration, AWS XML, and validation |
| Providers | `internal/encryption/provider.go`, `local_provider.go`, `aws_kms_provider.go` | Key-provider interface, local key ring, and AWS KMS implementation |
| POSIX format | `backend/posix/encryption.go`, `encrypted_reader.go`, `encrypted_writer.go` | Versioned container, atomic writes, authenticated reads, ranges, and multipart handling |
| Backend contract | `backend/encryption.go`, `backend/backend.go` | Capability discovery, configuration store, unsupported defaults, and object intent/result plumbing |
| S3 transport | `s3api/controllers/bucket-encryption.go`, shared SSE helpers, affected object controllers, `s3api/router.go` | Bucket CRUD, header/form parsing, policy values, TLS checks, and response headers |
| Policy and logging | `auth/`, `debuglogger/redact.go`, `debuglogger/logger.go` | Encryption condition keys and extensions to the existing redaction boundary and tests; no second redaction site |
| Transport security | shared transport resolver under `s3api/` and command option packages | Direct TLS and explicitly trusted proxy CIDRs for SSE-C |
| ScoutFS | `backend/scoutfs/` | POSIX ciphertext release/stage and restore integration |
| S3Proxy | `backend/s3proxy/` | Native bucket/object SSE forwarding without double encryption |
| Azure | `backend/azure/` | Backend-owned envelope encryption and validated native mappings |
| Startup and health | `embedgw/` and command option packages | Provider selection, non-secret key paths/IDs, readiness, and shutdown |
| Errors | `s3err/s3err.go` and tests | Exact protocol errors without provider-detail leakage |
| Tests | `internal/encryption/*_test.go`, backend tests, controller tests, `tests/integration/` | Protocol, crypto, corruption, race, backend, and differential coverage |
| Documentation and tooling | `README.md`, `docs/`, project-provided key utility | Setup, backup, rotation, rewrap, recovery, and compatibility guidance |

## Test Plan

### Cryptographic Tests

- Known-answer and round-trip tests for wrapping and chunk encryption.
- Wrong key, wrong context, wrong chunk index, modified header, truncated file, reordered chunk, and bit-flip failures.
- Nonce uniqueness across objects, versions, parts, retries, and DSSE layers.
- Range reads at chunk boundaries and one-byte ranges.
- Empty objects and zero-byte multipart parts.
- Key rotation and manifest-only rewrap.
- Missing key and corrupted key-ring behavior.

Tests verify observable behavior and corruption rejection rather than duplicating standard-library cipher internals.

### Controller and Policy Tests

- Bucket configuration XML and validation.
- Default SSE-S3 resolution.
- Explicit SSE headers overriding bucket default.
- Blocked SSE-C writes and permitted existing-object reads.
- SSE-C rejected over HTTP.
- Direct TLS accepted; trusted-proxy `X-Forwarded-Proto: https` accepted only from configured IPv4/IPv6 CIDRs.
- Spoofed forwarded protocol from an untrusted peer, malformed/multiple values, and trusted-proxy `http` are rejected.
- Missing, malformed, and mismatched SSE-C headers.
- KMS key ID and algorithm combinations.
- `AES256` plus `BucketKeyEnabled=true` is accepted and echoed without changing SSE-S3 cryptography; DSSE plus Bucket Keys is rejected.
- `GetBucketEncryption` returns 501 in capability-absent and audit modes and returns the exact default XML only after encryption is enabled.
- POST policy and bucket-policy encryption conditions.
- Exact response headers for every operation.
- Debug logs and errors contain no customer key or local key bytes.

### Backend Integration Tests

- POSIX with xattr and sidecar metadata.
- ScoutFS encryption combined with release, stage, and restore.
- S3Proxy native SSE-S3, SSE-C, SSE-KMS, DSSE-KMS, Copy, and multipart.
- Azure envelope encryption and access-tier interaction.
- Version overwrite, delete marker, noncurrent read, and Lifecycle expiration.
- Concurrent PUT/GET, restart during write, and restart during multipart completion.

### Differential Tests

Run a controlled matrix against Amazon S3 for general purpose buckets.

Compare error codes, required headers, response headers, copy behavior, multipart requirements, default changes, SSE-C blocking, and GET/HEAD behavior.

Do not compare ciphertext because provider representations are intentionally private.

### Final Verification

Run focused race-enabled tests, `make test`, static analysis available in the project toolchain, all affected integration suites, corruption/fault-injection tests, and the repository code-review workflow.

## Security Requirements

- Use Go standard-library cryptography or an established audited primitive already present in the module graph.
- Never design a custom block cipher, MAC, or key-derivation algorithm.
- Use authenticated encryption for all payload chunks and wrapped local data keys.
- Bind manifests and chunks to object/version identity through additional authenticated data.
- Generate keys, salts, nonces, and object IDs with `crypto/rand` only.
- Reject nonce or object-ID generation failure.
- Redact destination and copy-source SSE-C keys at the earliest logging boundary.
- Reject insecure SSE-C transport before reading object payload bytes; never trust forwarded transport headers without an explicit immediate-peer CIDR match.
- Never return provider error bodies or key paths to S3 clients.
- Keep local key directories outside bucket, version, sidecar, temporary, and archive roots.
- Do not follow symlinks while loading local keys.
- Document that process memory can contain plaintext data keys during active requests.
- Bound plaintext-key caches and disable them for SSE-C.
- Include key backups in disaster-recovery verification.
- Treat deletion of referenced key material as destructive and require explicit operator confirmation in any tooling.

## Rollout and Migration

Existing POSIX objects are plaintext and have no encryption manifest.

The backend continues to read those objects as legacy plaintext during migration.

Buckets created after the feature is enabled start with SSE-C writes blocked, matching the AWS April 2026 default cited in [Compatibility Scope](#compatibility-scope).

Pre-existing buckets retain an explicit migration state until a bounded inventory determines whether SSE-C objects exist, rather than silently changing their write policy.

Once Encryption is enabled for a local backend, every new write receives at least SSE-S3 according to the effective bucket default.

There is no secure implicit local master-key location.

Enabling local Encryption therefore requires an explicitly provisioned persistent key directory.

The gateway refuses to enable local Encryption when the active key configuration is missing or ephemeral.

The rollout sequence is:

1. Provision and back up the local key ring on every gateway instance.
2. Verify identical key IDs and bytes through non-secret fingerprints.
3. Enable audit mode and inventory legacy objects while keeping the advertised Encryption capability disabled; bucket encryption APIs continue to return 501 and object writes remain plaintext.
4. Enable SSE-S3 for new writes.
5. Re-encrypt existing objects through an explicit, resumable, version-aware job if required.
6. Verify every object version and archive reference before retiring a key or legacy reader path.

The migration job uses the normal conditional object rewrite path and never modifies locked versions without authorization.

## Acceptance Criteria

- Bucket Encryption CRUD matches current Amazon S3 general-purpose-bucket behavior.
- Every bucket has an effective SSE-S3 default and DELETE resets to that default.
- SSE-S3, SSE-C, SSE-KMS, and DSSE-KMS work for PUT, POST, Copy, multipart, GET, HEAD, versions, and ranges on the backends that advertise them.
- SSE-C blocking prevents new writes but does not make existing SSE-C objects unreadable.
- S3Proxy delegates encryption natively without gateway-level double encryption.
- POSIX and ScoutFS operate without cloud or third-party key-management software through the local key provider.
- Local key rotation affects new writes immediately and old objects remain readable.
- No stored manifest, log, metric, error, YAML file, or process argument contains a raw customer or local master key.
- Ciphertext corruption is detected before affected plaintext is returned.
- S3-compatible ETags, plaintext checksums, content lengths, copy semantics, and range responses remain correct.
- Lifecycle transition and restore preserve encrypted objects without changing encryption state.
- Missing historical keys produce a clear health failure and never silent data loss.
- Direct POSIX readers are explicitly documented as unable to read application-encrypted object payloads.
- The full unit, race, integration, differential, and fault-injection suites pass.

## Risks and Explicit Trade-Offs

Application-level POSIX encryption intentionally makes encrypted files opaque to direct filesystem readers.

Filesystem-level encryption could preserve transparent local reads, but it cannot implement request-specific SSE-C or per-object KMS semantics by itself.

Chunked authenticated encryption adds storage overhead and range-read amplification.

Multipart completion requires additional authenticated streaming I/O.

Local key files remove cloud dependency but place backup, distribution, rotation, and access-control responsibility on the operator.

AWS KMS availability becomes part of the read path for objects whose data keys are not cached.

Provider-native implementations may have different physical ciphertext while preserving the same S3 contract.

## Sources

- [Amazon S3 server-side encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html)
- [Amazon S3 PutBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html)
- [Amazon S3 GetBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html)
- [Amazon S3 DeleteBucketEncryption](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketEncryption.html)
- [Amazon S3 ServerSideEncryptionRule](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ServerSideEncryptionRule.html)
- [Amazon S3 ServerSideEncryptionByDefault](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ServerSideEncryptionByDefault.html)
- [Default SSE-C setting for new buckets FAQ](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-s3-c-encryption-setting-faq.html)
- [Blocking or unblocking SSE-C for a general purpose bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/blocking-unblocking-s3-c-encryption-gpb.html)
- [Using dual-layer server-side encryption with AWS KMS keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingDSSEncryption.html)
- [Reducing the cost of SSE-KMS with S3 Bucket Keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html)
- [AWS S3 getting-started example accepting AES256 with BucketKeyEnabled](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/s3_example_s3_GettingStarted_section.html)
- [Amazon S3 Object ETag behavior](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html)
