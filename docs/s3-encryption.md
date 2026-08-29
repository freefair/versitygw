# S3 Server-Side Encryption

- [Backend matrix](#backend-matrix)
- [Local key ring](#local-key-ring)
- [Optional AWS KMS](#optional-aws-kms)
- [SSE-C transport security](#sse-c-transport-security)
- [Rotation and recovery](#rotation-and-recovery)

VersityGW validates Amazon S3 encryption requests at the S3 boundary and passes
an explicit encryption intent to the selected backend. The backend owns the
physical representation: POSIX, ScoutFS, and Azure use an authenticated
envelope container; S3Proxy delegates encryption headers and bucket
configuration to the upstream S3 service.

## Backend matrix

| Backend | SSE-S3 | SSE-C | SSE-KMS | DSSE-KMS | Physical mechanism |
| --- | --- | --- | --- | --- | --- |
| POSIX | Yes | Yes | Local or explicitly selected AWS KMS | Yes | Chunked authenticated container |
| ScoutFS | Yes | Yes | Local or explicitly selected AWS KMS | Yes | POSIX container on ScoutFS |
| Azure | Yes | Yes | Local or explicitly selected AWS KMS | Yes | Container stored as an Azure blob |
| S3Proxy | Upstream | Upstream | Upstream | Upstream | Native upstream S3 behavior |

Encryption is inactive for POSIX, ScoutFS, and Azure unless a local key
directory is configured. When active, new buckets use SSE-S3 and block new
SSE-C writes by default. `PutBucketEncryption` can select `AES256`, `aws:kms`,
or `aws:kms:dsse` and can explicitly set `BlockedEncryptionTypes` to `SSE-C` or
`NONE`. Deleting the bucket configuration resets the effective SSE-S3 default.

Buckets that already existed when Encryption was enabled have an explicit
legacy migration state when no stored Encryption configuration is present:
new writes default to SSE-S3, but SSE-C remains unblocked. Creating a bucket or
deleting its Encryption configuration persists the new-bucket default with
SSE-C blocked, so a missing marker never silently changes an existing bucket's
write policy.

Object PUT, browser POST, copy, multipart upload/copy, GET, HEAD, attributes,
range reads, listings, versions, and deletes preserve S3-visible plaintext
sizes and encryption response headers. Authentication covers the object
identity, container header, chunks, and wrapped data-key records.

Encrypted browser POST requests use a one-request AES-256-GCM spool to determine
the exact file-part length before backend publication. Only ciphertext reaches
temporary storage, its key exists only in process memory, and POSIX unlinks the
open temporary file immediately so a crash does not leave a named spool.

## Local key ring

The cloud-free provider uses 256-bit symmetric wrapping keys. Create a protected
directory and generate the first key with the project CLI:

```bash
install -d -m 700 /etc/versitygw/keys
versitygw utils encryption-key generate \
  --directory /etc/versitygw/keys \
  --key-id 2026-01 \
  --activate
```

The command creates `/etc/versitygw/keys/2026-01.key` and the `active` reference
with mode `0600`. The directory must be owned by the gateway account, have mode
`0700`, contain no symlinks of any name, and live outside the canonical data,
version, sidecar, and archive roots. Every key file and the `active` file must
also be owned by the gateway account and must not grant group or other access.

Enable it on a backend:

```bash
versitygw posix \
  --encryption-key-directory /etc/versitygw/keys \
  --versioning-dir /srv/versitygw/versions \
  /srv/versitygw/data
```

With no `--encryption-kms-provider`, the local provider supplies SSE-S3,
SSE-KMS, and both DSSE layers. No AWS configuration or network client is loaded.
Key IDs and wrapped data keys may be stored with objects; raw wrapping keys and
SSE-C customer keys never are.

## Optional AWS KMS

AWS KMS is used only when explicitly selected:

```bash
versitygw posix \
  --encryption-key-directory /etc/versitygw/keys \
  --encryption-kms-provider aws \
  --encryption-kms-key-id alias/example-s3 \
  /srv/versitygw/data
```

In this mode SSE-KMS uses AWS KMS. DSSE-KMS deliberately uses AWS KMS for the
first layer and the local key ring for the second layer. Recovery therefore
requires both the AWS KMS key and the local key ring. AWS credentials and region
come from the normal AWS SDK environment or workload identity; they are not
stored in VersityGW configuration.

The Base64-decoded `x-amz-server-side-encryption-context` value must be a JSON
object whose keys and values are strings. Its pairs are passed unchanged as
AWS KMS Encryption Context entries. VersityGW adds the reserved
`versitygw:object-binding` entry to bind the wrapped data key to the authenticated
bucket, object version, mode, and layer; callers cannot supply that key. The
client context is stored in the encrypted container and passed again during
decrypt and rewrap operations, matching the [Amazon S3 encryption-context
contract](https://docs.aws.amazon.com/AmazonS3/latest/userguide/specifying-kms-encryption.html)
and the [AWS KMS map-of-string-pairs API](https://docs.aws.amazon.com/kms/latest/cryptographic-details/generating-data-keys.html).

## SSE-C transport security

SSE-C is accepted over direct TLS. Behind TLS termination, configure each
trusted immediate proxy CIDR with the repeatable global `--trusted-proxy-cidr`
option. Only a trusted peer may assert one unambiguous
`X-Forwarded-Proto: https` value. Forwarding headers are never trusted by
default. Destination and copy-source SSE-C key headers are redacted even at the
unsafe debug level; raw customer key material is never written to logs.

## Rotation and recovery

Generate and activate a new key for rotation. Existing objects remain readable
while every referenced old key file remains in the ring. The maintenance
commands operate on POSIX-compatible roots:

```bash
versitygw utils encryption inventory --key-directory /etc/versitygw/keys /srv/versitygw/data
versitygw utils encryption rewrap --dry-run --key-directory /etc/versitygw/keys /srv/versitygw/data
versitygw utils encryption rewrap --key-directory /etc/versitygw/keys /srv/versitygw/data
versitygw utils encryption reencrypt --dry-run --key-directory /etc/versitygw/keys /srv/versitygw/data
```

`inventory` reports formats and key references without reading payloads.
`rewrap` changes only wrapped data keys; `reencrypt` migrates legacy plaintext
objects to SSE-S3. Include matching `--sidecar`, `--versioning-dir`, and
`--archive-tier` options when the live backend uses them. For archived objects,
both the bucket metadata manifest and the adjacent recovery `.json` manifest
are refreshed with the new stored size, SHA-256, and Encryption result before a
maintenance operation is reported successful. A metadata or manifest refresh
failure restores the previous archive bytes and metadata before the command
returns an error.

Back up the entire key directory securely and test restoration. Do not remove
an old key until inventory proves that no live, versioned, or archived object
references it. Missing historical keys are reported by health/audit state and
make affected objects unreadable; VersityGW cannot reconstruct them.
