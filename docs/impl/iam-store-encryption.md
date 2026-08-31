# IAM Store Encryption Implementation

## Table of Contents

- [Goal](#goal)
- [Problem](#problem)
- [Options Considered](#options-considered)
- [Architecture](#architecture)
- [Stored Format](#stored-format)
- [Read Path and Caching](#read-path-and-caching)
- [Write Path](#write-path)
- [Migration Model](#migration-model)
- [Configuration Surface](#configuration-surface)
- [File Map](#file-map)
- [Test Coverage](#test-coverage)
- [Security Boundary](#security-boundary)
- [Out of Scope](#out-of-scope)

## Goal

Keep the file-backed IAM stores — the gateway's `users.json` and the IAM API
server's `iam.json` — encrypted at rest, without changing the authentication
path's cost and without a second cryptographic implementation in the tree.

## Problem

`auth.Account.Secret` and `iamapi/types.AccessKey.SecretAccessKey` are
serialized verbatim, and the store engine wrote them as `0600` JSON. SigV4
verification recomputes an HMAC from the secret, so the gateway needs the
plaintext value per request: hashing or one-way derivation cannot be used.
File permissions were the only protection, and they do not survive a backup, a
snapshot, or a copied data directory.

## Options Considered

| Option | Verdict |
| --- | --- |
| Hash the secrets | Impossible; SigV4 needs the plaintext secret |
| A new AES-GCM envelope inside `iamstore` | Rejected; a second crypto implementation to review and maintain |
| Reuse `internal/encryption`'s container and providers | Chosen; one format, one key ring, one review surface |
| Encrypt in each IAM backend | Rejected; both file-backed stores already share one engine |

## Architecture

`internal/iamstore` is the single point where both file-backed stores read and
write bytes, so encryption lives there:

```
auth.IAMServiceInternal  ──┐
                           ├─→ iamstore.Engine ─→ iamstore.Protector ─→ encryption.KeyProvider
iamapi/storage.InternalStore ┘                                            (local key ring | AWS KMS)
```

`Protector` is a thin adapter over `encryption.NewWriter` / `encryption.Open` /
`encryption.Rewrap`. It holds no key material: the wrapping key stays inside
the provider.

Local wrapping uses `LocalProvider.Derived("local-iam", "iam-store")`, the same
HKDF derivation the POSIX backend uses for the DSSE second layer. The IAM store
therefore never wraps with the object key itself, even when both share a key
directory, and an object container cannot be opened as an IAM store or the
reverse.

## Stored Format

The store file is a standard `VGWSSE1` container with one layer, bound to the
identity `{Bucket: "__versitygw_iam__", Key: "<store file name>"}`. Bucket
names cannot contain underscores, so that identity is unreachable for any S3
object. The identity feeds the container's AAD and the KMS encryption context,
so a container cannot be moved between store files.

The mode records how the data key is wrapped: `SSE-S3` for a local key,
`SSE-KMS` for AWS KMS.

The backup file is a byte copy of the previous store file and is bound to the
store file's identity, so restoring it stays a plain rename.

## Read Path and Caching

`GetUserAccount` runs on every authenticated request and previously read and
parsed the file each time — which is also the only coordination between
gateways sharing an IAM directory. The engine now caches the decrypted store:

- inside a one-second validity window a request is served straight from memory;
- after the window the file is **read**, and the SHA-256 of its bytes is
  compared with the cached one; equal bytes only refresh the window, so an idle
  gateway never decrypts twice and never calls KMS twice;
- different bytes are decrypted and replace the cache entry;
- a write fills the cache with the plaintext it just published, so an update
  costs no extra decryption;
- callers always receive a copy, and a replaced cache buffer is wiped.

Reading the file rather than trusting its metadata is deliberate. Identity and
modification time would be cheaper, but on NFS — a supported deployment for
this gateway — `stat` may be answered from the client attribute cache for up to
`acregmax`, while `open` forces close-to-open revalidation. Metadata alone
would also be fooled by inode reuse plus an equal-size store on a filesystem
with coarse timestamps. Content comparison has neither weakness, and the read
it costs is the one the code performed per request before.

Net effect: one read per second instead of one per request, no decryption while
the store is unchanged, and a change by another gateway visible within the
window — comfortably inside the account cache (`--iam-cache-ttl`) layered above
it.

## Write Path

`StoreIAM` keeps its read–update–rename strategy and its concurrency
trade-offs. Encryption slots in around the update callback: the previous file
is copied to the backup as raw bytes, decrypted for the callback, and the
result is re-encoded in the format the file already had. After the rename the
cache is filled with the plaintext just written, keyed by the digest of the
published bytes, so a write costs no extra decrypt and no extra KMS call.

## Migration Model

The gateway never changes a store's format on its own — the first encrypted
write would lock out every other gateway sharing the directory. Therefore:

- a store the engine creates is encrypted immediately when a key is configured;
- an existing plaintext store stays plaintext, with a startup warning;
- `--iam-encryption-required` turns that warning into a startup failure;
- an encrypted store without a configured key is a startup failure, never a
  silent empty start;
- `versitygw utils iam-encryption {status,encrypt,decrypt,rewrap}` performs the
  conversions, always covering the backup file as well.

## Configuration Surface

`iamstore.ProtectorConfig` carries the operator's settings and builds the
provider. `embedgw` exposes the settings as flat `IAMEncryption*` fields on
`Config` and `IAMConfig` — the embedding API must stay constructible from
outside the module, so no `internal/` type appears in it — and maps them into
`auth.Opts.StoreOptions` and `storage.Config.StoreOptions` as ready-made
`iamstore.Options`.

`embedgw.iamStoreOptions` refuses encryption settings when the selected IAM
backend is not the file-backed store: LDAP, Vault, FreeIPA, the standalone IAM
service, and the S3-hosted IAM object cannot honor them, and silently ignoring
them would leave the operator believing credentials were encrypted.

Provider validation rejects combinations that would otherwise fail late or
silently: a KMS key ID without the `aws` provider, an active key or key
directory with it, and `aws` without a key ID — which would otherwise fall back
to the S3-managed alias no non-S3 principal can use.

`gwcli.IAMEncryptionFlags(prefix, cfg)` defines the flags once: the gateway
binaries register them as `--iam-encryption-*`, the `iam` command and the
maintenance commands as `--encryption-*`. Environment variable names
(`VGW_IAM_ENCRYPTION_*`) are identical everywhere, so one deployment
configuration serves all three.

## File Map

| File | Role |
| --- | --- |
| `internal/iamstore/crypto.go` | `Protector`: encode, decode, rewrap, inspect |
| `internal/iamstore/config.go` | `ProtectorConfig`, provider construction, IAM key derivation |
| `internal/iamstore/migrate.go` | store/backup conversions used by the CLI |
| `internal/iamstore/engine.go` | format handling, plaintext cache, stamp validation |
| `auth/iam_internal.go`, `auth/iam.go` | `NewInternalWithOptions`, `Opts.StoreOptions` |
| `iamapi/storage/internal.go`, `storer.go` | `NewInternalWithOptions`, `Config.StoreOptions` |
| `embedgw/embedgw.go`, `embedgw/iam.go` | configuration plumbing |
| `cmd/internal/gwcli/iam_encryption.go` | shared flags and the maintenance command |
| `cmd/versitygw/main.go`, `cmd/vgwrdma/main.go`, `cmd/internal/gwcli/iam.go` | flag registration |

## Test Coverage

`internal/iamstore` covers the round trip, identity binding, a foreign key, a
tampered container, format detection, the plaintext-preserving write, the
strict mode, an encrypted store without a key, cache reuse and expiry versus a
foreign write, caller mutation of returned bytes, the CLI conversions including
the backup file, and the provider-configuration validation. `embedgw` covers
the backend gating and the flat-field mapping.

End to end, `versitygw test gw-iam` and `versitygw test iam` run against
encrypted stores.

## Security Boundary

Encryption at rest covers copies of the file: backups, snapshots, cloned
directories, and read access to the IAM directory without access to the key
directory. It does not cover an attacker with access to the running process or
to the host together with the key, and it does not prevent replaying an older
ciphertext of the same store — the plaintext format has neither property
either.

## Out of Scope

- `auth/iam_s3_object.go`, which stores its JSON in an S3 bucket through its
  own code path.
- The root account, which is read from the environment per start and never
  written to the store.
- Rollback protection for superseded ciphertexts.
