# IAM Store Encryption

- [What it protects](#what-it-protects)
- [Covered stores](#covered-stores)
- [Enabling encryption](#enabling-encryption)
- [Migrating an existing deployment](#migrating-an-existing-deployment)
- [Key rotation](#key-rotation)
- [Rolling back](#rolling-back)
- [AWS KMS](#aws-kms)
- [Operational notes](#operational-notes)

The file-backed IAM services store S3 secret access keys. SigV4 is an HMAC
construction, so the gateway must hold those secrets in plaintext at request
time — hashing them is not an option. What is possible is encrypting the store
at rest, which VersityGW does with the same envelope container and key
providers as S3 object encryption.

## What it protects

Encryption at rest removes the credentials from anything that copies the file
rather than the running process: backups, filesystem snapshots, a cloned data
directory, a disk leaving the building, an operator with read access to the IAM
directory but not to the key directory.

It does not protect against an attacker who reaches the gateway process or the
host it runs on with the key available, and it does not prevent replaying an
older ciphertext of the same store. Both are equally true of the plaintext
format; encryption narrows the exposure, it does not remove the need to protect
the host.

## Covered stores

| Store | File | Written by |
| --- | --- | --- |
| Gateway accounts | `users.json` (plus `users.json.backup`) | `--iam-dir` |
| IAM API database | `iam.json` (plus `iam.json.backup`) | `versitygw iam --dir` |

The backup file holds the same credentials as the store and is always kept in
the same format.

External IAM backends are unaffected: LDAP, Vault, FreeIPA, and the standalone
IAM service store their own data, and the S3-hosted IAM object
(`--s3-iam-*`) keeps its historical plaintext JSON. Configuring these flags
alongside one of those backends is refused at startup rather than accepted as
a false assurance.

## Enabling encryption

Create a protected key directory and generate a wrapping key with the same CLI
used for object encryption:

```bash
install -d -m 700 /etc/versitygw/keys
versitygw utils encryption-key generate \
  --directory /etc/versitygw/keys \
  --key-id iam-2026-01 \
  --activate
```

Point the gateway at it:

```bash
versitygw --iam-dir /var/lib/versitygw/iam \
  --iam-encryption-key-directory /etc/versitygw/keys \
  --iam-encryption-required \
  posix /var/lib/versitygw/data
```

The standalone IAM API server takes the same settings without the `iam-`
prefix, because every flag of that command is IAM-scoped already:

```bash
versitygw --port :7070 iam \
  --dir /var/lib/versitygw/iamapi \
  --encryption-key-directory /etc/versitygw/keys \
  --encryption-required
```

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--iam-encryption-key-directory` | `VGW_IAM_ENCRYPTION_KEY_DIRECTORY` | protected local wrapping keys |
| `--iam-encryption-active-key` | `VGW_IAM_ENCRYPTION_ACTIVE_KEY` | key ID to write with (default: the directory's `active` file) |
| `--iam-encryption-kms-provider` | `VGW_IAM_ENCRYPTION_KMS_PROVIDER` | `local` (default) or `aws` |
| `--iam-encryption-kms-key-id` | `VGW_IAM_ENCRYPTION_KMS_KEY_ID` | AWS KMS key or alias (required for `aws`) |
| `--iam-encryption-kms-timeout` | `VGW_IAM_ENCRYPTION_KMS_TIMEOUT` | per-call KMS timeout |
| `--iam-encryption-required` | `VGW_IAM_ENCRYPTION_REQUIRED` | refuse to start against a plaintext store |

A store the gateway creates itself is encrypted from its first byte. The key
directory may be shared with object encryption: the IAM store derives its own
wrapping key from the key file, so an IAM container and an object container can
never be opened with each other's key.

## Migrating an existing deployment

The gateway never changes the format of a store it did not create. The first
encrypted write would make the file unreadable for every other gateway sharing
the directory, so the switch is an explicit step:

1. Distribute the key directory to every gateway that shares the IAM directory.
2. Restart each gateway with `--iam-encryption-key-directory` (without
   `--iam-encryption-required`). Each one logs a warning that the store is
   still plaintext and keeps writing plaintext.
3. Stop the writers, or accept that an update racing the migration is lost the
   same way concurrent updates are lost today, and convert the store:

   ```bash
   versitygw utils iam-encryption encrypt \
     --dir /var/lib/versitygw/iam \
     --encryption-key-directory /etc/versitygw/keys
   ```

   Add `--file iam.json` for the IAM API server's database.
4. Restart with `--iam-encryption-required` so a plaintext store can no longer
   go unnoticed.

`versitygw utils iam-encryption status --dir <dir>` reports the stored format
and key reference of the store and its backup. It reads only the container
header, so it needs no access to the wrapping key.

## Key rotation

Generate the next key, activate it, and rewrap. Rewrapping replaces the wrapped
data key and leaves the encrypted payload untouched:

```bash
versitygw utils encryption-key generate \
  --directory /etc/versitygw/keys --key-id iam-2026-07 --activate
versitygw utils iam-encryption rewrap \
  --dir /var/lib/versitygw/iam \
  --encryption-key-directory /etc/versitygw/keys
```

Keep the previous key file in the directory until every store and backup that
references it has been rewrapped.

## Rolling back

```bash
versitygw utils iam-encryption decrypt \
  --dir /var/lib/versitygw/iam \
  --encryption-key-directory /etc/versitygw/keys
```

The store and its backup return to plaintext JSON, readable by a gateway with
no encryption configuration at all. Do this before removing the key directory,
not after: an encrypted store without its key is unrecoverable, and the gateway
refuses to start rather than silently coming up empty.

## AWS KMS

`--iam-encryption-kms-provider aws` wraps the store's data key with AWS KMS
instead of a local key. It requires `--iam-encryption-kms-key-id` and rejects
the local key directory and active key, so there is never a doubt about which
key is in use.

The gateway calls KMS only when the store's bytes actually change, not per
request and not per cache refresh, because an unchanged file revalidates the
plaintext already held in memory. A KMS outage therefore does not stall
authentication against an unchanged store, but it does block the next update
and any gateway starting up.

## Operational notes

- **Reads come from memory.** The decrypted store is cached in process memory
  for one second. After that the file is read again — which is what forces an
  NFS client to revalidate — but it is decrypted only when its bytes changed,
  so a gateway serving thousands of requests per second performs one read per
  second and no decryption at all while nothing changes. A write by another
  gateway sharing the directory therefore becomes visible within a second,
  which is well inside the account cache window (`--iam-cache-ttl`) that sits
  above it. Nothing decrypted is ever written back to disk.
- **Backups.** Copy the key directory and the IAM directory together, and keep
  them apart from each other in storage — a backup holding both is a backup of
  plaintext credentials.
- **File permissions still matter.** The store stays `0600`, and the key
  directory must be `0700` and owned by the gateway user; the gateway refuses
  to start otherwise.
- **The root account is not part of the store.** `ROOT_ACCESS_KEY` and
  `ROOT_SECRET_KEY` are read from the environment at startup and are not
  written to `users.json`. Passing them as command-line flags exposes them in
  `ps`; use the environment variables.

See [S3 Server-Side Encryption](s3-encryption.md) for object encryption, which
shares the key ring and the container format.
