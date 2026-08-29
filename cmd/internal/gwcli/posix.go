// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package gwcli

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/backend/posix"
	"github.com/versity/versitygw/internal/encryption"
)

var (
	chownuid, chowngid    bool
	bucketlinks           bool
	versioningDir         string
	dirPerms              uint
	sidecar               string
	nometa                bool
	forceNoTmpFile        bool
	forceNoCopyFileRange  bool
	enableODirect         bool
	actionsConcurrency    int
	ioBufferSize          int
	defaultEtag           string
	dataIntegrityEtag     bool
	encryptionKeyDir      string
	encryptionActiveKey   string
	encryptionKMSProvider string
	encryptionKMSKeyID    string
	encryptionKMSTimeout  time.Duration
	lifecycleArchiveTiers cli.StringSlice
)

// PosixCommand returns the "posix" subcommand, common to all versitygw
// binaries.
func PosixCommand() *cli.Command {
	return &cli.Command{
		Name:  "posix",
		Usage: "posix filesystem storage backend",
		Description: `Any posix filesystem that supports extended attributes. The top level
directory for the gateway must be provided. All sub directories of the
top level directory are treated as buckets, and all files/directories
below the "bucket directory" are treated as the objects. The object
name is split on "/" separator to translate to posix storage.
For example:
top level: /mnt/fs/gwroot
bucket: mybucket
object: a/b/c/myobject
will be translated into the file /mnt/fs/gwroot/mybucket/a/b/c/myobject`,
		Action: runPosix,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "chuid",
				Usage:       "chown newly created files and directories to client account UID",
				EnvVars:     []string{"VGW_CHOWN_UID"},
				Destination: &chownuid,
			},
			&cli.BoolFlag{
				Name:        "chgid",
				Usage:       "chown newly created files and directories to client account GID",
				EnvVars:     []string{"VGW_CHOWN_GID"},
				Destination: &chowngid,
			},
			&cli.BoolFlag{
				Name:        "bucketlinks",
				Usage:       "allow symlinked directories at bucket level to be treated as buckets",
				EnvVars:     []string{"VGW_BUCKET_LINKS"},
				Destination: &bucketlinks,
			},
			&cli.StringFlag{
				Name:        "versioning-dir",
				Usage:       "the directory path to enable bucket versioning",
				EnvVars:     []string{"VGW_VERSIONING_DIR"},
				Destination: &versioningDir,
			},
			&cli.UintFlag{
				Name:        "dir-perms",
				Usage:       "default directory permissions for new directories",
				EnvVars:     []string{"VGW_DIR_PERMS"},
				Destination: &dirPerms,
				DefaultText: "0755",
				Value:       0755,
			},
			&cli.StringFlag{
				Name:        "sidecar",
				Usage:       "use provided sidecar directory to store metadata",
				EnvVars:     []string{"VGW_META_SIDECAR"},
				Destination: &sidecar,
			},
			&cli.IntFlag{
				Name:        "concurrency",
				Usage:       "maximum concurrent actions allowed",
				EnvVars:     []string{"VGW_POSIX_CONCURRENCY"},
				Value:       5000,
				Destination: &actionsConcurrency,
			},
			&cli.IntFlag{
				Name:        "io-buffer-size",
				Usage:       "buffer size in bytes used by POSIX put/get/part read and write paths (<=0 uses backend default 1MiB)",
				EnvVars:     []string{"VGW_POSIX_IO_BUFFER_SIZE"},
				Value:       1024 * 1024,
				Destination: &ioBufferSize,
			},
			&cli.BoolFlag{
				Name:        "nometa",
				Usage:       "disable metadata storage",
				EnvVars:     []string{"VGW_META_NONE"},
				Destination: &nometa,
			},
			&cli.BoolFlag{
				Name:        "disableotmp",
				Usage:       "disable O_TMPFILE support for new objects",
				EnvVars:     []string{"VGW_DISABLE_OTMP"},
				Destination: &forceNoTmpFile,
			},
			&cli.BoolFlag{
				Name:        "disable-copy-file-range",
				Usage:       "explicitly copy multipart upload parts instead of using copy_file_range (which may hang with some NFS servers)",
				EnvVars:     []string{"VGW_DISABLE_COPY_FILE_RANGE"},
				Destination: &forceNoCopyFileRange,
			},
			&cli.BoolFlag{
				Name:        "enable-odirect",
				Usage:       "enable best-effort O_DIRECT for object data reads/writes",
				EnvVars:     []string{"VGW_ENABLE_O_DIRECT"},
				Destination: &enableODirect,
			},
			&cli.StringFlag{
				Name:        "default-etag",
				Usage:       "default ETag value returned for objects that do not have a stored etag attribute (e.g. files placed on the filesystem outside of versitygw)",
				EnvVars:     []string{"VGW_DEFAULT_ETAG"},
				Destination: &defaultEtag,
			},
			&cli.BoolFlag{
				Name:        "data-integrity-etag",
				Usage:       "use data-integrity checksum-derived ETags instead of MD5-based ETags (PUT object ETag, multipart part ETags, and completed multipart object ETag)",
				EnvVars:     []string{"VGW_DATA_INTEGRITY_ETAG"},
				Destination: &dataIntegrityEtag,
			},
			&cli.StringFlag{
				Name:        "encryption-key-directory",
				Usage:       "directory containing protected local encryption key files",
				EnvVars:     []string{"VGW_ENCRYPTION_KEY_DIRECTORY"},
				Destination: &encryptionKeyDir,
			},
			&cli.StringFlag{
				Name:        "encryption-active-key",
				Usage:       "active local encryption key ID (defaults to the key directory's active file)",
				EnvVars:     []string{"VGW_ENCRYPTION_ACTIVE_KEY"},
				Destination: &encryptionActiveKey,
			},
			&cli.StringFlag{
				Name:        "encryption-kms-provider",
				Usage:       "SSE-KMS provider: local or aws; AWS configuration is loaded only when aws is selected",
				EnvVars:     []string{"VGW_ENCRYPTION_KMS_PROVIDER"},
				Destination: &encryptionKMSProvider,
			},
			&cli.StringFlag{
				Name:        "encryption-kms-key-id",
				Usage:       "default AWS KMS key ID or alias",
				EnvVars:     []string{"VGW_ENCRYPTION_KMS_KEY_ID"},
				Destination: &encryptionKMSKeyID,
			},
			&cli.DurationFlag{
				Name:        "encryption-kms-timeout",
				Usage:       "maximum duration of one AWS KMS operation",
				EnvVars:     []string{"VGW_ENCRYPTION_KMS_TIMEOUT"},
				Value:       10 * time.Second,
				Destination: &encryptionKMSTimeout,
			},
			&cli.StringSliceFlag{
				Name:        "lifecycle-archive-tier",
				Usage:       "repeatable STORAGE_CLASS=/absolute/archive/root mapping for POSIX Lifecycle transitions",
				EnvVars:     []string{"VGW_LIFECYCLE_ARCHIVE_TIERS"},
				Destination: &lifecycleArchiveTiers,
			},
		},
	}
}

func runPosix(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return fmt.Errorf("no directory provided for operation")
	}

	gwroot := (ctx.Args().Get(0))

	if dirPerms > math.MaxUint32 {
		return fmt.Errorf("invalid directory permissions: %d", dirPerms)
	}

	if nometa && sidecar != "" {
		return fmt.Errorf("cannot use both nometa and sidecar metadata")
	}

	if actionsConcurrency <= 0 {
		return fmt.Errorf("concurrency must be positive, got %d", actionsConcurrency)
	}

	opts := posix.PosixOpts{
		ChownUID:             chownuid,
		ChownGID:             chowngid,
		BucketLinks:          bucketlinks,
		VersioningDir:        versioningDir,
		NewDirPerm:           fs.FileMode(dirPerms),
		ForceNoTmpFile:       forceNoTmpFile,
		ForceNoCopyFileRange: forceNoCopyFileRange,
		EnableODirect:        enableODirect,
		ValidateBucketNames:  DisableStrictBucketNames,
		Concurrency:          actionsConcurrency,
		IOBufferSize:         ioBufferSize,
		CopyObjectThreshold:  CopyObjectThreshold,
		DefaultEtag:          defaultEtag,
		DataIntegrityEtag:    dataIntegrityEtag,
	}
	primaryProvider, managedProvider, err := loadEncryptionProviders(ctx.Context)
	if err != nil {
		return err
	}
	opts.EncryptionProvider = primaryProvider
	opts.ManagedEncryptionProvider = managedProvider
	opts.EncryptionKeyDirectory = encryptionKeyDir
	opts.ArchiveTiers, err = parseArchiveTierFlags(lifecycleArchiveTiers.Value())
	if err != nil {
		return err
	}

	var ms meta.MetadataStorer
	switch {
	case sidecar != "":
		sc, err := meta.NewSideCar(sidecar)
		if err != nil {
			return fmt.Errorf("failed to init sidecar metadata: %w", err)
		}
		ms = sc
		opts.SideCarDir = sidecar
	case nometa:
		ms = meta.NoMeta{}
	default:
		ms = meta.XattrMeta{}
		err := meta.XattrMeta{}.Test(gwroot)
		if err != nil {
			return fmt.Errorf("xattr check failed: %w", err)
		}
	}

	be, err := posix.New(gwroot, ms, opts)
	if err != nil {
		return fmt.Errorf("failed to init posix backend: %w", err)
	}

	return RunGateway(ctx.Context, be)
}

func parseArchiveTierFlags(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	result := make(map[string]string, len(values))
	for _, value := range values {
		storageClass, root, found := strings.Cut(value, "=")
		storageClass = strings.ToUpper(strings.TrimSpace(storageClass))
		root = strings.TrimSpace(root)
		if !found || storageClass == "" || root == "" {
			return nil, fmt.Errorf("invalid lifecycle archive tier %q: expected STORAGE_CLASS=/absolute/path", value)
		}
		if _, exists := result[storageClass]; exists {
			return nil, fmt.Errorf("duplicate lifecycle archive tier %q", storageClass)
		}
		result[storageClass] = root
	}
	return result, nil
}

func loadEncryptionProviders(ctx context.Context) (encryption.KeyProvider, encryption.KeyProvider, error) {
	return loadEncryptionProvidersFrom(ctx, encryptionKeyDir, encryptionActiveKey, encryptionKMSProvider, encryptionKMSKeyID, encryptionKMSTimeout)
}

func loadEncryptionProvidersFrom(ctx context.Context, keyDirectory, activeKey, kmsProvider, kmsKeyID string, kmsTimeout time.Duration) (encryption.KeyProvider, encryption.KeyProvider, error) {
	selected := strings.ToLower(strings.TrimSpace(kmsProvider))
	if keyDirectory == "" {
		if activeKey != "" || selected != "" || kmsKeyID != "" {
			return nil, nil, fmt.Errorf("encryption provider settings require encryption-key-directory")
		}
		return nil, nil, nil
	}
	managed, err := encryption.NewLocalProvider(keyDirectory, activeKey)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize local encryption provider: %w", err)
	}
	if selected == "" || selected == "local" {
		if kmsKeyID != "" {
			managed.Close()
			return nil, nil, fmt.Errorf("encryption-kms-key-id requires encryption-kms-provider=aws")
		}
		return managed, managed, nil
	}
	if selected != "aws" {
		managed.Close()
		return nil, nil, fmt.Errorf("unsupported encryption KMS provider %q", kmsProvider)
	}
	awsConfiguration, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		managed.Close()
		return nil, nil, fmt.Errorf("load AWS configuration for encryption KMS: %w", err)
	}
	primary, err := encryption.NewAWSKMSProvider(kms.NewFromConfig(awsConfiguration), kmsKeyID, kmsTimeout)
	if err != nil {
		managed.Close()
		return nil, nil, fmt.Errorf("initialize AWS KMS encryption provider: %w", err)
	}
	return primary, managed, nil
}
