// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package azure

import (
	"errors"
	"testing"

	"github.com/versity/versitygw/internal/lifecycle"
	"github.com/versity/versitygw/s3err"
)

func TestAzureLifecycleProtectionFailsClosed(t *testing.T) {
	tests := []struct {
		name         string
		holdErr      error
		retention    []byte
		retentionErr error
		wantErr      bool
	}{
		{name: "legal hold lookup failure", holdErr: errors.New("metadata unavailable"), wantErr: true},
		{name: "retention lookup failure", retentionErr: errors.New("metadata unavailable"), wantErr: true},
		{name: "corrupt retention", retention: []byte(`{"Mode":"GOVERNANCE"`), wantErr: true},
		{
			name:         "missing lock metadata is unprotected",
			holdErr:      s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration),
			retentionErr: s3err.GetAPIError(s3err.ErrNoSuchObjectLockConfiguration),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := azureLifecycleObjectProtected(nil, test.holdErr, test.retention, test.retentionErr)
			if (err != nil) != test.wantErr {
				t.Fatalf("azureLifecycleObjectProtected() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestAzureLifecycleMutationGuardRejectsLostLease(t *testing.T) {
	az := &Azure{lifecycleLeases: make(map[string]*azureLifecycleLease)}
	active := &azureLifecycleLease{}
	az.lifecycleLeases["bucket"] = active
	if err := az.activeLifecycleLease("bucket"); err != nil {
		t.Fatalf("activeLifecycleLease() with active lease = %v", err)
	}
	active.lost.Store(true)
	if err := az.activeLifecycleLease("bucket"); !errors.Is(err, lifecycle.ErrLeaseUnavailable) {
		t.Fatalf("activeLifecycleLease() after loss = %v", err)
	}
}
