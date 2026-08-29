// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package s3event

import "testing"

func TestBackgroundLifecycleEventUsesServiceIdentity(t *testing.T) {
	version := "version"
	schema := createBackgroundEventSchema(BackgroundEventMeta{
		EventMeta: EventMeta{EventName: EventObjectRemovedDelete, ObjectSize: 42, VersionId: &version},
		Region:    "us-east-1", Bucket: "bucket", Key: "path/object",
	}, ConfigurationIdWebhook)
	if len(schema.Records) != 1 {
		t.Fatalf("records = %d", len(schema.Records))
	}
	record := schema.Records[0]
	if record.UserIdentity.PrincipalId != "versitygw:lifecycle" || record.S3.Bucket.Name != "bucket" || record.S3.Object.Key != "path/object" || record.S3.Object.VersionId == nil || *record.S3.Object.VersionId != version {
		t.Fatalf("background event = %#v", record)
	}
}
