// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package lifecycle

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAndMarshalConfiguration(t *testing.T) {
	t.Parallel()

	body := []byte(`<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>retain</ID><Filter><And><Prefix>logs/</Prefix><Tag><Key>archive</Key><Value>true</Value></Tag></And></Filter><Status>Enabled</Status><Expiration><Days>365</Days></Expiration><NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`)
	configuration, err := Parse(body, Capabilities{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := *configuration.Rules[0].NoncurrentVersionExpiration.NewerNoncurrentVersions; got != 3 {
		t.Fatalf("NewerNoncurrentVersions = %d, want 3", got)
	}

	encoded, err := Marshal(configuration)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(encoded), `xmlns="`+Namespace+`"`) {
		t.Fatalf("Marshal() omitted namespace: %s", encoded)
	}
	if _, err := Parse(encoded, Capabilities{}); err != nil {
		t.Fatalf("canonical XML did not round-trip: %v", err)
	}
}

func TestParseRejectsInvalidConfigurations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xml  string
		kind ErrorKind
	}{
		{name: "empty rules", xml: `<LifecycleConfiguration/>`, kind: ErrorMalformedXML},
		{name: "invalid status", xml: `<LifecycleConfiguration><Rule><Filter/><Status>Active</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`, kind: ErrorMalformedXML},
		{name: "missing action", xml: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status></Rule></LifecycleConfiguration>`, kind: ErrorInvalidRequest},
		{name: "prefix and filter", xml: `<LifecycleConfiguration><Rule><Prefix>a</Prefix><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`, kind: ErrorInvalidRequest},
		{name: "retention zero", xml: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>0</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`, kind: ErrorInvalidArgument},
		{name: "retention over maximum", xml: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>101</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`, kind: ErrorInvalidArgument},
		{name: "retention without filter", xml: `<LifecycleConfiguration><Rule><Prefix></Prefix><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`, kind: ErrorInvalidRequest},
		{name: "tag and multipart", xml: `<LifecycleConfiguration><Rule><Filter><Tag><Key>a</Key><Value>b</Value></Tag></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>`, kind: ErrorInvalidRequest},
		{name: "non-midnight date", xml: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Expiration><Date>2026-08-28T01:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>`, kind: ErrorInvalidRequest},
		{name: "unsupported transition", xml: `<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Transition><Days>0</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>`, kind: ErrorInvalidRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte(test.xml), Capabilities{})
			var validationError ValidationError
			if !errors.As(err, &validationError) {
				t.Fatalf("Parse() error = %v, want ValidationError", err)
			}
			if validationError.Kind != test.kind {
				t.Fatalf("Parse() kind = %s, want %s", validationError.Kind, test.kind)
			}
		})
	}
}

func TestParseAcceptsSupportedTransition(t *testing.T) {
	t.Parallel()

	body := []byte(`<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Transition><Days>0</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>`)
	_, err := Parse(body, Capabilities{Transitions: map[string]bool{"GLACIER": true}})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsUnknownAndDuplicateElements(t *testing.T) {
	for _, body := range []string{
		`<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Unknown/></Rule></LifecycleConfiguration>`,
		`<LifecycleConfiguration><Rule><Filter/><Status>Enabled</Status><Status>Disabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`,
	} {
		_, err := Parse([]byte(body), Capabilities{})
		var validation ValidationError
		if !errors.As(err, &validation) || validation.Kind != ErrorMalformedXML {
			t.Fatalf("Parse() error = %v, want MalformedXML", err)
		}
	}
}

func TestNormalizeTransitionMinimum(t *testing.T) {
	t.Parallel()

	if got, err := NormalizeTransitionMinimum(""); err != nil || got != TransitionMinimumAllStorageClasses128K {
		t.Fatalf("NormalizeTransitionMinimum(empty) = %q, %v", got, err)
	}
	if _, err := NormalizeTransitionMinimum("invalid"); err == nil {
		t.Fatal("NormalizeTransitionMinimum() accepted invalid value")
	}
}
