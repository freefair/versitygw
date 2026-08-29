// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package lifecycle

import (
	"testing"
	"time"
)

func TestEvaluateCurrentExpirationByVersioningState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days := int32(1)
	configuration := Configuration{Rules: []Rule{{Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{Days: &days}}}}
	tests := []struct {
		name       string
		versioning VersioningState
		want       ActionKind
	}{
		{name: "never versioned", versioning: VersioningNever, want: ActionDeleteCurrent},
		{name: "enabled", versioning: VersioningEnabled, want: ActionCreateDeleteMarker},
		{name: "suspended", versioning: VersioningSuspended, want: ActionExpireSuspendedCurrent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			actions := Evaluate(configuration, []Candidate{{
				Kind: CandidateObject, Key: "key", Current: true, Versioning: test.versioning,
				LastModified: now.Add(-72 * time.Hour),
			}}, now)
			if len(actions) != 1 || actions[0].Kind != test.want {
				t.Fatalf("Evaluate() = %#v, want %s", actions, test.want)
			}
		})
	}
}

func TestEvaluateRoundsAgeToFollowingMidnightUTC(t *testing.T) {
	t.Parallel()

	days := int32(1)
	configuration := Configuration{Rules: []Rule{{Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{Days: &days}}}}
	candidate := Candidate{Kind: CandidateObject, Key: "key", Current: true, LastModified: time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)}
	if actions := Evaluate(configuration, []Candidate{candidate}, time.Date(2026, 8, 27, 23, 59, 59, 0, time.UTC)); len(actions) != 0 {
		t.Fatalf("object expired before rounded midnight: %#v", actions)
	}
	if actions := Evaluate(configuration, []Candidate{candidate}, time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)); len(actions) != 1 {
		t.Fatalf("object did not expire at rounded midnight: %#v", actions)
	}
}

func TestEvaluateRetainsNewestNoncurrentVersions(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days, keep := int32(1), int32(2)
	configuration := Configuration{Rules: []Rule{{Filter: &Filter{}, Status: "Enabled", NoncurrentVersionExpiration: &NoncurrentVersionExpiration{
		NoncurrentDays: &days, NewerNoncurrentVersions: &keep,
	}}}}
	candidates := []Candidate{
		{Kind: CandidateObject, Key: "key", VersionID: "v3", NoncurrentSince: now.Add(-72 * time.Hour)},
		{Kind: CandidateObject, Key: "key", VersionID: "marker", DeleteMarker: true, NoncurrentSince: now.Add(-96 * time.Hour)},
		{Kind: CandidateObject, Key: "key", VersionID: "v2", NoncurrentSince: now.Add(-120 * time.Hour)},
		{Kind: CandidateObject, Key: "key", VersionID: "v1", NoncurrentSince: now.Add(-144 * time.Hour)},
	}
	actions := Evaluate(configuration, candidates, now)
	if len(actions) != 1 || actions[0].VersionID != "v1" || actions[0].Kind != ActionDeleteVersion {
		t.Fatalf("Evaluate() = %#v, want DeleteVersion v1", actions)
	}
}

func TestEvaluateExpiredDeleteMarkerOnlyWhenLoneVersion(t *testing.T) {
	t.Parallel()

	expire := true
	configuration := Configuration{Rules: []Rule{{Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{ExpiredObjectDeleteMarker: &expire}}}}
	marker := Candidate{Kind: CandidateObject, Key: "key", VersionID: "marker", Current: true, DeleteMarker: true}
	if actions := Evaluate(configuration, []Candidate{marker}, time.Now()); len(actions) != 1 || actions[0].Kind != ActionDeleteVersion {
		t.Fatalf("lone marker actions = %#v", actions)
	}
	older := Candidate{Kind: CandidateObject, Key: "key", VersionID: "old"}
	if actions := Evaluate(configuration, []Candidate{marker, older}, time.Now()); len(actions) != 0 {
		t.Fatalf("marker with older version actions = %#v", actions)
	}
}

func TestEvaluatePermanentDeletionWinsOverTransition(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days := int32(1)
	configuration := Configuration{Rules: []Rule{
		{Filter: &Filter{}, Status: "Enabled", Transitions: []Transition{{Days: &days, StorageClass: "GLACIER"}}},
		{Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{Days: &days}},
	}}
	actions := Evaluate(configuration, []Candidate{{Kind: CandidateObject, Key: "key", Current: true, LastModified: now.Add(-72 * time.Hour)}}, now)
	if len(actions) != 1 || actions[0].Kind != ActionDeleteCurrent {
		t.Fatalf("Evaluate() = %#v, want permanent deletion", actions)
	}
}

func TestEvaluateSameRuleTransitionBeatsDeleteMarkerCreation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 29, 0, 0, 0, 0, time.UTC)
	days := int32(1)
	configuration := Configuration{
		TransitionDefaultMinimumObjectSize: TransitionMinimumVariesByStorageClass,
		Rules: []Rule{{
			Filter: &Filter{}, Status: "Enabled", Expiration: &Expiration{Days: &days},
			Transitions: []Transition{{Days: &days, StorageClass: "GLACIER"}},
		}},
	}
	candidate := Candidate{
		Kind: CandidateObject, Key: "key", Current: true, Versioning: VersioningEnabled,
		LastModified: now.Add(-72 * time.Hour), Size: 256 * 1024,
	}
	actions := Evaluate(configuration, []Candidate{candidate}, now)
	if len(actions) != 1 || actions[0].Kind != ActionTransition {
		t.Fatalf("Evaluate() = %#v, want Transition", actions)
	}
}

func TestEvaluateMatchesExclusiveSizeAndTagFilters(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days := int32(1)
	greater, less := int64(10), int64(20)
	configuration := Configuration{Rules: []Rule{{Status: "Enabled", Filter: &Filter{And: &AndOperator{
		Prefix: stringPointer("logs/"), Tags: []Tag{{Key: "expire", Value: "yes"}}, ObjectSizeGreaterThan: &greater, ObjectSizeLessThan: &less,
	}}, Expiration: &Expiration{Days: &days}}}}
	base := Candidate{Kind: CandidateObject, Key: "logs/a", Current: true, Size: 15, Tags: map[string]string{"expire": "yes"}, LastModified: now.Add(-72 * time.Hour)}
	if actions := Evaluate(configuration, []Candidate{base}, now); len(actions) != 1 {
		t.Fatalf("matching candidate actions = %#v", actions)
	}
	base.Size = 10
	if actions := Evaluate(configuration, []Candidate{base}, now); len(actions) != 0 {
		t.Fatalf("exclusive boundary candidate actions = %#v", actions)
	}
}

func TestEvaluateAppliesTransitionDefaultMinimumObjectSize(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	days := int32(0)
	baseRule := Rule{Filter: &Filter{}, Status: "Enabled", Transitions: []Transition{{Days: &days, StorageClass: "GLACIER"}}}
	candidate := Candidate{Kind: CandidateObject, Key: "small", Current: true, Size: 128*1024 - 1, LastModified: now.Add(-48 * time.Hour)}

	configuration := Configuration{TransitionDefaultMinimumObjectSize: TransitionMinimumAllStorageClasses128K, Rules: []Rule{baseRule}}
	if actions := Evaluate(configuration, []Candidate{candidate}, now); len(actions) != 0 {
		t.Fatalf("small object transitioned under 128K default: %#v", actions)
	}
	configuration.TransitionDefaultMinimumObjectSize = TransitionMinimumVariesByStorageClass
	if actions := Evaluate(configuration, []Candidate{candidate}, now); len(actions) != 1 {
		t.Fatalf("small Glacier object did not transition under legacy default: %#v", actions)
	}

	greaterThan := int64(0)
	baseRule.Filter = &Filter{ObjectSizeGreaterThan: &greaterThan}
	configuration = Configuration{TransitionDefaultMinimumObjectSize: TransitionMinimumAllStorageClasses128K, Rules: []Rule{baseRule}}
	if actions := Evaluate(configuration, []Candidate{candidate}, now); len(actions) != 1 {
		t.Fatalf("explicit size filter did not override transition default: %#v", actions)
	}
}

func TestEvaluateTransitionNeverMovesBackwardAndChoosesLowestCost(t *testing.T) {
	days := int32(0)
	now := time.Now().UTC()
	configuration := Configuration{
		TransitionDefaultMinimumObjectSize: TransitionMinimumVariesByStorageClass,
		Rules: []Rule{
			{Filter: &Filter{}, Status: "Enabled", Transitions: []Transition{{Days: &days, StorageClass: "STANDARD_IA"}}},
			{Filter: &Filter{}, Status: "Enabled", Transitions: []Transition{{Days: &days, StorageClass: "GLACIER"}}},
		},
	}
	candidate := Candidate{
		Kind: CandidateObject, Bucket: "bucket", Key: "key", Current: true,
		LastModified: now.Add(-24 * time.Hour), Size: 256 * 1024, StorageClass: "STANDARD",
	}
	actions := Evaluate(configuration, []Candidate{candidate}, now)
	if len(actions) != 1 || actions[0].TargetStorageClass != "GLACIER" {
		t.Fatalf("STANDARD transition = %#v, want GLACIER", actions)
	}
	candidate.StorageClass = "GLACIER"
	if actions = Evaluate(configuration, []Candidate{candidate}, now); len(actions) != 0 {
		t.Fatalf("GLACIER moved backward: %#v", actions)
	}
}

func stringPointer(value string) *string { return &value }
