// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package lifecycle

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

type VersioningState string

const (
	VersioningNever     VersioningState = "Never"
	VersioningEnabled   VersioningState = "Enabled"
	VersioningSuspended VersioningState = "Suspended"
)

type CandidateKind string

const (
	CandidateObject    CandidateKind = "Object"
	CandidateMultipart CandidateKind = "Multipart"
)

type Candidate struct {
	Kind            CandidateKind
	Bucket          string
	Key             string
	VersionID       string
	UploadID        string
	ETag            string
	StateToken      string
	Current         bool
	DeleteMarker    bool
	Protected       bool
	Versioning      VersioningState
	Size            int64
	LastModified    time.Time
	NoncurrentSince time.Time
	NoncurrentRank  int
	VersionsForKey  int
	StorageClass    string
	Tags            map[string]string
}

type ActionKind string

const (
	ActionDeleteCurrent          ActionKind = "DeleteCurrent"
	ActionCreateDeleteMarker     ActionKind = "CreateDeleteMarker"
	ActionExpireSuspendedCurrent ActionKind = "ExpireSuspendedCurrent"
	ActionDeleteVersion          ActionKind = "DeleteVersion"
	ActionAbortMultipart         ActionKind = "AbortMultipart"
	ActionTransition             ActionKind = "Transition"
)

type Action struct {
	Kind               ActionKind
	Bucket             string
	Key                string
	VersionID          string
	UploadID           string
	ETag               string
	StateToken         string
	ObservedAt         time.Time
	Current            bool
	RuleID             string
	TargetStorageClass string
	Size               int64
}

// Evaluate selects at most one effective action for each candidate.
func Evaluate(configuration Configuration, candidates []Candidate, now time.Time) []Action {
	now = now.UTC()
	noncurrentRanks := calculateNoncurrentRanks(candidates)
	versionCounts := calculateVersionCounts(candidates)
	actions := make([]Action, 0)
	for index, candidate := range candidates {
		var selected Action
		selectedPriority := 0
		for ruleIndex, rule := range configuration.Rules {
			if rule.Status != "Enabled" || !matches(rule, candidate) {
				continue
			}
			action, priority, ok := evaluateRule(configuration, rule, candidate, noncurrentRanks[index], versionCounts[candidate.Key], now)
			if !ok || priority < selectedPriority || (priority == selectedPriority && !preferLifecycleAction(action, selected)) {
				continue
			}
			action.Bucket = candidate.Bucket
			action.Key = candidate.Key
			action.VersionID = candidate.VersionID
			action.UploadID = candidate.UploadID
			action.ETag = candidate.ETag
			action.StateToken = candidate.StateToken
			action.Current = candidate.Current
			action.Size = candidate.Size
			if candidate.Kind == CandidateMultipart {
				action.ObservedAt = candidate.LastModified
			} else if candidate.Current {
				action.ObservedAt = candidate.LastModified
			} else {
				action.ObservedAt = candidate.NoncurrentSince
			}
			if rule.ID != nil {
				action.RuleID = *rule.ID
			} else {
				action.RuleID = "rule-" + strconv.Itoa(ruleIndex+1)
			}
			selected = action
			selectedPriority = priority
		}
		if selectedPriority != 0 {
			actions = append(actions, selected)
		}
	}
	return actions
}

func evaluateRule(configuration Configuration, rule Rule, candidate Candidate, noncurrentRank, versionsForKey int, now time.Time) (Action, int, bool) {
	if candidate.Kind == CandidateMultipart {
		if rule.AbortIncompleteMultipartUpload != nil && eligibleByDays(candidate.LastModified, *rule.AbortIncompleteMultipartUpload.DaysAfterInitiation, now) {
			return Action{Kind: ActionAbortMultipart}, 3, true
		}
		return Action{}, 0, false
	}

	if candidate.Current {
		if candidate.DeleteMarker {
			if rule.Expiration != nil && rule.Expiration.ExpiredObjectDeleteMarker != nil && *rule.Expiration.ExpiredObjectDeleteMarker && versionsForKey == 1 && !candidate.Protected {
				return Action{Kind: ActionDeleteVersion}, 3, true
			}
			return Action{}, 0, false
		}
		var expirationAction Action
		expirationPriority := 0
		if rule.Expiration != nil && expirationEligible(*rule.Expiration, candidate.LastModified, now) {
			switch candidate.Versioning {
			case VersioningEnabled:
				expirationAction, expirationPriority = Action{Kind: ActionCreateDeleteMarker}, 1
			case VersioningSuspended:
				return Action{Kind: ActionExpireSuspendedCurrent}, 3, true
			default:
				if !candidate.Protected {
					return Action{Kind: ActionDeleteCurrent}, 3, true
				}
			}
		}
		if target, ok := selectTransition(configuration, rule, candidate, candidate.LastModified, now, rule.Transitions); ok {
			return Action{Kind: ActionTransition, TargetStorageClass: target}, 2, true
		}
		if expirationPriority != 0 {
			return expirationAction, expirationPriority, true
		}
		return Action{}, 0, false
	}

	if candidate.DeleteMarker {
		return Action{}, 0, false
	}
	if rule.NoncurrentVersionExpiration != nil && !candidate.Protected {
		expiration := rule.NoncurrentVersionExpiration
		countEligible := expiration.NewerNoncurrentVersions == nil || noncurrentRank > int(*expiration.NewerNoncurrentVersions)
		if countEligible && eligibleByDays(candidate.NoncurrentSince, *expiration.NoncurrentDays, now) {
			return Action{Kind: ActionDeleteVersion}, 3, true
		}
	}
	selectedTransition := ""
	for _, transition := range rule.NoncurrentVersionTransitions {
		countEligible := transition.NewerNoncurrentVersions == nil || noncurrentRank > int(*transition.NewerNoncurrentVersions)
		if countEligible && eligibleByDays(candidate.NoncurrentSince, *transition.NoncurrentDays, now) && transitionSizeEligible(configuration, rule, candidate, transition.StorageClass) && lifecycleTransitionAllowed(candidate.StorageClass, transition.StorageClass) && preferStorageClass(transition.StorageClass, selectedTransition) {
			selectedTransition = transition.StorageClass
		}
	}
	if selectedTransition != "" {
		return Action{Kind: ActionTransition, TargetStorageClass: selectedTransition}, 2, true
	}
	return Action{}, 0, false
}

func selectTransition(configuration Configuration, rule Rule, candidate Candidate, observedAt, now time.Time, transitions []Transition) (string, bool) {
	selected := ""
	for _, transition := range transitions {
		if transitionEligible(transition, observedAt, now) && transitionSizeEligible(configuration, rule, candidate, transition.StorageClass) && lifecycleTransitionAllowed(candidate.StorageClass, transition.StorageClass) && preferStorageClass(transition.StorageClass, selected) {
			selected = transition.StorageClass
		}
	}
	return selected, selected != ""
}

func preferLifecycleAction(candidate, selected Action) bool {
	if candidate.Kind != ActionTransition || selected.Kind != ActionTransition {
		return false
	}
	return preferStorageClass(candidate.TargetStorageClass, selected.TargetStorageClass)
}

func preferStorageClass(candidate, selected string) bool {
	if selected == "" {
		return true
	}
	return lifecycleStorageClassPreference(candidate) > lifecycleStorageClassPreference(selected)
}

// lifecycleStorageClassPreference implements Amazon S3's same-day conflict
// rule: select the lower-cost class, with Intelligent-Tiering preferred over
// non-archive classes and Glacier classes preferred over Intelligent-Tiering.
func lifecycleStorageClassPreference(storageClass string) int {
	switch storageClass {
	case "DEEP_ARCHIVE":
		return 600
	case "GLACIER":
		return 500
	case "INTELLIGENT_TIERING":
		return 400
	case "GLACIER_IR":
		return 300
	case "ONEZONE_IA":
		return 200
	case "STANDARD_IA":
		return 100
	default:
		return 0
	}
}

// lifecycleTransitionAllowed follows the S3 transition waterfall and prevents
// a later evaluation from moving an object back into a hotter storage class.
func lifecycleTransitionAllowed(current, target string) bool {
	if current == "" {
		current = "STANDARD"
	}
	if current == target {
		return false
	}
	switch current {
	case "STANDARD":
		return lifecycleStorageClassPreference(target) != 0
	case "STANDARD_IA":
		return target == "INTELLIGENT_TIERING" || target == "ONEZONE_IA" || target == "GLACIER_IR" || target == "GLACIER" || target == "DEEP_ARCHIVE"
	case "INTELLIGENT_TIERING":
		return target == "ONEZONE_IA" || target == "GLACIER_IR" || target == "GLACIER" || target == "DEEP_ARCHIVE"
	case "ONEZONE_IA", "GLACIER_IR":
		return target == "GLACIER" || target == "DEEP_ARCHIVE"
	case "GLACIER":
		return target == "DEEP_ARCHIVE"
	case "DEEP_ARCHIVE":
		return false
	default:
		return false
	}
}

func transitionSizeEligible(configuration Configuration, rule Rule, candidate Candidate, storageClass string) bool {
	if hasObjectSizeFilter(rule.Filter) {
		return true
	}
	minimum, err := NormalizeTransitionMinimum(configuration.TransitionDefaultMinimumObjectSize)
	if err != nil || candidate.Size >= 128*1024 {
		return err == nil
	}
	return minimum == TransitionMinimumVariesByStorageClass && (storageClass == "GLACIER" || storageClass == "DEEP_ARCHIVE")
}

func hasObjectSizeFilter(filter *Filter) bool {
	if filter == nil {
		return false
	}
	if filter.ObjectSizeGreaterThan != nil || filter.ObjectSizeLessThan != nil {
		return true
	}
	return filter.And != nil && (filter.And.ObjectSizeGreaterThan != nil || filter.And.ObjectSizeLessThan != nil)
}

func matches(rule Rule, candidate Candidate) bool {
	if rule.Prefix != nil && !strings.HasPrefix(candidate.Key, *rule.Prefix) {
		return false
	}
	if rule.Filter == nil {
		return true
	}
	filter := rule.Filter
	if filter.Prefix != nil && !strings.HasPrefix(candidate.Key, *filter.Prefix) {
		return false
	}
	if filter.Tag != nil && candidate.Tags[filter.Tag.Key] != filter.Tag.Value {
		return false
	}
	if filter.ObjectSizeGreaterThan != nil && candidate.Size <= *filter.ObjectSizeGreaterThan {
		return false
	}
	if filter.ObjectSizeLessThan != nil && candidate.Size >= *filter.ObjectSizeLessThan {
		return false
	}
	if filter.And != nil {
		and := filter.And
		if and.Prefix != nil && !strings.HasPrefix(candidate.Key, *and.Prefix) {
			return false
		}
		if and.ObjectSizeGreaterThan != nil && candidate.Size <= *and.ObjectSizeGreaterThan {
			return false
		}
		if and.ObjectSizeLessThan != nil && candidate.Size >= *and.ObjectSizeLessThan {
			return false
		}
		for _, tag := range and.Tags {
			if candidate.Tags[tag.Key] != tag.Value {
				return false
			}
		}
	}
	return true
}

func expirationEligible(expiration Expiration, modified, now time.Time) bool {
	if expiration.Days != nil {
		return eligibleByDays(modified, *expiration.Days, now)
	}
	if expiration.Date != nil {
		return !now.Before(expiration.Date.Time)
	}
	return false
}

func transitionEligible(transition Transition, modified, now time.Time) bool {
	if transition.Days != nil {
		return eligibleByDays(modified, *transition.Days, now)
	}
	if transition.Date != nil {
		return !now.Before(transition.Date.Time)
	}
	return false
}

func eligibleByDays(since time.Time, days int32, now time.Time) bool {
	if since.IsZero() {
		return false
	}
	deadline := since.UTC().Add(time.Duration(days) * 24 * time.Hour)
	deadline = deadline.Truncate(24 * time.Hour).Add(24 * time.Hour)
	return !now.Before(deadline)
}

func calculateNoncurrentRanks(candidates []Candidate) map[int]int {
	byKey := make(map[string][]int)
	ranks := make(map[int]int)
	for index, candidate := range candidates {
		if candidate.Kind == CandidateObject && !candidate.Current && !candidate.DeleteMarker {
			if candidate.NoncurrentRank > 0 {
				ranks[index] = candidate.NoncurrentRank
				continue
			}
			byKey[candidate.Key] = append(byKey[candidate.Key], index)
		}
	}
	for _, indexes := range byKey {
		sort.SliceStable(indexes, func(i, j int) bool {
			return candidates[indexes[i]].NoncurrentSince.After(candidates[indexes[j]].NoncurrentSince)
		})
		for rank, index := range indexes {
			ranks[index] = rank + 1
		}
	}
	return ranks
}

func calculateVersionCounts(candidates []Candidate) map[string]int {
	counts := make(map[string]int)
	for _, candidate := range candidates {
		if candidate.Kind == CandidateObject {
			if candidate.VersionsForKey > counts[candidate.Key] {
				counts[candidate.Key] = candidate.VersionsForKey
			} else if candidate.VersionsForKey == 0 {
				counts[candidate.Key]++
			}
		}
	}
	return counts
}
