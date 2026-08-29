// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package lifecycle

import (
	"fmt"
	"strings"
)

type ErrorKind string

const (
	ErrorMalformedXML    ErrorKind = "MalformedXML"
	ErrorInvalidRequest  ErrorKind = "InvalidRequest"
	ErrorInvalidArgument ErrorKind = "InvalidArgument"
)

type ValidationError struct {
	Kind    ErrorKind
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func malformed(format string, args ...any) error {
	return ValidationError{Kind: ErrorMalformedXML, Message: fmt.Sprintf(format, args...)}
}

func invalidRequest(format string, args ...any) error {
	return ValidationError{Kind: ErrorInvalidRequest, Message: fmt.Sprintf(format, args...)}
}

func invalidArgument(format string, args ...any) error {
	return ValidationError{Kind: ErrorInvalidArgument, Message: fmt.Sprintf(format, args...)}
}

func (configuration Configuration) Validate(capabilities Capabilities) error {
	if configuration.TransitionDefaultMinimumObjectSize != "" {
		if _, err := NormalizeTransitionMinimum(configuration.TransitionDefaultMinimumObjectSize); err != nil {
			return err
		}
	}
	if len(configuration.Rules) < 1 || len(configuration.Rules) > 1000 {
		return malformed("lifecycle configuration must contain between 1 and 1000 rules")
	}

	ids := make(map[string]struct{}, len(configuration.Rules))
	for index, rule := range configuration.Rules {
		if err := validateRule(rule, capabilities); err != nil {
			return fmt.Errorf("rule %d: %w", index+1, err)
		}
		if rule.ID != nil {
			if len(*rule.ID) > 255 {
				return invalidRequest("rule ID exceeds 255 characters")
			}
			if _, exists := ids[*rule.ID]; exists {
				return invalidRequest("rule ID %q is duplicated", *rule.ID)
			}
			ids[*rule.ID] = struct{}{}
		}
	}
	return nil
}

func NormalizeTransitionMinimum(value string) (string, error) {
	if value == "" {
		return TransitionMinimumAllStorageClasses128K, nil
	}
	switch value {
	case TransitionMinimumAllStorageClasses128K, TransitionMinimumVariesByStorageClass:
		return value, nil
	default:
		return "", invalidArgument("invalid transition default minimum object size %q", value)
	}
}

func validateRule(rule Rule, capabilities Capabilities) error {
	if rule.Status != "Enabled" && rule.Status != "Disabled" {
		return malformed("status must be Enabled or Disabled")
	}
	if rule.Prefix != nil && rule.Filter != nil {
		return invalidRequest("Prefix and Filter cannot both be specified")
	}
	if rule.Prefix == nil && rule.Filter == nil {
		return invalidRequest("rule requires Prefix or Filter")
	}
	if rule.Filter != nil {
		if err := validateFilter(*rule.Filter); err != nil {
			return err
		}
	}
	actionCount := 0
	if rule.Expiration != nil {
		actionCount++
		if err := validateExpiration(*rule.Expiration); err != nil {
			return err
		}
	}
	for _, transition := range rule.Transitions {
		actionCount++
		if err := validateTransition(transition, capabilities); err != nil {
			return err
		}
	}
	if rule.NoncurrentVersionExpiration != nil {
		actionCount++
		if err := validateNoncurrentExpiration(*rule.NoncurrentVersionExpiration, rule.Filter != nil); err != nil {
			return err
		}
	}
	for _, transition := range rule.NoncurrentVersionTransitions {
		actionCount++
		if err := validateNoncurrentTransition(transition, rule.Filter != nil, capabilities); err != nil {
			return err
		}
	}
	if rule.AbortIncompleteMultipartUpload != nil {
		actionCount++
		if rule.AbortIncompleteMultipartUpload.DaysAfterInitiation == nil || *rule.AbortIncompleteMultipartUpload.DaysAfterInitiation <= 0 {
			return invalidRequest("DaysAfterInitiation must be a positive integer")
		}
		if hasTagFilter(rule.Filter) {
			return invalidRequest("tag filters cannot be used with AbortIncompleteMultipartUpload")
		}
	}
	if actionCount == 0 {
		return invalidRequest("rule must contain at least one action")
	}
	return nil
}

func validateFilter(filter Filter) error {
	count := 0
	if filter.Prefix != nil {
		count++
	}
	if filter.Tag != nil {
		count++
	}
	if filter.ObjectSizeGreaterThan != nil {
		count++
	}
	if filter.ObjectSizeLessThan != nil {
		count++
	}
	if filter.And != nil {
		count++
	}
	// An empty Filter is the AWS representation for all objects.
	if count > 1 {
		return invalidRequest("Filter must contain at most one top-level predicate")
	}
	if filter.Tag != nil && filter.Tag.Key == "" {
		return invalidRequest("tag key must not be empty")
	}
	if filter.And != nil {
		if err := validateAnd(*filter.And); err != nil {
			return err
		}
	}
	return nil
}

func validateAnd(and AndOperator) error {
	predicates := len(and.Tags)
	if and.Prefix != nil {
		predicates++
	}
	if and.ObjectSizeGreaterThan != nil {
		predicates++
	}
	if and.ObjectSizeLessThan != nil {
		predicates++
	}
	if predicates < 2 {
		return invalidRequest("And must contain at least two predicates")
	}
	seen := make(map[string]struct{}, len(and.Tags))
	for _, tag := range and.Tags {
		if tag.Key == "" {
			return invalidRequest("tag key must not be empty")
		}
		if _, exists := seen[tag.Key]; exists {
			return invalidRequest("tag key %q is duplicated", tag.Key)
		}
		seen[tag.Key] = struct{}{}
	}
	if and.ObjectSizeGreaterThan != nil && and.ObjectSizeLessThan != nil && *and.ObjectSizeGreaterThan >= *and.ObjectSizeLessThan {
		return invalidRequest("ObjectSizeGreaterThan must be less than ObjectSizeLessThan")
	}
	return nil
}

func validateExpiration(expiration Expiration) error {
	count := 0
	if expiration.Date != nil {
		count++
	}
	if expiration.Days != nil {
		count++
	}
	if expiration.ExpiredObjectDeleteMarker != nil {
		count++
	}
	if count != 1 {
		return invalidRequest("Expiration requires exactly one of Date, Days, or ExpiredObjectDeleteMarker")
	}
	if expiration.Days != nil && *expiration.Days <= 0 {
		return invalidArgument("Expiration Days must be positive")
	}
	if expiration.Date != nil && !isMidnightUTC(expiration.Date) {
		return invalidRequest("Expiration Date must be midnight UTC")
	}
	return nil
}

func validateTransition(transition Transition, capabilities Capabilities) error {
	if (transition.Date == nil) == (transition.Days == nil) {
		return invalidRequest("Transition requires exactly one of Date or Days")
	}
	if transition.Days != nil && *transition.Days < 0 {
		return invalidArgument("Transition Days cannot be negative")
	}
	if transition.Date != nil && !isMidnightUTC(transition.Date) {
		return invalidRequest("Transition Date must be midnight UTC")
	}
	return validateStorageClass(transition.StorageClass, capabilities)
}

func validateNoncurrentExpiration(expiration NoncurrentVersionExpiration, hasFilter bool) error {
	if expiration.NoncurrentDays == nil || *expiration.NoncurrentDays <= 0 {
		return invalidArgument("NoncurrentDays must be positive")
	}
	return validateNewerCount(expiration.NewerNoncurrentVersions, hasFilter)
}

func validateNoncurrentTransition(transition NoncurrentVersionTransition, hasFilter bool, capabilities Capabilities) error {
	if transition.NoncurrentDays == nil || *transition.NoncurrentDays < 0 {
		return invalidArgument("NoncurrentDays cannot be negative")
	}
	if err := validateNewerCount(transition.NewerNoncurrentVersions, hasFilter); err != nil {
		return err
	}
	return validateStorageClass(transition.StorageClass, capabilities)
}

func validateNewerCount(count *int32, hasFilter bool) error {
	if count == nil {
		return nil
	}
	if *count < 1 || *count > 100 {
		return invalidArgument("NewerNoncurrentVersions must be between 1 and 100")
	}
	if !hasFilter {
		return invalidRequest("NewerNoncurrentVersions requires a Filter")
	}
	return nil
}

func validateStorageClass(storageClass string, capabilities Capabilities) error {
	valid := map[string]bool{
		"STANDARD_IA": true, "ONEZONE_IA": true, "INTELLIGENT_TIERING": true,
		"GLACIER_IR": true, "GLACIER": true, "DEEP_ARCHIVE": true,
	}
	if !valid[storageClass] {
		return invalidArgument("unsupported transition storage class %q", storageClass)
	}
	if capabilities.Transitions == nil || !capabilities.Transitions[storageClass] {
		return invalidRequest("backend does not support transition to %s", storageClass)
	}
	return nil
}

func isMidnightUTC(date *Date) bool {
	value := date.Time
	return value.Location() == value.UTC().Location() && value.Hour() == 0 && value.Minute() == 0 && value.Second() == 0 && value.Nanosecond() == 0
}

func hasTagFilter(filter *Filter) bool {
	return filter != nil && (filter.Tag != nil || filter.And != nil && len(filter.And.Tags) != 0)
}

func (e ValidationError) Is(target error) bool {
	other, ok := target.(ValidationError)
	return ok && strings.EqualFold(string(e.Kind), string(other.Kind))
}
