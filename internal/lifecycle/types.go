// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

// Package lifecycle implements transport-independent S3 Lifecycle semantics.
package lifecycle

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"time"
)

const Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

const (
	TransitionMinimumAllStorageClasses128K = "all_storage_classes_128K"
	TransitionMinimumVariesByStorageClass  = "varies_by_storage_class"
)

type Configuration struct {
	XMLName                            xml.Name `xml:"LifecycleConfiguration" json:"-"`
	XMLNS                              string   `xml:"xmlns,attr,omitempty" json:"-"`
	TransitionDefaultMinimumObjectSize string   `xml:"-" json:"transitionDefaultMinimumObjectSize,omitempty"`
	Rules                              []Rule   `xml:"Rule" json:"rules"`
}

type Rule struct {
	ID                             *string                         `xml:"ID,omitempty" json:"id,omitempty"`
	Prefix                         *string                         `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Filter                         *Filter                         `xml:"Filter,omitempty" json:"filter,omitempty"`
	Status                         string                          `xml:"Status" json:"status"`
	Expiration                     *Expiration                     `xml:"Expiration,omitempty" json:"expiration,omitempty"`
	Transitions                    []Transition                    `xml:"Transition,omitempty" json:"transitions,omitempty"`
	NoncurrentVersionExpiration    *NoncurrentVersionExpiration    `xml:"NoncurrentVersionExpiration,omitempty" json:"noncurrentVersionExpiration,omitempty"`
	NoncurrentVersionTransitions   []NoncurrentVersionTransition   `xml:"NoncurrentVersionTransition,omitempty" json:"noncurrentVersionTransitions,omitempty"`
	AbortIncompleteMultipartUpload *AbortIncompleteMultipartUpload `xml:"AbortIncompleteMultipartUpload,omitempty" json:"abortIncompleteMultipartUpload,omitempty"`
}

type Filter struct {
	Prefix                *string      `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Tag                   *Tag         `xml:"Tag,omitempty" json:"tag,omitempty"`
	ObjectSizeGreaterThan *int64       `xml:"ObjectSizeGreaterThan,omitempty" json:"objectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64       `xml:"ObjectSizeLessThan,omitempty" json:"objectSizeLessThan,omitempty"`
	And                   *AndOperator `xml:"And,omitempty" json:"and,omitempty"`
}

type AndOperator struct {
	Prefix                *string `xml:"Prefix,omitempty" json:"prefix,omitempty"`
	Tags                  []Tag   `xml:"Tag,omitempty" json:"tags,omitempty"`
	ObjectSizeGreaterThan *int64  `xml:"ObjectSizeGreaterThan,omitempty" json:"objectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64  `xml:"ObjectSizeLessThan,omitempty" json:"objectSizeLessThan,omitempty"`
}

type Tag struct {
	Key   string `xml:"Key" json:"key"`
	Value string `xml:"Value" json:"value"`
}

type Expiration struct {
	Date                      *Date  `xml:"Date,omitempty" json:"date,omitempty"`
	Days                      *int32 `xml:"Days,omitempty" json:"days,omitempty"`
	ExpiredObjectDeleteMarker *bool  `xml:"ExpiredObjectDeleteMarker,omitempty" json:"expiredObjectDeleteMarker,omitempty"`
}

type Transition struct {
	Date         *Date  `xml:"Date,omitempty" json:"date,omitempty"`
	Days         *int32 `xml:"Days,omitempty" json:"days,omitempty"`
	StorageClass string `xml:"StorageClass" json:"storageClass"`
}

type NoncurrentVersionExpiration struct {
	NoncurrentDays          *int32 `xml:"NoncurrentDays" json:"noncurrentDays"`
	NewerNoncurrentVersions *int32 `xml:"NewerNoncurrentVersions,omitempty" json:"newerNoncurrentVersions,omitempty"`
}

type NoncurrentVersionTransition struct {
	NoncurrentDays          *int32 `xml:"NoncurrentDays" json:"noncurrentDays"`
	NewerNoncurrentVersions *int32 `xml:"NewerNoncurrentVersions,omitempty" json:"newerNoncurrentVersions,omitempty"`
	StorageClass            string `xml:"StorageClass" json:"storageClass"`
}

type AbortIncompleteMultipartUpload struct {
	DaysAfterInitiation *int32 `xml:"DaysAfterInitiation" json:"daysAfterInitiation"`
}

// Date is an ISO-8601 timestamp that must represent midnight UTC.
type Date struct {
	time.Time
}

func (d *Date) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	var value string
	if err := decoder.DecodeElement(&value, &start); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return err
	}
	d.Time = parsed
	return nil
}

func (d Date) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	return encoder.EncodeElement(d.UTC().Format(time.RFC3339), start)
}

type Capabilities struct {
	Transitions map[string]bool
}

var (
	ErrConflict         = errors.New("lifecycle candidate changed after evaluation")
	ErrLeaseUnavailable = errors.New("lifecycle lease unavailable")
)

type Cursor struct {
	Phase           string
	KeyMarker       string
	VersionIDMarker string
	UploadIDMarker  string
	PreviousKey     string
	PreviousTime    time.Time
	NoncurrentRank  int
}

type Page struct {
	Candidates []Candidate
	Next       *Cursor
}

// Executor is implemented only by backends where the gateway owns Lifecycle
// execution. Delegating backends intentionally omit it.
type Executor interface {
	ListLifecycleBuckets(context.Context) ([]string, error)
	AcquireLifecycleLease(context.Context, string) (io.Closer, error)
	ListLifecycleCandidates(context.Context, string, Cursor, int32) (Page, error)
	ApplyLifecycleAction(context.Context, Action) error
}

type ConfigurationStore interface {
	GetLifecycleConfiguration(context.Context, string) (Configuration, error)
}

// Reconciler repairs backend-owned transition state while the bucket lease is
// held. It is optional because delegating backends do not own execution.
type Reconciler interface {
	ReconcileLifecycle(context.Context, string) error
}

// ReconciliationSource lists buckets that retain backend-owned Lifecycle state
// after their S3 Lifecycle configuration has been deleted. Implementations must
// also implement Reconciler.
type ReconciliationSource interface {
	ListLifecycleReconciliationBuckets(context.Context) ([]string, error)
}
