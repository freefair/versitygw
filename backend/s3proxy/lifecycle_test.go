// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package s3proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/versity/versitygw/internal/lifecycle"
)

func TestLifecycleConfigurationDelegatesToUpstream(t *testing.T) {
	requests := make(chan *http.Request, 3)
	requestBodies := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request: %v", err)
		}
		requests <- r.Clone(context.Background())
		requestBodies <- string(body)
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("x-amz-transition-default-minimum-object-size", "varies_by_storage_class")
			_, _ = io.WriteString(w, `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>archive</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration><Transition><Days>7</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>`)
		}
	}))
	t.Cleanup(server.Close)

	proxy := newTestProxy(t, server.URL)
	id, prefix, expirationDays, transitionDays := "archive", "logs/", int32(30), int32(7)
	configuration := lifecycle.Configuration{
		TransitionDefaultMinimumObjectSize: lifecycle.TransitionMinimumVariesByStorageClass,
		Rules:                              []lifecycle.Rule{{ID: &id, Filter: &lifecycle.Filter{Prefix: &prefix}, Status: "Enabled", Expiration: &lifecycle.Expiration{Days: &expirationDays}, Transitions: []lifecycle.Transition{{Days: &transitionDays, StorageClass: "GLACIER"}}}},
	}
	if err := proxy.PutLifecycleConfiguration(context.Background(), "bucket", configuration); err != nil {
		t.Fatalf("PutLifecycleConfiguration() error = %v", err)
	}
	putRequest, putBody := <-requests, <-requestBodies
	if putRequest.Method != http.MethodPut || !putRequest.URL.Query().Has("lifecycle") {
		t.Fatalf("PUT request = %s %s?%s", putRequest.Method, putRequest.URL.Path, putRequest.URL.RawQuery)
	}
	assertHeader(t, putRequest, "x-amz-transition-default-minimum-object-size", lifecycle.TransitionMinimumVariesByStorageClass)
	for _, expected := range []string{"<Prefix>logs/</Prefix>", "<Days>30</Days>", "<StorageClass>GLACIER</StorageClass>"} {
		if !strings.Contains(putBody, expected) {
			t.Errorf("PUT body does not contain %q: %s", expected, putBody)
		}
	}

	got, err := proxy.GetLifecycleConfiguration(context.Background(), "bucket")
	if err != nil {
		t.Fatalf("GetLifecycleConfiguration() error = %v", err)
	}
	<-requests
	<-requestBodies
	if got.TransitionDefaultMinimumObjectSize != lifecycle.TransitionMinimumVariesByStorageClass || len(got.Rules) != 1 || got.Rules[0].ID == nil || *got.Rules[0].ID != id {
		t.Fatalf("configuration = %#v", got)
	}

	if err := proxy.DeleteLifecycleConfiguration(context.Background(), "bucket"); err != nil {
		t.Fatalf("DeleteLifecycleConfiguration() error = %v", err)
	}
	deleteRequest := <-requests
	<-requestBodies
	if deleteRequest.Method != http.MethodDelete || !deleteRequest.URL.Query().Has("lifecycle") {
		t.Fatalf("DELETE request = %s %s?%s", deleteRequest.Method, deleteRequest.URL.Path, deleteRequest.URL.RawQuery)
	}
}
