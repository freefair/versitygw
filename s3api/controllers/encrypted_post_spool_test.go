// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package controllers

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestEncryptedPOSTSpoolStoresOnlyCiphertextAndRoundTrips(t *testing.T) {
	marker := []byte("browser-post-plaintext-must-never-appear-in-the-spool-file")
	plaintext := bytes.Repeat(marker, 4096)
	spool, size, err := spoolEncryptedPOSTObject(bytes.NewReader(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	if size != int64(len(plaintext)) {
		t.Fatalf("spooled size = %d, want %d", size, len(plaintext))
	}

	info, err := spool.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stored := make([]byte, info.Size())
	if _, err := spool.file.ReadAt(stored, 0); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, marker) {
		t.Fatal("plaintext marker is present in the POST spool file")
	}

	got, err := io.ReadAll(spool)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("decrypted POST spool did not reproduce the source")
	}
}

func TestEncryptedPOSTSpoolRejectsTampering(t *testing.T) {
	spool, _, err := spoolEncryptedPOSTObject(bytes.NewReader([]byte("sensitive payload")))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	info, err := spool.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	last := make([]byte, 1)
	if _, err := spool.file.ReadAt(last, info.Size()-1); err != nil {
		t.Fatal(err)
	}
	last[0] ^= 0xff
	if _, err := spool.file.WriteAt(last, info.Size()-1); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(spool); err == nil {
		t.Fatal("tampered POST spool was accepted")
	}
}

func TestEncryptedPOSTSpoolCloseRemovesNamedFile(t *testing.T) {
	spool, _, err := spoolEncryptedPOSTObject(bytes.NewReader([]byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	name := spool.fileName
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("POST spool path remains after close: %v", err)
	}
}
