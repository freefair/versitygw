// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

type Inventory struct {
	Buckets              int64             `json:"buckets"`
	Objects              int64             `json:"objects"`
	MultipartParts       int64             `json:"multipart_parts"`
	PlaintextLegacy      int64             `json:"plaintext_legacy"`
	Encrypted            int64             `json:"encrypted"`
	InvalidContainers    int64             `json:"invalid_containers"`
	MissingKeyObjects    int64             `json:"missing_key_objects"`
	FormatVersions       map[int]int64     `json:"format_versions"`
	ActiveKeyReferences  map[string]string `json:"active_key_references"`
	MissingKeyReferences map[string]int64  `json:"missing_key_references"`
}

func NewInventory() Inventory {
	return Inventory{
		FormatVersions:       make(map[int]int64),
		ActiveKeyReferences:  make(map[string]string),
		MissingKeyReferences: make(map[string]int64),
	}
}

func (inventory Inventory) Healthy() bool {
	return inventory.InvalidContainers == 0 && inventory.MissingKeyObjects == 0
}

type Health struct {
	Status                HealthStatus      `json:"status"`
	ActiveKeyReferences   map[string]string `json:"active_key_references,omitempty"`
	MissingKeyReferences  map[string]int64  `json:"missing_key_references,omitempty"`
	MissingKeyObjects     int64             `json:"missing_key_objects,omitempty"`
	InvalidContainerCount int64             `json:"invalid_container_count,omitempty"`
	InventoryUnavailable  bool              `json:"inventory_unavailable,omitempty"`
}

type MaintenanceResult struct {
	Scanned int64 `json:"scanned"`
	Changed int64 `json:"changed"`
	Skipped int64 `json:"skipped"`
	Failed  int64 `json:"failed"`
}

func (inventory Inventory) Health(auditErr error) Health {
	health := Health{
		Status:                HealthStatusHealthy,
		ActiveKeyReferences:   inventory.ActiveKeyReferences,
		MissingKeyReferences:  inventory.MissingKeyReferences,
		MissingKeyObjects:     inventory.MissingKeyObjects,
		InvalidContainerCount: inventory.InvalidContainers,
		InventoryUnavailable:  auditErr != nil,
	}
	if auditErr != nil || !inventory.Healthy() {
		health.Status = HealthStatusUnhealthy
	}
	return health
}
