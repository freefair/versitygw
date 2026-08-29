// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package lifecycle

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

// Parse decodes and validates an S3 LifecycleConfiguration document.
func Parse(data []byte, capabilities Capabilities) (Configuration, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Configuration{}, malformed("empty lifecycle configuration")
	}
	if err := validateLifecycleXMLShape(data); err != nil {
		return Configuration{}, malformed("invalid lifecycle XML: %v", err)
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return Configuration{}, malformed("invalid lifecycle XML: %v", err)
	}
	if configuration.XMLName.Local != "LifecycleConfiguration" {
		return Configuration{}, malformed("unexpected root element %q", configuration.XMLName.Local)
	}
	if err := ensureSingleDocument(decoder); err != nil {
		return Configuration{}, malformed("invalid lifecycle XML: %v", err)
	}
	configuration.XMLNS = Namespace
	if err := configuration.Validate(capabilities); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

type lifecycleXMLFrame struct {
	name   string
	counts map[string]int
}

func validateLifecycleXMLShape(data []byte) error {
	children := map[string]map[string]bool{
		"":                       {"LifecycleConfiguration": true},
		"LifecycleConfiguration": {"Rule": true},
		"Rule": {
			"ID": true, "Prefix": true, "Filter": true, "Status": true, "Expiration": true,
			"Transition": true, "NoncurrentVersionExpiration": true, "NoncurrentVersionTransition": true,
			"AbortIncompleteMultipartUpload": true,
		},
		"Filter":                         {"Prefix": true, "Tag": true, "ObjectSizeGreaterThan": true, "ObjectSizeLessThan": true, "And": true},
		"And":                            {"Prefix": true, "Tag": true, "ObjectSizeGreaterThan": true, "ObjectSizeLessThan": true},
		"Tag":                            {"Key": true, "Value": true},
		"Expiration":                     {"Date": true, "Days": true, "ExpiredObjectDeleteMarker": true},
		"Transition":                     {"Date": true, "Days": true, "StorageClass": true},
		"NoncurrentVersionExpiration":    {"NoncurrentDays": true, "NewerNoncurrentVersions": true},
		"NoncurrentVersionTransition":    {"NoncurrentDays": true, "NewerNoncurrentVersions": true, "StorageClass": true},
		"AbortIncompleteMultipartUpload": {"DaysAfterInitiation": true},
	}
	repeatable := map[string]bool{
		"LifecycleConfiguration/Rule":      true,
		"Rule/Transition":                  true,
		"Rule/NoncurrentVersionTransition": true,
		"And/Tag":                          true,
	}
	frames := []lifecycleXMLFrame{{counts: make(map[string]int)}}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			if len(frames) != 1 {
				return fmt.Errorf("unclosed XML element")
			}
			return nil
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			parent := frames[len(frames)-1].name
			if allowed, ok := children[parent]; !ok || !allowed[value.Name.Local] {
				return fmt.Errorf("unexpected element %s under %s", value.Name.Local, parent)
			}
			for _, attribute := range value.Attr {
				if attribute.Name.Local != "xmlns" && attribute.Name.Space != "xmlns" {
					return fmt.Errorf("unexpected attribute %s", attribute.Name.Local)
				}
			}
			frames[len(frames)-1].counts[value.Name.Local]++
			if frames[len(frames)-1].counts[value.Name.Local] > 1 && !repeatable[parent+"/"+value.Name.Local] {
				return fmt.Errorf("duplicate element %s", value.Name.Local)
			}
			frames = append(frames, lifecycleXMLFrame{name: value.Name.Local, counts: make(map[string]int)})
		case xml.EndElement:
			if len(frames) == 1 || frames[len(frames)-1].name != value.Name.Local {
				return fmt.Errorf("unbalanced element %s", value.Name.Local)
			}
			frames = frames[:len(frames)-1]
		case xml.CharData:
			current := frames[len(frames)-1].name
			if children[current] != nil && len(bytes.TrimSpace(value)) != 0 {
				return fmt.Errorf("unexpected character data in %s", current)
			}
		}
	}
}

func ensureSingleDocument(decoder *xml.Decoder) error {
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(value)) != 0 {
				return fmt.Errorf("trailing character data")
			}
		case xml.Comment, xml.Directive:
			continue
		default:
			return fmt.Errorf("trailing XML content")
		}
	}
}

// Marshal returns canonical AWS-compatible LifecycleConfiguration XML.
func Marshal(configuration Configuration) ([]byte, error) {
	configuration.XMLName = xml.Name{Local: "LifecycleConfiguration"}
	configuration.XMLNS = Namespace
	body, err := xml.Marshal(configuration)
	if err != nil {
		return nil, fmt.Errorf("marshal lifecycle configuration: %w", err)
	}
	return append([]byte(xml.Header), body...), nil
}

type storedConfiguration struct {
	Version       int           `json:"version"`
	Configuration Configuration `json:"configuration"`
}

func MarshalStored(configuration Configuration) ([]byte, error) {
	minimum, err := NormalizeTransitionMinimum(configuration.TransitionDefaultMinimumObjectSize)
	if err != nil {
		return nil, err
	}
	configuration.TransitionDefaultMinimumObjectSize = minimum
	body, err := json.Marshal(storedConfiguration{Version: 1, Configuration: configuration})
	if err != nil {
		return nil, fmt.Errorf("marshal stored lifecycle configuration: %w", err)
	}
	return body, nil
}

func ParseStored(data []byte, capabilities Capabilities) (Configuration, error) {
	if len(bytes.TrimSpace(data)) != 0 && bytes.TrimSpace(data)[0] == '{' {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		var stored storedConfiguration
		if err := decoder.Decode(&stored); err != nil || stored.Version != 1 {
			return Configuration{}, fmt.Errorf("invalid stored lifecycle configuration")
		}
		minimum, err := NormalizeTransitionMinimum(stored.Configuration.TransitionDefaultMinimumObjectSize)
		if err != nil {
			return Configuration{}, err
		}
		stored.Configuration.TransitionDefaultMinimumObjectSize = minimum
		if err := stored.Configuration.Validate(capabilities); err != nil {
			return Configuration{}, err
		}
		return stored.Configuration, nil
	}
	configuration, err := Parse(data, capabilities)
	if err != nil {
		return Configuration{}, err
	}
	configuration.TransitionDefaultMinimumObjectSize = TransitionMinimumAllStorageClasses128K
	return configuration, nil
}
