// Copyright 2026 Versity Software
// This file is licensed under the Apache License, Version 2.0.

package encryption

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
)

const Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

func ParseConfiguration(body []byte) (Configuration, error) {
	if err := validateConfigurationXMLShape(body); err != nil {
		return Configuration{}, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	var configuration Configuration
	if err := decoder.Decode(&configuration); err != nil {
		return Configuration{}, fmt.Errorf("%w: %v", ErrInvalidConfiguration, err)
	}
	if configuration.XMLName.Local != "ServerSideEncryptionConfiguration" {
		return Configuration{}, fmt.Errorf("%w: unexpected root element", ErrInvalidConfiguration)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Configuration{}, fmt.Errorf("%w: trailing XML data", ErrInvalidConfiguration)
	}
	configuration.XMLNS = Namespace
	return configuration, nil
}

func validateConfigurationXMLShape(body []byte) error {
	children := map[string]map[string]bool{
		"":                                   {"ServerSideEncryptionConfiguration": true},
		"ServerSideEncryptionConfiguration":  {"Rule": true},
		"Rule":                               {"ApplyServerSideEncryptionByDefault": true, "BucketKeyEnabled": true, "BlockedEncryptionTypes": true},
		"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": true, "KMSMasterKeyID": true},
		"BlockedEncryptionTypes":             {"EncryptionType": true},
	}
	repeatable := map[string]bool{"ServerSideEncryptionConfiguration/Rule": true}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var stack []string
	counts := make(map[string]int)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch value := token.(type) {
		case xml.StartElement:
			parent := ""
			if len(stack) != 0 {
				parent = stack[len(stack)-1]
			}
			if allowed, ok := children[parent]; !ok || !allowed[value.Name.Local] {
				return fmt.Errorf("unexpected element %s under %s", value.Name.Local, parent)
			}
			for _, attribute := range value.Attr {
				if attribute.Name.Local != "xmlns" && attribute.Name.Space != "xmlns" {
					return fmt.Errorf("unexpected attribute %s", attribute.Name.Local)
				}
			}
			key := parent + "/" + value.Name.Local
			counts[key]++
			if counts[key] > 1 && !repeatable[key] {
				return fmt.Errorf("duplicate element %s", value.Name.Local)
			}
			stack = append(stack, value.Name.Local)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != value.Name.Local {
				return fmt.Errorf("unbalanced element %s", value.Name.Local)
			}
			stack = stack[:len(stack)-1]
		}
	}
}

func MarshalConfiguration(cfg Configuration) ([]byte, error) {
	cfg.XMLName = xml.Name{Local: "ServerSideEncryptionConfiguration"}
	cfg.XMLNS = Namespace
	body, err := xml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal encryption configuration: %w", err)
	}
	return append([]byte(xml.Header), body...), nil
}
