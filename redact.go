package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// freeTextKeys are the package metadata fields that hold someone's own
// description of their work. syft copies them from manifests such as
// package.json, and they are where people over-share (a named person, a
// restricted project). They are removed before the inventory is written.
// Names that identify a package or its origin (author, homepage, maintainer,
// url) are kept.
var freeTextKeys = map[string]bool{
	"description": true,
	"summary":     true,
	"title":       true,
	"comments":    true,
}

// stripFreeText removes the free-text fields from every package's metadata
// in syft's JSON, at any depth, and leaves everything else as it was.
func stripFreeText(inventory []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(inventory, &doc); err != nil {
		return nil, fmt.Errorf("read syft's JSON: %w", err)
	}
	rawArtifacts, ok := doc["artifacts"]
	if !ok {
		return inventory, nil
	}
	var artifacts []map[string]json.RawMessage
	if err := json.Unmarshal(rawArtifacts, &artifacts); err != nil {
		return nil, fmt.Errorf("read syft's package list: %w", err)
	}

	for _, artifact := range artifacts {
		rawMetadata, ok := artifact["metadata"]
		if !ok {
			continue
		}
		// UseNumber keeps numbers exactly as syft wrote them.
		decoder := json.NewDecoder(bytes.NewReader(rawMetadata))
		decoder.UseNumber()
		var metadata any
		if err := decoder.Decode(&metadata); err != nil {
			return nil, fmt.Errorf("read a package's metadata: %w", err)
		}
		if !removeFreeText(metadata) {
			continue
		}
		cleaned, err := json.Marshal(metadata)
		if err != nil {
			return nil, err
		}
		artifact["metadata"] = cleaned
	}

	cleaned, err := json.Marshal(artifacts)
	if err != nil {
		return nil, err
	}
	doc["artifacts"] = cleaned
	return json.Marshal(doc)
}

// removeFreeText deletes the free-text keys from v and everything inside it,
// and reports whether it removed anything.
func removeFreeText(v any) bool {
	removed := false
	switch value := v.(type) {
	case map[string]any:
		for key, inner := range value {
			if freeTextKeys[strings.ToLower(key)] {
				delete(value, key)
				removed = true
			} else if removeFreeText(inner) {
				removed = true
			}
		}
	case []any:
		for _, inner := range value {
			if removeFreeText(inner) {
				removed = true
			}
		}
	}
	return removed
}
