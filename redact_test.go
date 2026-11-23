package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStripFreeText(t *testing.T) {
	const inventory = `{
  "artifacts": [
    {"id": "a1", "name": "demo-app", "type": "npm", "metadata": {
      "name": "demo-app", "version": "1.0.0",
      "description": "Blood chemistry analysis for a named patient",
      "author": "A. Researcher", "homepage": "https://example.com/demo", "url": "https://example.com/demo.git"}},
    {"id": "a2", "name": "analysis", "type": "python", "metadata": {
      "name": "analysis", "Summary": "sim for a restricted project", "author": "B. Researcher",
      "files": [{"path": "/opt/analysis/description", "size": 12345678901234567890}]}},
    {"id": "a3", "name": "lib", "type": "java-archive", "metadata": {
      "pomProject": {"name": "lib", "description": "nested free text", "url": "https://example.com/lib"}}},
    {"id": "a4", "name": "stats", "type": "R-package", "metadata": {"title": "My thesis stats", "maintainer": "C. Researcher"}},
    {"id": "a5", "name": "bash", "type": "deb", "metadata": {"package": "bash", "maintainer": "Somebody <s@example.com>"}},
    {"id": "a6", "name": "no-metadata", "type": "binary"}
  ],
  "distro": {"id": "debian", "prettyName": "Debian"},
  "descriptor": {"name": "patch-agent", "configuration": {"description": "not a package, left alone"}}
}`

	out, err := stripFreeText([]byte(inventory))
	if err != nil {
		t.Fatalf("stripFreeText: %v", err)
	}
	text := string(out)

	for _, gone := range []string{"Blood chemistry", "restricted project", "nested free text", "My thesis stats"} {
		if strings.Contains(text, gone) {
			t.Errorf("free text survived: %q", gone)
		}
	}
	for _, kept := range []string{
		"A. Researcher", "https://example.com/demo", "https://example.com/demo.git", // author, homepage, url
		"B. Researcher", "C. Researcher", "Somebody", // author and maintainer
		"https://example.com/lib",   // a nested url
		"/opt/analysis/description", // a VALUE that happens to say "description"
		"12345678901234567890",      // a number too big for a float, unchanged
		"not a package, left alone", // outside the package list
		`"prettyName":"Debian"`,
	} {
		if !strings.Contains(text, kept) {
			t.Errorf("should have been kept: %q\n%s", kept, text)
		}
	}

	var doc struct {
		Artifacts []struct {
			ID, Name, Type string
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if len(doc.Artifacts) != 6 || doc.Artifacts[5].Name != "no-metadata" || doc.Artifacts[0].ID != "a1" {
		t.Errorf("the package list changed shape: %+v", doc.Artifacts)
	}

	t.Run("an inventory with no package list is returned unchanged", func(t *testing.T) {
		in := []byte(`{"distro":{"id":"debian"}}`)
		out, err := stripFreeText(in)
		if err != nil || string(out) != string(in) {
			t.Errorf("got %s, %v", out, err)
		}
	})

	t.Run("input that is not JSON is an error", func(t *testing.T) {
		if _, err := stripFreeText([]byte("nope")); err == nil {
			t.Error("expected an error")
		}
	})
}
