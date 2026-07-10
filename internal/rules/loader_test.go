package rules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

func TestLoader_EmbeddedFS(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/python")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatal("expected rules from embedded FS, got 0")
	}

	v := rules.NewValidator()
	for _, r := range loaded {
		if errs := v.Validate(r); len(errs) > 0 {
			t.Errorf("rule %s failed validation: %v", r.ID, errs)
		}
	}
}

func TestLoader_ContainsExpectedRules(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/python")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	ids := make(map[string]bool, len(loaded))
	for _, r := range loaded {
		ids[r.ID] = true
	}

	for _, id := range []string{"ZS-PY-001", "ZS-PY-002", "ZS-PY-003", "ZS-PY-010"} {
		if !ids[id] {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
}

func TestLoader_TotalRuleCount(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/python")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded) < 23 {
		t.Errorf("expected ≥23 Python rules, got %d", len(loaded))
	}
}

func TestLoader_RuleFieldsPopulated(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, _ := loader.LoadDir("data/python")

	for _, r := range loaded {
		if r.ID == "" {
			t.Errorf("rule has empty ID")
		}
		if r.Name == "" {
			t.Errorf("rule %s has empty Name", r.ID)
		}
		if string(r.Language) == "" {
			t.Errorf("rule %s has empty Language", r.ID)
		}
		if r.Match.Kind == "" {
			t.Errorf("rule %s has empty Match.Kind", r.ID)
		}
	}
}

func TestLoader_LoadsRationale(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "ZS-TEST-001.yaml")
	content := `id: ZS-TEST-001
name: Test Rule
version: "1.0.0"
language: python
category: dangerous-functions
severity: high
confidence: high
lifecycle: released
description: |
  Test description.
message: "Test message"
match:
  kind: call
  callee: eval
fix_suggestion: "Use something safer."
rationale: |
  Calling eval() on untrusted input lets an attacker execute arbitrary
  code in the context of the application.
`
	if err := os.WriteFile(yamlPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}

	loader := rules.NewLoader()
	loaded, err := loader.Load(yamlPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(loaded))
	}
	want := "Calling eval() on untrusted input lets an attacker execute arbitrary\ncode in the context of the application.\n"
	if loaded[0].Rationale != want {
		t.Errorf("Rationale = %q, want %q", loaded[0].Rationale, want)
	}
}

// TestLoader_CalleeSuffixRoundTrips confirms match.callee_suffix in YAML
// round-trips into Rule.Match.CalleeSuffix, and that omitting it defaults
// to false (the pre-existing, unaffected behavior for every other rule).
func TestLoader_CalleeSuffixRoundTrips(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "ZS-TEST-002.yaml")
	content := `id: ZS-TEST-002
name: Test Suffix Rule
version: "1.0.0"
language: csharp
category: injection
severity: high
confidence: high
lifecycle: released
description: |
  Test description.
message: "Test message"
match:
  kind: call
  callee: Response.Write
  callee_suffix: true
fix_suggestion: "Test fix."
rationale: |
  Test rationale.
`
	if err := os.WriteFile(yamlPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}

	loader := rules.NewLoader()
	loaded, err := loader.Load(yamlPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(loaded))
	}
	if !loaded[0].Match.CalleeSuffix {
		t.Error("expected match.callee_suffix: true to round-trip into Rule.Match.CalleeSuffix")
	}
}
