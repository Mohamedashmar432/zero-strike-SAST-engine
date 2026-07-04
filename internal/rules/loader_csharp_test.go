package rules_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/rules"
)

func TestLoader_CSharpRulesLoad(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/csharp")
	if err != nil {
		t.Fatalf("LoadDir data/csharp: %v", err)
	}
	if len(loaded) < 6 {
		t.Errorf("expected ≥6 C# rules, got %d", len(loaded))
	}

	v := rules.NewValidator()
	ids := make(map[string]bool, len(loaded))
	for _, r := range loaded {
		ids[r.ID] = true
		if errs := v.Validate(r); len(errs) > 0 {
			t.Errorf("rule %s failed validation: %v", r.ID, errs)
		}
		if r.Language != "csharp" {
			t.Errorf("rule %s: expected language csharp, got %q", r.ID, r.Language)
		}
	}
	for _, id := range []string{"ZS-CS-001", "ZS-CS-002", "ZS-CS-003", "ZS-CS-004", "ZS-CS-005", "ZS-CS-006"} {
		if !ids[id] {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
}

// TestRuleDirs_CoversCSharp guards the RuleDirs list that the pipeline
// iterates when loading embedded rules.
func TestRuleDirs_CoversCSharp(t *testing.T) {
	found := false
	for _, d := range rules.RuleDirs {
		if d == "data/csharp" {
			found = true
		}
	}
	if !found {
		t.Error("rules.RuleDirs does not include data/csharp")
	}
}
