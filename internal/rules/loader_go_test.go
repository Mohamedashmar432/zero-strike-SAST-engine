package rules_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/rules"
)

func TestLoader_GoRulesLoad(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/go")
	if err != nil {
		t.Fatalf("LoadDir data/go: %v", err)
	}
	if len(loaded) < 5 {
		t.Errorf("expected ≥5 Go rules, got %d", len(loaded))
	}

	v := rules.NewValidator()
	ids := make(map[string]bool, len(loaded))
	for _, r := range loaded {
		ids[r.ID] = true
		if errs := v.Validate(r); len(errs) > 0 {
			t.Errorf("rule %s failed validation: %v", r.ID, errs)
		}
		if r.Language != "go" {
			t.Errorf("rule %s: expected language go, got %q", r.ID, r.Language)
		}
	}
	for _, id := range []string{"ZS-GO-001", "ZS-GO-002", "ZS-GO-003", "ZS-GO-004", "ZS-GO-005"} {
		if !ids[id] {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
}

// TestRuleDirs_CoversGo guards the RuleDirs list that the pipeline
// iterates when loading embedded rules.
func TestRuleDirs_CoversGo(t *testing.T) {
	found := false
	for _, d := range rules.RuleDirs {
		if d == "data/go" {
			found = true
		}
	}
	if !found {
		t.Error("rules.RuleDirs does not include data/go")
	}
}
