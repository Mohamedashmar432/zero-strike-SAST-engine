package rules_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/rules"
)

func TestLoader_PhpRulesLoad(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/php")
	if err != nil {
		t.Fatalf("LoadDir data/php: %v", err)
	}
	if len(loaded) < 5 {
		t.Errorf("expected ≥5 PHP rules, got %d", len(loaded))
	}

	v := rules.NewValidator()
	ids := make(map[string]bool, len(loaded))
	for _, r := range loaded {
		ids[r.ID] = true
		if errs := v.Validate(r); len(errs) > 0 {
			t.Errorf("rule %s failed validation: %v", r.ID, errs)
		}
		if r.Language != "php" {
			t.Errorf("rule %s: expected language php, got %q", r.ID, r.Language)
		}
	}
	for _, id := range []string{"ZS-PHP-001", "ZS-PHP-002", "ZS-PHP-003", "ZS-PHP-004", "ZS-PHP-005"} {
		if !ids[id] {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
}

// TestRuleDirs_CoversPhp guards the RuleDirs list that the pipeline
// iterates when loading embedded rules.
func TestRuleDirs_CoversPhp(t *testing.T) {
	found := false
	for _, d := range rules.RuleDirs {
		if d == "data/php" {
			found = true
		}
	}
	if !found {
		t.Error("rules.RuleDirs does not include data/php")
	}
}
