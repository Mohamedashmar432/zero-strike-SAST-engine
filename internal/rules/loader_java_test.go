package rules_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

func TestLoader_JavaRulesLoad(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/java")
	if err != nil {
		t.Fatalf("LoadDir data/java: %v", err)
	}
	if len(loaded) < 9 {
		t.Errorf("expected ≥9 Java rules, got %d", len(loaded))
	}

	v := rules.NewValidator()
	ids := make(map[string]bool, len(loaded))
	for _, r := range loaded {
		ids[r.ID] = true
		if errs := v.Validate(r); len(errs) > 0 {
			t.Errorf("rule %s failed validation: %v", r.ID, errs)
		}
		if r.Language != "java" {
			t.Errorf("rule %s: expected language java, got %q", r.ID, r.Language)
		}
	}
	for _, id := range []string{"ZS-JAVA-001", "ZS-JAVA-002", "ZS-JAVA-003", "ZS-JAVA-004", "ZS-JAVA-005", "ZS-JAVA-006", "ZS-JAVA-007", "ZS-JAVA-008", "ZS-JAVA-009"} {
		if !ids[id] {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
}

// TestRuleDirs_CoversJava guards the RuleDirs list that the pipeline
// iterates when loading embedded rules.
func TestRuleDirs_CoversJava(t *testing.T) {
	found := false
	for _, d := range rules.RuleDirs {
		if d == "data/java" {
			found = true
		}
	}
	if !found {
		t.Error("rules.RuleDirs does not include data/java")
	}
}
