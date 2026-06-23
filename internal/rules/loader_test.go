package rules_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/rules"
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
	if len(loaded) != 10 {
		t.Errorf("expected 10 Python rules, got %d", len(loaded))
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
