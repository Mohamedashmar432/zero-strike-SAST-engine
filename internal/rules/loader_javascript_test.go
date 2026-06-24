package rules_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/rules"
)

func TestLoader_JSRulesLoad(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/js")
	if err != nil {
		t.Fatalf("LoadDir data/js: %v", err)
	}
	if len(loaded) != 3 {
		t.Errorf("expected 3 JS rules, got %d", len(loaded))
	}

	v := rules.NewValidator()
	ids := make(map[string]bool, len(loaded))
	for _, r := range loaded {
		ids[r.ID] = true
		if errs := v.Validate(r); len(errs) > 0 {
			t.Errorf("rule %s failed validation: %v", r.ID, errs)
		}
	}
	for _, id := range []string{"ZS-JS-001", "ZS-JS-002", "ZS-JS-003"} {
		if !ids[id] {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
}

func TestLoader_ZS_PY_009_KindAssert(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	loaded, err := loader.LoadDir("data/python")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	for _, r := range loaded {
		if r.ID == "ZS-PY-009" {
			if r.Match.Kind != "assert_statement" {
				t.Errorf("ZS-PY-009: expected kind=assert_statement, got %q", r.Match.Kind)
			}
			if r.Match.Callee != "" {
				t.Errorf("ZS-PY-009: expected empty callee, got %q", r.Match.Callee)
			}
			return
		}
	}
	t.Error("ZS-PY-009 not found")
}

