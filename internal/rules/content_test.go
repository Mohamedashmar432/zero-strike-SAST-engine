package rules_test

import (
	"sort"
	"testing"

	"github.com/zerostrike/scanner/internal/rules"
)

// TestAllRules_HaveRationaleAndFixSuggestion is a repo-wide completeness gate:
// every rule shipped in the embedded rule set, across every language
// directory in rules.RuleDirs, must have both a reviewer-facing Rationale
// (what the pattern lets an attacker do, and why it's dangerous) and a
// FixSuggestion (how to remediate it). It fails loudly, listing every
// specific rule ID that is missing either field, so future rule additions
// that forget one of these fields are caught here rather than shipping
// silently incomplete.
func TestAllRules_HaveRationaleAndFixSuggestion(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)

	var (
		total             int
		missingRationale  []string
		missingFixSuggest []string
	)

	for _, dir := range rules.RuleDirs {
		loaded, err := loader.LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir(%s): %v", dir, err)
		}
		for _, r := range loaded {
			total++
			if r.Rationale == "" {
				missingRationale = append(missingRationale, r.ID)
			}
			if r.FixSuggestion == "" {
				missingFixSuggest = append(missingFixSuggest, r.ID)
			}
		}
	}

	if total == 0 {
		t.Fatal("expected to load rules from rules.RuleDirs, got 0")
	}

	sort.Strings(missingRationale)
	sort.Strings(missingFixSuggest)

	if len(missingRationale) > 0 {
		t.Errorf("%d/%d rules are missing a rationale: %v", len(missingRationale), total, missingRationale)
	}
	if len(missingFixSuggest) > 0 {
		t.Errorf("%d/%d rules are missing a fix_suggestion: %v", len(missingFixSuggest), total, missingFixSuggest)
	}
}
