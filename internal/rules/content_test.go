package rules_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
	"gopkg.in/yaml.v3"
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

// TestAllRules_PassValidator is a repo-wide validation gate: every rule shipped
// in the embedded rule set must pass rules.NewValidator().Validate (match.kind,
// severity, confidence, lifecycle). LoadDir already enforces this internally
// and would fail with an aggregated error if any rule were invalid, but this
// test validates each rule explicitly and reports every failing rule ID with
// its specific error, so a broken rule (or a validator change that the
// shipped rule set doesn't satisfy) is diagnosable in one run instead of
// discovered as an opaque LoadDir failure.
func TestAllRules_PassValidator(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)
	validator := rules.NewValidator()

	var total int
	var failures []string
	for _, dir := range rules.RuleDirs {
		loaded, err := loader.LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir(%s): %v", dir, err)
		}
		for _, r := range loaded {
			total++
			if errs := validator.Validate(r); len(errs) > 0 {
				failures = append(failures, r.ID+": "+strings.Join(errs, "; "))
			}
		}
	}

	if total == 0 {
		t.Fatal("expected to load rules from rules.RuleDirs, got 0")
	}

	sort.Strings(failures)
	if len(failures) > 0 {
		t.Errorf("%d/%d rules failed validation:\n%s", len(failures), total, strings.Join(failures, "\n"))
	}
}

// TestAllRules_HaveCoverageInBenchmarkCorpus is a sampling audit, not a gate:
// it cross-references every released rule ID against the rule_ids referenced
// in benchmark/corpus manifests and logs (never fails) any rule lacking a
// corpus fixture, so the coverage backlog is visible in verbose test output
// without blocking merges or CI.
func TestAllRules_HaveCoverageInBenchmarkCorpus(t *testing.T) {
	corpusDir := findCorpusDir(t)
	if corpusDir == "" {
		t.Skip("benchmark/corpus not found from this working directory; skipping coverage audit")
	}

	covered, err := corpusRuleIDs(corpusDir)
	if err != nil {
		t.Fatalf("scanning corpus manifests: %v", err)
	}

	loader := rules.NewLoader(rules.EmbeddedFS)
	var total int
	var missing []string
	for _, dir := range rules.RuleDirs {
		loaded, err := loader.LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir(%s): %v", dir, err)
		}
		for _, r := range loaded {
			total++
			if !covered[r.ID] {
				missing = append(missing, r.ID)
			}
		}
	}

	sort.Strings(missing)
	if len(missing) > 0 {
		t.Logf("%d/%d released rules lack benchmark corpus coverage: %v", len(missing), total, missing)
	}
}

// findCorpusDir locates benchmark/corpus relative to the package's working
// directory, walking up a few levels since `go test` runs from the package dir.
func findCorpusDir(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{"benchmark/corpus", "../benchmark/corpus", "../../benchmark/corpus"} {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

// corpusRuleIDs walks corpusDir and collects every rule_id referenced by a
// manifest.yaml's expect entries (skipping SCA entries, which key on
// dependency/package instead of rule_id).
func corpusRuleIDs(corpusDir string) (map[string]bool, error) {
	type manifest struct {
		Cases []struct {
			Expect []struct {
				RuleID string `yaml:"rule_id"`
			} `yaml:"expect"`
		} `yaml:"cases"`
	}

	covered := make(map[string]bool)
	err := filepath.Walk(corpusDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Name() != "manifest.yaml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var m manifest
		if err := yaml.Unmarshal(data, &m); err != nil {
			return err
		}
		for _, c := range m.Cases {
			for _, exp := range c.Expect {
				if exp.RuleID != "" {
					covered[exp.RuleID] = true
				}
			}
		}
		return nil
	})
	return covered, err
}
