package rules_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/zerostrike/scanner/internal/rules"
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

// TestAllRules_PassValidator is a repo-wide validation gate: all rules shipped
// in the embedded rule set must pass schema validation (match.kind, severity, confidence).
// LoadDir calls parseYAML which validates each rule before returning—if any rule is
// malformed, parseYAML fails fast with a validation error, so LoadDir will fail.
// This test succeeding proves that all embedded rules pass validation.
func TestAllRules_PassValidator(t *testing.T) {
	loader := rules.NewLoader(rules.EmbeddedFS)

	var total int
	for _, dir := range rules.RuleDirs {
		loaded, err := loader.LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir(%s) failed validation: %v", dir, err)
		}
		total += len(loaded)
	}

	if total == 0 {
		t.Fatal("expected to load rules from rules.RuleDirs, got 0")
	}
}

// TestAllRules_HaveCoverageInBenchmarkCorpus is a sampling audit test that checks
// if released rules have coverage in the benchmark corpus manifests.
// This test fails loudly if rules lack corpus coverage, helping teams see the backlog
// at a glance. It's an audit, not a gate—won't block merges—but ensures new rules added
// without corpus fixtures are caught and tracked.
//
// Known v1 scope gaps (skip-list):
// - ZS-PY-004, ZS-PY-012, ZS-PY-013: taint-gated rules excluded (require CGo verification)
// - These rules are documented in benchmark/README.md and tracked in the backlog
func TestAllRules_HaveCoverageInBenchmarkCorpus(t *testing.T) {
	// Skip-list: rules that are accepted as known gaps in v1 scope
	skipList := map[string]bool{
		"ZS-PY-004": true, // taint-gated, requires CGo verification
		"ZS-PY-012": true, // taint-gated, requires CGo verification
		"ZS-PY-013": true, // taint-gated, requires CGo verification
	}

	// Step 1: Parse all manifest files and collect covered rule IDs
	coveredRules := make(map[string]bool)
	corpusPath := findCorpusPath()
	if corpusPath == "" {
		t.Skip("benchmark/corpus directory not found; skipping corpus coverage audit")
	}
	if err := parseAllManifests(corpusPath, coveredRules); err != nil {
		t.Fatalf("failed to parse manifests: %v", err)
	}

	// Step 2: Load all rules
	loader := rules.NewLoader(rules.EmbeddedFS)
	var allRules []string

	for _, dir := range rules.RuleDirs {
		loaded, err := loader.LoadDir(dir)
		if err != nil {
			t.Fatalf("LoadDir(%s): %v", dir, err)
		}
		for _, r := range loaded {
			allRules = append(allRules, r.ID)
		}
	}

	// Step 3: Find rules that lack coverage
	var missingCoverage []string
	for _, ruleID := range allRules {
		if !coveredRules[ruleID] && !skipList[ruleID] {
			missingCoverage = append(missingCoverage, ruleID)
		}
	}

	// Step 4: Report results
	if len(missingCoverage) > 0 {
		sort.Strings(missingCoverage)
		skipped := []string{"ZS-PY-004", "ZS-PY-012", "ZS-PY-013"}
		t.Errorf("%d/%d rules lack corpus coverage: %v\n(Known v1 gaps (skip-list): %v)",
			len(missingCoverage), len(allRules), missingCoverage, skipped)
	}
}

// findCorpusPath locates the benchmark/corpus directory by trying relative paths
// and checking if it exists. Returns empty string if not found.
func findCorpusPath() string {
	candidates := []string{
		"benchmark/corpus",
		"../benchmark/corpus",
		"../../benchmark/corpus",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

// parseAllManifests walks the corpus directory and collects all rule_ids
// from manifest.yaml files (skipping SCA and other non-SAST entries).
func parseAllManifests(corpusDir string, coveredRules map[string]bool) error {
	type Manifest struct {
		Version string `yaml:"version"`
		Cases   []struct {
			File      string `yaml:"file"`
			Language  string `yaml:"language"`
			Ecosystem string `yaml:"ecosystem"`
			Expect    []struct {
				RuleID     string `yaml:"rule_id"`
				MinCount   int    `yaml:"min_count"`
				Dependency struct {
					Package string `yaml:"package"`
				} `yaml:"dependency"`
			} `yaml:"expect"`
		} `yaml:"cases"`
	}

	return filepath.Walk(corpusDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Name() == "manifest.yaml" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var manifest Manifest
			if err := yaml.Unmarshal(data, &manifest); err != nil {
				return err
			}

			// Extract rule_ids from expect entries, skipping SCA entries (dependency field)
			for _, c := range manifest.Cases {
				for _, exp := range c.Expect {
					// Skip SCA entries (they have dependency field instead of rule_id)
					if exp.Dependency.Package != "" {
						continue
					}
					// Only record actual rule_ids
					if exp.RuleID != "" {
						coveredRules[exp.RuleID] = true
					}
				}
			}
		}

		return nil
	})
}
