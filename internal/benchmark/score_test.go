package benchmark

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
)

func TestScoreCase_RuleMatchIsTP(t *testing.T) {
	c := Case{File: "vuln.py", Expect: []Expectation{{RuleID: "ZS-PY-001"}}}
	findings := []core.Finding{{RuleID: "ZS-PY-001", Kind: core.FindingKindSAST}}
	cr := scoreCase("python", c, findings)
	if cr.TP != 1 || cr.FP != 0 || cr.FN != 0 {
		t.Fatalf("got TP=%d FP=%d FN=%d, want TP=1 FP=0 FN=0", cr.TP, cr.FP, cr.FN)
	}
}

func TestScoreCase_MissingExpectedIsFN(t *testing.T) {
	c := Case{File: "vuln.py", Expect: []Expectation{{RuleID: "ZS-PY-001"}}}
	cr := scoreCase("python", c, nil)
	if cr.FN != 1 || cr.TP != 0 {
		t.Fatalf("got TP=%d FN=%d, want TP=0 FN=1", cr.TP, cr.FN)
	}
}

func TestScoreCase_UnexpectedFindingIsFP(t *testing.T) {
	c := Case{File: "clean.py", Expect: nil}
	findings := []core.Finding{{RuleID: "ZS-PY-001", Kind: core.FindingKindSAST}}
	cr := scoreCase("python", c, findings)
	if cr.FP != 1 || cr.TP != 0 {
		t.Fatalf("got TP=%d FP=%d, want TP=0 FP=1", cr.TP, cr.FP)
	}
}

func TestScoreCase_MinCountRequiresEnoughMatches(t *testing.T) {
	c := Case{File: "vuln.py", Expect: []Expectation{{RuleID: "ZS-PY-020", MinCount: 2}}}
	oneMatch := []core.Finding{{RuleID: "ZS-PY-020", Kind: core.FindingKindSAST}}
	cr := scoreCase("python", c, oneMatch)
	if cr.FN != 1 || cr.TP != 0 {
		t.Fatalf("min_count=2 with 1 match should be FN, got TP=%d FN=%d", cr.TP, cr.FN)
	}

	twoMatches := []core.Finding{
		{RuleID: "ZS-PY-020", Kind: core.FindingKindSAST},
		{RuleID: "ZS-PY-020", Kind: core.FindingKindSAST},
	}
	cr = scoreCase("python", c, twoMatches)
	if cr.TP != 1 || cr.FN != 0 || cr.FP != 0 {
		t.Fatalf("min_count=2 with 2 matches should be TP, got TP=%d FP=%d FN=%d", cr.TP, cr.FP, cr.FN)
	}
}

func TestScoreCase_DependencyExpectationMatchesByPackageAndEcosystem(t *testing.T) {
	c := Case{File: "package-lock.json", Expect: []Expectation{{Dependency: &DependencyExpectation{Package: "lodash", Ecosystem: "npm"}}}}
	findings := []core.Finding{{
		RuleID: "ZS-SCA-001",
		Kind:   core.FindingKindSCA,
		Dependency: &core.DependencyFinding{
			Package:   "lodash",
			Ecosystem: "npm",
		},
	}}
	cr := scoreCase("sca", c, findings)
	if cr.TP != 1 || cr.FP != 0 || cr.FN != 0 {
		t.Fatalf("got TP=%d FP=%d FN=%d, want TP=1", cr.TP, cr.FP, cr.FN)
	}
}

func TestScoreCase_DependencyExpectationDoesNotMatchDifferentPackage(t *testing.T) {
	c := Case{File: "package-lock.json", Expect: []Expectation{{Dependency: &DependencyExpectation{Package: "lodash", Ecosystem: "npm"}}}}
	findings := []core.Finding{{
		RuleID: "ZS-SCA-001",
		Kind:   core.FindingKindSCA,
		Dependency: &core.DependencyFinding{
			Package:   "express",
			Ecosystem: "npm",
		},
	}}
	cr := scoreCase("sca", c, findings)
	if cr.FN != 1 || cr.FP != 1 {
		t.Fatalf("mismatched package should be both an FN (expectation unmet) and an FP (unexpected finding), got FN=%d FP=%d", cr.FN, cr.FP)
	}
}

func TestSummary_PrecisionRecall(t *testing.T) {
	s := &Summary{TP: 8, FP: 2, FN: 2}
	if got := s.Precision(); got != 0.8 {
		t.Errorf("Precision() = %v, want 0.8", got)
	}
	if got := s.Recall(); got != 0.8 {
		t.Errorf("Recall() = %v, want 0.8", got)
	}
}

func TestLoadManifest_RejectsExpectationWithNeitherRuleIDNorDependency(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "manifest.yaml")
	content := "version: \"1\"\ncases:\n  - file: x.py\n    expect:\n      - min_count: 1\n"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifest(tmp); err == nil {
		t.Fatal("expected an error for an expectation with neither rule_id nor dependency")
	}
}
