package engine_test

import (
	"context"
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/engine"
	pythonparser "github.com/zerostrike/scanner/internal/parser/python"
	"github.com/zerostrike/scanner/internal/rules"
)

func loadPythonRules(t *testing.T) ([]*rules.Rule, *engine.RuleIndex) {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/python")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return allRules, engine.BuildIndex(allRules)
}

func matchSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := pythonparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.py", []byte(src))
	if err != nil {
		t.Fatalf("build IR: %v", err)
	}
	ar, err := analyzer.New().Analyze(context.Background(), irFile)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	mc := &engine.MatchContext{Index: idx, File: ar}
	results, err := engine.New().Match(context.Background(), mc)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return results
}

func hasRule(results []engine.MatchResult, id string) bool {
	for _, r := range results {
		if r.Rule.ID == id {
			return true
		}
	}
	return false
}

func TestIntegration_EvalFiresZSPY001(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "result = eval(user_input)\n")
	if !hasRule(results, "ZS-PY-001") {
		t.Error("expected ZS-PY-001 to fire on eval() call")
	}
}

func TestIntegration_PickleFiresZSPY002(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import pickle\nobj = pickle.loads(data)\n")
	if !hasRule(results, "ZS-PY-002") {
		t.Error("expected ZS-PY-002 to fire on pickle.loads() call")
	}
}

func TestIntegration_SubprocessFiresZSPY003(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import subprocess\nsubprocess.run(cmd, shell=True)\n")
	if !hasRule(results, "ZS-PY-003") {
		t.Error("expected ZS-PY-003 to fire on subprocess.run() call")
	}
}

func TestIntegration_OsSystemFiresZSPY005(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import os\nos.system(cmd)\n")
	if !hasRule(results, "ZS-PY-005") {
		t.Error("expected ZS-PY-005 to fire on os.system() call")
	}
}

func TestIntegration_TempfileFiresZSPY010(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import tempfile\npath = tempfile.mktemp()\n")
	if !hasRule(results, "ZS-PY-010") {
		t.Error("expected ZS-PY-010 to fire on tempfile.mktemp() call")
	}
}

func TestIntegration_HashlibFiresZSPY007(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import hashlib\nhashlib.md5(password.encode())\n")
	if !hasRule(results, "ZS-PY-007") {
		t.Error("expected ZS-PY-007 to fire on hashlib.md5() call")
	}
}

func TestIntegration_YamlLoadFiresZSPY010(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "import yaml\nyaml.load(stream)\n")
	if !hasRule(results, "ZS-PY-010") {
		t.Error("expected ZS-PY-010 to fire on yaml.load() call")
	}
}

// TestIntegration_AssertDoesNotFire documents the known ZS-PY-009 limitation:
// assert is a statement in tree-sitter, not a call node, so the rule cannot fire.
func TestIntegration_AssertDoesNotFire(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "assert user.is_admin()\n")
	if hasRule(results, "ZS-PY-009") {
		t.Error("ZS-PY-009 fired — assert now parsed as call? Update known issue in plan.")
	}
	// ponytail: expected non-firing — tree-sitter emits assert_statement not call
}
