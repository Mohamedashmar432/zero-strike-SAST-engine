//go:build cgo

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

func TestIntegration_OpenVariablePathFiresZSPY008(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "path = user_input\nf = open(path)\n")
	if !hasRule(results, "ZS-PY-008") {
		t.Error("expected ZS-PY-008 to fire on open() with variable path")
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

// TestIntegration_AssertFiresZSPY009 verifies the Sprint 4 fix for KI-001:
// assert_statement now maps to NodeKindAssert and ZS-PY-009 fires correctly.
func TestIntegration_AssertFiresZSPY009(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "assert user.is_admin()\n")
	if !hasRule(results, "ZS-PY-009") {
		t.Error("expected ZS-PY-009 to fire on assert statement")
	}
}

// TestIntegration_TaintedArgumentFiresZSPY004 verifies Sprint 11 taint tracking:
// ZS-PY-004 now only fires when the execute() argument traces back to a source.
func TestIntegration_TaintedArgumentFiresZSPY004(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "user_id = request.args.get('id')\nquery = \"SELECT \" + user_id\nexecute(query)\n")
	if !hasRule(results, "ZS-PY-004") {
		t.Error("expected ZS-PY-004 to fire when execute() argument is tainted")
	}
}

// TestIntegration_ConstantArgumentDoesNotFireZSPY004 verifies the false-positive
// fix: a constant string passed to execute() no longer fires ZS-PY-004.
func TestIntegration_ConstantArgumentDoesNotFireZSPY004(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "query = \"SELECT * FROM users\"\nexecute(query)\n")
	if hasRule(results, "ZS-PY-004") {
		t.Error("expected ZS-PY-004 to NOT fire when execute() argument is a constant")
	}
}

// TestIntegration_TaintedSubprocessCallFiresZSPY012 verifies taint tracking on subprocess.call.
func TestIntegration_TaintedSubprocessCallFiresZSPY012(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "cmd = request.args.get('cmd')\nsubprocess.call(cmd)\n")
	if !hasRule(results, "ZS-PY-012") {
		t.Error("expected ZS-PY-012 to fire when subprocess.call() argument is tainted")
	}
}

// TestIntegration_ConstantSubprocessCallDoesNotFireZSPY012 verifies the negative case.
func TestIntegration_ConstantSubprocessCallDoesNotFireZSPY012(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "subprocess.call(\"ls -la\")\n")
	if hasRule(results, "ZS-PY-012") {
		t.Error("expected ZS-PY-012 to NOT fire for a constant argument")
	}
}

// TestIntegration_FlaskDebugFiresZSPY016 verifies the new A02 rule pack.
func TestIntegration_FlaskDebugFiresZSPY016(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "app.run(debug=True)\n")
	if !hasRule(results, "ZS-PY-016") {
		t.Error("expected ZS-PY-016 to fire on app.run(debug=True)")
	}
}

func TestIntegration_DjangoDebugFiresZSPY017(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "DEBUG = True\n")
	if !hasRule(results, "ZS-PY-017") {
		t.Error("expected ZS-PY-017 to fire on DEBUG = True")
	}
}

func TestIntegration_HardcodedCredentialFiresZSPY020(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "password = \"hunter2\"\n")
	if !hasRule(results, "ZS-PY-020") {
		t.Error("expected ZS-PY-020 to fire on password = \"hunter2\"")
	}
}

func TestIntegration_BareExceptFiresZSPY023(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "try:\n    do_thing()\nexcept:\n    pass\n")
	if !hasRule(results, "ZS-PY-023") {
		t.Error("expected ZS-PY-023 to fire on a bare except:")
	}
}

func TestIntegration_TypedExceptDoesNotFireZSPY023(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "try:\n    do_thing()\nexcept ValueError:\n    log(e)\n")
	if hasRule(results, "ZS-PY-023") {
		t.Error("expected ZS-PY-023 to NOT fire on a typed except clause")
	}
}

func TestIntegration_EmptyExceptHandlerFiresZSPY024(t *testing.T) {
	_, idx := loadPythonRules(t)
	results := matchSource(t, idx, "try:\n    do_thing()\nexcept ValueError:\n    pass\n")
	if !hasRule(results, "ZS-PY-024") {
		t.Error("expected ZS-PY-024 to fire on an empty (pass-only) except handler")
	}
}
