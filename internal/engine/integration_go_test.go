//go:build cgo

package engine_test

import (
	"context"
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/engine"
	goparser "github.com/zerostrike/scanner/internal/parser/golang"
	"github.com/zerostrike/scanner/internal/rules"
)

func loadGoRules(t *testing.T) *engine.RuleIndex {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/go")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine.BuildIndex(allRules)
}

func matchGoSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := goparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.go", []byte(src))
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

// TestIntegration_TaintedExecCommandFiresZSGO001 verifies command-injection detection.
func TestIntegration_TaintedExecCommandFiresZSGO001(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc run() {\n\tcmd := os.Args[1]\n\texec.Command(cmd)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-001") {
		t.Error("expected ZS-GO-001 to fire when exec.Command argument is tainted")
	}
}

// TestIntegration_ConstantExecCommandDoesNotFireZSGO001 verifies the negative case.
func TestIntegration_ConstantExecCommandDoesNotFireZSGO001(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc run() {\n\texec.Command(\"ls\")\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-001") {
		t.Error("expected ZS-GO-001 to NOT fire for a constant argument")
	}
}

// TestIntegration_TaintedDbQueryFiresZSGO002 verifies SQL-injection detection.
func TestIntegration_TaintedDbQueryFiresZSGO002(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc handler() {\n\tid := r.URL.Query().Get(\"id\")\n" +
		"\tquery := \"SELECT * FROM users WHERE id = \" + id\n" +
		"\tdb.Query(query)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-002") {
		t.Error("expected ZS-GO-002 to fire when db.Query argument is tainted")
	}
}

// TestIntegration_ConstantDbQueryDoesNotFireZSGO002 verifies the negative case.
func TestIntegration_ConstantDbQueryDoesNotFireZSGO002(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc handler() {\n\tdb.Query(\"SELECT 1\")\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-002") {
		t.Error("expected ZS-GO-002 to NOT fire for a constant query")
	}
}

// TestIntegration_TaintedOsOpenFiresZSGO003 verifies path-traversal detection.
func TestIntegration_TaintedOsOpenFiresZSGO003(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc handler() {\n\tpath := r.FormValue(\"path\")\n\tos.Open(path)\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-003") {
		t.Error("expected ZS-GO-003 to fire when os.Open argument is tainted")
	}
}

// TestIntegration_ConstantOsOpenDoesNotFireZSGO003 verifies the negative case.
func TestIntegration_ConstantOsOpenDoesNotFireZSGO003(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc handler() {\n\tos.Open(\"/etc/config\")\n}\n"
	if hasRule(matchGoSource(t, idx, src), "ZS-GO-003") {
		t.Error("expected ZS-GO-003 to NOT fire for a constant path")
	}
}

// TestIntegration_Md5NewFiresZSGO004 verifies weak-crypto detection.
func TestIntegration_Md5NewFiresZSGO004(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc hash() {\n\th := md5.New()\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-004") {
		t.Error("expected ZS-GO-004 to fire on md5.New()")
	}
}

// TestIntegration_HardcodedCredentialFiresZSGO005 verifies hardcoded-secret detection.
func TestIntegration_HardcodedCredentialFiresZSGO005(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc main() {\n\tapiKey := \"sk-12345\"\n}\n"
	if !hasRule(matchGoSource(t, idx, src), "ZS-GO-005") {
		t.Error("expected ZS-GO-005 to fire on apiKey := \"sk-12345\"")
	}
}

// TestIntegration_CleanGoSourceHasNoFindings verifies the negative fixture shape.
func TestIntegration_CleanGoSourceHasNoFindings(t *testing.T) {
	idx := loadGoRules(t)
	src := "package main\nfunc main() {\n\tgreeting := \"hello\"\n\tfmt.Println(greeting)\n}\n"
	if results := matchGoSource(t, idx, src); len(results) != 0 {
		t.Errorf("expected no findings on clean source, got %d (first: %s)", len(results), results[0].Rule.ID)
	}
}
