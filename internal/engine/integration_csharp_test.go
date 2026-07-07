//go:build cgo

package engine_test

import (
	"context"
	"testing"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/engine"
	csparser "github.com/zerostrike/scanner/internal/parser/csharp"
	"github.com/zerostrike/scanner/internal/rules"
)

func loadCSharpRules(t *testing.T) *engine.RuleIndex {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/csharp")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine.BuildIndex(allRules)
}

func matchCSharpSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := csparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.cs", []byte(src))
	if err != nil {
		t.Fatalf("build IR: %v", err)
	}
	ar, err := analyzer.New(false).Analyze(context.Background(), irFile)
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

// TestIntegration_TaintedProcessStartFiresZSCS001 verifies command-injection detection.
func TestIntegration_TaintedProcessStartFiresZSCS001(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var cmd = Request.QueryString[\"cmd\"];\nProcess.Start(cmd); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-001") {
		t.Error("expected ZS-CS-001 to fire when Process.Start argument is tainted")
	}
}

// TestIntegration_ConstantProcessStartDoesNotFireZSCS001 verifies the negative case.
func TestIntegration_ConstantProcessStartDoesNotFireZSCS001(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { Process.Start(\"notepad.exe\"); } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-001") {
		t.Error("expected ZS-CS-001 to NOT fire for a constant argument")
	}
}

// TestIntegration_TaintedSqlCommandFiresZSCS002 verifies SQL-injection detection.
func TestIntegration_TaintedSqlCommandFiresZSCS002(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var name = Request.QueryString[\"name\"];\n" +
		"var query = \"SELECT * FROM Users WHERE Name = '\" + name + \"'\";\n" +
		"var cmd = new SqlCommand(query, conn); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-002") {
		t.Error("expected ZS-CS-002 to fire when SqlCommand query is tainted")
	}
}

// TestIntegration_ConstantSqlCommandDoesNotFireZSCS002 verifies the negative case.
func TestIntegration_ConstantSqlCommandDoesNotFireZSCS002(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var cmd = new SqlCommand(\"SELECT 1\", conn); } }"
	if hasRule(matchCSharpSource(t, idx, src), "ZS-CS-002") {
		t.Error("expected ZS-CS-002 to NOT fire for a constant query")
	}
}

// TestIntegration_BinaryFormatterFiresZSCS003 verifies deserialization detection.
func TestIntegration_BinaryFormatterFiresZSCS003(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { object M(Stream s) { var f = new BinaryFormatter();\nreturn f.Deserialize(s); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-003") {
		t.Error("expected ZS-CS-003 to fire on new BinaryFormatter()")
	}
}

// TestIntegration_TaintedResponseWriteFiresZSCS004 verifies XSS-sink detection.
func TestIntegration_TaintedResponseWriteFiresZSCS004(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var name = Request.QueryString[\"name\"];\nResponse.Write(\"<h1>\" + name + \"</h1>\"); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-004") {
		t.Error("expected ZS-CS-004 to fire when Response.Write value is tainted")
	}
}

// TestIntegration_Md5CreateFiresZSCS005 verifies weak-crypto detection.
func TestIntegration_Md5CreateFiresZSCS005(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var h = MD5.Create(); } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-005") {
		t.Error("expected ZS-CS-005 to fire on MD5.Create()")
	}
}

// TestIntegration_HardcodedCredentialFiresZSCS006 verifies hardcoded-secret detection.
func TestIntegration_HardcodedCredentialFiresZSCS006(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var password = \"hunter2\"; } }"
	if !hasRule(matchCSharpSource(t, idx, src), "ZS-CS-006") {
		t.Error("expected ZS-CS-006 to fire on password = \"hunter2\"")
	}
}

// TestIntegration_CleanCSharpSourceHasNoFindings verifies the negative fixture shape.
func TestIntegration_CleanCSharpSourceHasNoFindings(t *testing.T) {
	idx := loadCSharpRules(t)
	src := "class C { void M() { var greeting = \"hello\";\nConsole.WriteLine(greeting); } }"
	if results := matchCSharpSource(t, idx, src); len(results) != 0 {
		t.Errorf("expected no findings on clean source, got %d (first: %s)", len(results), results[0].Rule.ID)
	}
}
