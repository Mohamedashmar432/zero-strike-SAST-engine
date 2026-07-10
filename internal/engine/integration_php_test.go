//go:build cgo

package engine_test

import (
	"context"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	phpparser "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/php"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

func loadPhpRules(t *testing.T) *engine.RuleIndex {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/php")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine.BuildIndex(allRules)
}

func matchPhpSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := phpparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.php", []byte(src))
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

// TestIntegration_TaintedSystemFiresZSPHP001 verifies command-injection detection.
func TestIntegration_TaintedSystemFiresZSPHP001(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$cmd = $_GET['cmd'];\nsystem($cmd);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-001") {
		t.Error("expected ZS-PHP-001 to fire when system() argument is tainted")
	}
}

// TestIntegration_ConstantSystemDoesNotFireZSPHP001 verifies the negative case.
func TestIntegration_ConstantSystemDoesNotFireZSPHP001(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nsystem(\"ls -la\");\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-001") {
		t.Error("expected ZS-PHP-001 to NOT fire for a constant argument")
	}
}

// TestIntegration_TaintedMysqliQueryFiresZSPHP002 verifies SQL-injection detection.
func TestIntegration_TaintedMysqliQueryFiresZSPHP002(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$id = $_GET['id'];\n" +
		"$query = \"SELECT * FROM users WHERE id = \" . $id;\n" +
		"mysqli_query($conn, $query);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-002") {
		t.Error("expected ZS-PHP-002 to fire when mysqli_query argument is tainted")
	}
}

// TestIntegration_ConstantMysqliQueryDoesNotFireZSPHP002 verifies the negative case.
func TestIntegration_ConstantMysqliQueryDoesNotFireZSPHP002(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nmysqli_query($conn, \"SELECT 1\");\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-002") {
		t.Error("expected ZS-PHP-002 to NOT fire for a constant query")
	}
}

// TestIntegration_UnserializeFiresZSPHP003 verifies deserialization detection.
func TestIntegration_UnserializeFiresZSPHP003(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$obj = unserialize($data);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-003") {
		t.Error("expected ZS-PHP-003 to fire on unserialize()")
	}
}

// TestIntegration_TaintedEchoFiresZSPHP004 verifies XSS-sink detection.
func TestIntegration_TaintedEchoFiresZSPHP004(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$name = $_GET['name'];\necho $name;\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-004") {
		t.Error("expected ZS-PHP-004 to fire when echo argument is tainted")
	}
}

// TestIntegration_ConstantEchoDoesNotFireZSPHP004 verifies the negative case.
func TestIntegration_ConstantEchoDoesNotFireZSPHP004(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\necho \"hello\";\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-004") {
		t.Error("expected ZS-PHP-004 to NOT fire for a constant echo")
	}
}

// TestIntegration_HardcodedCredentialFiresZSPHP005 verifies hardcoded-secret detection.
func TestIntegration_HardcodedCredentialFiresZSPHP005(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$password = \"hunter2\";\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-005") {
		t.Error("expected ZS-PHP-005 to fire on $password = \"hunter2\"")
	}
}

// TestIntegration_CleanPhpSourceHasNoFindings verifies the negative fixture shape.
func TestIntegration_CleanPhpSourceHasNoFindings(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$greeting = \"hello\";\necho $greeting;\n"
	if results := matchPhpSource(t, idx, src); len(results) != 0 {
		t.Errorf("expected no findings on clean source, got %d (first: %s)", len(results), results[0].Rule.ID)
	}
}

// TestIntegration_TaintedShellExecFiresZSPHP006 verifies command-injection
// detection for shell_exec(), the sibling sink ZS-PHP-001's own description
// already flagged as a follow-up.
func TestIntegration_TaintedShellExecFiresZSPHP006(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$ip = $_REQUEST['ip'];\nshell_exec($ip);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-006") {
		t.Error("expected ZS-PHP-006 to fire when shell_exec() argument is tainted")
	}
}

// TestIntegration_TaintedIncludeFiresZSPHP007 verifies the PHP builder's new
// include_expression synthetic-call handling end-to-end through the real
// tree-sitter-php grammar, not just against hand-built IR.
func TestIntegration_TaintedIncludeFiresZSPHP007(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$file = $_GET['page'];\ninclude($file);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-007") {
		t.Error("expected ZS-PHP-007 to fire when include() argument is tainted")
	}
}

// TestIntegration_ConstantIncludeDoesNotFireZSPHP007 verifies the negative case.
func TestIntegration_ConstantIncludeDoesNotFireZSPHP007(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\ninclude(\"header.php\");\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-007") {
		t.Error("expected ZS-PHP-007 to NOT fire for a constant include path")
	}
}

// TestIntegration_TaintedRequireFiresZSPHP008 verifies the same builder
// change for require_expression.
func TestIntegration_TaintedRequireFiresZSPHP008(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\n$file = $_GET['page'];\nrequire($file);\n"
	if !hasRule(matchPhpSource(t, idx, src), "ZS-PHP-008") {
		t.Error("expected ZS-PHP-008 to fire when require() argument is tainted")
	}
}

// TestIntegration_ConstantRequireDoesNotFireZSPHP008 verifies the negative case.
func TestIntegration_ConstantRequireDoesNotFireZSPHP008(t *testing.T) {
	idx := loadPhpRules(t)
	src := "<?php\nrequire(\"header.php\");\n"
	if hasRule(matchPhpSource(t, idx, src), "ZS-PHP-008") {
		t.Error("expected ZS-PHP-008 to NOT fire for a constant require path")
	}
}
