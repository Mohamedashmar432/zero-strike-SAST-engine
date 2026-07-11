//go:build cgo

package engine_test

import (
	"context"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	jsparser "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/javascript"
	tsparser "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/typescript"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

func loadJSRules(t *testing.T) *engine.RuleIndex {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/js")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine.BuildIndex(allRules)
}

func loadTSRules(t *testing.T) *engine.RuleIndex {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/ts")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine.BuildIndex(allRules)
}

func matchJSSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := jsparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.js", []byte(src))
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

func matchTSSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := tsparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.ts", []byte(src))
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

// TestIntegration_TaintedEvalFiresZSJS001 verifies taint tracking on eval().
func TestIntegration_TaintedEvalFiresZSJS001(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "let userInput = req.query.q;\neval(userInput);\n")
	if !hasRule(results, "ZS-JS-001") {
		t.Error("expected ZS-JS-001 to fire when eval() argument is tainted")
	}
}

// TestIntegration_ConstantEvalDoesNotFireZSJS001 verifies the false-positive fix.
func TestIntegration_ConstantEvalDoesNotFireZSJS001(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "eval(\"1+1\");\n")
	if hasRule(results, "ZS-JS-001") {
		t.Error("expected ZS-JS-001 to NOT fire for a constant argument")
	}
}

// TestIntegration_TaintedInnerHTMLFiresZSJS002 verifies the new TaintedRHS filter.
func TestIntegration_TaintedInnerHTMLFiresZSJS002(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "let userInput = req.query.name;\nel.innerHTML = userInput;\n")
	if !hasRule(results, "ZS-JS-002") {
		t.Error("expected ZS-JS-002 to fire when innerHTML RHS is tainted")
	}
}

// TestIntegration_ConstantInnerHTMLDoesNotFireZSJS002 verifies the negative case.
func TestIntegration_ConstantInnerHTMLDoesNotFireZSJS002(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "el.innerHTML = \"<b>hello</b>\";\n")
	if hasRule(results, "ZS-JS-002") {
		t.Error("expected ZS-JS-002 to NOT fire for a constant RHS")
	}
}

// TestIntegration_RejectUnauthorizedFiresZSJS006 verifies the new A02 rule.
func TestIntegration_RejectUnauthorizedFiresZSJS006(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "https.request(url, {rejectUnauthorized: false});\n")
	if !hasRule(results, "ZS-JS-006") {
		t.Error("expected ZS-JS-006 to fire on rejectUnauthorized: false")
	}
}

// TestIntegration_HardcodedCredentialFiresZSJS007 verifies the new A07 rule.
func TestIntegration_HardcodedCredentialFiresZSJS007(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "const password = \"hunter2\";\n")
	if !hasRule(results, "ZS-JS-007") {
		t.Error("expected ZS-JS-007 to fire on password = \"hunter2\"")
	}
}

// TestIntegration_JwtDecodeFiresZSJS008 verifies the new A07 rule.
func TestIntegration_JwtDecodeFiresZSJS008(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "const payload = jwt.decode(token);\n")
	if !hasRule(results, "ZS-JS-008") {
		t.Error("expected ZS-JS-008 to fire on jwt.decode()")
	}
}

// TestIntegration_EmptyCatchFiresZSJS010 verifies the new A10 rule.
func TestIntegration_EmptyCatchFiresZSJS010(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "try {\n  doThing();\n} catch (e) {\n}\n")
	if !hasRule(results, "ZS-JS-010") {
		t.Error("expected ZS-JS-010 to fire on an empty catch block")
	}
}

// TestIntegration_NonEmptyCatchDoesNotFireZSJS010 verifies the negative case.
func TestIntegration_NonEmptyCatchDoesNotFireZSJS010(t *testing.T) {
	idx := loadJSRules(t)
	results := matchJSSource(t, idx, "try {\n  doThing();\n} catch (e) {\n  console.error(e);\n}\n")
	if hasRule(results, "ZS-JS-010") {
		t.Error("expected ZS-JS-010 to NOT fire when the catch block logs the error")
	}
}

// TestIntegration_TaintedPoolQueryFiresZSJS021 verifies node-postgres/mysql2 pool SQLi detection.
func TestIntegration_TaintedPoolQueryFiresZSJS021(t *testing.T) {
	idx := loadJSRules(t)
	src := "const id = req.query.id;\n" +
		"const sql = \"SELECT * FROM users WHERE id = \" + id;\n" +
		"pool.query(sql);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-021") {
		t.Error("expected ZS-JS-021 to fire when pool.query argument is tainted")
	}
}

// TestIntegration_ConstantPoolQueryDoesNotFireZSJS021 verifies the negative case.
func TestIntegration_ConstantPoolQueryDoesNotFireZSJS021(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "pool.query(\"SELECT 1\");\n"), "ZS-JS-021") {
		t.Error("expected ZS-JS-021 to NOT fire for a constant query")
	}
}

// TestIntegration_TaintedClientQueryFiresZSJS022 verifies node-postgres/mysql2 client SQLi detection.
func TestIntegration_TaintedClientQueryFiresZSJS022(t *testing.T) {
	idx := loadJSRules(t)
	src := "const id = req.query.id;\n" +
		"const sql = \"SELECT * FROM users WHERE id = \" + id;\n" +
		"client.query(sql);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-022") {
		t.Error("expected ZS-JS-022 to fire when client.query argument is tainted")
	}
}

// TestIntegration_TaintedEvalFiresZSTS001 verifies taint tracking transfers to TypeScript.
func TestIntegration_TaintedEvalFiresZSTS001(t *testing.T) {
	idx := loadTSRules(t)
	results := matchTSSource(t, idx, "let userInput: string = req.query.q;\neval(userInput);\n")
	if !hasRule(results, "ZS-TS-001") {
		t.Error("expected ZS-TS-001 to fire when eval() argument is tainted")
	}
}

// TestIntegration_EmptyCatchFiresZSTS005 verifies the new TS A10 rule.
func TestIntegration_EmptyCatchFiresZSTS005(t *testing.T) {
	idx := loadTSRules(t)
	results := matchTSSource(t, idx, "try {\n  doThing();\n} catch (e) {\n}\n")
	if !hasRule(results, "ZS-TS-005") {
		t.Error("expected ZS-TS-005 to fire on an empty catch block")
	}
}

// TestIntegration_TaintedPoolQueryFiresZSTS006 verifies TS inherits nothing from JS —
// this rule must be defined for TypeScript directly to fire on a .ts file.
func TestIntegration_TaintedPoolQueryFiresZSTS006(t *testing.T) {
	idx := loadTSRules(t)
	src := "const id: string = req.query.id;\n" +
		"const sql: string = \"SELECT * FROM users WHERE id = \" + id;\n" +
		"pool.query(sql);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-006") {
		t.Error("expected ZS-TS-006 to fire when pool.query argument is tainted")
	}
}

// TestIntegration_SessionSecureFalseFiresZSTS008 verifies the TS cookie-secure rule.
func TestIntegration_SessionSecureFalseFiresZSTS008(t *testing.T) {
	idx := loadTSRules(t)
	src := "app.use(session({ secret: \"s\", cookie: { secure: false } }));\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-008") {
		t.Error("expected ZS-TS-008 to fire on session({ cookie: { secure: false } })")
	}
}
