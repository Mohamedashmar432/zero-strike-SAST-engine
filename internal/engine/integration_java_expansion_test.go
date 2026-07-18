//go:build cgo

package engine_test

import (
	"context"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
	javaparser "github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/java"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/rules"
)

func loadJavaRules(t *testing.T) *engine.RuleIndex {
	t.Helper()
	loader := rules.NewLoader(rules.EmbeddedFS)
	allRules, err := loader.LoadDir("data/java")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine.BuildIndex(allRules)
}

func matchJavaSource(t *testing.T, idx *engine.RuleIndex, src string) []engine.MatchResult {
	t.Helper()
	builder := javaparser.NewIRBuilder()
	irFile, _, err := builder.Build("test.java", []byte(src))
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

// TestIntegration_TaintedXPathEvaluateFiresZSJAVA025 verifies XPath-injection detection.
func TestIntegration_TaintedXPathEvaluateFiresZSJAVA025(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { String user = request.getParameter(\"user\");\n" +
		"xpath.evaluate(\"//users/user[@name='\" + user + \"']\", doc); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-025") {
		t.Error("expected ZS-JAVA-025 to fire when xpath.evaluate() expression is tainted")
	}
}

// TestIntegration_ConstantXPathEvaluateDoesNotFireZSJAVA025 verifies the negative case.
func TestIntegration_ConstantXPathEvaluateDoesNotFireZSJAVA025(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { xpath.evaluate(\"//users/user[@name='admin']\", doc); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-025") {
		t.Error("expected ZS-JAVA-025 to NOT fire for a constant expression")
	}
}

// TestIntegration_TaintedDirContextSearchFiresZSJAVA026 verifies LDAP-injection detection.
func TestIntegration_TaintedDirContextSearchFiresZSJAVA026(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { String uid = request.getParameter(\"uid\");\n" +
		"ctx.search(\"ou=people,dc=example,dc=com\", \"(uid=\" + uid + \")\", null); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-026") {
		t.Error("expected ZS-JAVA-026 to fire when ctx.search() filter is tainted")
	}
}

// TestIntegration_ConstantDirContextSearchDoesNotFireZSJAVA026 verifies the negative case.
func TestIntegration_ConstantDirContextSearchDoesNotFireZSJAVA026(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { ctx.search(\"ou=people,dc=example,dc=com\", \"(uid=admin)\", null); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-026") {
		t.Error("expected ZS-JAVA-026 to NOT fire for a constant filter")
	}
}

// TestIntegration_TaintedContextLookupFiresZSJAVA027 verifies JNDI-injection detection.
func TestIntegration_TaintedContextLookupFiresZSJAVA027(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { String name = request.getParameter(\"name\");\nctx.lookup(name); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-027") {
		t.Error("expected ZS-JAVA-027 to fire when ctx.lookup() name is tainted")
	}
}

// TestIntegration_ConstantContextLookupDoesNotFireZSJAVA027 verifies the negative case.
func TestIntegration_ConstantContextLookupDoesNotFireZSJAVA027(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { ctx.lookup(\"java:comp/env/jdbc/AppDS\"); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-027") {
		t.Error("expected ZS-JAVA-027 to NOT fire for a constant lookup name")
	}
}

// TestIntegration_TaintedClassForNameFiresZSJAVA028 verifies unsafe-reflection detection.
func TestIntegration_TaintedClassForNameFiresZSJAVA028(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { String cls = request.getParameter(\"handler\");\nClass.forName(cls); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-028") {
		t.Error("expected ZS-JAVA-028 to fire when Class.forName() argument is tainted")
	}
}

// TestIntegration_ConstantClassForNameDoesNotFireZSJAVA028 verifies the negative case.
func TestIntegration_ConstantClassForNameDoesNotFireZSJAVA028(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { Class.forName(\"com.example.KnownHandler\"); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-028") {
		t.Error("expected ZS-JAVA-028 to NOT fire for a constant class name")
	}
}

// TestIntegration_SnakeYamlLoadFiresZSJAVA029 verifies unsafe-SnakeYAML detection.
func TestIntegration_SnakeYamlLoadFiresZSJAVA029(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { Object m(String document) { Yaml yaml = new Yaml();\nreturn yaml.load(document); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-029") {
		t.Error("expected ZS-JAVA-029 to fire on yaml.load()")
	}
}

// TestIntegration_XMLDecoderReadObjectFiresZSJAVA030 verifies XMLDecoder detection.
func TestIntegration_XMLDecoderReadObjectFiresZSJAVA030(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { Object m(InputStream in) { XMLDecoder decoder = new XMLDecoder(in);\nreturn decoder.readObject(); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-030") {
		t.Error("expected ZS-JAVA-030 to fire on decoder.readObject()")
	}
}

// TestIntegration_TaintedXStreamFromXMLFiresZSJAVA031 verifies XStream detection.
func TestIntegration_TaintedXStreamFromXMLFiresZSJAVA031(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { String payload = request.getParameter(\"payload\");\n" +
		"Object obj = xstream.fromXML(payload); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-031") {
		t.Error("expected ZS-JAVA-031 to fire when xstream.fromXML() input is tainted")
	}
}

// TestIntegration_ConstantXStreamFromXMLDoesNotFireZSJAVA031 verifies the negative case.
func TestIntegration_ConstantXStreamFromXMLDoesNotFireZSJAVA031(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { Object obj = xstream.fromXML(\"<point/>\"); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-031") {
		t.Error("expected ZS-JAVA-031 to NOT fire for a constant document")
	}
}

// TestIntegration_SensitiveLoggerInfoFiresZSJAVA032 verifies sensitive-log detection.
func TestIntegration_SensitiveLoggerInfoFiresZSJAVA032(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m(String apiKey) { logger.info(apiKey); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-032") {
		t.Error("expected ZS-JAVA-032 to fire when a sensitive-looking identifier is logged")
	}
}

// TestIntegration_BenignLoggerInfoDoesNotFireZSJAVA032 verifies the negative case.
func TestIntegration_BenignLoggerInfoDoesNotFireZSJAVA032(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m(String requestId) { logger.info(requestId); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-032") {
		t.Error("expected ZS-JAVA-032 to NOT fire for a benign identifier")
	}
}

// TestIntegration_WeakTLSProtocolFiresZSJAVA033 verifies deprecated-protocol detection.
func TestIntegration_WeakTLSProtocolFiresZSJAVA033(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { SSLContext legacy = SSLContext.getInstance(\"SSLv3\"); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-033") {
		t.Error("expected ZS-JAVA-033 to fire on SSLContext.getInstance(\"SSLv3\")")
	}
}

// TestIntegration_ModernTLSProtocolDoesNotFireZSJAVA033 verifies TLSv1.3 is not flagged.
func TestIntegration_ModernTLSProtocolDoesNotFireZSJAVA033(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { SSLContext modern = SSLContext.getInstance(\"TLSv1.3\"); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-033") {
		t.Error("expected ZS-JAVA-033 to NOT fire on SSLContext.getInstance(\"TLSv1.3\")")
	}
}

// TestIntegration_TaintedParseExpressionFiresZSJAVA034 verifies SpEL-injection detection.
func TestIntegration_TaintedParseExpressionFiresZSJAVA034(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { String expr = request.getParameter(\"expr\");\nparser.parseExpression(expr); } }"
	if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-034") {
		t.Error("expected ZS-JAVA-034 to fire when parser.parseExpression() input is tainted")
	}
}

// TestIntegration_ConstantParseExpressionDoesNotFireZSJAVA034 verifies the negative case.
func TestIntegration_ConstantParseExpressionDoesNotFireZSJAVA034(t *testing.T) {
	idx := loadJavaRules(t)
	src := "class C { void m() { parser.parseExpression(\"payload.amount > 100\"); } }"
	if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-034") {
		t.Error("expected ZS-JAVA-034 to NOT fire for a constant expression")
	}
}
