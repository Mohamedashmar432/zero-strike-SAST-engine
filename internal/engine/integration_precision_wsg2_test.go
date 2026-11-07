//go:build cgo

package engine_test

import "testing"

// Precision tests for workstream G2 (tighten the noisiest rules that must
// stay). Each suppressed case has a twin proving the vulnerable case still
// fires. All values are synthetic.

func TestPrecisionG2_FilePathNeedsARealSource(t *testing.T) {
	idx := loadJavaRules(t)
	// A helper whose parameter is only "tainted" by being a parameter.
	helper := "class C { File open(String home, String user) { return new File(home, user); } }"
	if hasRule(matchJavaSource(t, idx, helper), "ZS-JAVA-006") {
		t.Error("ZS-JAVA-006 must not fire on a bare helper parameter")
	}
	// The request is not always called "request".
	for _, recv := range []string{"request", "req", "httpRequest"} {
		src := "class C { void m(HttpServletRequest " + recv + ") { String n = " + recv + ".getParameter(\"f\");\n" +
			"File f = new File(\"/srv/pdf/\" + n); } }"
		if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-006") {
			t.Errorf("ZS-JAVA-006 must still fire for %s.getParameter flowing into new File", recv)
		}
	}
	upload := "class C { void m(MultipartFile file) { String n = file.getOriginalFilename();\n" +
		"File f = new File(\"/srv/up\", n); } }"
	if !hasRule(matchJavaSource(t, idx, upload), "ZS-JAVA-006") {
		t.Error("ZS-JAVA-006 must still fire on an uploaded file name")
	}
}

func TestPrecisionG2_ExecuteNeedsAJDBCReceiver(t *testing.T) {
	idx := loadJavaRules(t)
	for _, src := range []string{
		"class C { void m(String dir, String cmd) { execute(dir, cmd); } }",
		"class C { void m(String dir, String cmd) { commandExecutionService.execute(dir, cmd); } }",
		"class C { void m(String f, String n) { super.execute(f, n); } }",
	} {
		if hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-037") {
			t.Errorf("ZS-JAVA-037 must not fire on a non-JDBC execute: %s", src)
		}
	}
	for _, recv := range []string{"statement", "stmt", "jdbcTemplate"} {
		src := "class C { void m(HttpServletRequest request) { String n = request.getParameter(\"n\");\n" +
			recv + ".execute(\"DELETE FROM t WHERE n = '\" + n + \"'\"); } }"
		if !hasRule(matchJavaSource(t, idx, src), "ZS-JAVA-037") {
			t.Errorf("ZS-JAVA-037 must still fire on %s.execute with a tainted query", recv)
		}
	}
}

func TestPrecisionG2_NumericParameterIsNotInjectable(t *testing.T) {
	idx := loadJavaRules(t)
	numeric := "class C { void m(long id) { String q = \"SELECT * FROM t WHERE id = \" + id;\n" +
		"statement.executeQuery(q); } }"
	if hasRule(matchJavaSource(t, idx, numeric), "ZS-JAVA-001") {
		t.Error("ZS-JAVA-001 must not fire when the concatenated parameter is a long")
	}
	text := "class C { void m(String id) { String q = \"SELECT * FROM t WHERE id = \" + id;\n" +
		"statement.executeQuery(q); } }"
	if !hasRule(matchJavaSource(t, idx, text), "ZS-JAVA-001") {
		t.Error("ZS-JAVA-001 must still fire when the concatenated parameter is a String")
	}
}
