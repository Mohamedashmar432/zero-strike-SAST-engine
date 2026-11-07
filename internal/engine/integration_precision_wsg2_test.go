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

func TestPrecisionG2_InnerHTMLTernaryOfLiterals(t *testing.T) {
	idx := loadJSRules(t)
	lit := "function f(saved) { var el = document.getElementById('t'); el.innerHTML = saved === 'dark' ? '<b>sun</b>' : '<i>moon</i>'; }"
	if hasRule(matchJSSource(t, idx, lit), "ZS-JS-002") {
		t.Error("ZS-JS-002 must not fire when both ternary branches are literals")
	}
	vuln := "function f(req) { var v = req.query.q; var el = document.getElementById('t'); el.innerHTML = v ? v : 'none'; }"
	if !hasRule(matchJSSource(t, idx, vuln), "ZS-JS-002") {
		t.Error("ZS-JS-002 must still fire when a branch is the tainted value")
	}
}

func TestPrecisionG2_CsrfExemptOnlyMattersWhenTheViewReadsABody(t *testing.T) {
	_, idx := loadPythonRules(t)
	render := "@csrf_exempt\ndef landing(request):\n    if not request.user.is_authenticated:\n        return redirect('login')\n    return render(request, 'a.html')\n"
	if hasRule(matchSource(t, idx, render), "ZS-PY-090") {
		t.Error("ZS-PY-090 must not fire on an exempt view that never reads a body")
	}
	for _, src := range []string{
		"@csrf_exempt\ndef pay(request):\n    amount = request.POST.get('amount')\n    return render(request, 'a.html')\n",
		"@csrf_exempt\ndef pay(request):\n    if request.method == 'POST':\n        return render(request, 'a.html')\n",
		"@csrf_exempt\ndef pay(request):\n    body = json.loads(request.body)\n    return JsonResponse(body)\n",
	} {
		if !hasRule(matchSource(t, idx, src), "ZS-PY-090") {
			t.Errorf("ZS-PY-090 must still fire on an exempt view that reads a body: %s", src)
		}
	}
}

func TestPrecisionG2_TranslationLabelIsNotACredential(t *testing.T) {
	idx := loadJSRules(t)
	label := "var lang = {\n  \"Password\": \"Contraseña\"\n};\n"
	if hasRule(matchJSSource(t, idx, label), "ZS-JS-141") {
		t.Error("ZS-JS-141 must not fire on a Title-case translation label")
	}
	cred := "var cfg = {\n  password: \"Tr0ub4dor-horse\"\n};\n"
	if !hasRule(matchJSSource(t, idx, cred), "ZS-JS-141") {
		t.Error("ZS-JS-141 must still fire on a literal password")
	}
}
