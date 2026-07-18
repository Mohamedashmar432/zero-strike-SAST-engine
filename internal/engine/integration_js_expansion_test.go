//go:build cgo

package engine_test

import (
	"testing"
)

// Integration tests for the JavaScript rule expansion ZS-JS-035..ZS-JS-048.
// Helpers (loadJSRules, matchJSSource, hasRule) live in
// integration_javascript_test.go / integration_test.go.

// --- ZS-JS-035: SSRF via axios.get ---

func TestIntegration_TaintedAxiosGetFiresZSJS035(t *testing.T) {
	idx := loadJSRules(t)
	src := "const target = req.query.url;\naxios.get(target);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-035") {
		t.Error("expected ZS-JS-035 to fire when axios.get URL is tainted")
	}
}

func TestIntegration_ConstantAxiosGetDoesNotFireZSJS035(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "axios.get(\"https://example.com/status\");\n"), "ZS-JS-035") {
		t.Error("expected ZS-JS-035 to NOT fire for a constant URL")
	}
}

// --- ZS-JS-036: SSRF via axios.post ---

func TestIntegration_TaintedAxiosPostFiresZSJS036(t *testing.T) {
	idx := loadJSRules(t)
	src := "axios.post(req.body.endpoint, { ok: true });\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-036") {
		t.Error("expected ZS-JS-036 to fire when axios.post URL is tainted")
	}
}

func TestIntegration_ConstantAxiosPostDoesNotFireZSJS036(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "axios.post(\"https://example.com/api\", { ok: true });\n"), "ZS-JS-036") {
		t.Error("expected ZS-JS-036 to NOT fire for a constant URL")
	}
}

// --- ZS-JS-037: SSRF via fetch ---

func TestIntegration_TaintedFetchFiresZSJS037(t *testing.T) {
	idx := loadJSRules(t)
	src := "const target = req.query.url;\nfetch(target);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-037") {
		t.Error("expected ZS-JS-037 to fire when fetch URL is tainted")
	}
}

func TestIntegration_ConstantFetchDoesNotFireZSJS037(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "fetch(\"https://example.com/data\");\n"), "ZS-JS-037") {
		t.Error("expected ZS-JS-037 to NOT fire for a constant URL")
	}
}

// --- ZS-JS-038: SSRF via http.get ---

func TestIntegration_TaintedHTTPGetFiresZSJS038(t *testing.T) {
	idx := loadJSRules(t)
	src := "const target = req.query.target;\nhttp.get(target);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-038") {
		t.Error("expected ZS-JS-038 to fire when http.get URL is tainted")
	}
}

func TestIntegration_ConstantHTTPGetDoesNotFireZSJS038(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "http.get(\"http://internal.example/health\");\n"), "ZS-JS-038") {
		t.Error("expected ZS-JS-038 to NOT fire for a constant URL")
	}
}

// --- ZS-JS-039: NoSQL injection via collection.find ---

func TestIntegration_TaintedCollectionFindFiresZSJS039(t *testing.T) {
	idx := loadJSRules(t)
	src := "const term = req.query.q;\ncollection.find(term);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-039") {
		t.Error("expected ZS-JS-039 to fire when collection.find argument is tainted")
	}
}

func TestIntegration_ConstantCollectionFindDoesNotFireZSJS039(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "collection.find({ status: \"active\" });\n"), "ZS-JS-039") {
		t.Error("expected ZS-JS-039 to NOT fire for a constant filter")
	}
}

// --- ZS-JS-040: prototype pollution via __proto__ assignment ---

func TestIntegration_TaintedProtoAssignmentFiresZSJS040(t *testing.T) {
	idx := loadJSRules(t)
	src := "const payload = req.body.data;\nsettings.__proto__ = payload;\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-040") {
		t.Error("expected ZS-JS-040 to fire when __proto__ RHS is tainted")
	}
}

func TestIntegration_ConstantProtoAssignmentDoesNotFireZSJS040(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "settings.__proto__ = {};\n"), "ZS-JS-040") {
		t.Error("expected ZS-JS-040 to NOT fire for a constant RHS")
	}
}

// --- ZS-JS-041: SSTI via ejs.render ---

func TestIntegration_TaintedEjsRenderFiresZSJS041(t *testing.T) {
	idx := loadJSRules(t)
	src := "const tpl = req.body.template;\nejs.render(tpl, {});\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-041") {
		t.Error("expected ZS-JS-041 to fire when ejs.render template is tainted")
	}
}

func TestIntegration_ConstantEjsRenderDoesNotFireZSJS041(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "ejs.render(\"<b>hi</b>\", {});\n"), "ZS-JS-041") {
		t.Error("expected ZS-JS-041 to NOT fire for a constant template")
	}
}

// --- ZS-JS-042: SSTI via pug.render ---

func TestIntegration_TaintedPugRenderFiresZSJS042(t *testing.T) {
	idx := loadJSRules(t)
	if !hasRule(matchJSSource(t, idx, "pug.render(req.body.tpl);\n"), "ZS-JS-042") {
		t.Error("expected ZS-JS-042 to fire when pug.render template is tainted")
	}
}

func TestIntegration_ConstantPugRenderDoesNotFireZSJS042(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "pug.render(\"p hello\");\n"), "ZS-JS-042") {
		t.Error("expected ZS-JS-042 to NOT fire for a constant template")
	}
}

// --- ZS-JS-043: dynamic code via vm.runInNewContext ---

func TestIntegration_TaintedVMRunInNewContextFiresZSJS043(t *testing.T) {
	idx := loadJSRules(t)
	src := "const code = req.query.expr;\nvm.runInNewContext(code, {});\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-043") {
		t.Error("expected ZS-JS-043 to fire when vm.runInNewContext code is tainted")
	}
}

func TestIntegration_ConstantVMRunInNewContextDoesNotFireZSJS043(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "vm.runInNewContext(\"1+1\", {});\n"), "ZS-JS-043") {
		t.Error("expected ZS-JS-043 to NOT fire for a constant code string")
	}
}

// --- ZS-JS-044: weak cipher via crypto.createCipheriv ---

func TestIntegration_WeakCipherFiresZSJS044(t *testing.T) {
	idx := loadJSRules(t)
	if !hasRule(matchJSSource(t, idx, "const cipher = crypto.createCipheriv('des-ede3', key, iv);\n"), "ZS-JS-044") {
		t.Error("expected ZS-JS-044 to fire on crypto.createCipheriv('des-ede3')")
	}
}

func TestIntegration_ModernCipherDoesNotFireZSJS044(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n"), "ZS-JS-044") {
		t.Error("expected ZS-JS-044 to NOT fire on crypto.createCipheriv('aes-256-gcm')")
	}
}

// --- ZS-JS-045: command injection via execSync ---

func TestIntegration_TaintedExecSyncFiresZSJS045(t *testing.T) {
	idx := loadJSRules(t)
	src := "const host = req.body.host;\nconst cmd = 'ping -c 2 ' + host;\nexecSync(cmd);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-045") {
		t.Error("expected ZS-JS-045 to fire when execSync argument is tainted")
	}
}

func TestIntegration_ConstantExecSyncDoesNotFireZSJS045(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "execSync(\"ls -la\");\n"), "ZS-JS-045") {
		t.Error("expected ZS-JS-045 to NOT fire for a constant command")
	}
}

// --- ZS-JS-046: DOM open redirect via location.href ---

func TestIntegration_TaintedLocationHrefFiresZSJS046(t *testing.T) {
	idx := loadJSRules(t)
	src := "const target = location.search;\nlocation.href = target;\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-046") {
		t.Error("expected ZS-JS-046 to fire when location.href RHS is tainted")
	}
}

func TestIntegration_ConstantLocationHrefDoesNotFireZSJS046(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "location.href = \"/home\";\n"), "ZS-JS-046") {
		t.Error("expected ZS-JS-046 to NOT fire for a constant RHS")
	}
}

// --- ZS-JS-047: DOM XSS via insertAdjacentHTML ---

func TestIntegration_TaintedInsertAdjacentHTMLFiresZSJS047(t *testing.T) {
	idx := loadJSRules(t)
	src := "const html = req.query.msg;\nel.insertAdjacentHTML('beforeend', html);\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-047") {
		t.Error("expected ZS-JS-047 to fire when insertAdjacentHTML argument is tainted")
	}
}

func TestIntegration_ConstantInsertAdjacentHTMLDoesNotFireZSJS047(t *testing.T) {
	idx := loadJSRules(t)
	if hasRule(matchJSSource(t, idx, "el.insertAdjacentHTML('beforeend', '<b>hi</b>');\n"), "ZS-JS-047") {
		t.Error("expected ZS-JS-047 to NOT fire for constant HTML")
	}
}

// --- ZS-JS-048: JWT verification accepting alg none ---

func TestIntegration_JwtVerifyAlgNoneFiresZSJS048(t *testing.T) {
	idx := loadJSRules(t)
	src := "jwt.verify(tok, signingKey, { algorithms: ['none'] });\n"
	if !hasRule(matchJSSource(t, idx, src), "ZS-JS-048") {
		t.Error("expected ZS-JS-048 to fire when jwt.verify allows the 'none' algorithm")
	}
}

func TestIntegration_JwtVerifyRealAlgDoesNotFireZSJS048(t *testing.T) {
	idx := loadJSRules(t)
	src := "jwt.verify(tok, signingKey, { algorithms: ['RS256'] });\n"
	if hasRule(matchJSSource(t, idx, src), "ZS-JS-048") {
		t.Error("expected ZS-JS-048 to NOT fire when only real algorithms are allowed")
	}
}
