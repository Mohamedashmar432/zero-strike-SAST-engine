//go:build cgo

package engine_test

import (
	"testing"
)

// Integration tests for the TypeScript rule expansion ZS-TS-033..ZS-TS-046
// (mirrors of ZS-JS-035..ZS-JS-048). Helpers (loadTSRules, matchTSSource,
// hasRule) live in integration_javascript_test.go / integration_test.go.

// --- ZS-TS-033: SSRF via axios.get ---

func TestIntegration_TaintedAxiosGetFiresZSTS033(t *testing.T) {
	idx := loadTSRules(t)
	src := "const target: string = req.query.url;\naxios.get(target);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-033") {
		t.Error("expected ZS-TS-033 to fire when axios.get URL is tainted")
	}
}

func TestIntegration_ConstantAxiosGetDoesNotFireZSTS033(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "axios.get(\"https://example.com/status\");\n"), "ZS-TS-033") {
		t.Error("expected ZS-TS-033 to NOT fire for a constant URL")
	}
}

// --- ZS-TS-034: SSRF via axios.post ---

func TestIntegration_TaintedAxiosPostFiresZSTS034(t *testing.T) {
	idx := loadTSRules(t)
	src := "axios.post(req.body.endpoint, { ok: true });\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-034") {
		t.Error("expected ZS-TS-034 to fire when axios.post URL is tainted")
	}
}

func TestIntegration_ConstantAxiosPostDoesNotFireZSTS034(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "axios.post(\"https://example.com/api\", { ok: true });\n"), "ZS-TS-034") {
		t.Error("expected ZS-TS-034 to NOT fire for a constant URL")
	}
}

// --- ZS-TS-035: SSRF via fetch ---

func TestIntegration_TaintedFetchFiresZSTS035(t *testing.T) {
	idx := loadTSRules(t)
	src := "const target: string = req.query.url;\nfetch(target);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-035") {
		t.Error("expected ZS-TS-035 to fire when fetch URL is tainted")
	}
}

func TestIntegration_ConstantFetchDoesNotFireZSTS035(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "fetch(\"https://example.com/data\");\n"), "ZS-TS-035") {
		t.Error("expected ZS-TS-035 to NOT fire for a constant URL")
	}
}

// --- ZS-TS-036: SSRF via http.get ---

func TestIntegration_TaintedHTTPGetFiresZSTS036(t *testing.T) {
	idx := loadTSRules(t)
	src := "const target: string = req.query.target;\nhttp.get(target);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-036") {
		t.Error("expected ZS-TS-036 to fire when http.get URL is tainted")
	}
}

func TestIntegration_ConstantHTTPGetDoesNotFireZSTS036(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "http.get(\"http://internal.example/health\");\n"), "ZS-TS-036") {
		t.Error("expected ZS-TS-036 to NOT fire for a constant URL")
	}
}

// --- ZS-TS-037: NoSQL injection via collection.find ---

func TestIntegration_TaintedCollectionFindFiresZSTS037(t *testing.T) {
	idx := loadTSRules(t)
	src := "const term: string = req.query.q;\ncollection.find(term);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-037") {
		t.Error("expected ZS-TS-037 to fire when collection.find argument is tainted")
	}
}

func TestIntegration_ConstantCollectionFindDoesNotFireZSTS037(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "collection.find({ status: \"active\" });\n"), "ZS-TS-037") {
		t.Error("expected ZS-TS-037 to NOT fire for a constant filter")
	}
}

// --- ZS-TS-038: prototype pollution via __proto__ assignment ---

func TestIntegration_TaintedProtoAssignmentFiresZSTS038(t *testing.T) {
	idx := loadTSRules(t)
	src := "const payload: any = req.body.data;\nsettings.__proto__ = payload;\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-038") {
		t.Error("expected ZS-TS-038 to fire when __proto__ RHS is tainted")
	}
}

func TestIntegration_ConstantProtoAssignmentDoesNotFireZSTS038(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "settings.__proto__ = {};\n"), "ZS-TS-038") {
		t.Error("expected ZS-TS-038 to NOT fire for a constant RHS")
	}
}

// --- ZS-TS-039: SSTI via ejs.render ---

func TestIntegration_TaintedEjsRenderFiresZSTS039(t *testing.T) {
	idx := loadTSRules(t)
	src := "const tpl: string = req.body.template;\nejs.render(tpl, {});\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-039") {
		t.Error("expected ZS-TS-039 to fire when ejs.render template is tainted")
	}
}

func TestIntegration_ConstantEjsRenderDoesNotFireZSTS039(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "ejs.render(\"<b>hi</b>\", {});\n"), "ZS-TS-039") {
		t.Error("expected ZS-TS-039 to NOT fire for a constant template")
	}
}

// --- ZS-TS-040: SSTI via pug.render ---

func TestIntegration_TaintedPugRenderFiresZSTS040(t *testing.T) {
	idx := loadTSRules(t)
	if !hasRule(matchTSSource(t, idx, "pug.render(req.body.tpl);\n"), "ZS-TS-040") {
		t.Error("expected ZS-TS-040 to fire when pug.render template is tainted")
	}
}

func TestIntegration_ConstantPugRenderDoesNotFireZSTS040(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "pug.render(\"p hello\");\n"), "ZS-TS-040") {
		t.Error("expected ZS-TS-040 to NOT fire for a constant template")
	}
}

// --- ZS-TS-041: dynamic code via vm.runInNewContext ---

func TestIntegration_TaintedVMRunInNewContextFiresZSTS041(t *testing.T) {
	idx := loadTSRules(t)
	src := "const code: string = req.query.expr;\nvm.runInNewContext(code, {});\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-041") {
		t.Error("expected ZS-TS-041 to fire when vm.runInNewContext code is tainted")
	}
}

func TestIntegration_ConstantVMRunInNewContextDoesNotFireZSTS041(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "vm.runInNewContext(\"1+1\", {});\n"), "ZS-TS-041") {
		t.Error("expected ZS-TS-041 to NOT fire for a constant code string")
	}
}

// --- ZS-TS-042: weak cipher via crypto.createCipheriv ---

func TestIntegration_WeakCipherFiresZSTS042(t *testing.T) {
	idx := loadTSRules(t)
	if !hasRule(matchTSSource(t, idx, "const cipher = crypto.createCipheriv('des-ede3', key, iv);\n"), "ZS-TS-042") {
		t.Error("expected ZS-TS-042 to fire on crypto.createCipheriv('des-ede3')")
	}
}

func TestIntegration_ModernCipherDoesNotFireZSTS042(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n"), "ZS-TS-042") {
		t.Error("expected ZS-TS-042 to NOT fire on crypto.createCipheriv('aes-256-gcm')")
	}
}

// --- ZS-TS-043: command injection via execSync ---

func TestIntegration_TaintedExecSyncFiresZSTS043(t *testing.T) {
	idx := loadTSRules(t)
	src := "const host: string = req.body.host;\nconst cmd: string = 'ping -c 2 ' + host;\nexecSync(cmd);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-043") {
		t.Error("expected ZS-TS-043 to fire when execSync argument is tainted")
	}
}

func TestIntegration_ConstantExecSyncDoesNotFireZSTS043(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "execSync(\"ls -la\");\n"), "ZS-TS-043") {
		t.Error("expected ZS-TS-043 to NOT fire for a constant command")
	}
}

// --- ZS-TS-044: DOM open redirect via location.href ---

func TestIntegration_TaintedLocationHrefFiresZSTS044(t *testing.T) {
	idx := loadTSRules(t)
	src := "const target: string = location.search;\nlocation.href = target;\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-044") {
		t.Error("expected ZS-TS-044 to fire when location.href RHS is tainted")
	}
}

func TestIntegration_ConstantLocationHrefDoesNotFireZSTS044(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "location.href = \"/home\";\n"), "ZS-TS-044") {
		t.Error("expected ZS-TS-044 to NOT fire for a constant RHS")
	}
}

// --- ZS-TS-045: DOM XSS via insertAdjacentHTML ---

func TestIntegration_TaintedInsertAdjacentHTMLFiresZSTS045(t *testing.T) {
	idx := loadTSRules(t)
	src := "const html: string = req.query.msg;\nel.insertAdjacentHTML('beforeend', html);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-045") {
		t.Error("expected ZS-TS-045 to fire when insertAdjacentHTML argument is tainted")
	}
}

func TestIntegration_ConstantInsertAdjacentHTMLDoesNotFireZSTS045(t *testing.T) {
	idx := loadTSRules(t)
	if hasRule(matchTSSource(t, idx, "el.insertAdjacentHTML('beforeend', '<b>hi</b>');\n"), "ZS-TS-045") {
		t.Error("expected ZS-TS-045 to NOT fire for constant HTML")
	}
}

// --- ZS-TS-046: JWT verification accepting alg none ---

func TestIntegration_JwtVerifyAlgNoneFiresZSTS046(t *testing.T) {
	idx := loadTSRules(t)
	src := "jwt.verify(tok, signingKey, { algorithms: ['none'] });\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-046") {
		t.Error("expected ZS-TS-046 to fire when jwt.verify allows the 'none' algorithm")
	}
}

func TestIntegration_JwtVerifyRealAlgDoesNotFireZSTS046(t *testing.T) {
	idx := loadTSRules(t)
	src := "jwt.verify(tok, signingKey, { algorithms: ['RS256'] });\n"
	if hasRule(matchTSSource(t, idx, src), "ZS-TS-046") {
		t.Error("expected ZS-TS-046 to NOT fire when only real algorithms are allowed")
	}
}
