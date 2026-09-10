//go:build cgo

package engine_test

import (
	"testing"
)

// Integration tests for the precision filters added to stop the false-positive
// classes verified against a real scan. Each filter is tested in both
// directions: the false positive must go away, and the genuine finding the
// rule exists for must still fire. Helpers (loadTSRules, matchTSSource,
// loadPythonRules, matchSource, hasRule) live in the other integration files.

// --- require_real_source: parameter-only taint must not fire ---

// TestPrecision_ParameterDelayDoesNotFireSetTimeout is the use-debounced.ts
// false positive: an arrow function plus a parameter delay. The rule fired
// because every function parameter is seeded tainted.
func TestPrecision_ParameterDelayDoesNotFireSetTimeout(t *testing.T) {
	idx := loadTSRules(t)
	src := "function useDebounced(value: string, delay: number) {\n" +
		"  const timer = setTimeout(() => setSettled(value), delay);\n" +
		"  return timer;\n}\n"
	if hasRule(matchTSSource(t, idx, src), "ZS-TS-054") {
		t.Error("ZS-TS-054 must not fire when the only taint is a function parameter")
	}
}

// TestPrecision_RealSourceStillFiresSetTimeout is the recall half: a genuine
// string from location.hash must still be reported.
func TestPrecision_RealSourceStillFiresSetTimeout(t *testing.T) {
	idx := loadTSRules(t)
	src := "const code: string = location.hash.slice(1);\nsetTimeout(code, 100);\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-054") {
		t.Error("expected ZS-TS-054 to fire for a real source reaching argument 0")
	}
}

// TestPrecision_ConstantFetchDoesNotFireSSRF is the frontend/lib/api.ts false
// positive: a browser API client whose host is a build-time constant and whose
// path is a plain parameter.
func TestPrecision_ConstantFetchDoesNotFireSSRF(t *testing.T) {
	idx := loadTSRules(t)
	src := "const API_BASE = \"http://localhost:8000\";\n" +
		"export async function request(path: string) {\n" +
		"  return fetch(`${API_BASE}${path}`);\n}\n"
	if hasRule(matchTSSource(t, idx, src), "ZS-TS-035") {
		t.Error("ZS-TS-035 must not fire when the URL is a constant plus a parameter")
	}
}

func TestPrecision_RealSourceStillFiresFetchSSRF(t *testing.T) {
	idx := loadTSRules(t)
	src := "function proxy(req: any) {\n  const target = req.query.url;\n  fetch(target);\n}\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-035") {
		t.Error("expected ZS-TS-035 to fire when the fetch URL comes from req.query")
	}
}

// TestPrecision_ParameterRegexDoesNotFireReDoS is the rhf-rules.ts false
// positive: a pattern from an admin-authored template field, arriving as a
// function parameter.
func TestPrecision_ParameterRegexDoesNotFireReDoS(t *testing.T) {
	idx := loadTSRules(t)
	src := "function fieldRules(field: { regex: string }) {\n" +
		"  return { value: new RegExp(field.regex) };\n}\n"
	if hasRule(matchTSSource(t, idx, src), "ZS-TS-031") {
		t.Error("ZS-TS-031 must not fire when the pattern is a function parameter")
	}
}

func TestPrecision_RealSourceStillFiresReDoS(t *testing.T) {
	idx := loadTSRules(t)
	src := "function search(req: any) {\n  return new RegExp(req.query.pattern);\n}\n"
	if !hasRule(matchTSSource(t, idx, src), "ZS-TS-031") {
		t.Error("expected ZS-TS-031 to fire when the RegExp pattern comes from req.query")
	}
}

// --- argument_kind_not_at: argument 0 being a function ---

// TestPrecision_ArrowFunctionArgumentSuppressed pins the argument-kind filter
// independently of taint tiering. Even with a real source inside the callback
// body, argument 0 is a function, so this is not code injection -- reporting
// it would flag the exact pattern the rule's own message recommends.
func TestPrecision_ArrowFunctionArgumentSuppressed(t *testing.T) {
	idx := loadTSRules(t)
	src := "function h(req: any) {\n  setTimeout(() => run(req.query.cmd), 100);\n}\n"
	if hasRule(matchTSSource(t, idx, src), "ZS-TS-054") {
		t.Error("ZS-TS-054 must not fire when argument 0 is an arrow function, even with a tainted body")
	}
}

// TestPrecision_TaintedDelayArgumentSuppressed covers the positional half:
// a tainted delay is argument 1, and argument 1 is never executed as code.
func TestPrecision_TaintedDelayArgumentSuppressed(t *testing.T) {
	idx := loadTSRules(t)
	src := "function h(req: any) {\n  setTimeout(tick, req.query.delay);\n}\n"
	if hasRule(matchTSSource(t, idx, src), "ZS-TS-054") {
		t.Error("ZS-TS-054 must not fire for a tainted delay; only argument 0 is eval'd")
	}
}

// --- ZS-PY-015: urlopen is now taint-gated ---

// TestPrecision_ConstantUrlopenDoesNotFire records the deliberate narrowing of
// this rule from "urlopen is used" to "urlopen with an untrusted target". The
// old unconditional form reported an operator-configured webhook URL as SSRF.
func TestPrecision_ConstantUrlopenDoesNotFire(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import urllib.request\nurllib.request.urlopen(\"https://status.internal/health\")\n"
	if hasRule(matchSource(t, idx, src), "ZS-PY-015") {
		t.Error("ZS-PY-015 must not fire for a constant URL")
	}
}

func TestPrecision_TaintedUrlopenStillFires(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "import urllib.request\nurl = request.args.get('u')\nurllib.request.urlopen(url)\n"
	if !hasRule(matchSource(t, idx, src), "ZS-PY-015") {
		t.Error("expected ZS-PY-015 to fire when the urlopen target comes from request.args")
	}
}

// --- Guarded sentinels ---

// TestPrecision_SentinelNotReportedAsCredential is the config.py:9 false
// positive: a known-bad literal that exists so a start-up guard can detect it.
func TestPrecision_SentinelNotReportedAsCredential(t *testing.T) {
	_, idx := loadPythonRules(t)
	src := "INSECURE_JWT_SECRET = \"insecure-development-only\"\n"
	if hasRule(matchSource(t, idx, src), "ZS-PY-020") {
		t.Error("ZS-PY-020 must not fire on a guarded sentinel literal")
	}
}

func TestPrecision_OrdinaryHardcodedCredentialStillFires(t *testing.T) {
	_, idx := loadPythonRules(t)
	if !hasRule(matchSource(t, idx, "password = \"hunter2\"\n"), "ZS-PY-020") {
		t.Error("expected ZS-PY-020 to still fire on an ordinary hardcoded password")
	}
}
