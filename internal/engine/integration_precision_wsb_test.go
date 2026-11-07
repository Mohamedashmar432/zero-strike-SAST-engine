//go:build cgo

package engine_test

import (
	"testing"
)

// Precision tests for the Precision-75 workstream B fixes (see
// docs/roadmap/PRECISION_75_AND_FRAMEWORK_PLAN.md section 3). Each suppressed
// case has a twin proving the real case still fires. All values are synthetic.

func TestPrecisionB_HexDigestIsNotAHardcodedCredential(t *testing.T) {
	_, idx := loadPythonRules(t)
	digest := "config = dict(password=\"" + "0123456789abcdef0123456789abcdef" + "\")\n"
	if hasRule(matchSource(t, idx, digest), "ZS-PY-141") {
		t.Error("ZS-PY-141 must not fire on a 32-digit hex digest")
	}
	if hasRule(matchSource(t, idx, "reply = dict(Password=\"Updated.\")\n"), "ZS-PY-141") {
		t.Error("ZS-PY-141 must not fire on a status message")
	}
	if !hasRule(matchSource(t, idx, "config = dict(password=\"Tr0ub4dor-horse-battery\")\n"), "ZS-PY-141") {
		t.Error("ZS-PY-141 must still fire on a literal password")
	}
	// Hex shorter than a digest is still a plausible password.
	if !hasRule(matchSource(t, idx, "config = dict(password=\"deadbeef1234\")\n"), "ZS-PY-141") {
		t.Error("ZS-PY-141 must still fire on a short hex password")
	}
}

func TestPrecisionB_CookieReportedOncePerCall(t *testing.T) {
	_, idx := loadPythonRules(t)
	none := matchSource(t, idx, "def f(r, t):\n    r.set_cookie('auth', t)\n")
	if !hasRule(none, "ZS-PY-099") || hasRule(none, "ZS-PY-098") {
		t.Error("a cookie with neither flag must be reported once, by ZS-PY-099")
	}
	secure := matchSource(t, idx, "def f(r, t):\n    r.set_cookie('auth', t, secure=True)\n")
	if !hasRule(secure, "ZS-PY-098") || hasRule(secure, "ZS-PY-099") {
		t.Error("a Secure cookie without HttpOnly must be reported once, by ZS-PY-098")
	}
	both := matchSource(t, idx, "def f(r, t):\n    r.set_cookie('auth', t, secure=True, httponly=True)\n")
	if hasRule(both, "ZS-PY-098") || hasRule(both, "ZS-PY-099") {
		t.Error("a cookie with both flags must not be reported")
	}
}

func TestPrecisionB_LocalPathRedirect(t *testing.T) {
	_, idx := loadPythonRules(t)
	local := "def f(request):\n    uid = request.args.get('id')\n    return redirect('/users/' + str(uid) + '/home')\n"
	if hasRule(matchSource(t, idx, local), "ZS-PY-028") {
		t.Error("ZS-PY-028 must not fire when the destination starts with a literal local path")
	}
	pct := "def f(request):\n    uid = request.args.get('id')\n    return redirect('/users/%s/home' % uid)\n"
	if hasRule(matchSource(t, idx, pct), "ZS-PY-028") {
		t.Error("ZS-PY-028 must not fire on a percent-formatted local path")
	}
	for _, src := range []string{
		"def f(request):\n    n = request.args.get('n')\n    return redirect('/' + n)\n",
		"def f(request):\n    n = request.args.get('n')\n    return redirect('//' + n)\n",
		"def f(request):\n    n = request.args.get('n')\n    return redirect(n)\n",
	} {
		if !hasRule(matchSource(t, idx, src), "ZS-PY-028") {
			t.Errorf("ZS-PY-028 must still fire on %q", src)
		}
	}
}
