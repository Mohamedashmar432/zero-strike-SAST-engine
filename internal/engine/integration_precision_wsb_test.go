//go:build cgo

package engine_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/engine"
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
	// retired for measured precision, see commit 37cf7e3
	if hasRule(none, "ZS-PY-099") || hasRule(none, "ZS-PY-098") {
		t.Error("a cookie with neither flag is not reported: ZS-PY-099 is retired and ZS-PY-098 must not double-report")
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

func countRule(results []engine.MatchResult, id string) (n, occ int) {
	for _, r := range results {
		if r.Rule.ID == id {
			n++
			occ += r.Occurrences
		}
	}
	return n, occ
}

func TestPrecisionB_IdenticalTraceCallsAggregate(t *testing.T) {
	_, idx := loadPythonRules(t)
	same := "import sqlite3\n" +
		"def a():\n    c = sqlite3.connect('a.db')\n    c.set_trace_callback(print)\n" +
		"def b():\n    c = sqlite3.connect('a.db')\n    c.set_trace_callback(print)\n" +
		"def c():\n    c = sqlite3.connect('a.db')\n    c.set_trace_callback(print)\n"
	if n, occ := countRule(matchSource(t, idx, same), "ZS-PY-078"); n != 1 || occ != 3 {
		t.Errorf("three identical trace calls: got %d findings, %d occurrences; want 1 and 3", n, occ)
	}
	// Different callbacks are different decisions and are not folded.
	diff := "import sqlite3, logging\n" +
		"def a():\n    c = sqlite3.connect('a.db')\n    c.set_trace_callback(print)\n" +
		"def b():\n    c = sqlite3.connect('a.db')\n    c.set_trace_callback(logging.debug)\n"
	if n, _ := countRule(matchSource(t, idx, diff), "ZS-PY-078"); n != 2 {
		t.Errorf("distinct trace callbacks: got %d findings, want 2", n)
	}
}

func linesOf(results []engine.MatchResult, id string) []int {
	var out []int
	for _, r := range results {
		if r.Rule.ID == id {
			out = append(out, r.Node.Location.StartLine)
		}
	}
	return out
}

func TestPrecisionB_JWTNoneReportedAtOptionsDeclaration(t *testing.T) {
	shared := "const jwt = require('jsonwebtoken');\n" + // 1
		"const options = {\n" + // 2
		"  algorithms: ['HS256', 'none'],\n" + // 3
		"};\n" + // 4
		"function a(token) { return jwt.verify(token, 'k', options); }\n" + // 5
		"function b(token) { return jwt.verify(token, 'k', options); }\n" // 6
	got := linesOf(matchJSSource(t, loadJSRules(t), shared), "ZS-JS-048")
	if len(got) != 1 || got[0] != 3 {
		t.Errorf("JS: shared options object: got findings at lines %v, want one at line 3", got)
	}
	got = linesOf(matchTSSource(t, loadTSRules(t), shared), "ZS-TS-046")
	if len(got) != 1 || got[0] != 3 {
		t.Errorf("TS: shared options object: got findings at lines %v, want one at line 3", got)
	}
	// An inline options literal has no declaration to move to: one finding per call.
	inline := "const jwt = require('jsonwebtoken');\n" +
		"function a(t) { return jwt.verify(t, 'k', { algorithms: ['none'] }); }\n" +
		"function b(t) { return jwt.verify(t, 'k', { algorithms: ['none'] }); }\n"
	if got := linesOf(matchJSSource(t, loadJSRules(t), inline), "ZS-JS-048"); len(got) != 2 {
		t.Errorf("JS: inline options: got %v, want a finding per call", got)
	}
	// A pinned algorithm list still does not fire.
	pinned := "const jwt = require('jsonwebtoken');\nconst options = { algorithms: ['HS256'] };\njwt.verify(t, 'k', options);\n"
	if hasRule(matchJSSource(t, loadJSRules(t), pinned), "ZS-JS-048") {
		t.Error("JS: pinned algorithms must not fire")
	}
}

func TestPrecisionB_PathSanitizersAreSinkAware(t *testing.T) {
	idx := loadTSRules(t)
	safe := "import path from 'path';\nimport fs from 'fs';\n" +
		"function load(req: any) {\n" +
		"  const name = path.basename(req.query.f);\n" +
		"  const full = path.join(DIR, name);\n" +
		"  document.write(name);\n" +
		"  return fs.readFileSync(full);\n}\n"
	res := matchTSSource(t, idx, safe)
	if hasRule(res, "ZS-TS-089") || hasRule(res, "ZS-TS-023") {
		t.Error("path.basename must clear taint for path.join and fs.readFileSync")
	}
	if !hasRule(res, "ZS-TS-003") {
		t.Error("path.basename must NOT clear taint for a document.write sink")
	}
	inline := "function load(req: any) {\n  return path.join(DIR, path.basename(req.query.f));\n}\n"
	if hasRule(matchTSSource(t, idx, inline), "ZS-TS-089") {
		t.Error("an inline path.basename wrapper must clear path.join taint")
	}
	random := "function save(req: any, data: Buffer) {\n" +
		"  const stored = `${randomUUID()}.${req.query.ext}`;\n" +
		"  const out = fs.createWriteStream(path.join(DIR, stored));\n}\n"
	if hasRule(matchTSSource(t, idx, random), "ZS-TS-062") || hasRule(matchTSSource(t, idx, random), "ZS-TS-089") {
		t.Error("a random generated name must clear path taint")
	}
	// The real cases still fire.
	if !hasRule(matchTSSource(t, idx, "function f(req: any) { return path.join(DIR, req.query.f); }\n"), "ZS-TS-089") {
		t.Error("ZS-TS-089 must still fire on unsanitized request input")
	}
	// retired for measured precision, see commit 37cf7e3
	for rule, src := range map[string]string{
		"ZS-TS-023": "function f(req: any) { return fs.readFileSync(req.query.f); }\n",
		"ZS-TS-062": "function f(req: any) { return fs.createWriteStream(req.body.dest); }\n",
	} {
		if hasRule(matchTSSource(t, idx, src), rule) {
			t.Errorf("%s is retired and must not fire", rule)
		}
	}
	// A variable path-sanitized in one statement is tainted again by reassignment.
	reassigned := "function f(req: any) {\n  let n = path.basename(req.query.f);\n  n = req.query.g;\n  return path.join(DIR, n);\n}\n"
	if !hasRule(matchTSSource(t, idx, reassigned), "ZS-TS-089") {
		t.Error("reassignment from a source must drop the path-safe mark")
	}
}

func TestPrecisionB_RouteParamsCannotCarryOperatorsRetiredDoesNotFire(t *testing.T) {
	idx := loadTSRules(t)
	params := "function f(req: any) {\n  const id = req.params.id;\n  return db.collection('u').updateOne({ _id: id }, { $set: { a: 1 } });\n}\n"
	if hasRule(matchTSSource(t, idx, params), "ZS-TS-128") {
		t.Error("ZS-TS-128 must not fire when the only source is req.params")
	}
	inline := "function f(req: any) {\n  return db.collection('u').updateOne({ _id: req.params.id }, { $set: { a: 1 } });\n}\n"
	if hasRule(matchTSSource(t, idx, inline), "ZS-TS-128") {
		t.Error("ZS-TS-128 must not fire on an inline req.params value")
	}
	for name, src := range map[string]string{
		"req.body":  "function f(req: any) {\n  const f = req.body.filter;\n  return db.collection('u').updateOne(f, { $set: { a: 1 } });\n}\n",
		"req.query": "function f(req: any) {\n  return db.collection('u').deleteMany(req.query.filter);\n}\n",
		"mixed":     "function f(req: any) {\n  const f = { a: req.params.id, b: req.body.b };\n  return db.collection('u').updateOne(f, { $set: { a: 1 } });\n}\n",
	} {
		// retired for measured precision, see commit 37cf7e3
		if hasRule(matchTSSource(t, idx, src), "ZS-TS-128") {
			t.Errorf("retired ZS-TS-128 must not fire on %s input", name)
		}
	}
}

func TestPrecisionB_PrismaSpreadOfParameterStillFires(t *testing.T) {
	idx := loadTSRules(t)
	plain := "export async function notify(input: { title: string }) {\n  await prisma.notification.create({ data: input });\n}\n"
	if hasRule(matchTSSource(t, idx, plain), "ZS-TS-138") {
		t.Error("ZS-TS-138 must not fire on data: <helper parameter>")
	}
	spread := "export async function update(id: string, updates: Record<string, unknown>) {\n  return prisma.patient.update({ where: { id }, data: { ...updates } });\n}\n"
	if !hasRule(matchTSSource(t, idx, spread), "ZS-TS-138") {
		t.Error("ZS-TS-138 must still fire on data: { ...parameter }")
	}
	real := "async function h(req: any) {\n  return prisma.user.create({ data: req.body });\n}\n"
	if !hasRule(matchTSSource(t, idx, real), "ZS-TS-138") {
		t.Error("ZS-TS-138 must still fire on data: req.body")
	}
}

func TestPrecisionB_PathOpenReceiverConstant(t *testing.T) {
	_, idx := loadPythonRules(t)
	constant := "from pathlib import Path\nHERE = Path(__file__).parent\n\n" +
		"def leaked():\n    with (HERE / 'words.txt').open() as f:\n        return f.read()\n"
	if hasRule(matchSource(t, idx, constant), "ZS-PY-008") {
		t.Error("ZS-PY-008 must not fire on Path.open() of a constant pathlib join")
	}
	dynamic := "from pathlib import Path\nHERE = Path(__file__).parent\n\n" +
		"def read(name):\n    with (HERE / name).open() as f:\n        return f.read()\n"
	if !hasRule(matchSource(t, idx, dynamic), "ZS-PY-008") {
		t.Error("ZS-PY-008 must still fire on Path.open() of a parameter-derived path")
	}
}
