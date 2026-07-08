# Sprint 25 Release Notes — v0.18.0

## Summary

The user asked why the Flask test app showed zero findings, given the
scanner can already detect framework-level misconfiguration. The answer
wasn't a bug in either system: **the wrong repo had been scanned all
along**. `sub-braining/www-project-vulnerable-flask-app` is genuinely just
the OWASP project's Jekyll landing page (5 markdown files, a `_config.yml`,
zero `.py` files) — confirmed via its own docs, git remote, and commit
history. The framework-misconfiguration scanner was independently confirmed
innocent too: it matches files by extension/basename (not by language), so
it would happily inspect Jekyll's `_config.yml` — it just checks 4 specific
misconfigurations (Django `DEBUG`, Express `helmet`, CORS wildcard, Laravel
`APP_DEBUG`), none of which a Jekyll config's real keys would ever trigger.

A real target already existed, unused: `targets/vulnerable-flask` — a
genuine 712-line Flask app with 17 real vulnerabilities, 5 explicit
false-positive tests, and a `sast_expected_findings.json` ground-truth file
(25 expected findings, `minimum_detection_rate: 0.85`) clearly built for
validating a SAST tool. Scanning it against the current 23-rule Python set
surfaced something more consequential than "wrong directory": **the
flagship SQLi rule didn't match realistic code** — `ZS-PY-004` required the
exact bare callee `execute`, but virtually all real Python DB-API code
calls `cursor.execute(...)`, which the rule's exact-match couldn't see.

## Item 1 — Fixed the scan target

Future scans of "the Flask app" should use
`C:\Users\MohamedAshmar\playground\targets\vulnerable-flask`, not the dead
Jekyll page. Also flagged, not fixed: `.github/workflows/ci.yml`'s
`scan-e2e` job checks out a *third*, different repo
(`we45/Vulnerable-Flask-App`) — its live status is unverified from this
environment (no network access) and is worth a human check.

## Item 2 — Fixed ZS-PY-004's callee realism gap

Changed `match.callee` from `execute` to `cursor.execute` and added
`callee_suffix: true` — the capability Sprint 24 built and applied to
exactly one rule (`ZS-CS-004`), now rolled out to a second. This exact-
matches `cursor.execute` and suffix-matches longer real chains
(`self.cursor.execute`, `conn.cursor.execute`) without broadening risk,
since `cursor.execute` is the universal DB-API-2.0 idiom (sqlite3,
psycopg2, MySQLdb, pyodbc all use it identically) — a bare top-level
`execute()` call essentially never occurs in real code. Updated the
existing corpus fixture and 4 CGO integration tests
(`internal/engine/integration_test.go`) that previously used the
unrealistic bare-`execute()` shape.

## Item 3 — 6 new Python rules

- **`ZS-PY-025`/`ZS-PY-026`** — SSRF via `requests.get`/`requests.post` +
  `tainted_argument`. Python's version of `ZS-GO-012` (added last sprint).
- **`ZS-PY-027`** — SSTI via `render_template_string`. Uses
  `argument_count: 1` **and** `tainted_argument` together: `
  tainted_argument` alone checks every argument, so a safe call passing a
  fixed template plus a tainted render variable
  (`render_template_string(template, name=name)`) would false-positive on
  the variable, not the template. Requiring exactly one argument isolates
  "the template itself is tainted" from "a value substituted into a fixed
  template is tainted," using only existing filter primitives — caught and
  fixed during this sprint's own review before it ever reached benchmark,
  the same discipline as catching PY-023/PY-024 cross-talk in Sprint 23.
- **`ZS-PY-028`** — Open redirect via Flask's `redirect()` +
  `tainted_argument`. Python's version of `ZS-JS-015`.
- **`ZS-PY-029`** — Weak DES cipher (`DES.new`, PyCryptodome), unconditional.
  Sibling to `ZS-GO-008`.
- **`ZS-PY-030`** — CORS misconfiguration: an assignment to a header dict
  entry named `Access-Control-Allow-Origin` whose value is tainted. Needed
  a taint-source broadening first (below) to be reachable at all.

## Taint-source broadening: `request.headers`

`pythonPatterns.Sources` had no pattern for `request.headers` — HTTP
headers (Origin, Referer, X-Forwarded-For) are exactly as attacker-
controlled as query args/form fields, but were invisible to every
taint-gated Python rule. Added `request\.(...|headers)` to the source list;
this is what makes `ZS-PY-030`'s CORS check (and any other current or
future header-derived source) actually taint-reachable.

## Vendored a realistic multi-vulnerability fixture

Added `benchmark/corpus/python/cases/vuln_realistic_flask.py` — one file
modeling several vulnerabilities together the way a real app does
(receiver-object method calls, f-string SQL, three explicit safe/false-
positive functions), rather than only synthetic one-sink-per-file
snippets. This is what actually proves the fixes generalize: Sprint 23/24
each learned the hard way (`urllib.request.urlopen`, `context.Response.
Write`) that a fixture testing only the easy shape hides exactly the gap
that matters. All 8 real vulnerabilities in it fire; all 3 safe functions
correctly produce zero findings.

## Confirmed against the real ground-truthed app — what fires, what doesn't, and why

Scanned `targets/vulnerable-flask/app.py` directly (not estimated): **0 →
20 findings** (15 SAST + 1 SCA + 4 secrets). Cross-referencing the 17-item
`sast_expected_findings.json`:

**Detected**: SQL injection, insecure deserialization (`pickle.loads`),
SSRF (both `requests.get` and `.post`, 4 occurrences total), weak hashing
(MD5 ×3, SHA1 ×1), debug mode, hardcoded secret key, weak DES cipher, open
redirect, CORS misconfiguration.

**Confirmed missed, with a specific reason each** (not silently absent):

- **Command injection** (`subprocess.check_output(cmd, shell=True)`) — no
  rule covers this exact callee; `ZS-PY-003`/`ZS-PY-012` only cover
  `subprocess.run`/`subprocess.call`. New gap, found via this scan,
  not fixed this sprint.
- **XXE** (`ET.fromstring`) — no Python XXE rule exists at all yet.
- **Code injection** (bare `exec(plugin_code)`) — `ZS-PY-001` only covers
  `eval()`; the builtin `exec()` has no equivalent rule.
- **Path traversal** (`send_file(filename)`) — `ZS-PY-008` only covers
  `open()`; Flask's `send_file` is an equally common, uncovered sink.
- **Reflected/stored XSS** (bare `return f"<h1>Hello {name}!</h1>"`) —
  confirmed and already documented as out of scope: no sink *call* exists
  to match against; needs a new `kind: return` + tainted-expression match
  capability, a real but contained future engine change.
- **SSTI** — the rule fires correctly on its own fixture and the vendored
  realistic fixture, but **not on this specific real file**, and the
  reason is worth recording precisely: `app.py` has two functions
  (`template_injection` and, later in the same file, `safe_template`) that
  both assign a local variable named `template` — one tainted, one a fixed
  string. Taint tracking in this engine is file-scoped and flow-
  insensitive (documented in `taint.go` since Sprint 11): the *last*
  assignment to a name wins for the whole file. Since `safe_template`'s
  clean assignment comes later in source order, it overwrites `template`'s
  taint verdict file-wide, masking the real vulnerability earlier in the
  same file. This is a concrete, real-world confirmation of an
  already-known, already-deferred limitation (the same one CallGraph/
  interprocedural taint is tracked against) — not a new bug, but the
  clearest evidence yet of its real-world cost.
- **Missing authorization / IDOR** — semantic/business-logic, consistently
  out of scope every sprint.

**Also confirmed**: all 5 of the ground truth's explicit
`false_positives_should_not_detect` cases correctly produce zero findings
(parameterized ORM query, allowlisted command, properly-escaped template,
AES-GCM encryption, bcrypt hashing) — `FP=0` holds on real adversarial-style
code, not just the synthetic corpus.

**One observed, non-reproducible anomaly**: the very first full-directory
scan (with `--enable-sca --enable-secrets --enable-framework-checks`) was
missing the DES finding that six subsequent identical reruns (with and
without those flags, with `--workers 1`, and under `go build -race`) all
found consistently. Investigated seriously (isolated the file, dumped IR to
confirm the `DES.new` call node and its attributes were correct, tested
single-worker and race-instrumented builds) but could not reproduce it a
second time. Recorded for awareness, not acted on — asserting a fix for an
unreproduced anomaly would be worse than naming the uncertainty.

## Verification

- `go build ./...` / `go vet ./...` / `go test ./... -count=1` — clean
  under both `CGO_ENABLED=0` and `CGO_ENABLED=1`.
- `zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`:
  **TP=107 FP=0 FN=0** (up from TP=93 at the end of Sprint 24 — 6 new
  rules' fixtures + the 8-vulnerability realistic fixture, net of the
  `ZS-PY-004` fixture update).
- `TestAllRules_HaveCoverageInBenchmarkCorpus`: 0 missing, **86 rules
  total** (up from 80).
- Rebuilt the real CGO binary and scanned `targets/vulnerable-flask`
  directly: 0 → 20 findings, cross-checked line-by-line against the
  ground-truth JSON (above).

## Out of scope (confirmed via this sprint's own investigation, not just carried forward)

`command_injection` via `subprocess.check_output`, XXE via `ET.fromstring`,
code injection via bare `exec()`, path traversal via `send_file` — four
newly-identified Python sink gaps, each a small sibling-rule addition
similar in shape to this sprint's other rules; good Sprint 26 candidates,
not done here to keep this sprint's scope to what the investigation
directly motivated. Bare-string-return XSS (needs new `kind: return` match
capability). IDOR/missing-authorization (semantic, not a sink pattern).
Sweeping `callee_suffix: true` to more rules beyond `ZS-PY-004` (still a
Sprint 24-tracked fast-follow, not expanded further here). The unverified
CI Flask target and the one non-reproducible DES anomaly, both noted above.
