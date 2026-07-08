# Sprint 28 Release Notes — v0.21.0

## Summary

QA tested Sprint 27 (v0.20.0) and filed `docs/release-notes/QA-REPORT-SPRINT-27.md`
with ~16 claimed scanner gaps, 6 rated CRITICAL, from a "Deep Manual Code
Audit" across 5 vulnerable apps. Before building anything, every claim was
checked against the actual rule set and the actual target-app source — this
project has hit this exact failure mode before (Sprint 23's "why is
detection ~1.4%" incident, root-caused to a stale CGO-disabled binary, not
a real regression). The same root cause recurred here, plus a second one.

## Root cause #1 — QA's test machine had no C compiler

The report's own §0 states the `CGO_ENABLED=1` build failed (no gcc) and
QA fell back to a `CGO_ENABLED=0` binary. That disables tree-sitter parsing
entirely, which means **100% of SAST rule matching was disabled** for the
whole test cycle, for every language. §3.2-3.4's "SAST findings" rows in
the report are old v0.16.0 reference numbers, not real v0.20.0
measurements — no real SAST scan ran this cycle at all. Only the
framework-scanner checks (pure text/regex, no CGO needed) and secrets/SCA
produced real v0.20.0 data. §6's "Deep Manual Code Audit" then read source
code by eye and guessed at scanner behavior, without cross-checking the
actual rules directory.

## Root cause #2 — several "critical gaps" already have rules; the report never checked

Verified directly against `internal/rules/data/` and the real target
sources cited in the report:

- **"No ZS-GO-SQLI/CI rule exists" (rated CRITICAL) — false.**
  `ZS-GO-001` (`exec.Command` + `tainted_argument`) and `ZS-GO-002`/
  `ZS-GO-007` (`db.Query`/`db.Exec` + `tainted_argument`) all exist.
  Read `sub-braining/damn-vulnerable-golang/main.go:60-80` directly: the
  "attacker input" in both cited lines is a **hardcoded string literal**
  (`userInput := "ls -l; rm -rf ./"`, `pass := "' OR 1=1--"`) — never
  assigned from a taint source. This is the exact same file and the exact
  same by-design correct non-detection this project already documented in
  an earlier QA cycle (a taint engine correctly refusing to flag a literal
  as "attacker-controlled" is not a gap).
- **"No SQL Injection rule for .NET" (rated CRITICAL) — false.**
  `ZS-CS-002` (SqlCommand) and `ZS-CS-007` (MySqlCommand) both exist. Read
  `SqliteDbProvider.cs:75-91` directly: the real, already-tracked issue is
  the documented interprocedural-taint-barrier limitation (the tainted
  `email`/`encoded_password` are method *parameters* set by a caller in a
  different file) — recorded since Sprint 24, not a missing rule. There
  WAS one genuinely new, narrower gap in this same file: no rule targeted
  `SqliteDataAdapter`/`SQLiteCommand` at all — closed this sprint (below).
- **"No session/cookie taint tracking, PHP" — outdated.** PHP's
  `$_SESSION` and `$_COOKIE` are both already taint sources
  (`$_SESSION` added in Sprint 26; `$_COOKIE` has been a source since this
  list existed). DVWA's cited X-Forwarded-For case reads via
  `$_SERVER[...]`, also already a source.

## New rules — the claims that checked out

Three claims were verified as real, novel gaps by reading the actual
ground-truth code, not just trusting the report:

- **`ZS-PY-041`** NoSQL injection via `collection.find` + `tainted_argument`.
  Confirmed at `targets/vulnerable-flask/app.py:130`:
  `collection.find({"$where": f"...{query}..."})` where `query` comes from
  `request.args.get('q')` — genuinely tainted, no rule covered MongoDB's
  `.find()` at all.
- **`ZS-PY-042`** JWT `jwt.encode(..., algorithm='none')` — unconditional
  kwarg match, no taint needed (the danger is the algorithm choice itself,
  same shape as `ZS-PY-018`'s `verify=False`). Confirmed at
  `app.py:245`. A distinct vulnerability shape from the existing
  `ZS-PY-021` (`jwt.decode(verify=False)`).
- **`ZS-PY-043`** JWT `jwt.decode(..., algorithms=[...])` where the list
  contains `'none'` — the decode-side equivalent of `ZS-PY-042`, so a
  server that itself never signs with `none` is still exploitable if it
  *accepts* `none` on decode.
- **`ZS-PY-044`** LDAP injection via `conn.search` + `tainted_argument`.
  Confirmed at `app.py:156-157`: `conn.search(base, search_filter)` where
  `search_filter` is an f-string built from `request.args.get('username')`.
  Sprint 25 deferred LDAP injection as "exotic" without a concrete
  example; this is now a concrete example in our own primary ground-truth
  target, which changed the calculus.
- **`ZS-GO-013`** cleartext HTTP server via `http.ListenAndServe`,
  unconditional (same shape as `ZS-PY-016`'s `app.run(debug=True)`).
  Confirmed at `damn-vulnerable-golang/main.go:152`.
- **`ZS-CS-011`** SQLite SQL injection via `SqliteDataAdapter`/
  `SQLiteCommand` + `tainted_argument`. Closes the missing-sink gap next
  to `ZS-CS-002`/`ZS-CS-007`. Documented plainly that, like its siblings,
  it won't fire on the specific cross-function-parameter shape QA found in
  `SqliteDbProvider.cs` until interprocedural taint analysis exists — its
  value is the same-function case.

**Confirmed against the real ground-truth apps, not just synthetic
fixtures**: rescanned `targets/vulnerable-flask/app.py` directly —
`ZS-PY-041`, `ZS-PY-042`, and `ZS-PY-044` all fired on the real lines cited
above. Rescanned `damn-vulnerable-golang/main.go` directly — `ZS-GO-013`
fired on the real `http.ListenAndServe` line, and `ZS-GO-001`/`002`/`007`
correctly still did not fire on the hardcoded-literal lines, confirming
root cause #2 above rather than asserting it from the rule text alone.

## A genuinely new engine limitation, found and NOT shipped around

The original plan included `ZS-GO-014` (integer-overflow risk via
`int16(...)` narrowing a tainted value), motivated by
`main.go:136-138`'s `num, _ := strconv.Atoi(val)` → `int16(num)`. Verified
Go's tree-sitter grammar represents `int16(x)` as a plain `call_expression`
(reachable as `kind: call, callee: int16`), so the rule was written and
benchmarked — and it did not fire. Root-caused via the benchmark fixture,
not assumed: `internal/analyzer/taint/taint.go`'s `BuildContext` stores a
variable's taint verdict keyed by the assignment's raw LHS text
(`n.Attrs["lhs"]`). For Go's extremely common multi-value short variable
declaration (`num, _ := strconv.Atoi(val)`), the Go builder's `lhs` text is
the **entire comma-separated expression** (`"num, _"`), not split into
individual names — so the taint map only ever gains a `"num, _"` key,
never a `"num"` key, and any later reference to the bare identifier `num`
(as in `int16(num)`) is invisible to taint tracking. This silently loses
taint on effectively every `value, err := fn()` assignment in Go — likely
the single most common assignment idiom in the language.

This is a real, previously-undiscovered engine gap, not a Sprint 25-style
"by design" non-detection — but fixing it properly (splitting
multi-target LHS text into individual taint-map entries across
`taint.go`'s Go handling) is a change to shared taint-tracking logic that
could affect every existing Go rule's behavior, not a contained rule
addition. Shipping `ZS-GO-014` anyway would mean shipping a rule that
silently never fires on the realistic shape it was written for — worse
than not shipping it. `ZS-GO-014` and its fixture were removed before
this sprint's benchmark gate; this is flagged as a real Sprint 29+
candidate: **fix multi-value short-var-decl taint splitting for Go**, a
contained, well-scoped engine fix now that its blast radius is understood.

## Corrections to the QA process itself

The report's own §0 already surfaced the CGO=0 problem, so this isn't a
QA-team failure — it's the process's second collision with the exact
failure mode Sprint 23 named ("never trust a QA report's verdict without
checking which binary it actually ran"). The next QA test-plan document
should make a `CGO_ENABLED=1` build failure a **hard blocker** for every
SAST-dependent section (rather than a caveat next to results that then get
treated as data) — this is a template fix for future sprints' QA test
plans, not a change to QA's already-filed Sprint 27 report.

## Confirmed correctly out of scope, same reasoning as every prior sprint

IDOR / missing authorization / privilege escalation via a user-settable
`role`/`level` field, CAPTCHA-bypass and other multi-step business-logic
flaws, race conditions (TOCTOU), user enumeration via distinct error
messages, second-order/stored XSS requiring a DB round-trip, DOM-based XSS
in client-side JS/EJS templates (no parser), CSP policy content analysis,
decompression-bomb / missing-bounds-check patterns (structural, not a
single-sink shape). All semantic or requiring real new engine capability
already tracked elsewhere.

## Verification

- `go build ./...` / `go vet ./...` — clean.
- `go test ./... -count=1` — clean under both `CGO_ENABLED=0` and
  `CGO_ENABLED=1 CC=gcc`.
- `zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`:
  **TP=140 FP=0 FN=0** (up from TP=134 at the end of Sprint 27) — reached
  after fixing two real issues the benchmark caught before ship: the
  `ZS-GO-014` non-firing described above (removed), and a fixture
  self-inflicted false positive (`vuln_jwt_decode_algorithms_none.py`'s
  original `token = "eyJ..."` variable name collided with the existing
  `ZS-PY-020` hardcoded-credential rule's `token` pattern — fixed by
  sourcing the value from a request header instead of a hardcoded literal,
  which is also more realistic).
- Rebuilt the real CGO binary and rescanned both `targets/vulnerable-flask`
  and `damn-vulnerable-golang` directly, confirmed above.
