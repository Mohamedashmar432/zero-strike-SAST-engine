# Sprint 26 Release Notes — v0.19.0

## Summary

A QA report (`SPRINT-25-QA-REPORT.md`) scanned six vulnerable applications
with the Sprint 25 binary and catalogued every undetected vulnerability into
9 root-cause "bottleneck" classes, ranked by fix difficulty. Four of those
classes were rated **Easy** — a well-understood sink with no rule yet, or a
taint source regex missing one keyword — and all four were already named as
Sprint 26 candidates in the Sprint 25 release notes' "Out of scope" section.
This sprint closes exactly those four, plus the one **Easy** taint-source
gap, and re-verifies against the same real ground-truthed Flask app used to
validate Sprint 25.

## New Python rules (4)

- **`ZS-PY-031`** — Command injection via `subprocess.check_output` +
  `tainted_argument`. Sibling to `ZS-PY-003`/`ZS-PY-012`, which only covered
  `subprocess.run`/`.call` — `check_output` is the third common entry point
  and was a confirmed miss on the real Flask app (`execute_command`).
- **`ZS-PY-032`** — XXE via `ET.fromstring` (the standard
  `import xml.etree.ElementTree as ET` alias) + `tainted_argument`. No
  Python XXE rule existed at all before this.
- **`ZS-PY-033`** — Code injection via bare `exec()`, unconditional, mirrors
  `ZS-PY-001`'s treatment of `eval()`. `exec()` had no equivalent despite
  being the more commonly abused of the two builtins for plugin/dynamic-code
  loading vulnerabilities.
- **`ZS-PY-034`** — Path traversal via Flask's `send_file` + `tainted_argument`.
  `ZS-PY-008` only covered the generic `open()` sink; `send_file` is Flask's
  own dedicated file-serving sink and equally common in real apps.

All four were confirmed against `targets/vulnerable-flask/app.py` directly —
each maps 1:1 to a real line in that file (`execute_command`, `parse_xml`,
`upload_plugin`, `path_traversal`), not just a synthetic fixture.

## Taint-source fix: PHP `$_SESSION`

`phpPatterns.Sources` covered `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`
but not `$_SESSION` — session data is exactly as attacker-influenced as any
other superglobal once an attacker can write to it (e.g. via a prior
unvalidated request), so every taint-gated PHP rule was blind to
session-derived sinks. Added `SESSION` to the source regex; regression test
`TestBuild_PHPSessionSourceTaintsVariable` added alongside the existing
Sprint 25 `request.headers` test of the same shape.

## Fixtures

Each new rule got a minimal one-sink fixture
(`vuln_check_output.py`, `vuln_xxe.py`, `vuln_exec.py`, `vuln_send_file.py`)
plus a manifest entry, and all four sinks were added to the vendored
`vuln_realistic_flask.py` fixture (alongside a `send_file` safe counterpart
with a hardcoded filename, proving `tainted_argument` doesn't false-positive
on a fixed path) — same "prove it generalizes beyond the easy shape"
discipline as Sprint 25.

## Confirmed against the real ground-truthed app

Rescanned `targets/vulnerable-flask/app.py` directly: **20 → 24 findings**
(19 SAST + 4 secrets + 1 SCA). All 4 new rules fired exactly once each, on
the real lines named in `sast_expected_findings.json`
(`COMMAND_INJECTION`, `XXE`, `CODE_INJECTION`, `PATH_TRAVERSAL`). Of the
17 ground-truthed real vulnerabilities, detection is now **13/17**, up from
11/17 at the end of Sprint 25.

**Still not detected, for reasons already documented and unchanged by this
sprint** (not new discoveries):

- **XSS reflected / stored** — no sink *call* exists to match against
  (`return f"<h1>Hello {name}!</h1>"`); needs the `kind: return` +
  tainted-expression match capability named in Sprint 25's release notes.
  Not attempted here — real engine capability, not a rule addition.
- **SSTI (`ZS-PY-027`)** — the rule still doesn't fire on this file for the
  exact reason recorded in Sprint 25: a later `safe_template()` function
  reassigns a variable also named `template`, and file-scoped/flow-insensitive
  taint tracking lets the last assignment win file-wide. Unchanged.
- **Missing authorization** (`admin_panel`) — semantic/business-logic,
  consistently out of scope.

## Bottleneck classes from the QA report intentionally NOT addressed this sprint

Per the QA report's own difficulty ratings, everything rated **Medium** or
**Hard** was left alone — these require actual engine capability
(interprocedural/CallGraph taint, a new tree-sitter grammar, flow-sensitive
taint, or inline-argument-as-source matching) rather than a rule addition,
and mixing a scoped rule sprint with an architecture change was avoided the
same way Sprint 25 kept `kind: return` out of scope. Specifically:
inline-argument taint gap (dvna), custom-sink wrapper indirection (DVWA),
missing EJS parser (dvna), interprocedural taint barrier (.NET),
file-scoped taint overwrite (Flask SSTI). Each remains a good candidate for
a dedicated future sprint scoped to that one engine change.

## Verification

- `go build ./...` / `go vet ./...` — clean.
- `go test ./... -count=1` — clean under both `CGO_ENABLED=0` and
  `CGO_ENABLED=1 CC=gcc`.
- `zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`:
  **TP=115 FP=0 FN=0** (up from TP=107 at the end of Sprint 25 — 4 new
  rules' isolated fixtures + 4 new occurrences in the realistic fixture).
- Rebuilt the real CGO binary and scanned `targets/vulnerable-flask`
  directly: 20 → 24 findings, all 4 new rules confirmed firing on real
  lines, cross-checked against `sast_expected_findings.json`.

## Out of scope (carried forward, unchanged)

Everything in Sprint 25's "Out of scope" list that wasn't one of this
sprint's 4 items: `kind: return` match capability (XSS), interprocedural/
CallGraph taint, flow-sensitive taint, sweeping `callee_suffix: true`
further, insecure cookie flags, NoSQL/LDAP injection, IDOR, the unverified
CI Flask target, and the one non-reproducible Sprint 25 DES anomaly (not
observed again this sprint).
