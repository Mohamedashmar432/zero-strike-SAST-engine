# QA Test Plan — Sprint 25: Flask Scan Target Fix + Python Rule-Realism Gaps (v0.18.0)

**Target:** `C:\Users\MohamedAshmar\playground\targets\vulnerable-flask` (the
correct Flask test app — see §0 before using any other Flask directory)
**Engine:** ZeroStrike v0.18.0
**Engine Repo:** https://github.com/Mohamedashmar432/zero-strike-SAST-engine
**Commit:** `c6b2fc5`
**Date:** 2026-07-08
**Dev release notes (technical detail/rationale):** `docs/release-notes/release-notes/SPRINT-25-RELEASE-NOTES.md`

This is a **test plan**, not a completed report — each numbered item below
has an expected result; QA should run it and record actual vs. expected.
Baseline numbers quoted throughout are from the engineering verification
pass on commit `c6b2fc5` and should reproduce exactly.

---

## 0. Before you start: which Flask repo to use

Three different "vulnerable Flask app" directories exist on this machine.
**Only one is correct:**

| Path | What it actually is | Use for testing? |
|---|---|---|
| `C:\Users\MohamedAshmar\playground\targets\vulnerable-flask` | Real Flask app, 712 lines, 17 real vulns + ground truth | **Yes — use this one** |
| `sub-braining\www-project-vulnerable-flask-app` | OWASP Jekyll landing page, zero `.py` files | No — will always show 0 findings, this is expected and not a bug |
| CI's `we45/Vulnerable-Flask-App` (third-party GitHub checkout) | Unverified from this environment | Not used for local QA |

If a scan of the Jekyll repo shows 0 findings, that is correct behavior,
not a regression — do not file it as a bug.

---

## 1. Build

```bash
export PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH"
CGO_ENABLED=1 CC=gcc go build -o zerostrike.exe ./cmd/zerostrike/
```

**Expected:** clean build, no errors. `./zerostrike.exe --version` reports
`v0.18.0`.

---

## 2. Full regression suite

```bash
CGO_ENABLED=1 CC=gcc go test ./... -count=1        # real parsers
CGO_ENABLED=0 go test ./... -count=1               # pure-Go paths
```

**Expected:** all packages `ok`, zero failures, under both configs.

---

## 3. Benchmark accuracy gate

```bash
CGO_ENABLED=1 CC=gcc go run ./cmd/zerostrike-bench --corpus benchmark/corpus \
  --min-recall 0.90 --max-fp 0 --json-out bench.json --md-out bench.md
```

**Expected:** `TP=107 FP=0 FN=0` (precision 100.00%, recall 100.00%). Any
`FP > 0` is an automatic fail — do not wave it through.

---

## 4. Real-app scan — the actual QA target for this sprint

```bash
./zerostrike.exe scan --no-cache --enable-sca --enable-secrets \
  --enable-framework-checks --format json --output flask-scan.json \
  "C:\Users\MohamedAshmar\playground\targets\vulnerable-flask"
```

**Expected:** exit code `1` (findings found, not an error), **20 total
findings**: 15 SAST + 1 SCA + 4 secrets.

### 4.1 Rules that MUST fire (verify each appears at least once)

| Rule ID | Vulnerability | Ground-truth item |
|---|---|---|
| `ZS-PY-002` | `pickle.loads()` insecure deserialization | INSECURE_DESERIALIZATION |
| `ZS-PY-004` | `cursor.execute()` SQL injection | SQL_INJECTION |
| `ZS-PY-007` | `hashlib.md5()` weak hash (×3 occurrences expected) | WEAK_HASH_ALGORITHM |
| `ZS-PY-011` | `hashlib.sha1()` weak hash | WEAK_HASH_ALGORITHM |
| `ZS-PY-016` | `app.run(debug=True)` | DEBUG_MODE_ENABLED |
| `ZS-PY-020` | Hardcoded `SECRET_KEY` | HARDCODED_SECRET |
| `ZS-PY-025` | `requests.get()` SSRF (×3 occurrences expected) | SSRF |
| `ZS-PY-026` | `requests.post()` SSRF | SSRF (webhook variant) |
| `ZS-PY-028` | `redirect()` open redirect | OPEN_REDIRECT |
| `ZS-PY-029` | `DES.new()` weak cipher | WEAK_CRYPTO_ALGORITHM |
| `ZS-PY-030` | Reflected CORS origin | CORS_MISCONFIGURATION |

If any of these is missing, **that is a real regression** — file it.

### 4.2 Findings that will NOT appear — confirmed gaps, not bugs to file

These are real, known gaps identified *during* this sprint's own
investigation and explicitly deferred (see dev release notes §"Out of
scope"). Do not file these as new bugs — they're already tracked as Sprint
26 candidates:

- **Command injection** via `subprocess.check_output(cmd, shell=True)` —
  no rule covers this exact call yet (`ZS-PY-003`/`ZS-PY-012` only cover
  `subprocess.run`/`.call`).
- **XXE** via `ET.fromstring(xml_data)` — no Python XXE rule exists yet.
- **Code injection** via bare `exec(plugin_code)` — `ZS-PY-001` only
  covers `eval()`, not the `exec()` builtin.
- **Path traversal** via `send_file(filename)` — `ZS-PY-008` only covers
  `open()`.
- **Reflected/stored XSS** (`return f"<h1>Hello {name}!</h1>"`) — no sink
  function call exists to match against; needs a new match-kind capability
  (`kind: return`), tracked separately.
- **SSTI** (`ZS-PY-027`, `render_template_string`) — **the rule itself
  works** (verify via §5 below) but will NOT fire on this specific real
  file. Reason, confirmed: `app.py` has two functions that both use a
  local variable named `template` — one tainted (the real vuln), one a
  fixed string (a different, later function). Taint tracking is
  file-scoped, and the later clean assignment overwrites the taint verdict
  for the whole file. This is a known, already-documented engine
  limitation (see `internal/analyzer/taint/taint.go`'s doc comment),
  confirmed here with a concrete real-world example — not a new defect.
- **Missing authorization / IDOR** (`admin_panel`, `user_profile`,
  `delete_user`) — semantic/business-logic pattern, out of scope for every
  sprint so far (not expressible as a single AST sink match).

### 4.3 False-positive check — should NEVER appear

The ground truth (`targets/vulnerable-flask/sast_expected_findings.json`,
`false_positives_should_not_detect`) lists 5 deliberately safe patterns.
**None of these should produce any finding**:

- `safe_sql()` — parameterized ORM query
- `safe_command()` — allowlisted action, no shell string built from input
- `safe_template()` — fixed template, only the render variable is tainted
- `safe_crypto()` — AES-256-GCM
- `safe_hash()` — bcrypt

If any of these fires, **that is a false positive — file it immediately**,
this is exactly the kind of regression the `--max-fp 0` benchmark gate
exists to prevent.

### 4.4 One item to watch, not act on

The very first engineering scan of this target was missing the
`ZS-PY-029` (DES) finding; six identical reruns afterward (including
`--workers 1` and a `-race`-instrumented build) all found it correctly. It
was not reproduced a second time despite deliberate attempts. **If QA
observes a missing finding that reappears on rerun, please note it here
with the exact command and run count** — this would be the second
independent observation and would upgrade it from "anomaly" to "reproducible
bug worth root-causing."

---

## 5. Isolated rule verification (fast, no real-app dependency)

Each of the 6 new/changed rules also has a minimal standalone fixture
under `benchmark/corpus/python/cases/`. To sanity-check a single rule in
isolation:

```bash
./zerostrike.exe scan --no-cache --format json --output out.json \
  benchmark/corpus/python/cases/vuln_ssti.py
# expect: ZS-PY-027 fires

./zerostrike.exe scan --no-cache --format json --output out.json \
  benchmark/corpus/python/cases/clean.py
# expect: 0 findings — this file specifically includes the
# fixed-template-plus-tainted-variable SSTI negative case
# (render_template_string("...", name=name)), proving ZS-PY-027 doesn't
# false-positive on the safe shape.
```

Fixture-to-rule map: `vuln_execute_tainted.py`→`ZS-PY-004`,
`vuln_ssrf_get.py`→`ZS-PY-025`, `vuln_ssrf_post.py`→`ZS-PY-026`,
`vuln_ssti.py`→`ZS-PY-027`, `vuln_open_redirect.py`→`ZS-PY-028`,
`vuln_des.py`→`ZS-PY-029`, `vuln_cors.py`→`ZS-PY-030`,
`vuln_realistic_flask.py`→ all of the above together in one file plus 3
safe functions (negative cases).

---

## 6. Sign-off checklist

- [ ] §1 Build succeeds, version reports `v0.18.0`
- [ ] §2 Full test suite passes under both CGO configs
- [ ] §3 Benchmark: `TP=107 FP=0 FN=0`
- [ ] §4 Real-app scan: 20 total findings, all 11 rules in §4.1 present
- [ ] §4.3 None of the 5 false-positive cases fire
- [ ] §5 Isolated fixtures behave as mapped

**Pass criteria:** all boxes checked, zero unexplained findings, zero
missing findings from §4.1. Anything in §4.2/§4.4 showing up as "missing"
is expected, not a failure — the point of this test plan is to confirm the
engine behaves *exactly* as documented, gaps included.
