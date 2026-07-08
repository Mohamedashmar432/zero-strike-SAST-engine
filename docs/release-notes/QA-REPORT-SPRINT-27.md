# QA Test Plan — Sprint 27: Framework-Misconfiguration Coverage Expansion (v0.20.0)

**Engine:** ZeroStrike v0.20.0
**Engine Repo:** https://github.com/Mohamedashmar432/zero-strike-SAST-engine
**Commit:** `8e94d95`
**Date:** 2026-07-08
**Dev release notes (technical detail/rationale):**
`docs/release-notes/release-notes/SPRINT-27-RELEASE-NOTES.md` (also covers
Sprint 26, bundled into the same commit)

This is a **test plan**, not a completed report — each numbered item below
has an expected result; QA should run it and record actual vs. expected.
Baseline numbers quoted throughout are from the engineering verification
pass on commit `8e94d95` and should reproduce exactly.

Unlike Sprint 25/26, this sprint is NOT about one vulnerable app — it closes
a *coverage* gap in the framework-misconfiguration scanner across 8
languages/frameworks that previously had 0-4 checks total. Verification is
therefore mostly isolated per-check fixtures (§3-5) rather than one real
target app, plus a no-regression check against the existing Flask ground
truth (§2).

---

## 0. Build

```bash
export PATH="/c/Users/MohamedAshmar/mingw64/mingw64/bin:$PATH"
CGO_ENABLED=1 CC=gcc go build -o zerostrike.exe ./cmd/zerostrike/
```

**Expected:** clean build, no errors. `./zerostrike.exe --version` reports
`v0.20.0`.

---

## 1. Full regression suite

```bash
CGO_ENABLED=1 CC=gcc go test ./... -count=1        # real parsers
CGO_ENABLED=0 go test ./... -count=1               # pure-Go paths
```

**Expected:** all packages `ok`, zero failures, under both configs.

---

## 2. Benchmark accuracy gate

```bash
CGO_ENABLED=1 CC=gcc go run ./cmd/zerostrike-bench --corpus benchmark/corpus \
  --min-recall 0.90 --max-fp 0 --json-out bench.json --md-out bench.md
```

**Expected:** `TP=134 FP=0 FN=0` (precision 100.00%, recall 100.00%), up
from `TP=115` at the end of Sprint 26. Any `FP > 0` is an automatic fail —
do not wave it through.

---

## 3. Real-app no-regression check

```bash
./zerostrike.exe scan --no-cache --enable-sca --enable-secrets \
  --enable-framework-checks --format json --output flask-scan.json \
  "C:\Users\MohamedAshmar\playground\targets\vulnerable-flask"
```

**Expected:** still exactly **24 findings**, identical rule set to Sprint
26's baseline (`ZS-SEC-004`×4, `ZS-PY-020`, `ZS-PY-004`, `ZS-PY-031`,
`ZS-PY-029`, `ZS-PY-007`×3, `ZS-PY-011`, `ZS-PY-032`, `ZS-PY-002`,
`ZS-PY-025`×3, `ZS-PY-033`, `ZS-PY-026`, `ZS-PY-034`, `ZS-PY-028`,
`ZS-PY-030`, `ZS-PY-016`, `ZS-SCA-001`). **None of this sprint's new rules
should appear here** — this specific app has no Django/Spring/ASP.NET/
Laravel config surface for them to fire on. If any new-rule ID
(`ZS-PY-035..040`, `ZS-JS-018..020`, `ZS-CFG-005..010`) appears, or the
count changed, that's a regression — file it.

---

## 4. New rules — isolated fixture verification

Each new rule has a minimal standalone fixture. Run each and confirm the
expected rule fires and nothing else does.

### 4.1 Python — Django/Flask cookie, CSRF, HSTS settings

```bash
./zerostrike.exe scan --no-cache --format json --output out.json \
  benchmark/corpus/python/cases/vuln_django_cookie_secure.py
# expect: ZS-PY-035 fires (bare SESSION_COOKIE_SECURE = False)

./zerostrike.exe scan --no-cache --format json --output out.json \
  benchmark/corpus/python/cases/vuln_flask_cookie_secure.py
# expect: ZS-PY-039 fires (app.config['SESSION_COOKIE_SECURE'] = False)
# — and ZS-PY-035 does NOT also fire here (subscript form is Flask-only)
```

| Fixture | Rule |
|---|---|
| `vuln_django_cookie_secure.py` | `ZS-PY-035` |
| `vuln_django_csrf_cookie_secure.py` | `ZS-PY-036` |
| `vuln_django_ssl_redirect.py` | `ZS-PY-037` |
| `vuln_django_hsts.py` | `ZS-PY-038` |
| `vuln_flask_cookie_secure.py` | `ZS-PY-039` |
| `vuln_flask_csrf_disabled.py` | `ZS-PY-040` |

**Important same-line overlap check:** `vuln_django_cookie_secure.py`
(bare `SESSION_COOKIE_SECURE = False`) must fire **only** `ZS-PY-035`, not
also `ZS-PY-039` — the benchmark caught exactly this double-count before
ship (see dev release notes) and `ZS-PY-039` was narrowed to Flask's
`app.config[...]` subscript form specifically to fix it. If both fire on
that file, that regression has come back — file it as high priority.

### 4.2 JavaScript — Express cookie and CSP settings

```bash
./zerostrike.exe scan --no-cache --format json --output out.json \
  benchmark/corpus/js/cases/vuln_session_secure_false.js
# expect: ZS-JS-018 fires

./zerostrike.exe scan --no-cache --format json --output out.json \
  benchmark/corpus/js/cases/vuln_helmet_csp_disabled.js
# expect: ZS-JS-020 fires
```

| Fixture | Rule |
|---|---|
| `vuln_session_secure_false.js` | `ZS-JS-018` |
| `vuln_session_httponly_false.js` | `ZS-JS-019` |
| `vuln_helmet_csp_disabled.js` | `ZS-JS-020` |

---

## 5. New framework-scanner checks — isolated fixture verification

These are the checks that close the "zero coverage for C#/Go/Java" gap.
Scan each fixture **directory** (not a single file — some checks require a
specific path shape, e.g. `config/session.php`):

```bash
./zerostrike.exe scan --no-cache --enable-framework-checks --format json \
  --output out.json benchmark/corpus/framework/cases/spring/
# expect: ZS-CFG-005 fires on application-vuln-actuator.properties
#         ZS-CFG-006 fires on application-vuln-cookie.properties
#         nothing fires on the two application-clean-*.properties files

./zerostrike.exe scan --no-cache --enable-framework-checks --format json \
  --output out.json benchmark/corpus/framework/cases/aspnet/
# expect: ZS-CFG-007 fires under vuln_customerrors/web.config
#         ZS-CFG-008 fires under vuln_directorybrowse/web.config
#         nothing fires under either clean_*/web.config

./zerostrike.exe scan --no-cache --enable-framework-checks --format json \
  --output out.json benchmark/corpus/framework/cases/laravel/
# expect: ZS-CFG-009 fires under vuln_session/config/session.php
#         ZS-CFG-010 fires under vuln_csrf/VerifyCsrfToken.php
#         nothing fires under either clean_*/... path

./zerostrike.exe scan --no-cache --enable-framework-checks --format json \
  --output out.json benchmark/corpus/framework/cases/cors/
# expect: ZS-CFG-003 fires on vuln_wildcard.go, vuln_wildcard.java,
#         vuln_wildcard.cs, vuln_wildcard_header.php (4 findings)
#         nothing fires on clean_restricted_go.go
```

| Fixture | Rule | Framework |
|---|---|---|
| `spring/application-vuln-actuator.properties` | `ZS-CFG-005` | Spring Boot |
| `spring/application-vuln-cookie.properties` | `ZS-CFG-006` | Spring Boot |
| `aspnet/vuln_customerrors/web.config` | `ZS-CFG-007` | ASP.NET |
| `aspnet/vuln_directorybrowse/web.config` | `ZS-CFG-008` | ASP.NET |
| `laravel/vuln_session/config/session.php` | `ZS-CFG-009` | Laravel |
| `laravel/vuln_csrf/VerifyCsrfToken.php` | `ZS-CFG-010` | Laravel |
| `cors/vuln_wildcard.{go,java,cs,php}` | `ZS-CFG-003` | Go/Java/C#/PHP |

**Filename note:** the Spring fixtures must start with `application` (e.g.
`application-vuln-actuator.properties`) — this matches Spring Boot's real
naming convention and is required for the check to even look at the file;
a fixture named e.g. `vuln_actuator.properties` will silently produce zero
findings (this was the exact bug the benchmark caught before ship).

---

## 6. Confirmed gaps — NOT bugs to file

These are real, known gaps identified during this sprint's own engine
capability audit and explicitly deferred (see dev release notes
"Deferred" section). Do not file these as new bugs:

- **Django `@csrf_exempt` decorator** — no rule exists; the IR has no
  decorator node kind at all yet.
- **Spring `.csrf().disable()` / any fluent chain with a call in the
  middle** (e.g. `builder.AddCors(...).AllowAnyOrigin()`) — the engine's
  callee-chain resolution can't see past an intermediate call-with-parens.
- **C# `new CookieOptions { Secure = false }` / Go `http.Cookie{Secure:
  false}` object/struct-literal fields** — investigated, not shipped; Go's
  builder has no composite-literal support at all yet.
- **Default admin credentials** — intentionally left to the existing
  secrets scanner (`ZS-SEC-*`), not a new misconfiguration class.
- **Exposed debug/admin endpoints** beyond Spring Actuator and Django
  `ALLOWED_HOSTS` — no reliable generic signal without route-table
  analysis.

---

## 7. Sign-off checklist

- [ ] §0 Build succeeds, version reports `v0.20.0`
- [ ] §1 Full test suite passes under both CGO configs
- [ ] §2 Benchmark: `TP=134 FP=0 FN=0`
- [ ] §3 Real Flask app: still 24 findings, no new-rule IDs appear
- [ ] §4.1 All 6 new Python rules fire on their fixture; no
      `ZS-PY-035`/`ZS-PY-039` double-count on the Django fixture
- [ ] §4.2 All 3 new JS rules fire on their fixture
- [ ] §5 All 6 new framework-scanner checks fire on their vuln fixture and
      stay silent on the paired clean fixture

**Pass criteria:** all boxes checked, zero unexplained findings, zero
missing findings from §4-5. Anything in §6 showing up as "missing" is
expected, not a failure.
