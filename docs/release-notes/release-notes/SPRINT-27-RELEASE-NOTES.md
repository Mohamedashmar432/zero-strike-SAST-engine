# Sprint 27 Release Notes — v0.20.0

## Summary

The user asked whether framework-level security misconfiguration detection
exists for all supported language frameworks. A coverage audit found the
framework scanner (`internal/scanner/framework/`) still implemented exactly
the same 4 checks it shipped with at Sprint 15-16 (Django `DEBUG`, Express
missing `helmet()`, wildcard CORS, Laravel `APP_DEBUG`) — never revisited
since, and unlike every other deferred item in this project, never
documented as deliberately out of scope. Zero checks existed at all for
C#/ASP.NET, Go, or Java, and no check anywhere covered cookie/session
flags, CSRF, or verbose-error settings. The user chose to close as much of
this gap as the engine could honestly support in one sprint, across all
frameworks.

## Engine capability audit (informed what was buildable)

Before writing rules, audited what `internal/engine/engine.go`'s matcher
can express: `kind: assignment` + `lhs_identifier`/`rhs_literal` works on
subscript-assignment LHS text too (already proven by `ZS-PY-030`), and the
`kwarg` filter walks a call's full argument subtree (`ir.Descendants`), so
it can reach a key nested two levels inside an object literal
(`session({cookie: {secure: false}})`) even though no shipped rule
exercised that before this sprint. It CANNOT express decorator-gated rules
(no `NodeKindDecorator` exists in the IR at all) or any callee chain where
an intermediate segment is itself a call-with-parens
(`http.csrf().disable()`) — `attributeText` only recurses through
`NodeKindIdentifier`/`NodeKindAttribute`, so the chain collapses to just
the last segment. These two gaps blocked a Django `@csrf_exempt` rule and
a Spring `.csrf().disable()` rule — both deferred, not attempted.

A targeted spike into whether C#'s `new CookieOptions { Secure = false }`
or Go's `http.Cookie{Secure: false}` struct-literal fields could be reached
found: Go's builder has **zero** composite-literal/keyed-element handling
at all (confirmed via grep — everything falls to `NodeKindUnknown`), and
C#'s initializer members would need a context-sensitive builder change
(mapping `assignment_expression` differently depending on whether it's
inside an `initializer_expression`) that couldn't be verified safe in the
time budgeted. Both deferred rather than shipped blind.

## New Python rules (6) — Django + Flask cookie/CSRF/HSTS settings

Same shape as the existing `ZS-PY-017`/`ZS-PY-019` (`kind: assignment` +
`lhs_identifier`/`rhs_literal`):

- `ZS-PY-035` Django `SESSION_COOKIE_SECURE = False`
- `ZS-PY-036` Django `CSRF_COOKIE_SECURE = False`
- `ZS-PY-037` Django `SECURE_SSL_REDIRECT = False`
- `ZS-PY-038` Django `SECURE_HSTS_SECONDS = 0`
- `ZS-PY-039` Flask `app.config['SESSION_COOKIE_SECURE'] = False`
- `ZS-PY-040` Flask `WTF_CSRF_ENABLED = False`

`ZS-PY-039` was originally written with an unanchored `SESSION_COOKIE_SECURE`
pattern (to also catch the subscript form), but the benchmark caught a real
double-count: Django's identical bare `SESSION_COOKIE_SECURE = False` line
matched both `ZS-PY-035` and `ZS-PY-039`, since the two frameworks share
the exact same setting name and there's no way to tell them apart from that
one line. Fixed by scoping `ZS-PY-039` to Flask's `config[...]` subscript
shape specifically, leaving the bare form to `ZS-PY-035` alone — caught by
the benchmark gate before it shipped, the same discipline that has caught
every prior sprint's rule-overlap bug.

## New JS rules (3) — Express cookie/CSP settings

Using `kind: call` + nested `kwarg`, new territory for a shipped rule but
proven reachable by the engine audit above:

- `ZS-JS-018`/`ZS-JS-019` `session({cookie: {secure: false}})` /
  `{httpOnly: false}` — express-session's insecure cookie flags
- `ZS-JS-020` `helmet({contentSecurityPolicy: false})` — complements
  `ZS-CFG-002`, which only catches helmet's total absence, not a
  present-but-neutered config

## Framework scanner — 6 new checks, 3 new languages covered

Following the existing `check{ruleID, accepts, detect}` pattern
(`internal/scanner/framework/spring.go`, `aspnet.go`,
`laravel_session.go`):

- `ZS-CFG-005` Spring Boot Actuator fully exposed
  (`management.endpoints.web.exposure.include=*` in
  `application.properties`/`.yml`, reusing the existing `ParseProperties`
  helper that had been built in an earlier sprint but never wired to a
  check, and `ParseYAMLFlat`)
- `ZS-CFG-006` Spring Boot insecure session cookie
  (`server.servlet.session.cookie.secure=false`)
- `ZS-CFG-007` ASP.NET verbose errors (`<customErrors mode="Off">` in
  `web.config`)
- `ZS-CFG-008` ASP.NET directory browsing enabled
  (`<directoryBrowse enabled="true">` in `web.config`)
- `ZS-CFG-009` Laravel insecure session cookie (`'secure' => false` /
  `'http_only' => false` in `config/session.php`) — pure text regex,
  sidestepping the confirmed gap that PHP's `'key' => value` array-literal
  entries are structurally invisible to `kind: assignment` today (PHP's
  builder only maps `assignment_expression`)
- `ZS-CFG-010` Laravel CSRF protection bypassed (non-empty `$except` array
  in `VerifyCsrfToken.php`)
- Extended existing `ZS-CFG-003` (not a new rule ID — same vulnerability
  class) with a source-file branch for `.go`/`.java`/`.cs`/`.php`, matching
  the header-set-call idiom (`w.Header().Set("Access-Control-Allow-Origin",
  "*")`, `response.setHeader(...)`, `header('Access-Control-Allow-Origin: *')`).
  Deliberately anchored on the full literal header name, not the bare word
  "origin" the existing config-file regex uses — general-purpose source
  code (unlike structured `.env`/`.yaml`/`.json`/`.conf` files) can contain
  short identifiers named "origin" for unrelated reasons, e.g. Go's
  pointer-dereference syntax `origin = *ptr` would otherwise false-positive.

This closes the "zero framework-specific checks at all" gap for C#/ASP.NET,
Go, and Java that the coverage audit found.

## Fixtures

Every new rule/check got a minimal isolated fixture plus a manifest entry:
`benchmark/corpus/python/cases/vuln_django_*.py` and `vuln_flask_*.py`,
`benchmark/corpus/js/cases/vuln_session_*.js` and
`vuln_helmet_csp_disabled.js`, and new `benchmark/corpus/framework/cases/`
subdirectories for `spring/`, `aspnet/`, `laravel/vuln_session`,
`laravel/vuln_csrf`, plus `cors/vuln_wildcard.{go,java,cs,php}`. The two
new `.go` CORS fixtures needed a non-`main` package with uniquely-named
functions — `go build ./...` compiles every non-`testdata` directory as a
real Go package, and two files both declaring `package main` with a
`handler` function in the same directory failed to compile until fixed.

## Confirmed against the real ground-truthed app — no regression

Rescanned `targets/vulnerable-flask/app.py`: still exactly **24 findings**,
identical rule set to Sprint 26's baseline. Expected — none of this
sprint's new rules target a vulnerability class present in that specific
app (it has no Django/Spring/ASP.NET/Laravel config surface, and its CORS
misconfiguration is caught by the existing `ZS-PY-030` Python rule, not the
framework scanner). This sprint closes a documented *coverage* gap, not a
miss on this specific ground-truth target.

## Verification

- `go build ./...` / `go vet ./...` — clean.
- `go test ./... -count=1` — clean under both `CGO_ENABLED=0` and
  `CGO_ENABLED=1 CC=gcc`.
- `zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`:
  **TP=134 FP=0 FN=0** (up from TP=115 at the end of Sprint 26) — reached
  after two real issues the benchmark caught and this sprint fixed: the
  Spring fixtures were initially named `vuln_actuator.properties` /
  `vuln_cookie.properties`, which don't start with `application` and so
  were never accepted by `isSpringConfigFile` (0 findings instead of 1);
  and the `ZS-PY-039`/`ZS-PY-035` double-count described above.
- Rebuilt the real CGO binary and rescanned `targets/vulnerable-flask`:
  24 findings, unchanged from Sprint 26 — confirmed no regression.

## Deferred (documented, not silently dropped)

- **Django `@csrf_exempt` decorator detection** — needs a new
  `NodeKindDecorator` IR capability across the Python (and eventually TS)
  builders.
- **Spring `.csrf().disable()` / any fluent-chain-through-a-call pattern**
  (also blocks a cleaner ASP.NET `AddCors(...).AllowAnyOrigin()` rule) —
  needs `attributeText` to recurse through `NodeKindCall`, not just
  `NodeKindIdentifier`/`NodeKindAttribute`.
- **C# `CookieOptions` object-initializer fields / Go `http.Cookie{}`
  struct-literal fields** — investigated this sprint, not shipped: Go's
  builder has no composite-literal handling at all; C# would need a
  context-sensitive builder change not verified safe in the time budgeted.
- **Default admin credentials** — already the generic secrets scanner's
  job (`ZS-SEC-*`), not a distinct new misconfiguration class.
- **Exposed debug/admin endpoints** beyond Spring Actuator and Django
  `ALLOWED_HOSTS` (already `ZS-PY-019`) — no reliable generic signal
  without route-table analysis.
- Everything already carried forward from Sprints 25-26 (interprocedural
  taint, `kind: return` match capability, the unverified CI Flask target,
  the one non-reproducible Sprint 25 DES anomaly — not observed again).
