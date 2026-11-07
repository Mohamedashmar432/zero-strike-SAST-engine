# Precision, framework checks and coverage: plan for 5 to 8 November 2026

*Written 4 November 2026 for engineering leads at thinkbridge. Scanner under test: a CGo build of
the current tree (version label v0.42.0-latest, last commit 3 November 2026). Benchmark: the
RealVuln ground truth at its current `main`. Nothing in the scanner source or rules was changed to
produce this document.*

Companion documents this plan builds on, and does not repeat:
[docs/benchmarks/realvuln-v0.37.0.md](../benchmarks/realvuln-v0.37.0.md) (method, the original
dev/held-out split, and the hand-verified "real but unlabeled" classes),
[gap.md](../../gap.md) (P0 measurement principles), [improve.md](../../improve.md) (status note on
the self-authored corpus) and [baseline.md](../../baseline.md) (internal corpus report format).

## 1. Summary and verdict

**Verdict: a RealVuln precision above 75 percent by Sunday 8 November is not achievable honestly.
An adjudicated precision above 75 percent is achievable, and the plan below targets that, together
with a strict RealVuln precision of about 55 percent at no loss of recall.**

The evidence, all from the nine-repo run of 4 November:

| Measure | Value |
|---|---|
| True positives / false positives / false negatives | 216 / 259 / 244 |
| Strict precision / recall | 45.5% / 47.0% |
| False positives that hit a labeled trap (`is_vulnerable: false`) | 1 of 259 |
| False positives at a location with no label at all | 258 of 259 |
| Rules that fired / produced a TP / produced an FP / produced only FPs | 126 / 89 / 76 / 37 |
| Share of FPs from the 12 noisiest rules | 142 of 259 (55%) |

Three findings shape the verdict.

**The benchmark has not moved in five releases.** The per-repo counts on 4 November are identical to
the v0.37.0 report of 7 October for eight of nine repos, and dvws-node differs by one FP (23 to 24).
v0.37.0's dev set was 179 / 207 / 157 and its held-out set 37 / 51 / 87, which sum to 216 / 258 /
244. The four "next release" items in that report were not delivered: first-party JS under
`static/` and `public/` is still skipped (`internal/walker/filter.go:19` and `:70`), `path.basename`
is still not a JS/TS sanitizer (`internal/analyzer/taint/patterns.go:47-52`), the Next.js and
`req.cookies`/`req.headers` sources are still absent (`patterns.go`, JS source list), and every
"confirmed noise" rule it named (ZS-PY-141, ZS-TS-089, ZS-TS-150) still fires.

**Most false positives are not wrong.** Of the 202 FPs from the 30 noisiest rules, which I reviewed
line by line, 83 are real weaknesses that RealVuln did not label (session cookies without Secure,
`@csrf_exempt` views, error text returned to clients, JWT verification that accepts `none`), 42 are
duplicate reports of one root cause, 33 lack a context gate, 19 are in the wrong output tier and 25
still need review. RealVuln states its labels are not exhaustive and scores one finding per label,
so any scanner that reports every instance of a real weakness is penalized.

**The arithmetic ceiling.** Simulating the zero-recall-loss fixes in section 3 against the scorer
gives 216 TP / 179 FP, strict precision 54.7 percent, recall unchanged at 47.0 percent. Reaching 75
percent strict at 216 TP requires FP of 72 or fewer, so 107 more FPs would have to go. The remaining
FPs are dominated by the 83 real-but-unlabeled findings. Removing them means suppressing true
weaknesses because a labeler skipped them, which is tuning to the answer key.

The scenarios in the brief reproduce exactly (`sim.py` in the scratchpad bench directory), and each
fails for a stated reason:

| Scenario | TP / FP | Precision | Recall | Why it is rejected |
|---|---|---|---|---|
| Baseline | 216 / 259 | 45.5% | 47.0% | |
| Drop the 37 rules with zero TP here | 216 / 150 | 59.0% | 47.0% | Deletes real detections (JWT `none`, CORS reflection, cookie flags) because nine repos did not label them |
| Drop the 23 rules under 40% precision with 3+ FPs | 180 / 85 | 67.9% | 39.1% | Loses 36 TPs |
| Both | 180 / 56 | 76.3% | 39.1% | Tuned and scored on the same nine repos; 48 rules deleted |
| Dedupe every rule per file | 168 / 139 | 54.7% | 36.5% | Loses 48 TPs; labels are per instance |
| Section 3 fixes (this plan) | 216 / 179 | 54.7% | 47.0% | Accepted: no TP loss, each fix is correct on real code |

**What "above 75 percent" can honestly mean.** Adjudicated precision counts a finding as correct
when it matches a label or when an independent reviewer confirms it is a real weakness at that
location; everything else stays an FP. After the section 3 fixes it is (216 + 83) / (216 + 179) =
75.7 percent, provided all 83 survive adjudication. That is a knife edge: at 395 findings the gate
needs at least 81 confirmed, so only two may be rejected. Clearing the 25 unreviewed top-30 FPs and
part of the 57-FP tail (workstream E) widens the margin: with 20 genuinely wrong FPs removed, the
gate needs 66 of 83 confirmed. Adjudicated precision must always be published next to strict
RealVuln precision, never instead of it, and the adjudication log must be checked in.

**Overfitting risk.** All nine repos have now been examined finding by finding (v0.37.0 examined the
five dev repos, and this analysis examined all nine), so none is a held-out set any more. Every
number above is a dev-set number. Section 7 defines a new 13-repo held-out set (422 labels) that
covers Java Spring, Flask, FastAPI, Express and Next.js, measured as sealed aggregates only.

**Recall cost.** The accepted fixes cost no recall on the dev set. Section 5 adds rules for 42 of the
244 missed labels; if all landed, recall would be (216 + 42) / 460 = 56.1 percent. New rules add
their own unlabeled hits, so precision is protected by putting new rules through the same gates.

## 2. Why "519 rules" reads as "264 active"

There is no rule-state problem in the scanner. `internal/rules/data` holds 521 YAML files; 519 have
`lifecycle: released` and two (`python/ZS-PY-009.yaml`, `python/ZS-PY-060.yaml`) have
`lifecycle: retired`. Every released rule is loaded and runs.

The figure of about 264 is the number of rules gated on taint. The count depends on which predicates
are included, which is itself a source of confusion:

| Counted predicates | JS | TS | Python | Go | Java | PHP | C# | Total |
|---|---|---|---|---|---|---|---|---|
| `tainted_argument` only | 67 | 67 | 32 | 25 | 24 | 18 | 14 | 247 |
| plus `tainted_rhs`, `value_tainted` | 75 | 75 | 33 | 25 | 24 | 18 | 16 | 266 |
| plus `lhs_flows_to_call` | 77 | 77 | 33 | 25 | 24 | 18 | 16 | 270 |

(Grep over released rule files on 4 November. The 264 in the brief sits inside this range.) The
remaining rules are structural: 447 rules use `kind: call`, 52 `kind: assignment`, and a handful
use `binary_op`, `try`, `decorator`, `literal` and `keyword_argument`. Structural rules are active;
they simply do not need a source.

Where a smaller number surfaces to users:

1. **Portal Scan Engine page without `SCANNER_RULES_DIR`.** `rule_stats()` in
   `zero-strike-portal/backend/app/services/scan_engine_service.py` builds its rows from rules that
   have produced a finding unless the YAML catalog is configured. Every such row has
   `state: "active"`, and the page shows "Showing N of N rules" with a muted banner
   (`frontend/app/(dashboard)/admin/scan-engine/page.tsx:222-245`). Locally, where
   `backend/.env.example:15` leaves `SCANNER_RULES_DIR` commented out, "active" therefore means
   "has fired at least once in this database". This is the most likely origin of the 264 figure; it
   could not be confirmed against the live database from here.
2. **Portal page with the catalog loaded.** `_load_catalog()` reads all 521 YAML files and the row
   state is derived only from portal overrides, so the two YAML-retired rules display as
   "active". The page shows 521 active rules while the scanner runs 519.
3. **SARIF.** `internal/report/sarif/sarif.go:178` adds a rule to `tool.driver.rules` only when a
   finding references it, so SARIF consumers see the fired-rule count.
4. **Tier exclusion.** Default output hides hardening and quality findings
   (`Stats.TierExcluded`). On 4 November that hid 82 findings across the nine repos, from five rule
   ids, which makes rules look inactive.

Fixes (portal and docs only, no scanner coupling): the portal should treat a YAML
`lifecycle: retired` as retired, label the uncatalogued view "rules that have fired" instead of
"active", and show `Stats.TierExcludedByRule` next to the findings count. The scanner README should
state the three numbers: rules shipped, rules taint-gated, rules hidden by default tier.

## 3. False-positive anatomy

### 3.1 Root causes

The 30 noisiest rules produced 202 of the 259 FPs. Each was read at the reported line in the cloned
repo and assigned one cause.

| Root cause | FPs | Fixable without suppressing a real weakness |
|---|---|---|
| Unlabeled real weakness | 83 | No. Adjudicate instead |
| Duplicate per-file noise (two rules on one call, or one call repeated) | 42 | Yes |
| Missing context gate (sanitizer, constant, weak parameter taint, hash not credential) | 33 | Yes |
| Not yet reviewed (some likely real) | 25 | Unknown |
| Wrong severity tier (no exploit path) | 19 | Yes |
| **Top 30 total** | **202** | |
| Long tail, 96 rules, not reviewed line by line | 57 | Unknown |

"Genuinely wrong match" is rare in the reviewed set and appears as individual cases inside the gate
row, for example ZS-PY-008 firing on `(HERE / 'leaked_passwords.txt').open()` in vulpy
`good/libuser.py:129`, a constant pathlib join. Most wrongness is context the rule does not check.

Two structural causes deserve separate mention:

- **Weak parameter taint.** The taint analyzer seeds every function parameter as untrusted and marks
  it weak (`internal/rules/rules.go:125-133`). Rules without `require_real_source: true` (27 rules
  carry it) fire on library functions whose arguments are ordinary parameters. All seven ZS-TS-089
  hits in healthcare-clinic-nextjs are in `src/lib/*.ts` helpers.
- **One label absorbs one finding.** The scorer matches each label once; 59 FPs sit in a file where
  the same rule already scored a TP. Deduplicating all rules per file loses 48 TPs, because many
  files carry several labels of one class, so dedupe must be targeted (rows below).

### 3.2 The worst 25 rules and the fix for each

FP and TP columns are from `deep.json`. "Sim" is the measured change from `sim.py` when the fix is
modeled as a filter or targeted dedupe on the existing output; "est" marks a fix not simulated.

| # | Rule | TP / FP | Cause | Fix | Effect |
|---|---|---|---|---|---|
| 1 | ZS-PY-099 cookie without Secure | 0 / 22 | Duplicate with ZS-PY-098 on the same 22 `set_cookie` calls; the rest real | Merge 098 and 099 into one finding per call, single primary CWE (CWE-614 when Secure is missing, else CWE-1004), message lists the missing flags | Sim: -22 FP, 0 TP (labels re-absorbed by the merged finding) |
| 2 | ZS-PY-098 cookie without HttpOnly | 5 / 17 | Same | Same | Included above |
| 3 | ZS-PY-090 `@csrf_exempt` | 9 / 16 | Unlabeled real; every hit is a real exemption (v0.37.0 report) | None. Per-file dedupe was simulated and loses 8 TPs | Adjudicate |
| 4 | ZS-PY-078 `set_trace_callback(print)` | 6 / 15 | Duplicate: identical call repeated per function, all in vulpy | Aggregate identical calls (same callee, same constant arguments) per file into one finding with an occurrence count | Sim: -15 FP, 0 TP |
| 5 | ZS-PY-141 hardcoded credential kwarg | 3 / 14 | Gate: 7 are hex digests (`password="65079b00..."`, pygoat `introduction/views.py:866-872,1164-1167`); 1 is a response message (`'Password': 'Updated.'`, vampi `api_views/users.py:199`); 4 are seed users in djangoat `management/commands/seed.py` | Add `not` filters: rhs matches `^[bru]?["'][0-9a-fA-F]{32,128}["']$` (emit at most a separate low-severity "hardcoded password hash"); rhs contains whitespace or a sentence period. Keep seed scripts: vulpy labels identical seed lists as CWE-798 | Sim: -8 FP, 0 TP |
| 6 | ZS-JS-048 JWT accepts `none` | 0 / 11 | Duplicate plus unlabeled real: 7 `algorithms: ["HS256", "none"]` declarations in dvws-node, each used by one or two `jwt.verify` calls | Report at the options declaration when the verify argument is an identifier bound to an object literal in the same file | Sim (per-file): -5 FP; 6 remain, real and critical |
| 7 | ZS-PY-024 empty `except: pass` | 0 / 10 | Wrong tier: a code-quality issue with no exploit path | `tier: quality`, matching ZS-PY-023 | Sim: -10 FP |
| 8 | ZS-TS-120 error details in response | 12 / 9 | Unlabeled real: 7 are `NextResponse.json({ error: e instanceof Error ? e.message : "..." })` in healthcare API routes | None | Adjudicate |
| 9 | ZS-HTML-004 iframe without sandbox | 0 / 9 | Wrong tier: constant YouTube embeds in nodegoat tutorials | Default tier only when `src` is a template expression or same-origin path; constant external `src` goes to `tier: hardening` | Sim: -9 FP |
| 10 | ZS-TS-089 `path.join` tainted | 3 / 8 | Gate: `path.basename` result (`consent-library.ts:16`, `intake-templates.ts:27`, `policy-library.ts:13`), `randomBytes` names (`files.ts:48`, `letterhead-assets.ts:34`), and weak parameter taint | Sink-class sanitizers for path rules: `path.basename`, names derived from `randomBytes`/`randomUUID`/`uuid`; do not add them to the global sanitizer list, which would also clear XSS taint | Sim (with rows 17, 25): -10 FP, 0 TP |
| 11 | ZS-TS-150 Angular `bypassSecurityTrust*` | 3 / 6 | Mislocated: juice-shop labels the template binding (`search-result.component.html:13`, `about.component.html:51`), not the component call | Register ZS-CFG-020 (section 4); leave this rule unchanged | Est: +2 TP from the template rule |
| 12 | ZS-JS-120 error details in response | 27 / 5 | Unlabeled real: further instances in dvws files that already hold a label | None | Adjudicate |
| 13 | ZS-PY-140 hardcoded credential comparison | 3 / 4 | Unlabeled real (`password == "admin"`) | None | Adjudicate |
| 14 | ZS-PY-007 MD5 | 2 / 4 | Unlabeled real: MD5 used for passwords | None; do not re-tag CWE to match labels | Adjudicate |
| 15 | ZS-PY-142 literal JWT key | 1 / 4 | Unlabeled real (`jwt.decode(cookie, 'csrf_vulneribility', ...)`) | None | Adjudicate |
| 16 | ZS-TS-128 NoSQL operator injection | 0 / 4 | Review: `req.params.*` is always a string in Express and cannot carry an operator object | Exclude taint whose only source is `req.params` for operator-injection rules; keep `req.body` and `req.query` (the `qs` parser builds objects) | Est: -1 to -2 FP |
| 17 | ZS-TS-132 `fs.promises` write | 0 / 4 | Gate: generated names; `widget-assets.ts:18` is labeled CWE-434, not CWE-22 | Same sanitizers as row 10 | Included in row 10 |
| 18 | ZS-TS-023 `readFileSync` tainted | 0 / 4 | Review: juice-shop code-fix loaders build paths from a challenge key | Review each; likely gate on allowlisted key lookup | Est: 0 to -4 |
| 19 | ZS-TS-138 Prisma mass assignment | 2 / 4 | Gate: `data: input` where `input` is a helper parameter | `require_real_source: true` on the `value_tainted` filter | Est: -3 to -4 FP |
| 20 | ZS-PY-028 open redirect | 0 / 4 | Gate: `redirect("/users/" + str(current_user.id) + ...)` in djangoat | Skip when the first concatenation operand is a literal starting with `/` but not `//` or `/\`; constant-propagate `url = "/users/%s/..." % id` | Sim: -3 FP; est -1 more |
| 21 | ZS-PY-008 `open()` non-constant | 1 / 3 | Gate plus one genuinely wrong (pathlib join of a literal) | Treat `Path / "literal"` and `Path(__file__).parent` chains as constant | Est: -1 to -3 |
| 22 | ZS-HTML-022 value inside HTML comment | 1 / 3 | Unlabeled real: pygoat renders full SSN and card number inside a comment | None | Adjudicate |
| 23 | ZS-PY-096 weak password hash | 3 / 3 | Unlabeled real (SHA-256 of a password) | None | Adjudicate |
| 24 | ZS-TS-037 NoSQL query | 0 / 3 | Review: value derived from the authenticated user's email | Review; possible gate on values read from the server-side session | Est: 0 to -3 |
| 25 | ZS-TS-062 `createWriteStream` | 0 / 3 | Gate plus a CWE-73-only label at `routes/fileUpload.ts:45` | Same sanitizers as row 10. Do not add CWE-73 (v0.37.0 rejected this as benchmark-only) | Included in row 10 |

Cumulative simulation of the fixes that could be modeled (rows 1 to 7, 9, 10, 17, 20, 25):

| Step | TP | FP | Precision | Recall |
|---|---|---|---|---|
| Baseline | 216 | 259 | 45.5% | 47.0% |
| Merge PY-098/099 | 216 | 237 | 47.7% | 47.0% |
| PY-024 to quality | 216 | 227 | 48.8% | 47.0% |
| HTML-004 constant src to hardening | 216 | 218 | 49.8% | 47.0% |
| PY-078 identical-call aggregation | 216 | 203 | 51.6% | 47.0% |
| JS-048 per declaration | 216 | 198 | 52.2% | 47.0% |
| PY-141 hash and message gates | 216 | 190 | 53.2% | 47.0% |
| PY-028 relative-path gate | 216 | 187 | 53.6% | 47.0% |
| Path sanitizers (TS-089/132/062) | 216 | 179 | 54.7% | 47.0% |

A coarser version of the last step, `require_real_source` on every path rule, was also simulated and
lost 3 TPs (213 / 177), which is why the plan uses sink-class sanitizers instead.

### 3.3 The tier lever, evaluated

Only four YAML rules carry a non-default tier today: ZS-HTML-001, -005 and -008 (`hardening`) and
ZS-PY-023 (`quality`). Two framework checks set it in code (ZS-CFG-002 in `express.go:69`,
ZS-CFG-012 in `github_actions.go:87`). Tiering is the cheapest lever, and it is honest only for
rules with no exploit path on their own. Assessed against that test:

- **Move:** ZS-PY-024 (empty except) to quality; ZS-HTML-004 with constant external `src` to
  hardening. Combined: -19 FP, 0 TP.
- **Do not move:** cookie flags on session or token cookies (pygoat's `set_cookie('session', ...)`
  is a real session-hijack aid), `@csrf_exempt`, error details in responses (39 TPs between
  ZS-JS-120 and ZS-TS-120), JWT `none` (critical). Tiering cookie flags would cost 5 TPs and remove
  17 real findings from default output.
- **Optional split:** ZS-PY-099 could keep default tier only when the cookie name matches
  `(?i)session|token|auth|sid|jwt|remember` and drop to hardening otherwise. In these nine repos
  almost every hit is an auth cookie, so this gains nothing here; it is still the right rule for
  customer code.

One product consequence: the portal runs cloud scans without `--include-hardening`, so tiered
findings never reach customers. That is the intent, but the portal should show the excluded counts
(section 2).

## 4. Framework misconfiguration gap

### 4.1 Why the framework scanner looked silent

With `--enable-framework-checks`, `Stats.ByKind` on all nine repos contained only `sast`, `sca` and
`secret`. The scanner did run and did produce findings; all six were hidden by tier:
`Stats.TierExcludedByRule` shows ZS-CFG-002 once (dvws-node) and ZS-CFG-012 five times (juice-shop
1, vampi 4), both hardening. The silence has four causes:

1. **A finished check was never registered.** `rawHTMLBindingCheck` (ZS-CFG-020,
   `internal/scanner/framework/frontend_html.go:33`) is defined, documented and tested in isolation,
   but it is missing from the `checks` slice in `scanner.go:24-38`. It is the check that would catch
   juice-shop's Angular `[innerHTML]` bindings whose component calls `bypassSecurityTrustHtml`.
2. **Narrow file scope.** Checks read `.env`, `docker-compose`, `application.properties`/`.yml`,
   `web.config`, `php.ini`, GitHub workflows and, for helmet, JS entry files. Nothing reads
   Dockerfiles, Kubernetes manifests, Terraform, nginx, `next.config.*`, or Python settings modules.
   `djangoDebugCheck` reads only `.env` files by design (`django.go:8-11`), because ZS-PY-017 already
   matches `DEBUG = True` in `settings.py`.
3. **The work lives elsewhere.** Framework misconfiguration in source is already detected by SAST
   rules and the secrets scanner, so it is reported as `Kind: sast` or `secret`. In this run:
   ZS-PY-020 (Django/Flask `SECRET_KEY`) 11, ZS-JS-141 (literal secret) 7, ZS-PY-016 (Flask debug) 5,
   ZS-PY-017 (Django `DEBUG`) 3, ZS-PY-146 3, ZS-PY-019 (`ALLOWED_HOSTS`) 2, ZS-JS-018/019
   (express-session flags) 2, ZS-TS-069 (`cors()`) 1, and ZS-SEC-031/032 for `.env` and compose
   credentials.
4. **Substring suppression.** `detectExpressMissingHelmet` returns early when the file contains the
   string "helmet" anywhere (`express.go:36`). nodegoat's `server.js` mentions helmet only in
   comments and commented-out code, so the check is suppressed.

### 4.2 Design rule for new checks

Keep the existing split and write it down in `internal/scanner/framework/doc.go`: settings that are
source code (Python settings modules, Express `app.use(...)` calls, Spring `SecurityFilterChain`)
belong in YAML SAST rules, which have an AST, taint and caching; files that are not source
(Dockerfile, compose, Kubernetes, Terraform, nginx, `.properties`, `.env`, JSON/YAML config) belong
in the framework scanner, which is pure Go and needs no CGo. Do not change the `Kind` of existing
SAST rules: the portal and customer gates read report fields, and the layout contract in
`cmd/zerostrike/exemptions_test.go` (`TestReportLayoutContract`) must keep passing. To make
framework coverage visible without changing kinds, add a `Stats.ByFramework` count derived from each
finding's existing `Config.Framework` or rule tags.

### 4.3 Checks to build

"Labeled" means the setting carries a RealVuln label in these repos; unlabeled checks earn no
benchmark TP and must stand on their own merit.

| Framework | File | Setting | Severity / tier | Where in the benchmark repos | Home |
|---|---|---|---|---|---|
| Angular, AngularJS, Vue | `*.component.html`, templates | `[innerHTML]` with sibling `bypassSecurityTrust*`, `ng-bind-html` with SCE off, `v-html` | High, low confidence (existing ZS-CFG-020) | juice-shop `about.component.html:51`, `search-result.component.html:13` (labeled) | Register in `checks` |
| Express + jsonwebtoken | JS/TS | `ignoreExpiration: true` in verify options | Medium, CWE-613 | dvws-node `app.js:49`, `utils.js:13` (labeled) | New JS/TS rule |
| express-session | JS/TS | `session({...})` with no `cookie.secure: true` (the library default is insecure) | Medium, CWE-614 | nodegoat `server.js:78` (labeled) | Widen ZS-JS-018 / ZS-TS-008 (today they match only an explicit `secure: false`) |
| Express sessions and cookies | JS/TS | Literal `secret:` / `cookieSecret` | High, CWE-321 (as ZS-PY-146 does for Django) | nodegoat `config/env/all.js:8`, vulnnodeapp `app.js:25` (labeled CWE-321; today reported as CWE-798) | Primary CWE on ZS-JS-141 and ZS-SEC-016 when the key is a signing secret |
| Swig, Nunjucks, Handlebars, EJS | JS entry file | `autoescape: false`, `noEscape: true` | High, one finding per app | nodegoat `server.js:135-137` | New rule. Labels sit on 7 of 54 template expressions, so a per-expression rule would score about 7 TP to 47 FP; report once at the setting |
| Express `cors` | JS/TS | `origin: true` or a reflecting function together with `credentials: true` | High, CWE-942 | dvws-node `app.js:53-55` (unlabeled) | New rule beside ZS-JS-071 |
| Django | `settings*.py` | `DATABASES` literal `PASSWORD`, including placeholder-like values | High, CWE-798 | djangoat `pygoat/docker_settings.py:5-6` (labeled) | New Python rule; ZS-PY-141's placeholder filter deliberately skips `'password'` |
| Django | `settings*.py` | Missing `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_SSL_REDIRECT`; MD5 in `PASSWORD_HASHERS` | Low / hardening | djangoat, pygoat settings modules | New Python rules |
| Flask | `*.py` | `X.run(debug=True)` for any receiver bound to `Flask(...)` or `connexion.App(...)` | High, CWE-489 | vampi `app.py:17` (`vuln_app.run`, labeled) | Widen ZS-PY-016 (callee is pinned to `app.run`) |
| Flask | `*.py` | App with POST routes and no `CSRFProtect` / Flask-WTF | Medium, CWE-352 | vulpy `bad/` and `good/` `mod_*.py` (8 labels) | Needs the app-level model in section 5 |
| FastAPI, Starlette | `*.py` | `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`; `debug=True` | High | None in these nine; FastAPI held-out repos | New Python rules |
| Next.js | `next.config.*` | `headers()` without CSP/HSTS, `poweredByHeader` not false, `images.remotePatterns` wildcard | Hardening | healthcare `next.config.mjs` (no headers) | Framework scanner |
| Spring Boot | `application*.properties|yml` | `server.error.include-stacktrace=always`, `spring.h2.console.enabled=true`, `management.endpoints.web.exposure.include=*` | Medium to high | Java held-out repos (unmeasured) | Extend `spring.go` |
| Spring Security | Java | `csrf().disable()`, `csrf(c -> c.disable())`, `permitAll()` on `/**` | Medium to high | Java held-out repos | New Java rules (none exist today) |
| Docker | `Dockerfile` | No `USER` (runs as root), `FROM x:latest` or untagged, `ADD http...`, secrets in `ENV`/`ARG` | Hardening, except secrets | No `USER`: dvws-node, pygoat (4 files), vampi, vulnnodeapp; `ubuntu:latest`: vulnnodeapp | New check `dockerfile.go` |
| Docker Compose | compose files | `network_mode: host`, `pid: host`, Docker socket mount, `cap_add: ALL` | High | None here; compose credentials already caught by ZS-SEC-032 | Extend `docker_compose.go` |
| Kubernetes | `*.yaml` with `apiVersion` and `kind` | `privileged`, `runAsUser: 0`, `allowPrivilegeEscalation`, `hostNetwork`, no resource limits | High / hardening | None here | New check |
| Terraform | `*.tf` | Public S3 ACL, `0.0.0.0/0` ingress on admin ports, unencrypted storage | High | None here | Next sprint (needs an HCL parser) |
| helmet | JS entry file | Suppression on any "helmet" text | n/a | nodegoat `server.js:10` comment | Strip comments before the substring test |

Weekend scope is the first nine rows plus the Dockerfile check and the helmet fix. Their combined
expected benchmark effect is +9 TP (2 CFG-020, 2 `ignoreExpiration`, 1 express-session, 2 CWE-321,
1 Django `DATABASES`, 1 Flask debug) and a small number of unlabeled findings (dvws CORS, nodegoat
autoescape). Dockerfile findings are hardening tier and do not enter default output or the score.

## 5. Missed findings

### 5.1 Buckets

Each of the 244 missed labels was assigned to one bucket: by vulnerability class for the 100
authorization and business-logic labels, and by reading the labeled source line in the cloned repo
for the other 144.

| Bucket | Labels | Share | What it needs |
|---|---|---|---|
| 1. Detectable now: new or widened single-file rule, or a small scanner fix | 42 | 17% | Rules, extensions, one registration |
| 2. Needs new engine capability | 138 | 57% | Route, middleware and ownership model; interprocedural taint; template-engine linkage |
| 3. Not realistically deterministic, or a benchmark artifact | 64 | 26% | Portal AI analysis or nothing |
| **Total** | **244** | | |

Bucket 1 detail (42): single-file rules 22, EJS raw output 6, first-party JS and HTML under
`public/` and `static/` 6, registering ZS-CFG-020 3 (2 expected to match), config rules 2, CWE-321
consistency 3 (2 to fix, 1 to decline).

Bucket 2 detail (138): route and authorization model 100 (BOLA 16, missing authentication 15,
sensitive data in HTTP responses 13, broken access control 7, missing authorization 6, missing
rate limiting 5, client-asserted authorization 5, missing access control 5, IDOR 4, mass assignment
4, brute-force exposure 4, uncontrolled resource consumption 4, session invalidation 3, session
fixation 3, field-level data exposure 5, unsafe upload 1); interprocedural taint and new sources 17;
app-level CSRF middleware model 14; template-engine autoescape linkage 7.

Bucket 3 detail (64): business logic, enumeration, weak OTP, missing audit logging, plaintext storage
inferred from a schema, padding oracle and similar 51; benchmark artifacts 13 (CWE-73-only write
sinks already declined in v0.37.0, labels absorbed by a neighboring finding, SQL built only from
literals in a seed script, a CTF flag labeled as sensitive data, credentials in tutorial text, and
seed-user lists that conflict with the ZS-PY-141 seed decision).

### 5.2 Bucket 1: rules to write

| Rule (proposed) | Labels | Example (repo, file:line) |
|---|---|---|
| Raw EJS output `<%- expr %>` (map `.ejs` to the HTML builder, add a `template.raw_expr` callee, exclude `<%- include(...) %>`) | 6 | vulnnodeapp `views/reflected-xss.ejs:65`, `views/navigation.ejs:17` |
| Scan first-party JS/HTML under `public/` and `static/`, with vendored-file detection (minified, license banner, known library names) | 6 | dvws-node `public/static/receiver.js:11` (`innerHTML = e.data`), `public/home.html:36`, `public/static/userdisplay.js:7` (`postMessage(..., '*')`); pygoat `introduction/static/js/a9.js:40`; djangoat `static/app/javascript/users/pay/index.js:44` |
| Register ZS-CFG-020 | 2 of 3 | juice-shop `about.component.html:51`, `search-result.component.html:13` (`product-details.component.html:16` has no bypass in its component and stays missed) |
| `jwt.verify` options with `ignoreExpiration: true` | 2 | dvws-node `app.js:49`, `utils.js:13` |
| Prisma `$queryRawUnsafe` / `$executeRawUnsafe` with a non-literal | 1 | healthcare `src/app/(app)/admin/actions.ts:262` |
| `new Function(...)` with a non-constant body | 1 | healthcare `src/lib/referral-correspondence.ts:38` |
| `vm.runIn*Context` whose sandbox object carries request data | 1 | juice-shop `routes/b2bOrder.ts:23` |
| Mongo `$where` with an interpolated template string | 1 | nodegoat `app/data/allocations-dao.js:78` (label at :86) |
| XXE: `noent: true` passed to `libxml.parseXml` | 1 | juice-shop `routes/fileUpload.ts:83` |
| Chained `?.document.write(x)` DOM sink | 1 | juice-shop `data-export.component.ts:71` |
| Recursive merge without a `__proto__`/`constructor` guard | 1 | dvws-node `controllers/storage.js:18` |
| `new RegExp` with request data (CWE-943 query injection) | 1 | vulnnodeapp `utils/utility.js:94` |
| `res.locals.message = err.message` rendered by an error view | 1 | vulnnodeapp `app.js:52` |
| Python error text in a response (`Response(...exc.message...)`, `jsonify(error=str(e))`) | 1 | vampi `api_views/users.py:80` |
| Server template `{{ var }}` inside `<script>` without `escapejs` / `json_script` | 2 | pygoat `Lab/XSS/xss_lab_3.html:22`; djangoat `users/performance/index.html:57` |
| Django POST form with no valid `{% csrf_token %}` (catches the `{ % crsf_token % }` typo) | 1 | djangoat `template/admin/modal.html:7` |
| PyCryptodome `MD5.new()` / `SHA.new()` (only `hashlib` is matched today) | 1 | djangoat `password_resets/views.py:44` |
| PyCryptodome `AES.new(..., MODE_CBC, ...)` without a MAC in scope | 1 | djangoat `app/models/utils.py:10` |
| Nested-quantifier regex applied to request data (ReDoS) | 1 | vampi `api_views/users.py:144` |
| Flask debug via any app receiver (widen ZS-PY-016) | 1 | vampi `app.py:17` |
| Logging an object that holds credentials (`console.error(..., { config })` where `config` has token fields) | 2 | healthcare `src/lib/reminder-relay.ts:38`, `:43` |
| `new Hashids('<literal salt>', ...)` as a security token | 1 | juice-shop `routes/continueCode.ts:13` |
| express-session without `cookie.secure` (section 4) | 1 | nodegoat `server.js:78` |
| Django `DATABASES` literal password (section 4) | 1 | djangoat `pygoat/docker_settings.py:5` |
| CWE-321 primary on signing secrets (section 4) | 2 | nodegoat `config/env/all.js:8`; vulnnodeapp `app.js:25` |

Declined from bucket 1: djangoat `pygoat/settings.py:25` (`DEBUG = True`) is labeled CWE-209/200,
while ZS-PY-017 correctly emits CWE-489. Changing the CWE to match the label would be the kind of
change v0.37.0 rejected.

Precision guard: each new rule is run on all nine repos before merge, and its unlabeled hits are
counted. Measured exposure for two of them: EJS `<%-` occurs 14 times in vulnnodeapp, 6 labeled, so
the rule enters at 43 percent on that repo unless the other 8 prove real; per-expression autoescape
would be 7 of 54. The `public/`/`static/` change re-admits 25 non-minified JS files across dvws-node,
pygoat, djangoat and juice-shop's frontend tree and must ship with vendored-file detection.

### 5.3 Bucket 2: engine capabilities (next sprint, not this weekend)

1. **Route and handler model.** Extract routes per framework (Express `app.METHOD`/`router.METHOD`,
   Flask `@route(methods=...)`, Django `urls.py` to view, FastAPI decorators, Next.js `app/api/**/route.ts`
   exports and server actions, Spring `@*Mapping`), with the middleware or decorator chain in front
   of each. This alone enables CSRF (14 labels: state-changing route with no CSRF middleware in its
   chain or app), missing authentication (15: a state-changing or data-returning route with no auth
   middleware while sibling routes have one) and rate limiting on login routes (9).
2. **Ownership-check heuristic for BOLA/IDOR (20 labels).** Flag a handler that loads a record by an
   id taken from the request and returns or mutates it without comparing an owner field to the
   session principal. Expect a high FP rate; ship in a non-default tier first.
3. **Response field sensitivity (18).** Flag serialization of a whole user or account model
   (`res.json(user)`, `NextResponse.json({ patients })`) whose schema has password, token or SSN
   fields. Needs model-schema extraction for Sequelize, Prisma, Mongoose, Django ORM.
4. **Interprocedural taint and new sources (17).** Taint through same-repo wrappers
   (`executeQuery(query)` in vulnnodeapp `models/usersModel.js:8,16,43`, `security.hash` in juice-shop
   `models/user.ts:77`, console wrappers); the sources listed as next-release in v0.37.0 (Next.js
   `request.json()`, `formData()`, `headers()`, `cookies()`; Express `req.cookies`, `req.headers`,
   `req.get()`); Python `request.json`, `request.get_json()`, `request.cookies`, `request.data`;
   Java Spring `@RequestParam`, `@PathVariable`, `@RequestBody` (today only servlet
   `request.getParameter`/`getHeader` are real Java sources). The graph layer
   (`docs/roadmap/SPRINT-22-GRAPH-LAYER-CFG-DFG.md`) is Python-only and gated behind
   `--enable-graphs`.

Buckets 1 and 2 are where the previous report's 84 "out of reach" labels now sit; this plan moves
the route model from "do not chase" to "next sprint, non-default tier first", because the held-out
Java and FastAPI repos are dominated by these classes.

### 5.4 Bucket 3: what to do instead

These 64 labels (state-machine bypass, enumeration by message difference, weak OTP length, missing
audit logging, padding oracles, business validation) cannot be found deterministically without an
unacceptable FP rate. They belong to the portal's AI analysis, which already reasons per finding
group; the scanner's contribution is to emit route and handler inventory (bucket 2, item 1) so the
AI step has the attack surface. Do not write pattern rules for them.

## 6. Language and framework coverage

### 6.1 How a language is added

`internal/langreg/langreg.go` holds a registry of `{Language, NewBuilder, RuleDir}`; each parser
package registers in `init()` behind `//go:build cgo` (for example
`internal/parser/python/register.go`). Adding a language means: a constant in
`internal/core/language.go`, extensions in `internal/detector/extension.go`, a tree-sitter grammar,
an IR builder (existing builders are 267 to 569 lines, `internal/parser/*/builder.go`), taint
sources and sanitizers in `internal/analyzer/taint/patterns.go`, a rule directory, and corpus
fixtures. Today's parsers: C#, Go, HTML, Java, JavaScript, PHP, Python, TypeScript. Rule counts
(released): TypeScript 127, JavaScript 126, Python 93, Java 49, Go 46, PHP 32, C# 31, HTML 15.

### 6.2 Missing languages and template formats

Effort figures are estimates for one engineer, covering builder, sources and a first 15 to 20 rules
with fixtures. The grammar column is from the upstream smacker/go-tree-sitter repository listing; I
could not list the pinned module locally, so confirm before scheduling.

| Target | In RealVuln | Grammar | Estimate | When |
|---|---|---|---|---|
| EJS (`<%- %>`) | Yes (vulnnodeapp) | Reuse HTML builder | 0.5 day | Weekend |
| Handlebars `{{{ }}}`, Swig/Nunjucks raw filters | Yes (nodegoat) | Reuse HTML builder | 0.5 day | Weekend |
| Dockerfile | Files present in 7 of 9 repos | Not needed (line parser in framework scanner) | 0.5 day | Weekend |
| Kubernetes YAML | No | Not needed (YAML) | 1 to 2 days | Next week |
| Vue and Svelte single-file components | Yes, fastify-vue (10 repos) | Split `<script>` to JS/TS builder and `<template>` to HTML builder with line offsets | 1 to 2 days | Next week |
| JSP, Thymeleaf, FreeMarker, JTE, Qute, Micronaut views, JSF | Yes, RealVuln v4 Java apps by name (springmvc-jsp, legal-case-freemarker, webflux-thymeleaf, support-desk-thymeleaf-htmx, onboarding-kyc-jte, fintech-lending-quarkus-qute, education-lms-micronaut-views, healthcare-clinic-jakartaee-jsf) | Extend HTML template layer: `th:utext`, JSP `<%= %>` and `${}` outside `c:out`, FreeMarker `?no_esc`, JTE `$unsafe{}`, Qute `.raw` | 1 day per engine | Next week |
| MyBatis mapper XML `${}` | Common in RealVuln Java apps (jeecgboot, ruoyi-vue, mall) | XML line scan | 1 day | Next week |
| Kotlin | Yes (property-management-kotlin-thymeleaf, 3 variants) | Available upstream | 4 to 6 days | Two weeks |
| Terraform | No | HCL available upstream | 2 to 3 days | Two weeks |
| Ruby (Rails) | No | Available upstream | 5 to 8 days | Later |
| Scala, Swift, Rust | No | Available upstream | 5+ days each | Later |
| C/C++ | No | Available upstream | Poor fit: memory-safety classes need a different engine | Not planned |
| Dart | No | Not in upstream list | Unknown | Not planned |

### 6.3 Framework coverage inside supported languages

Counting rules whose `tags:` line names the framework (a rough measure; some rules omit tags):
Express 22, JWT 16, Django 15, Flask 9, Next.js 4, Prisma 4, Spring 4, Jinja 2, React 2,
Sequelize 2, Angular 1, SQLAlchemy 1, and zero for FastAPI, NestJS, Vue, Mongoose, Laravel, ASP.NET,
Gin, JSP and Thymeleaf. Java has no CSRF, Spring Security, JPA/JPQL concatenation or template-engine
rules. RealVuln's corpus, by contrast, has 203 ground-truth directories on 4 November: Java 63
repos (2,980 scored vulnerable labels), Python 66 (1,902), TypeScript 53 (1,873), JavaScript 21
(363). The brief cites 144 repos and 3,267 Java labels; the difference is likely the corpus version
and whether traps and non-scoring entries are counted. Either way, Java is the largest label pool and
has never been measured.

## 7. Evaluation protocol

### 7.1 Sets

- **Dev set (open):** the nine repos in the scratchpad `bench/repos`, pinned SHAs in `repos.txt`.
  Anyone may read any finding.
- **Held-out set (sealed), 13 repos, 422 labels**, chosen by stack and checked against the scanner
  repo's docs so none was used before (WebGoat, DVNA and Vulnerable-Flask-App were excluded because
  earlier QA reports used them):

| Stack | Repo id (ground-truth directory) | Labels |
|---|---|---|
| Java, servlet/JSP | realvuln-javavulnerablelab | 43 |
| Java, Spring Boot | realvuln-eladmin | 35 |
| Java, Spring Boot (seeded) | vc-sonnet-5-claude-code-seeded-v4-corp-payments-springboot | 57 |
| Flask | realvuln-extremely-vulnerable-flask-app | 32 |
| Flask | realvuln-threatbyte | 26 |
| FastAPI | realvuln-vfapi | 9 |
| FastAPI | realvuln-python-insecure-app | 8 |
| FastAPI (seeded) | vc-claude-code-seeded-v2-support-desk-fastapi | 34 |
| Express | realvuln-nodejs-goof | 17 |
| Express | realvuln-vuln-node-express-swagger | 49 |
| Next.js | realvuln-oss-oopssec-store | 40 |
| Next.js (seeded) | vc-codex-high-seeded-v3-education-lms-nextjs | 48 |
| Django | realvuln-lets-be-bad-guys | 24 |

Sealing rules: the held-out scoring script prints only per-repo and total TP, FP, FN, precision and
recall. Nobody opens held-out findings, FP lists or source until Sunday's final run is recorded. The
baseline is taken Thursday morning on the unchanged binary. If a held-out result prompts a fix, that
repo moves to the dev set and is replaced from the same stack.

### 7.2 Commands

Build (CGo is mandatory; a CGo-disabled build registers no parsers, see `improve.md`):

```
cd zero-strike-code-scanner
CGO_ENABLED=1 go build -o zerostrike.exe ./cmd/zerostrike
```

Clone a held-out repo at its pinned commit (URL and `commit_sha` come from its
`ground-truth/<id>/ground-truth.json`):

```
git clone <repo_url> "$SP/bench/heldout/<id>"
git -C "$SP/bench/heldout/<id>" checkout <commit_sha>
```

Scan with the scoring profile used since v0.37.0 (no SCA, which is network-dependent and outside the
deterministic gate per `gap.md`):

```
./zerostrike.exe scan "$SP/bench/repos/<slug>" --format json --enable-secrets \
  --enable-framework-checks -o "$SP/bench/out/<slug>.json"
```

Score (file match, CWE in `acceptable_cwes`, line within 10, one finding per label):

```
python -I "$SP/bench/score.py" "$SP/rv/Real-Vuln-Benchmark/ground-truth" "$SP/bench/out" \
  pygoat=realvuln-pygoat vulpy=realvuln-vulpy juice-shop=realvuln-juice-shop \
  dvws-node=realvuln-dvws-node healthcare-clinic-nextjs=vc-claude-code-seeded-v3-healthcare-clinic-nextjs \
  djangoat=realvuln-djangoat nodegoat=realvuln-nodegoat vampi=realvuln-vampi vulnnodeapp=realvuln-vulnnodeapp
```

Once on Thursday, confirm that `score.py` and the benchmark's own `scorer/matcher.py` (as wrapped by
`zs-runs/bench.py` in the v0.37.0 report) agree on the baseline. The 4 November figures come from
the re-implementation only.

Internal corpus and tests:

```
go run ./cmd/zerostrike-bench -corpus benchmark/corpus -max-fp 0 -md-out "$SP/bench/internal.md"
CGO_ENABLED=1 go test ./...
CGO_ENABLED=1 go test ./cmd/zerostrike -run 'TestReportLayoutContract'
```

Before the scripts are relied on by more than one engineer, copy `score.py`, `sim.py` and the
analysis script into `scripts/realvuln/` in the scanner repo so results are reproducible from a
commit, not from a temp directory.

### 7.3 Acceptance gates for Sunday

| Gate | Threshold | Source |
|---|---|---|
| Dev strict precision | At least 54.0% | Section 3 simulation reaches 54.7% |
| Dev recall | At least 47.0% (TP at least 216); no label that matched on 4 November may be lost | Baseline |
| Dev adjudicated precision | At least 75.0%, with `docs/benchmarks/adjudication-2026-11-08.md` listing every finding counted as real, the reviewer, and a second reviewer's sign-off | Section 1 |
| Held-out strict precision and recall | Not below Thursday's held-out baseline; both reported per stack | Section 7.1 |
| Internal corpus | TP at least 597, FP 0, FN 0; every new rule adds a positive and a negative fixture | `cmd/zerostrike-bench` |
| Report layout | `TestReportLayoutContract` and `TestReportLayoutContractWithDependencies` pass | `cmd/zerostrike/exemptions_test.go:61`, `:105` |
| Unit tests | `CGO_ENABLED=1 go test ./...` green | |
| Fingerprint stability | For rules not deliberately changed, fingerprints on the nine repos are identical before and after | New diff script |

The layout contract is a JSON-report contract (customers' CI gates grep `"Severity"` at a fixed
indentation, per the portal's CLAUDE.md), not an HTML one. The fingerprint gate matters because
merging ZS-PY-098/099 and moving JS-048 to the declaration change fingerprints for those findings,
which detaches any portal-accepted exemptions for them. Release notes must say so.

## 8. Schedule, Thursday 5 to Sunday 8 November

Five workstreams can run in parallel after workstream A's first half-day. Each owner works in its
own branch or worktree; merges go through the gates in 7.3. "Owner" is a role, assignable to an
engineer or an agent.

### Workstream A: measurement (owner: benchmark engineer)

- Thursday morning: copy scoring scripts into `scripts/realvuln/`; reconcile with the official
  matcher; clone and seal the 13 held-out repos; record the held-out baseline (aggregates only);
  write the fingerprint diff script.
- Friday to Sunday: re-run dev and sealed held-out scoring on every merge to the integration
  branch; publish the numbers table.
- Files: `scripts/realvuln/*`, `docs/benchmarks/realvuln-v0.43.0.md` (new, Sunday).
- Done: baseline numbers recorded Thursday by 13:00; final report Sunday with dev strict,
  adjudicated and held-out figures side by side.

### Workstream B: precision fixes (owner: rules engineer)

- Thursday: merge ZS-PY-098/099 into one finding per call; ZS-PY-024 to `tier: quality`; ZS-HTML-004
  constant-src gate to hardening; ZS-PY-141 hash and message filters; ZS-PY-028 relative-path gate.
- Friday: identical-call aggregation (for ZS-PY-078) in `internal/findings`, opt-in per rule via a
  new YAML key, never global; ZS-JS-048 reported at the options declaration.
- Saturday: sink-class sanitizers for path rules (`path.basename`, random-name generators) in
  `internal/analyzer/taint` and `internal/engine`; `require_real_source` on ZS-TS-138; the
  `req.params` gate on ZS-TS-128.
- Files: `internal/rules/data/python/ZS-PY-{024,028,078,098,099,141}.yaml`,
  `internal/rules/data/html/ZS-HTML-004.yaml`, `internal/rules/data/{js,ts}/ZS-*-048.yaml`,
  `internal/rules/data/ts/ZS-TS-{089,132,062,128,138}.yaml`, `internal/findings/*`,
  `internal/analyzer/taint/patterns.go`, `internal/engine/*`, matching `testdata/` fixtures.
- Done: dev 216 TP / at most 179 FP; corpus 597+/0/0; each change has a fixture showing the
  suppressed case and a fixture proving the real case still fires.

### Workstream C: framework checks (owner: framework engineer)

- Thursday: register ZS-CFG-020 in `scanner.go`; fix the helmet comment suppression; Dockerfile
  check (hardening tier).
- Friday: `ignoreExpiration`, express-session missing `cookie.secure`, CWE-321 on signing secrets,
  Flask debug for any app receiver, Django `DATABASES` password.
- Saturday: autoescape-off setting (one per app), `cors({origin: true, credentials: true})`,
  Spring properties additions, `Stats.ByFramework`, `doc.go` design note.
- Files: `internal/scanner/framework/{scanner,express,frontend_html,dockerfile,spring,doc}.go`,
  `internal/rules/data/{js,ts,python}/` new YAML, `internal/report` for the stats field.
- Done: framework findings appear in default output on juice-shop (CFG-020); +9 dev TP expected per
  section 4.3; no new dev FP from hardening-tier checks; corpus green.

### Workstream D: recall rules (owner: second rules engineer)

- Thursday: EJS extension and `template.raw_expr`; Handlebars triple-stash.
- Friday: `public/` and `static/` first-party scanning with vendored-file detection in
  `internal/walker`; DOM sinks (`?.document.write`, `postMessage(..., '*')`).
- Saturday: the remaining bucket-1 rules in section 5.2, in table order.
- Files: `internal/detector/extension.go`, `internal/parser/html/template.go`,
  `internal/walker/filter.go`, `internal/walker/fswalker.go`, new YAML under
  `internal/rules/data/{js,ts,python,html}/`.
- Done: at least 25 of the 42 bucket-1 labels matched on the dev set; for each new rule, its
  unlabeled hits on the nine repos are listed in the PR and either adjudicated real or gated.

### Workstream E: FP review and adjudication (owner: two security reviewers, analyst and skeptic)

- Thursday to Friday: review the 25 unreviewed top-30 FPs and the 57-FP tail; classify each as real,
  wrong (file a fix for workstream B) or uncertain.
- Saturday: adjudicate the 83 unlabeled-real findings. The analyst argues real; the skeptic tries to
  refute, as in v0.37.0. Only findings both accept count.
- Sunday: adjudication file committed; adjudicated precision computed by workstream A.
- Files: `docs/benchmarks/adjudication-2026-11-08.md`.
- Done: every dev FP has a recorded verdict.

### Sunday integration

Morning: merge freeze at 10:00; full gate run. Afternoon: held-out unsealed and scored once; results
written up whatever they show. If dev strict precision is under 54 percent or any TP was lost,
revert the responsible change rather than tune further.

### Next sprint (from 9 November)

Route and middleware model with CSRF and missing-auth rules in a non-default tier; Spring sources
and Java template engines; Vue/Svelte SFC; interprocedural wrapper taint; Kotlin. Measure each on the
held-out set, which is sealed again with fresh repos once Sunday's numbers are published.

## 9. Risks and what not to do

- **Do not delete rules to move the metric.** The 37 zero-TP rules include JWT `none` acceptance
  (critical), reflected CORS origin and HTTP subresources. A rule is retired only if its hits are
  shown wrong on code outside RealVuln.
- **Do not change CWEs to match labels.** Keep the v0.37.0 decisions: no CWE-73 on write sinks, no
  CWE-209 on `DEBUG = True`. The CWE-321 change in section 4 is justified by consistency with
  ZS-PY-146, not by the labels.
- **Do not train on the held-out set.** Aggregates only until Sunday; a repo whose findings are read
  becomes a dev repo.
- **Do not dedupe globally.** Per-file dedupe across all rules loses 48 TPs. Aggregation must be
  opt-in per rule and limited to identical calls or a shared declaration.
- **Do not make sanitizers global.** `path.basename` clears path taint, not HTML or SQL taint; the
  existing sanitizer list in `patterns.go` is not sink-aware.
- **Do not report adjudicated precision as RealVuln precision.** Publish both, with the adjudication
  log.
- **Tier is not a hiding place.** Only rules with no exploit path on their own move to hardening or
  quality. Session-cookie flags, CSRF exemptions and error disclosure stay in default output.
- **New recall adds unlabeled hits.** EJS raw output and `public/` scanning are the two biggest
  risks; both ship with the gates in workstream D and are reverted if dev strict precision falls
  under 54 percent.
- **Fingerprint churn.** Merged and relocated findings detach existing portal exemptions; release
  notes must list the affected rule ids.
- **Portal coupling.** All portal changes in section 2 read report fields and rule YAML as data; none
  imports scanner code.
- **Evidence gap.** No Java repo has been measured. Java has the largest label pool in RealVuln and
  the thinnest rule set (49 rules, no Spring Security or template rules, servlet-only sources).
  Expect the held-out Java numbers to be weak and treat them as the baseline for the next sprint,
  not as a failure of this one.
