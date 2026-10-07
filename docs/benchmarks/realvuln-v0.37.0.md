# ZeroStrike on the RealVuln benchmark: v0.36.1 vs v0.37.0

*Measured 7 October 2026. Benchmark: [kolega-ai/Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark)
at its current `main`. Each target repo was checked out at the commit pinned in
its ground truth.*

## Method

RealVuln labels vulnerabilities by hand in 140 intentionally vulnerable
applications, 66 in Python and 74 in TypeScript/JavaScript. It covers only these
two languages, so we selected repos by framework rather than by language. A
finding counts as a true positive only when it matches a label on all three of
these:

- the same repo-relative file;
- a CWE in the label's `acceptable_cwes`;
- a line within ±10 of the labelled range.

Each label can absorb only one finding. Labels with `is_vulnerable: false` are
false-positive traps. The headline metric is F3, which weights recall nine
times as heavily as precision. We converted ZeroStrike's JSON output into the
benchmark's Semgrep format and scored it with the benchmark's own matcher
(`scorer/matcher.py`), so every number is comparable with the published
results of other scanners.

Scans were run with `--enable-secrets --enable-framework-checks`, using the
default exclusions.

We used two sets of repos:

- **Development set:** 5 repos. We triaged every FP and FN in these to decide
  what to change.
- **Held-out set:** 4 repos. Nobody looked at their findings or code until both
  versions had been built. It checks that the changes generalize and are not
  tuned to the development set.

The benchmark also ranks about 45 agentic LLM scanners. Those tools reason over
the whole application, which makes them a different class of tool, so we
compare against them only for context. The like-for-like comparison is with
the traditional SAST tools in the benchmark: Semgrep, Snyk, SonarQube and
Rowan.

## Results

### Development set

| Repo (stack) | Labels | v0.36.1 TP / FP / FN | F3 | **v0.37.0 TP / FP / FN** | **F3** | Best traditional SAST |
|---|---|---|---|---|---|---|
| pygoat (Python/Django) | 78 + 10 traps | 23 / 233 / 55 | 24.0 | **52 / 86 / 26** | **61.9** | Snyk 38.8 |
| vulpy (Python/Flask) | 57 + 6 traps | 15 / 28 / 42 | 27.0 | **32 / 31 / 25** | **55.6** | Semgrep 28.7 |
| juice-shop (TS/Express) | 81 | 1 / 165 / 80 | 1.1 | **35 / 40 / 46** | **43.5** | Semgrep 11.2 |
| dvws-node (JS/Express) | 77 | 3 / 12 / 74 | 4.2 | **45 / 23 / 32** | **59.1** | Semgrep 12.1 |
| healthcare-clinic (TS/Next.js, AI-written) | 43 | 8 / 20 / 35 | 19.3 | **15 / 27 / 28** | **35.0** | Semgrep 12.3 |
| **Total** | 336 | **50 / 458 / 286** | | **179 / 207 / 157** | | |

- **Recall:** 15% → 53%.
- **Precision:** 10% → 46%.
- **Ranking among all scanners, LLMs included:**

  | Repo | v0.36.1 | v0.37.0 |
  |---|---|---|
  | pygoat | 41st of 51 | 8th |
  | vulpy | 29th of 51 | 8th |
  | juice-shop | 11th of 11 | 4th |
  | dvws-node | 8th of 11 | 4th |

### Held-out set

| Repo (stack) | v0.36.1 TP / FP / FN | F3 | **v0.37.0 TP / FP / FN** | **F3** | Best traditional SAST |
|---|---|---|---|---|---|
| djangoat (Python/Django) | 13 / 57 / 39 | 24.2 | **17 / 26 / 35** | **33.3** | Rowan 23.5 |
| nodegoat (JS/Express) | 2 / 49 / 26 | 6.6 | **8 / 18 / 20** | **28.8** | Semgrep 20.0 |
| vampi (Python/Flask API) | 1 / 8 / 14 | 6.9 | **1 / 2 / 14** | **7.2** | Rowan 7.1 |
| vulnnodeapp (JS/Express) | 5 / 19 / 24 | 17.5 | **11 / 5 / 18** | **39.7** | Semgrep 12.8 |
| **Total** | **21 / 133 / 113** | | **37 / 51 / 87** | | |

The held-out set improves in the same direction as the development set. TP
rose 76% and FP fell 62%, and v0.37.0 now beats every traditional tool on all
four repos. The gain is smaller than on the development set, as we expected:
some development-set fixes target patterns those repos happen to contain. vampi
barely moves because its labels are almost all API authorization flaws (BOLA,
mass assignment through the ORM, missing auth). See "Out of reach" below.

Internal corpus: v0.36.1 scored TP=459 FP=0 FN=0, and v0.37.0 scores **TP=554
FP=0 FN=0**.

## Why v0.36.1 scored poorly

### False positives: 458, mostly from five rule clusters

| Cluster | FPs | Verdict |
|---|---|---|
| ZS-HTML-003 inline event handler | 121 (pygoat) | Every hit was a constant handler (`onclick="toggleTheme()"`). An inline handler matters for CSP hardening, but it is not XSS. |
| ZS-TS-081 log forging | 103 (juice-shop) | `console.log` in the Angular frontend. A browser console is not a log store. |
| Hardening and quality rules | ~130 across all repos | The rules for missing SRI, missing password autocomplete, `target=_blank`, unpinned first-party `actions/*`, bare `except:` and missing helmet. None of these is exploitable on its own. |
| ZS-TS-036 / ZS-TS-016 | 18 | Callee text collapse: `this.http.get` matched `http.get`, and `new RegExp().exec` matched `exec`. |
| ZS-TS-021 Math.random | 14 | Fired on non-security uses. |

### False negatives: 286, root-caused one by one

| Root cause | Count | Example |
|---|---|---|
| No rule for the class | 111 | CWE-209 error details in responses (33 on the two Express repos), cookie flags, CSRF exemption |
| Business logic / authorization | 76 | IDOR, missing auth on a route, state-machine bypass |
| Rule too narrow | 34 | sequelize pinned to `db.sequelize.query`, mongo `$where` |
| Needs deeper data flow | 26 | taint through object fields, cross-file wrappers |
| CWE mapping | 10 | `eval` reported as CWE-95 where industry practice and the labels use CWE-94 |
| Questionable label | 10 | SQL built only from literals, or a CTF flag labelled as a credential |
| File not scanned | 7 | first-party JS under `static/` or `public/` |
| Secret findings without a CWE | 7 | ZS-SEC findings had no CWE at all, so every CWE-keyed consumer (SARIF, this benchmark) dropped them |

## What v0.37.0 changed

See [SPRINT-40-RELEASE-NOTES.md](../release-notes/release-notes/SPRINT-40-RELEASE-NOTES.md).
In summary, the release does five things:

1. **Output tiers:** hardening and quality rules are excluded by default. They
   are always counted, and `--include-hardening` restores them.
2. **Context conditions on noisy rules:** for example, a handler is reported
   only if it interpolates template data, and log forging requires a real
   source and skips browser code.
3. **Engine fixes:** JS/TS callee text no longer collapses, catch bindings are
   tracked, Python import aliases are canonicalized, and HTML templates produce
   expression nodes.
4. **78 new rules:** CWE-209, credentials and keys, template XSS, CSRF, cookie
   flags, and sinks that were missing.
5. **Secret findings now carry CWE-798 or CWE-321.**

Every fix had to be correct on real-world code. The analysis explicitly rejected
proposals that would only raise this benchmark's score, for example:

- adding CWE-73 to the path-traversal rule;
- making CWE-73 the primary CWE on write sinks;
- path-specific exclusions.

## Real vulnerabilities RealVuln does not label

The ground truth is not exhaustive. A finding scored as FP is not necessarily
wrong.

**Individually verified.** One analyst claimed each of these and a separate
skeptic tried and failed to refute it.

| Repo | Location | Issue |
|---|---|---|
| juice-shop | `routes/fileServer.ts:33` | The allowlist check runs on the raw filename, before `cutOffPoisonNullByte`, so `x.md%00.bak` bypasses it (CWE-158) |
| juice-shop | `frontend/src/app/Services/user.service.ts:54` | `changePassword()` sends the current, new and repeated passwords in a GET query string (CWE-598) |
| dvws-node | `rpc_server.js:13` | The unauthenticated XML-RPC method name, controlled by the attacker, is written to the log unsanitized (CWE-117) |
| healthcare-clinic | `src/app/(auth)/actions.ts:130` | The password reset token is logged in plaintext (CWE-532) |

**Classes behind most of v0.37.0's remaining FPs.** We reviewed samples of
each by hand:

- **Session and token cookies without HttpOnly or Secure** (ZS-PY-098/099,
  35 hits). For example, `response.set_cookie('session', session_token)` in
  pygoat's broken-auth lab. These are real; the labellers listed only some
  instances.
- **`@csrf_exempt` views** (ZS-PY-090, 16 hits). Each hit is an exemption
  that really is present.
- **Error details in responses** (ZS-JS/TS-120, 14 hits). For example,
  `NextResponse.json({ error: e.message })` and
  `res.status(500).json(getErrorMessage(error))`. The dvws hits are further
  instances in files that already contain a labelled one.
- **`set_trace_callback(print)`** (ZS-PY-078, 15 hits). These are further call
  sites of a labelled flow. Each label absorbs only one finding.
- **JWT accepting `none`** (ZS-JS-048, 11 hits). dvws really does configure
  `algorithms: ["HS256", "none"]` in five places.

**Remaining confirmed noise:**

- Some hardcoded-credential hits on seed and fixture scripts (ZS-PY-141).
- Path-join findings in Next.js (ZS-TS-089).
- Angular `bypassSecurityTrust*` hits whose arguments are already sanitized
  (ZS-TS-150).

These are next-release candidates.

## Out of reach for pattern SAST

About 84 of the misses, 76 of them in the development set, are authorization,
IDOR, missing-auth, rate-limit, session-lifecycle and business-logic flaws.
Pattern SAST cannot find these without a high false-positive rate. Semgrep,
Snyk and SonarQube score near zero on them too. We do not chase them in the
default profile.

## Benchmark matching quirks to know when reading these numbers

- **One finding per label.** Extra real instances of the same flow score as
  FP.
- **Multi-CWE findings are split into one finding per CWE.** A rule therefore
  emits a single primary CWE.
- **Some labels accept a narrow CWE set** that differs from common industry
  tagging, for example CWE-73-only write sinks or CWE-1336-only template
  injection. We did not change our CWEs to match.
- **The ±10-line window** occasionally credits a coincidental nearby finding,
  or misses a finding we report at the definition when the label is at the call
  site.

## Next release

1. **JS/TS taint sources:** Next.js `request.json()`/`formData()`/`cookies()`,
   destructured Express handler parameters, `req.cookies` and `req.headers`.
2. **Taint precision bundle:** `path.basename` and allowlist sanitizers, and no
   taint through ORM finder results.
3. **First-party JS under `static/` and `public/`**, with vendored-file
   detection.
4. **Trimming the remaining confirmed-noise rules listed above.**

## Reproducing

Scored with `zs-runs/bench.py` (outside the repo), which converts ZeroStrike
JSON into RealVuln's Semgrep format and calls `scorer.matcher.match_findings`
and `scorer.metrics.compute_scorecard`. Run Python with `PYTHONUTF8=1` on
Windows, because the benchmark parser opens files in the locale codec.
