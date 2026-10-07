# Sprint 40 — RealVuln-driven precision and recall

**v0.37.0**

We scored ZeroStrike against the public RealVuln benchmark (kolega-ai, labelled
intentionally-vulnerable apps, scored by file + CWE + line ±10, headline metric
F3). We used five repos to find defects and four other repos, which we did not
look at while making changes, to check that the gains are not overfitting.
v0.36.1 lost to Semgrep on every JS/TS repo. v0.37.0 now beats every
traditional SAST tool in the benchmark (Semgrep, Snyk, SonarQube, Rowan) on all
nine repos. Full analysis: [docs/benchmarks/realvuln-v0.37.0.md](../../benchmarks/realvuln-v0.37.0.md).

## Before / after

| Development set (5 repos) | v0.36.1 | **v0.37.0** |
|---|---|---|
| TP | 50 | **179** |
| FP | 458 | **207** |
| FN | 286 | **157** |

| Held-out set (4 repos, never inspected) | v0.36.1 | **v0.37.0** |
|---|---|---|
| TP | 21 | **37** |
| FP | 133 | **51** |

Corpus **TP=554 FP=0 FN=0**, up from 459. 78 new rules, bringing the total to
494 (from 416), and every new rule has a vulnerable and a clean corpus case.

## What changed

**Output tiers.** Rules can now declare `tier: hardening` or `tier: quality`.
These findings are left out of the default output and their count is always
reported in `Stats.TierExcluded`. `--include-hardening` restores them. This
applies to:

- missing SRI and missing password autocomplete;
- `target=_blank`;
- unpinned first-party `actions/*`;
- missing helmet;
- bare `except:` and `except: pass`.

None of these has an exploit path of its own. Together they were about 130 of
the 458 FPs.

**Context-aware rules.**

- **Inline event handlers:** ZS-HTML-003 fires only when the handler
  interpolates template data. Before, it fired on every static
  `onclick="toggleTheme()"` (121 FPs on pygoat).
- **Log forging:** ZS-TS-081 and ZS-JS-083 require a real source and skip
  browser contexts (103 FPs on juice-shop's Angular frontend).
- **Math.random:** fires only when the value is used for security.
- **spawn:** reports CWE-78 only for a tainted program or `shell: true`.
- **Path rules:** constant paths (`os.path.join(dirname(__file__), 'x')`) are
  folded and no longer reported.

**Engine.**

- **JS/TS callee text no longer collapses:** `this.http.get` used to match as
  `http.get`, and `res.status(500).send` was matched only as `send`.
- **Catch bindings and err-first callback parameters are tracked**, so the
  engine knows when an error object is sent in a response.
- **Python:** import aliases are canonicalized, decorators are lowered, and
  HTML templates now produce expression nodes.

**New detection.**

- **Error details in HTTP responses (CWE-209):** catch bindings, `err.message`
  or `err.stack` sent through `res.send`/`json`, `res.status().x` or
  `NextResponse.json`.
- **Secret findings carry a CWE:** CWE-798 for credentials and CWE-321 for key
  material. Before, CWE-keyed consumers such as SARIF and RealVuln dropped
  every secret finding.
- **Hardcoded credentials and keys in code:** credential pairs in dicts and
  objects, `process.env.X || 'literal'` fallbacks, literal keys passed to
  jwt, HMAC, Fernet and Hashids, and password comparisons.
- **Template XSS:** Django/Jinja `|safe` and `{% autoescape off %}`, and
  Angular `bypassSecurityTrust*`.
- **CSRF:** `@csrf_exempt` (CWE-352).
- **Cookie flags:** HttpOnly (CWE-1004) and Secure (CWE-614), in JS, TS and
  Python, as separate rules.
- **New sinks:** sequelize, libxmljs, mongo `$where`, xpath, SSRF clients,
  `res.download`, `fs.promises`, Prisma raw queries, mass assignment and
  Next.js redirects.
- **Python:** `set_trace_callback(print)` (CWE-532), weak PRNG for tokens,
  a fast hash used on passwords, tainted writes into `.py` and template files,
  `glob`, xml.sax external entities and PIL `ImageMath.eval`.

**CWE corrections.**

- `eval`/`vm` → CWE-94
- errorhandler → CWE-489
- md5/sha1 → CWE-328

`MatchSemanticsRevision` is now 5, so cached results from earlier versions are
invalidated.

## Behaviour changes to note

- The default output no longer contains hardening- or quality-tier findings.
  Pipelines that relied on them need `--include-hardening`.
- New session-cookie, `@csrf_exempt` and CWE-209 findings will appear on real
  code. In the benchmark, most findings scored as FP come from these classes:
  they are genuine issues the labellers did not list.
- The release does not update the SaaS cloud-scan engine. That engine is baked
  into the sast-backend image and needs its own rebuild.

## Not attempted

About 84 of the remaining misses are authorization, IDOR, missing-auth,
rate-limit or business-logic flaws, which pattern SAST cannot find reliably.
The JS/TS taint-source expansion (Next.js request objects, destructured
handler parameters), the taint precision bundle, and scanning first-party JS
under `static/` and `public/` are deferred to the next release.
