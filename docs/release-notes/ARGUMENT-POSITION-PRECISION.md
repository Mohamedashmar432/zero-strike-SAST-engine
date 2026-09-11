# Argument-position precision pass

Follow-on to `PRECISION-OVERHAUL.md`. That pass fixed *which files* get scanned and *which
taint counts*; this one fixes *which argument* has to be tainted for a sink rule to fire.

Benchmark after: **TP=459 FP=0 FN=0**, precision 100%, recall 100%, with 21 new
false-positive fixtures in the gate. TP moved 460 → 459 for one reason, explained under
"Corpus expectation removed" below — no detection was lost.

## 1. Why this was needed

`tainted_argument: true` means "any argument, anywhere in its subtree, is tainted."
For most sinks that is the wrong predicate: one specific position carries the danger and
the rest are plumbing. Before this pass only 31 of 416 rules pinned a position
(SQL 23/23, format-string 6/6, dangerous-functions 2/17); command-injection,
path-traversal, SSRF and XSS were 0%.

The cost was not theoretical. Every one of these fired on safe code:

| Code | Rule | Why it fired |
| --- | --- | --- |
| `http.ServeFile(w, r, "./static/index.html")` | ZS-GO-033 | `r` is the taint source in *every* handler, so this matched on literally every ServeFile call |
| `fmt.Fprintf(w, "<h1>Status OK</h1>")` | ZS-GO-017 | argument 0 is the `io.Writer`, and handler parameters are seeded tainted |
| `axios.post(API_URL, userBody)` | ZS-JS-036 | a tainted request *body* is not SSRF; only the URL decides where the request goes |
| `os.WriteFile(CONFIG_PATH, userData, 0644)` | ZS-GO-024 | tainted *contents* to a constant path is not traversal |
| `el.insertAdjacentHTML(pos, "<b>hi</b>")` | ZS-JS-047 | argument 0 is a fixed position keyword, not markup |
| `subprocess.run(["ls", "-la"])` | ZS-PY-003 | see below — no `shell=True` check at all |

## 2. Two rules whose match contradicted their own documentation

**ZS-PY-003** — the name, rationale, message and fix_suggestion are all about `shell=True`,
but `match:` checked only `callee: subprocess.run`. Every `subprocess.run` call in a
repository was reported as command injection, including the list form the rule's own
fix_suggestion recommends. Now requires `shell=True` *and* a non-literal command.

It is gated on non-literal rather than on taint deliberately: taint here is file-scoped, so
requiring it drops the command assembled from a module global, a config read, or another
file — which is most real `shell=True` code. `TestIntegration_SubprocessFiresZSPY003`
(`subprocess.run(cmd, shell=True)`, no visible source) is exactly that case, and it is a
true positive worth keeping.

**ZS-PY-008** — its own `description` admitted it fired on constant paths. Now excludes a
literal path argument, while still reporting `open(user_path)`. An f-string or a
concatenation is not a literal, so those still fire.

## 3. New filter: `tainted_argument_min_index`

`fmt.Fprintf(w, format, args...)` writes the format string **and** every substituted value
into the response, so no single `tainted_argument_index` describes it — pinning 1 drops
`Fprintf(w, "Hello, %s", name)`, pinning -1 drops `Fprintf(w, "%s %s", tainted, constant)`.
But argument 0 is the writer, and every handler parameter is seeded weakly tainted, so
"any argument" reported every constant-response handler as XSS.

`tainted_argument_min_index: N` scans arguments N onward. ZS-GO-017 is the only rule that
needs it today. `require_real_source` was rejected as the fix because
`func render(w http.ResponseWriter, name string)` writing `name` is a genuine XSS whose
only taint is parameter taint.

`version.MatchSemanticsRevision` is bumped 2 → 3 accordingly: this is a Go-side change that
alters findings for byte-identical source, so cached findings must be invalidated.

## 4. Coverage

66 rules narrowed across four families (60 at index 0, 3 at index 1, 2 at index 2, 1
min-index). Audited but **deliberately left broad**, each now carrying a YAML comment so the
next audit reads it as a decision rather than an oversight:

- **`path.join` / variadic joiners** (ZS-JS-091, ZS-TS-089) — every segment can introduce `../`.
- **`new File(...)`** (ZS-JAVA-006) — every constructor argument is itself a path component.
- **`new URL(...)`** (ZS-JAVA-019) — four overloads put the destination at different
  positions; a tainted *host* is the worst case and no index covers it. No argument is a
  body or an option, so "any argument" is already correct.
- **`ProcessBuilder`, `spawnSync`, `execFileSync`** — dangerous at index 0 *and* 1
  (`spawnSync('sh', ['-c', cmd])`); the schema cannot express "0 or 1".
- **`fmt.Fprintf`, `document.write(ln)`, `echo`** — variadic sinks where every argument
  reaches the output stream.
- **Single-argument sinks** (`w.Write`, `out.println`, `mark_safe`, `template.HTML`, …) —
  an index would be a no-op.

The **zero-filter audit** covered 16 rules that match a callee with no filters at all.
Most are intentional and were left alone: `eval`, `exec`, `os.system`, `jwt.decode`,
`tempfile.mktemp`, archive `extractall`, and the XXE factory rules each state in their own
YAML that they fire regardless of taint by design — taint-gating them would silently drop
true positives. Only ZS-PY-003 and ZS-PY-008 were genuine defects.

## 5. Corpus expectation removed (the 460 → 459)

`benchmark/corpus/php/manifest.yaml`, case `cases/vuln_format_string.php`, expectation
`ZS-PHP-024`. The fixture's trailing line is
`file_put_contents('greeting.log', $greeting)` — tainted *contents* to a **literal**
destination. That is precisely the false-positive class this pass removes, so the
expectation encoded a false positive as a true positive. ZS-PHP-024 still fires on its own
fixture, `cases/vuln_file_write.php`, which is unchanged.

## 6. Real-target verification, and the regression it caught

The corpus is self-authored, so passing it proves only that rules still do what their author
intended. Every target in `playground/targets/` was therefore scanned with a binary built
from the baseline commit and with the new one, and the two finding sets diffed by
(rule, file, line):

| Target | Before | After | Delta |
| --- | --- | --- | --- |
| WebGoat | 160 | 160 | 0 |
| DVWA | 103 | 101 | **−2 (both verified false positives)** |
| Damm-Vulnerable-dotNet-Application | 40 | 40 | 0 |
| Vulnerable-Flask-App | 9 | 9 | 0 |
| damn-vulnerable-golang | 11 | 11 | 0 |
| dvna | 10 | 10 | 0 |
| dvpwa | 0 | 0 | 0 |

The two removals, read in source and confirmed non-exploitable:
`recaptchalib.php:28` — `file_get_contents($url, …)` where `$url` is assigned the literal
`'https://www.google.com/recaptcha/api/siteverify'` sixteen lines above; and
`oracle_attack.php:52` — `curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data))`, the POST
**body**, while the real `CURLOPT_URL` line 49 still fires.

**This is also how a real regression was caught.** An earlier revision of this pass set
`require_real_source: true` on ZS-JAVA-019 and ZS-PHP-013. The corpus reported
TP=459 FP=0 FN=0 — a perfect score — while the WebGoat scan lost three findings, two of
them canonical true positives: `SSRFTask2.furBall` (`@RequestParam String url` →
`new URL(url)`, WebGoat's own SSRF lesson) and `JWTHeaderJKUEndpoint` (attacker-chosen
`jku` header → `new URL(jku.asString())`). Because taint is file-scoped, a controller that
hands its request parameter to a helper leaves the helper's parameter carrying only weak
taint, so "require a real source" deletes the whole cross-method shape.

Both were reverted; WebGoat returned to 160 with the DVWA false positives still gone,
proving the argument-index pinning was doing the precision work on its own and
`require_real_source` was contributing nothing but recall loss. **Do not re-add it to those
rules without re-scanning WebGoat** — each rule now carries that instruction in its YAML.

A corpus fixture asserting `new URL(AUDIT_URL + path)` as a required non-finding was
removed for the same reason: the engine cannot distinguish it from `new URL(url)` in
WebGoat, so the fixture was demanding a precision that can only be bought with a real
detection. **Third occurrence of the corpus encoding a false positive as required
behaviour** (Sprint 34, Sprint 35, here).

## 7. Known limitations, unchanged by this pass

- Taint is still file-scoped, flow-insensitive and intra-procedural; a sink fed from another
  file, or through a helper call, is still missed. This pass improved precision only — it
  did not add a single new detection.
- `require_real_source` is left off across the SSRF family (see above).
- `ZS-PHP-014` now requires the option to be the literal `CURLOPT_URL` identifier, so
  setting the URL through a variable option (`curl_setopt($ch, $opt, $url)`) is no longer
  reported.
- Separate bug, not addressed here: `scan --rules <dir>` against an external rule directory
  returns few or no findings even on known-vulnerable files, while embedded rules work.
  Two independent agents hit this. Worth its own investigation.
