# Sprint 24 Release Notes — v0.17.0

## Summary

Sprint 23 fixed the actual "engine is broken" QA complaint (a stale
`CGO_ENABLED=0` binary built from a pre-Sprint-21 commit) and added a
stderr warning so that failure mode can't hide again. The user's
follow-up was the right one: even correctly built, the scanner was still
finding far fewer vulnerabilities than these deliberately-vulnerable test
apps actually contain. Three parallel research agents traced every gap to
a specific file:line in the real apps. The verdict: two separable,
well-understood problems, neither a taint-engine defect —

1. **Whole vulnerability classes had zero rule for some languages**, even
   though a sibling language already covered the identical class (JS had
   no command-injection or SQLi rule at all, despite Go/Python/PHP all
   having one).
2. **The callee matcher required a full exact-string match** on the
   resolved dotted chain, so real code reaching a sink through a longer
   chain than the rule author anticipated (`context.Response.Write` vs.
   the rule's `Response.Write`) silently never matched.

## Item 1 — 16 new rules closing confirmed missing-class gaps

One rule per exact sink, matching the existing convention, each with a
benchmark corpus fixture:

- **JavaScript** (`ZS-JS-011..015`): Sequelize SQL injection
  (`db.sequelize.query`), `child_process.exec()` command injection, XXE
  via `libxmljs.parseXmlString({noent:true})`, `node-serialize`
  insecure deserialization, open redirect (`res.redirect`).
- **Go** (`ZS-GO-008..012`): DES and RC4 weak ciphers, TLS `MinVersion`
  set to SSLv3 (a `kind: identifier` match — no engine change needed,
  already supported and already indexed), weak PRNG (`math/rand.Int()`,
  disambiguated from `crypto/rand.Int()` via the existing
  `argument_count` filter), SSRF (`http.Get`).
- **PHP** (`ZS-PHP-006..008`): `shell_exec()` command injection (sibling
  to `ZS-PHP-001`'s `system()`), and two local-file-inclusion rules for
  `include()`/`require()`.
- **C#** (`ZS-CS-007..008`): `MySqlCommand` SQL injection (sibling to
  `ZS-CS-002`'s `SqlCommand`, for apps using MySqlConnector instead of
  `System.Data.SqlClient`), and `new Process()` instantiation (lower
  confidence — a syntactic approximation, same treatment as `ZS-PY-008`,
  since this architecture can't correlate a later
  `StartInfo.FileName`/`Arguments` assignment with the eventual
  no-argument `Start()` call).

### PHP builder prerequisite

`include_expression`/`require_expression` are distinct tree-sitter node
types, not `function_call_expression` — confirmed they fell to
`NodeKindUnknown` with zero rule able to match them, the same problem
`echo_statement` already had a precedented fix for.
`internal/parser/php/builder.go` gained `buildIncludeAsCall`, mirroring
the existing `buildEchoAsCall`: a synthetic `NodeKindCall` with a
synthetic `"include"`/`"require"` identifier, so the LFI rules use the
same `tainted_argument` mechanism as every other sink rule. Verified
against a real IR dump before wiring the rule, same discipline as this
sprint's other real-shape confirmations.

### Two taint-source regex broadenings

- **Go** (`goPatterns.Sources`): dropped the literal `r\.` receiver
  anchor on the SSRF pattern — `r\.(URL\.Query\(\)|...)` →
  `\.(URL\.Query\(\)|...)` — a strict superset that now also matches
  `resp.Request.URL.Query()`, which the old anchor missed.
- **C#** (`csharpPatterns.Sources`): added `Request\[` alongside the
  existing `Request\.(QueryString|Form|Params|Cookies)` — ASP.NET's
  `HttpRequest` indexer (`Request["key"]`) checks the same untrusted
  collections via shorthand syntax. Confirmed via the real
  `Damm-Vulnerable-dotNet-Application` app: `Autocomplete.ashx.cs` reads
  `context.Request["query"]` this way, and without this fix the
  downstream `context.Response.Write(json)` call (see Item 2) never saw
  `json` as tainted, since `query` was never recognized as a source.

## Item 2 — Opt-in suffix callee matching

**Problem**: `calleeText`/`attributeText` already resolve a call's full
dotted chain correctly (last session's `urllib.request.urlopen` fix), but
the match step required the chain to *equal* the rule's `callee` exactly.
Real code routinely prefixes a sink with a receiver — confirmed via
`WebGoatCoins/Autocomplete.ashx.cs:33`'s `context.Response.Write(json)`
against `ZS-CS-004`'s bare `Response.Write`.

**Design — opt-in, not a blanket default.** New `match.callee_suffix:
true` YAML field. When set (and only when the callee has ≥2 dot-separated
segments — enforced by the validator, since 5 of the pre-existing 48
callee rules are single-segment and would become dangerously broad
otherwise), `internal/engine`'s `RuleIndex` gains a `byCalleeSuffix`
index keyed by each rule's **last dot segment**, giving an O(1) shortlist
per call node; `calleeSuffixMatches` then verifies the real dot-boundary
suffix (`callText == ruleCallee || strings.HasSuffix(callText,
"."+ruleCallee)`) against just that shortlist — the dot-boundary check is
what stops `"XResponse.Write"` from matching `"Response.Write"` on bare
substring grounds.

Chose opt-in over a blanket default because: (a) this codebase's own
`--max-fp 0` CI gate means a global semantic change needs the whole
benchmark re-verified in one sitting across all 34 eligible rules at
once, vs. one independently-reviewable line per rule; (b) 14 of 48
existing callee rules are single-segment, several with zero other
filters (`eval`, `open`, `unserialize`) — a "just require ≥2 segments"
blanket rule still needs the same conditional carve-out opt-in already
provides for free; (c) matches this codebase's consistent practice of
shipping narrow, individually-verified fixes with a specific before/after
number, not sweeping behavioral changes.

**Phase 1 scope (this sprint)**: shipped the engine capability and
flipped `callee_suffix: true` on exactly `ZS-CS-004` (the one confirmed
real gap), with a new fixture (`vuln_xss_context_prefix.cs`) proving
`context.Response.Write` now matches. The other ~33 eligible 2+-segment
rules (spot-checked candidates: `ZS-GO-002`/`ZS-GO-007` for struct-field
receivers like `s.db.Query`, `ZS-JS-003`/`ZS-TS-003` for
`window.document.write`) are an explicit fast-follow, not swept in here.

## Newly discovered, explicitly deferred: inline-argument taint gap

Two of the 16 new rules (`ZS-JS-012` exec, `ZS-JS-015` open-redirect)
don't fire on dvna's *exact* real lines, even though they fire on their
own corpus fixtures. Root cause, confirmed and documented in both rule
YAMLs rather than hidden: `tainted_argument` only recognizes a **named
variable** previously assigned from a source
(`const x = req.body.y; sink(x)`) — it doesn't recognize the source used
**directly inline** as the argument (`sink(req.body.y)`), because taint
tracking records tainted variable *names*, not arbitrary tainted
expressions. dvna's real code is written the inline way for both of
these. Broadening `tainted_argument`/`anyArgument` to also check an
argument subtree's text against the language's source patterns directly
(not only via `taintedVars`) would close this for every taint-gated rule
across every language at once — a good Sprint 25 candidate, not attempted
here since it's a cross-cutting engine change, not a rule fix.

## Also confirmed, not re-litigated

`MySqlCommand` (`ZS-CS-007`) still doesn't fire on the real
`GetCustomerEmail(string customerNumber)` call site — `customerNumber` is
a method **parameter**, and whether it's tainted depends on what the
*caller* (in a different file) passed in. This is the same
already-deferred CallGraph/interprocedural-taint limitation from prior
sprints, not a new gap; confirming it here is additional evidence for
that backlog item, not new scope.

## Verification

- `go build ./...` / `go vet ./...` / `go test ./... -count=1` — clean
  under both `CGO_ENABLED=0` and `CGO_ENABLED=1` (MinGW-w64 gcc).
- `zerostrike-bench --corpus benchmark/corpus --min-recall 0.90 --max-fp 0`:
  **TP=93 FP=0 FN=0, precision=100.00%, recall=100.00%** (up from TP=75 at
  the end of Sprint 23's own work — 18 net-new true positives: 16 new
  rules + 1 `ZS-CS-004` suffix fixture + 1 from the two new Go rules added
  ahead of this sprint's rule-expansion pass).
- `TestAllRules_HaveCoverageInBenchmarkCorpus`: 0 missing, 80 rules total
  (up from 65).
- Rebuilt the real CGO binary from HEAD and rescanned all 5 vulnerable
  test apps directly (not estimated):

  | Repo | Before (stale-binary QA) | After Sprint 23 fix | After Sprint 24 |
  |---|---|---|---|
  | dvna (Node.js) | 1 | 1 | **5** |
  | DVWA (PHP) | 0 | 33 | **41** |
  | damn-vulnerable-golang | 0 | 3 | **8** |
  | OWASP Flask app | 0 | 0 | 0 (unchanged — dead upstream, no `.py` source exists) |
  | .NET WebForms app | 0 | 43 | **44** |

  The .NET delta looks small relative to the rule additions because two
  of its three new/fixed rules (`ZS-CS-004` suffix match, aided by the
  `Request[` regex fix) landed as +1 finding, and `ZS-CS-007`
  (`MySqlCommand`) is blocked by the interprocedural-taint gap noted
  above — the fixes are real and verified via unit/corpus tests, but this
  particular app's exact vulnerable line needs a bigger architectural
  change to reach.

## Out of scope (unchanged from the approved plan)

EJS template parsing, IDOR/CSRF/weak-session-ID/viewstate-tampering
pattern rules, the `dvwaHtmlEcho()` custom-sink-wrapper indirection,
`$_SESSION` as a PHP taint source, a bare `.Start()` C# rule, an
ignored-Go-error rule, a decompression-bomb structural rule, sweeping
`callee_suffix: true` across all other eligible rules, and
interprocedural/cross-file taint (`CallGraph`) — all confirmed still out
of scope, several with concrete new evidence from this sprint's real-app
rescans.
