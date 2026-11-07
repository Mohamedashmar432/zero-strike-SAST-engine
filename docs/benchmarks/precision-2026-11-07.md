# Precision work, 7 November 2026

Branch `feat/precision-75`. Scores use the RealVuln matcher re-implemented in `scripts/realvuln/` (same file, CWE in
`acceptable_cwes`, line within 10, one finding per label). The re-implementation has not been compared with RealVuln's own
`scorer/matcher.py`. Every CWE on a finding is scored as a separate entry.

| Set | True positives | False positives | Missed | Precision | Recall |
|---|---|---|---|---|---|
| Dev, 9 repos, before | 216 | 259 | 244 | 45.5% | 47.0% |
| Dev, 9 repos, after | 236 | 139 | 224 | 62.9% | 51.3% |
| New 10 repos, before | 103 | 393 | 256 | 20.8% | 28.7% |
| New 10 repos, after | 98 | 103 | 261 | 48.8% | 27.3% |
| Held-out 13 repos, before | 96 | 225 | 287 | 29.9% | 25.1% |
| Held-out 13 repos, after | 88 | 159 | 295 | 35.6% | 23.0% |
| Java only (3 held-out repos), before | 15 | 89 | 120 | 14.4% | 11.1% |
| Java only (3 held-out repos), after | 11 | 47 | 124 | 19.0% | 8.1% |

Pooled over the 19 dev and new repos: 334 true positives and 242 false positives, 58.0% precision. The 60% target was not
reached. The dev and new-10 figures are in-sample (rules were chosen or tightened using them); held-out is the closest
measure of unseen code. Three held-out repos were opened during debugging and are no longer sealed.

Gates at the end: internal corpus 618/0/0, `go test ./...` green, `TestReportLayoutContract` green. `TestInventoryEqualsParsedDeps`
in `internal/scanner/sca` is intermittently flaky (npm `direct` flag) and predates this work.

## Rules retired (reversible: set `lifecycle: released`)

Retired on production tag evidence: ZS-JS-085, ZS-TS-037, ZS-JS-039, ZS-JS-061, ZS-PY-145.

Retired on measured precision under 35 percent across 19 repos: ZS-HTML-006, ZS-HTML-022, ZS-JAVA-010, ZS-JAVA-011,
ZS-JAVA-015, ZS-JAVA-017, ZS-JAVA-021, ZS-JAVA-038, ZS-JAVA-048, ZS-JS-004, ZS-JS-010, ZS-JS-027, ZS-JS-040, ZS-JS-046,
ZS-JS-055, ZS-JS-158, ZS-JS-178, ZS-JS-181, ZS-JS-185, ZS-PY-007, ZS-PY-099, ZS-TS-023, ZS-TS-050, ZS-TS-062, ZS-TS-128,
ZS-TS-185. Also retired in Go: secret detector ZS-SEC-011 and framework check ZS-CFG-020.

Kept despite low precision because they are critical severity or found real injection, path or authentication issues:
Java SQL injection and path traversal, `exec`, JWT `none`, innerHTML, hardcoded credentials. These were tightened instead.

## Release notes

Fingerprints change for: ZS-PY-098 and ZS-PY-099 (merged), ZS-JS-048 and ZS-TS-046 (reported at the options declaration),
ZS-PY-078 (aggregated), ZS-HTML-004 to ZS-HTML-011 (constant external `src`), and the signing-secret findings that moved from
ZS-JS-141 and ZS-TS-141 to ZS-JS-180 and ZS-TS-180. Portal exemptions on those findings detach.
Retired rules stop reporting; a real instance of their shape is no longer found.
