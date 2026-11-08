# thinkShield scanner: third-party measurement, PHP, frameworks and IOC scanner

8 November 2026. Branch `feat/precision-75`, not yet released.

## Summary

This round replaced our own test applications with independent ones as the measure that counts. That changed the
picture: on three third-party applications nobody tuned on (WebGoat.NET for C#, XVWA for PHP, govwa for Go), precision
is 43 percent, well below the 75 to 98 percent our purpose-built applications showed. The earlier C# figure of 98 percent
does not hold on third-party code, where it is 48 percent.

Work this round cut PHP false alarms on DVWA from 35 to 12 (precision 46 to 72 percent), added framework detection for
eight more frameworks without losing ground on the 32-application benchmark (60.1 percent), and delivered a new
indicator-of-compromise (IOC) scanner that caught all 58 planted indicators in its test set with zero false alarms across
42 real applications. The PHP gains carried over to unseen PHP only slightly (35 to 39 percent on XVWA).

## The measure that counts: unseen third-party applications

| Application | Language | Precision before | Precision now | Found now | False alarms now |
|---|---|---|---|---|---|
| WebGoat.NET | C# (.NET Framework) | 48.4% | 48.4% | 31% (15 of 49) | 16 |
| XVWA | PHP | 35.1% | 38.9% | 47% (14 of 30) | 22 |
| govwa | Go | 41.7% | 41.7% | 22% (5 of 23) | 7 |
| All three | | 41.3% | 43.0% | 33% | 45 |

All three were added this round, pinned to a commit, labeled from each application's own documented vulnerabilities and
kept sealed: no fix was written while looking at their results. Go is measured for the first time.

## PHP

| Application | Precision before | Precision now | False alarms before → now |
|---|---|---|---|
| DVWA (now used for tuning) | 46.2% | 72.1% | 35 → 12 |
| Purpose-built Laravel app | 94.4% | 100% | 1 → 0 |
| XVWA (unseen) | 35.1% | 38.9% | 24 → 22 |

The fixes: a SQL query built only from integer casts, hashes or escaped values inside quotes no longer counts as
injectable; `$_SERVER` counts as user input only for the request-derived keys; rules that reported two weakness types
for one finding now report one; generated upload names count as safe; and a new rule covers files moved to a
client-chosen path. Two findings from the remaining false alarms point to engine limits, not rules: the data-flow pass
keeps one verdict per variable for a whole file, so a later safe reassignment hides an earlier real injection, and some
PHP vulnerabilities cross files.

## Framework detection

| Framework | Detected on the benchmark | Effect |
|---|---|---|
| Django | 4 of 4 Django apps | Request accessors are sources; helper functions no longer count as user input |
| Flask | 5 apps plus two embedded labs | Same |
| FastAPI | 4 of 4 | Typed `Query`, `Body`, `Path` parameters are sources |
| Spring | 3 of 3 | `@RequestParam`, `@PathVariable`, `@RequestBody` and servlet accessors are sources |
| Next.js | 3 of 3 | Route handlers, server actions and `searchParams` are sources |
| NestJS, Gin, Echo | No such apps in the benchmark | Covered by tests only |

Struts, servlet and aiohttp applications correctly detect no framework and keep the previous behavior. Detection now
covers 14 frameworks.

## Main benchmark (32 RealVuln applications)

| Language | Precision before | Precision now |
|---|---|---|
| Python | 69.1% | 69.4% |
| JavaScript | 67.6% | 67.9% |
| TypeScript | 53.9% | 53.6% |
| Java | 33.7% | 33.0% |
| All (409 real, 272 false alarms) | 60.0% | 60.1% |

One real finding was lost: an SSRF in a helper function that was only found because every helper parameter counted as
user input.

## IOC scanner

New, off by default (`--enable-ioc`). It looks for signs that a repository has already been tampered with, rather than
for coding mistakes: install scripts that download and run code or harvest credentials, executed encoded payloads, web
shells, reverse shells, crypto miners, data sent to known collection services, GitHub Actions versions with a published
compromise, and matches against an organization's own indicator list (`--ioc-feed`). Known malicious packages are
already reported by dependency scanning through OSV's malicious-package records and are now marked critical.

| Measure | Result |
|---|---|
| Planted indicators caught (test set, 8 rules) | 58 of 58 |
| Safe look-alikes left alone | 64 of 64 |
| False alarms on 42 real applications | 0 |

The test set was written by the same team as the rules, so 58 of 58 is an upper bound; the zero false alarms on 42
untouched applications is the stronger result. The portal accepts IOC findings as their own kind, so CI pipelines can
turn the flag on.

## Where we stand

| Language | Unseen third-party code | Purpose-built and tuned applications | RealVuln |
|---|---|---|---|
| C# | 48% | 98% | |
| PHP | 39% | 80% | |
| Go | 42% | | |
| Python | | | 69% |
| JavaScript | | 82% | 68% |
| TypeScript | | | 54% |
| Java | | | 33% |

The third-party column is the one to quote externally. The scanner is usable on JavaScript and Python and not yet on C#,
PHP, Go or Java.

## Next move

1. Tune C#, PHP and Go on WebGoat.NET, XVWA and govwa, which unseals them, and bring in a fresh independent application
   per language as the new sealed check (bWAPP for PHP, a second .NET application, a Gin-based Go application). Target:
   55 percent on the new sealed apps.
2. Make the data-flow pass order-aware, so a later safe assignment cannot hide an earlier real injection. This affects
   every language and is the largest recall item found this round.
3. Java: Spring detection is in place; the next step is the Java sinks it now reaches. Target above 50 percent.
4. IOC: enable it on portal cloud scans behind a workspace setting, and confirm it on a repository with a known historical
   compromise.

Guardrails held this round: internal corpus at 703 cases with zero false alarms and zero misses, unit tests green, report
format unchanged apart from additive fields.
