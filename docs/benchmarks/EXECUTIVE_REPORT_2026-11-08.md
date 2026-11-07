# thinkShield scanner: precision report

8 November 2026. Branch `feat/precision-75`, not yet released.

## Summary

The scanner now reports far fewer false alarms without finding fewer real vulnerabilities. On a fixed benchmark of 32
deliberately vulnerable applications with 1,202 known vulnerabilities, false positives fell from 808 to 279 (down 65
percent) while true positives held steady (409 to 411). Precision rose from 33.6 percent to 59.6 percent: six in ten
findings are now real, up from one in three.

Two things still hold the scanner back. It finds about a third of the known vulnerabilities, and that has not moved this
week. Java is the weakest language on both measures.

## Scorecard

One benchmark: 32 RealVuln applications in Java, JavaScript, TypeScript and Python, scored by matching each finding to a
known vulnerability (same file, same weakness type, within 10 lines).

| Measure | 4 November (start) | 8 November (now) | Change |
|---|---|---|---|
| Findings reported | 1,217 | 690 | down 43% |
| Real (true positives) | 409 | 411 | +2 |
| False alarms (false positives) | 808 | 279 | down 65% |
| Precision: share of findings that are real | 33.6% | 59.6% | +26.0 points |
| Recall: share of known vulnerabilities found | 34.0% | 34.2% | flat |
| Missed vulnerabilities | 793 | 791 | flat |

## By language

| Language | Precision, start | Precision, now | Recall, now |
|---|---|---|---|
| Python | 47.5% | 69.1% | 34.3% |
| JavaScript | 47.8% | 67.4% | 53.4% |
| TypeScript | 37.4% | 52.6% | 41.1% |
| Java | 10.6% | 33.7% | 11.8% |

Go, C# and PHP are supported by the scanner but cannot be scored: the benchmark has no labeled applications in those
languages.

## What changed

Rules that were mostly wrong were retired: 47 rules and 4 built-in detectors, each kept in the code with its measured
evidence and switchable back on. Five of them were chosen from false-positive tags by portal users, the rest from this
benchmark. Rules that are critical, or that found real injection, path traversal or authentication flaws, were kept even
when noisy, and tightened instead: SSRF, command execution, Java SQL and file paths, HTML `javascript:` links,
`innerHTML`, CSRF exemptions and several secret detectors. New checks were added for framework settings (Dockerfile,
Express sessions, Spring, Django, Flask) and for EJS templates.

Every change passes the internal test corpus (600 cases, no false positives, no misses), the full unit test suite and
the report-format contract that customers' CI pipelines depend on.

## Where we stand

The scanner has moved from noisy to usable on false alarms. It is not yet thorough: two in three known vulnerabilities go
unreported, and most of those are authorization and business-logic flaws (missing login checks, one user reading another
user's records). Pattern rules cannot see those; they need the scanner to understand an application's routes and
permission checks.

One caution on the headline. The rules retired or tightened this week were chosen by looking at these same applications,
so the benchmark flatters the result. On applications the team had not looked at, last measured on 7 November before the
final round, precision was 35.6 percent. Real-world precision is likely between that figure and 59.6 percent until it is
confirmed on new applications.

## Next move

1. Confirm the result on 10 to 15 applications nobody has looked at. This is the measure that matters most now: precision
   on unseen code, with a target of 55 percent or better. If it holds, release the build.
2. Java. Model how Spring and servlet applications receive user input, so Java findings follow real user data.
   Target: Java precision above 50 percent and recall above 25 percent.
3. Recall. Teach the scanner routes, middleware and ownership checks so it can report missing authorization. Target:
   recall from 34 percent to 45 percent while precision stays at or above 55 percent.

Guardrails for every step: no loss of real findings without a stated reason, internal corpus at zero false positives and
zero misses, and no change to the report format.

## Release notes for portal users

Retired rules stop reporting, so some existing findings will disappear after an upgrade. A few findings change identity
(merged cookie findings, JWT findings reported at the options object, signing secrets moved to a new rule), which
detaches any accepted exemption on them. The full list is in `docs/benchmarks/precision-2026-11-07.md` and the retired
rules carry their evidence in their rule files.
