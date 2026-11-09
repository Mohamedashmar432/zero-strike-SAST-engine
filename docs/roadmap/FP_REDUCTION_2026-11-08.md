# False-positive reduction, round 3

Planned 8 November 2026. One benchmark, one number: the 32 RealVuln repos in `scripts/realvuln/benchmark-set.txt`,
scored by `scripts/realvuln/eval.sh` (same file, CWE in `acceptable_cwes`, line within 10, one finding per label).

## Starting point

| Measure | Value |
|---|---|
| Labeled real vulnerabilities | 1,202 |
| Findings reported | 821 |
| True positives / false positives / missed | 422 / 399 / 780 |
| Precision (reported findings that are real) | 51.4% |
| False-positive share (reported findings that are wrong) | 48.6% |
| Recall (real vulnerabilities found) | 35.1% |

116 rules produced at least one false positive. Rules with no true positive at all produced 123 of the 399.

## Policy

A rule is retired (`lifecycle: retired`, reversible) when, across the 32 repos, either:

- it produced no true positive and at least two false positives, unless it is critical severity, or it is a high-severity
  injection, path, XSS, authentication or SSRF rule with only two false positives (too little evidence to drop the
  detection); or
- its precision is under 30 percent with at least three false positives, unless it is critical severity or a high-severity
  injection, path, XSS, authentication or SSRF rule with at least two true positives.

A rule whose false positives share one safe shape that a predicate can separate is tightened instead of retired.

## Work list

Retire (YAML): ZS-JS-083, ZS-TS-139, ZS-JAVA-022, ZS-JAVA-012, ZS-PY-142, ZS-TS-014, ZS-TS-129, ZS-JS-007, ZS-JS-052,
ZS-JAVA-018, ZS-TS-069, ZS-JAVA-035, ZS-PY-147, ZS-TS-024, ZS-HTML-009, ZS-HTML-004.

Tighten: ZS-HTML-002 (42 false positives, none real: a literal `javascript:` URI written by the developer, such as
`href="javascript:void(0)"`, is not XSS; keep the finding when the URI contains a template expression or user value).

Go-coded detectors, tighten or retire on the same policy: ZS-SEC-032 (3 TP / 10 FP), ZS-SEC-028 (2 / 7), ZS-SEC-016 (1 / 3).

Kept and left for a later precision round (high-severity, two false positives each, no true positive yet): ZS-JS-021,
ZS-TS-030, ZS-JAVA-014, ZS-TS-002, ZS-TS-061, ZS-TS-058, ZS-JS-025, ZS-JAVA-007, ZS-TS-132.

## Projection

Retiring the list above without the nine kept rules: about 410 true positives and 278 false positives, 59.6 percent.
Tightening ZS-HTML-002 removes up to 42 more false positives at no true-positive cost, which would put precision above
60 percent. These are projections from the baseline counts; the result is what `eval.sh` measures after the build.

## Gates

Internal corpus `go run ./cmd/zerostrike-bench -corpus benchmark/corpus -max-fp 0` at FP 0 and FN 0; `go test ./...`;
`TestReportLayoutContract`. Tests that assert a retired rule fires are flipped to assert it does not.

## Retired on production evidence, 2026-11-09

Nine more rules retired on false-positive tags set by production portal users (Scan Engine noisy-rule list,
2026-11-09). Counts are findings tagged false positive over total findings across production projects.

| Rule | Detector | Tagged false positive | Projects |
| --- | --- | --- | --- |
| ZS-JS-035 | axios.get SSRF | 96 of 133 (72%) | 4 |
| ZS-JS-011 | Sequelize SQL injection | 60 of 60 | 2 |
| ZS-TS-080 | https.get SSRF | 45 of 75 (60%) | 1 |
| ZS-PY-004 | SQL string formatting | 38 of 69 (55%) | 4 |
| ZS-CS-016 | HttpClient.GetAsync SSRF | 24 of 50 (48%) | 4 |
| ZS-JS-012 | child_process exec command injection | 20 of 20 | 2 |
| ZS-PY-032 | XXE via ET.fromstring | 10 of 15 (67%) | 3 |
| ZS-SEC-012 | mongodb-uri secret detector | 10 of 13 (77%) | 4 |
| ZS-SEC-013 | postgresql-uri secret detector | 6 of 9 (67%) | 4 |

The seven YAML rules carry `lifecycle: retired`; the two Go detectors use the `retired` field. All nine are
reversible (set the lifecycle back to `released`, or delete the `retired` field), but a genuine instance of these
patterns is not reported while they are retired. `MatchSemanticsRevision` is 9. Corpus expectations for these rules
were removed (fixtures kept; 703 to 685 expected true positives); tests that asserted they fire now assert they do not.
Framework taint-seeding tests that used ZS-JS-012 and ZS-PY-004 as probes now use ZS-JS-001 (eval) and ZS-PY-058
(cursor.executescript).
