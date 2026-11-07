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
