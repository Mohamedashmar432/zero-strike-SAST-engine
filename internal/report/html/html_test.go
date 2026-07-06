package html

import (
	"strings"
	"testing"
	"time"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/report"
)

func emptyReport() *report.Report {
	return &report.Report{
		ScanID:         "test-scan-id",
		ScannerVersion: "v0.6.0",
		StartedAt:      time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC),
		RootPath:       "/repo",
	}
}

func TestHTMLReporter_Format(t *testing.T) {
	r := New()
	if r.Format() != "html" {
		t.Errorf("Format() = %q, want html", r.Format())
	}
}

func TestHTMLReporter_EmptyReport(t *testing.T) {
	var buf strings.Builder
	if err := New().Render(emptyReport(), &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("output missing DOCTYPE")
	}
	if !strings.Contains(out, "test-scan-id") {
		t.Error("output missing scan ID")
	}
	if !strings.Contains(out, "clean scan") {
		t.Error("output missing empty-state message")
	}
}

func TestHTMLReporter_FindingsRendered(t *testing.T) {
	rep := emptyReport()
	rep.Findings = []core.Finding{
		{
			RuleID:   "ZS-PY-001",
			RuleName: "Dangerous eval",
			Severity: core.SeverityHigh,
			Message:  "eval() with untrusted input",
			Location: core.Location{File: "src/app.py", StartLine: 42},
			Kind:     core.FindingKindSAST,
		},
		{
			RuleID:   "ZS-SEC-002",
			RuleName: "GitHub Token",
			Severity: core.SeverityCritical,
			Message:  "GitHub token detected",
			Location: core.Location{File: "config.py", StartLine: 7},
			Kind:     core.FindingKindSecret,
		},
	}
	rep.Stats.TotalFindings = 2

	var buf strings.Builder
	if err := New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ZS-PY-001", "ZS-SEC-002", "src/app.py", "config.py", "Critical", "High"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestHTMLReporter_GroupByFile_LabelsNotCapitalized(t *testing.T) {
	rep := emptyReport()
	rep.GroupBy = report.GroupByFile
	rep.Findings = []core.Finding{
		{
			RuleID:   "ZS-PY-001",
			Severity: core.SeverityHigh,
			Message:  "eval() with untrusted input",
			Location: core.Location{File: "src/app.py", StartLine: 42},
			Kind:     core.FindingKindSAST,
		},
		{
			RuleID:   "ZS-SEC-002",
			Severity: core.SeverityCritical,
			Message:  "GitHub token detected",
			Location: core.Location{File: "config/secrets.py", StartLine: 7},
			Kind:     core.FindingKindSecret,
		},
	}
	rep.Stats.TotalFindings = 2

	var buf strings.Builder
	if err := New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"src/app.py", "config/secrets.py"} {
		if !strings.Contains(out, "<h2>"+want) {
			t.Errorf("output missing raw file-path heading %q; got:\n%s", want, out)
		}
	}
	// File paths must not be capitalized (that would be nonsensical for a path).
	if strings.Contains(out, "<h2>Src/app.py") || strings.Contains(out, "<h2>Config/secrets.py") {
		t.Error("file-path group labels were incorrectly capitalized")
	}
}

func TestHTMLReporter_RationaleRemediationTaintContext(t *testing.T) {
	rep := emptyReport()
	rep.Findings = []core.Finding{
		{
			RuleID:      "ZS-PY-001",
			Severity:    core.SeverityHigh,
			Message:     "eval() with untrusted input",
			Location:    core.Location{File: "src/app.py", StartLine: 42},
			Kind:        core.FindingKindSAST,
			Rationale:   "Untrusted input reaching eval() allows arbitrary code execution.",
			Remediation: "Use ast.literal_eval or avoid eval entirely.",
			TaintContext: &core.TaintContext{
				SourceVar:  "q",
				SourceExpr: "request.args.get('q')",
				Sink:       "eval",
			},
		},
	}
	rep.Stats.TotalFindings = 1

	var buf strings.Builder
	if err := New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"Untrusted input reaching eval() allows arbitrary code execution.",
		"Fix: Use ast.literal_eval or avoid eval entirely.",
		"Tainted: q",
		"request.args.get(&#39;q&#39;)",
		"eval",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestHTMLReporter_EscapesUntrustedContent(t *testing.T) {
	rep := emptyReport()
	rep.Findings = []core.Finding{
		{
			RuleID:    "ZS-PY-001",
			Severity:  core.SeverityHigh,
			Message:   "<script>alert(1)</script>",
			Location:  core.Location{File: "src/app.py", StartLine: 42},
			Kind:      core.FindingKindSAST,
			Rationale: "<img src=x onerror=alert(2)>",
		},
	}
	rep.Stats.TotalFindings = 1

	var buf strings.Builder
	if err := New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("message was not HTML-escaped; raw <script> tag found in output")
	}
	if strings.Contains(out, "<img src=x onerror=alert(2)>") {
		t.Error("rationale was not HTML-escaped; raw <img> tag found in output")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped &lt;script&gt; in output")
	}
}

func TestHTMLReporter_BadgeColorPerFindingSeverity(t *testing.T) {
	rep := emptyReport()
	rep.GroupBy = report.GroupByFile
	rep.Findings = []core.Finding{
		{
			RuleID:   "ZS-PY-001",
			Severity: core.SeverityCritical,
			Message:  "critical finding",
			Location: core.Location{File: "src/app.py", StartLine: 1},
			Kind:     core.FindingKindSAST,
		},
		{
			RuleID:   "ZS-PY-002",
			Severity: core.SeverityLow,
			Message:  "low finding",
			Location: core.Location{File: "src/app.py", StartLine: 2},
			Kind:     core.FindingKindSAST,
		},
	}
	rep.Stats.TotalFindings = 2

	var buf strings.Builder
	if err := New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	for _, want := range []string{`class="badge critical"`, `class="badge low"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q (per-finding badge class); got:\n%s", want, out)
		}
	}
}
