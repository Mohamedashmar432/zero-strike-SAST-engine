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
