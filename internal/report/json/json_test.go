package jsonreport_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/zerostrike/scanner/internal/core"
	jsonreport "github.com/zerostrike/scanner/internal/report/json"
	"github.com/zerostrike/scanner/internal/report"
)

func TestJSONReporter_Format(t *testing.T) {
	if jsonreport.New().Format() != "json" {
		t.Error("Format() != json")
	}
}

func TestJSONReporter_Render(t *testing.T) {
	rep := &report.Report{
		ScannerVersion: "v0.5.0",
		StartedAt:      time.Now(),
		Findings: []core.Finding{
			{RuleID: "ZS-PY-001", Message: "eval usage", Severity: core.SeverityHigh},
		},
		Stats: report.ScanStats{
			FilesScanned:  3,
			TotalFindings: 1,
			ByScanner:     map[string]int{"sast": 1},
			ByKind:        map[core.FindingKind]int{core.FindingKindSAST: 1},
		},
	}

	var buf bytes.Buffer
	if err := jsonreport.New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var out struct {
		ScannerVersion string `json:"ScannerVersion"`
		Findings       []struct {
			RuleID string `json:"RuleID"`
		} `json:"Findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, buf.String())
	}
	if out.ScannerVersion != "v0.5.0" {
		t.Errorf("ScannerVersion = %q, want v0.5.0", out.ScannerVersion)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(out.Findings))
	}
	if out.Findings[0].RuleID != "ZS-PY-001" {
		t.Errorf("findings[0].RuleID = %q, want ZS-PY-001", out.Findings[0].RuleID)
	}
}

func TestJSONReporter_EmptyFindings(t *testing.T) {
	rep := &report.Report{ScannerVersion: "v0.5.0"}
	var buf bytes.Buffer
	if err := jsonreport.New().Render(rep, &buf); err != nil {
		t.Fatalf("Render empty: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Errorf("output is not valid JSON: %s", buf.String())
	}
}
