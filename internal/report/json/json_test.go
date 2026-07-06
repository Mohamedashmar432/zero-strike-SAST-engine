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

	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["Findings"]; !ok {
		t.Error(`expected top-level "Findings" key when GroupBy is unset`)
	}
	if _, ok := m["Groups"]; ok {
		t.Error(`unexpected top-level "Groups" key when GroupBy is unset`)
	}
}

func TestJSONReporter_Render_UnrecognizedGroupBy(t *testing.T) {
	// An unrecognized GroupBy value must be treated the same as GroupByNone
	// (per report.IsGrouped/report.GroupFindings' documented equivalence) —
	// flat top-level Findings, no Groups wrapper.
	rep := &report.Report{
		ScannerVersion: "v0.5.0",
		GroupBy:        report.GroupBy("bogus"),
		Findings: []core.Finding{
			{RuleID: "ZS-PY-001", Message: "eval usage", Severity: core.SeverityHigh},
		},
	}

	var buf bytes.Buffer
	if err := jsonreport.New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, buf.String())
	}
	if _, ok := m["Findings"]; !ok {
		t.Error(`expected top-level "Findings" key for an unrecognized GroupBy value`)
	}
	if _, ok := m["Groups"]; ok {
		t.Error(`unexpected top-level "Groups" key for an unrecognized GroupBy value`)
	}
}

func TestJSONReporter_Render_Grouped(t *testing.T) {
	rep := &report.Report{
		ScannerVersion: "v0.5.0",
		GroupBy:        report.GroupByRule,
		Findings: []core.Finding{
			{RuleID: "ZS-PY-001", Message: "eval usage", Severity: core.SeverityHigh},
			{RuleID: "ZS-PY-002", Message: "sql injection", Severity: core.SeverityCritical},
			{RuleID: "ZS-PY-001", Message: "eval usage again", Severity: core.SeverityHigh},
		},
	}

	var buf bytes.Buffer
	if err := jsonreport.New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	// The top-level document must expose Groups, not a flat Findings array.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, buf.String())
	}
	if _, ok := m["Findings"]; ok {
		t.Error(`unexpected top-level "Findings" key when GroupBy is set`)
	}
	if _, ok := m["Groups"]; !ok {
		t.Fatal(`expected top-level "Groups" key when GroupBy is set`)
	}

	var out struct {
		ScannerVersion string `json:"ScannerVersion"`
		GroupBy        string `json:"GroupBy"`
		Groups         []struct {
			Key      string `json:"Key"`
			Label    string `json:"Label"`
			Findings []struct {
				RuleID string `json:"RuleID"`
			} `json:"Findings"`
		} `json:"Groups"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, buf.String())
	}

	if out.ScannerVersion != "v0.5.0" {
		t.Errorf("ScannerVersion = %q, want v0.5.0", out.ScannerVersion)
	}
	if out.GroupBy != string(report.GroupByRule) {
		t.Errorf("GroupBy = %q, want %q", out.GroupBy, report.GroupByRule)
	}
	if len(out.Groups) != 2 {
		t.Fatalf("groups len = %d, want 2", len(out.Groups))
	}

	for _, g := range out.Groups {
		if g.Key != g.Label {
			t.Errorf("group Key %q != Label %q", g.Key, g.Label)
		}
		for _, f := range g.Findings {
			if f.RuleID != g.Key {
				t.Errorf("group %q contains finding with RuleID %q", g.Key, f.RuleID)
			}
		}
	}

	if out.Groups[0].Key != "ZS-PY-001" {
		t.Errorf("Groups[0].Key = %q, want ZS-PY-001 (first-appearance order)", out.Groups[0].Key)
	}
	if len(out.Groups[0].Findings) != 2 {
		t.Errorf("Groups[0] findings len = %d, want 2", len(out.Groups[0].Findings))
	}
	if out.Groups[1].Key != "ZS-PY-002" {
		t.Errorf("Groups[1].Key = %q, want ZS-PY-002", out.Groups[1].Key)
	}
	if len(out.Groups[1].Findings) != 1 {
		t.Errorf("Groups[1] findings len = %d, want 1", len(out.Groups[1].Findings))
	}
}
