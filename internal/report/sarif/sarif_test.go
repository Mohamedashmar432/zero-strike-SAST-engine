package sarif_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/report"
	"github.com/zerostrike/scanner/internal/report/sarif"
)

func TestSARIF_Format(t *testing.T) {
	if sarif.New().Format() != "sarif" {
		t.Error("Format() != sarif")
	}
}

func TestSARIF_Render(t *testing.T) {
	rep := &report.Report{
		ScannerVersion: "v0.5.0",
		RootPath:       "/project",
		Findings: []core.Finding{
			{
				RuleID:   "ZS-PY-001",
				RuleName: "eval-injection",
				Message:  "Use of eval",
				Severity: core.SeverityHigh,
				Location: core.Location{File: "/project/src/main.py", StartLine: 10},
			},
			{
				RuleID:   "ZS-PY-002",
				RuleName: "pickle-loads",
				Message:  "Unsafe deserialization",
				Severity: core.SeverityMedium,
				Location: core.Location{File: "/project/src/utils.py", StartLine: 5},
			},
		},
	}

	var buf bytes.Buffer
	if err := sarif.New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, buf.String())
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "ZeroStrike" {
		t.Errorf("driver.name = %q, want ZeroStrike", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "v0.5.0" {
		t.Errorf("driver.version = %q, want v0.5.0", run.Tool.Driver.Version)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules len = %d, want 2 (one per unique ruleId)", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "ZS-PY-001" {
		t.Errorf("rules[0].id = %q, want ZS-PY-001", run.Tool.Driver.Rules[0].ID)
	}
	if len(run.Results) != 2 {
		t.Fatalf("results len = %d, want 2", len(run.Results))
	}
	if run.Results[0].RuleID != "ZS-PY-001" {
		t.Errorf("results[0].ruleId = %q, want ZS-PY-001", run.Results[0].RuleID)
	}
	if run.Results[0].Level != "error" {
		t.Errorf("results[0].level = %q, want error (high severity)", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("results[1].level = %q, want warning (medium severity)", run.Results[1].Level)
	}
	if run.Results[0].Locations[0].PhysicalLocation.Region.StartLine != 10 {
		t.Errorf("startLine = %d, want 10", run.Results[0].Locations[0].PhysicalLocation.Region.StartLine)
	}
	// URI should be root-relative
	uri := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri == "" {
		t.Error("artifactLocation.uri is empty")
	}
}

func TestSARIF_SeverityLevels(t *testing.T) {
	cases := []struct {
		sev   core.Severity
		level string
	}{
		{core.SeverityCritical, "error"},
		{core.SeverityHigh, "error"},
		{core.SeverityMedium, "warning"},
		{core.SeverityLow, "note"},
		{core.SeverityInfo, "note"},
	}
	for _, tc := range cases {
		rep := &report.Report{
			Findings: []core.Finding{
				{RuleID: "ZS-X-001", Severity: tc.sev, Location: core.Location{StartLine: 1}},
			},
		}
		var buf bytes.Buffer
		sarif.New().Render(rep, &buf) //nolint:errcheck
		var doc struct {
			Runs []struct {
				Results []struct{ Level string `json:"level"` } `json:"results"`
			} `json:"runs"`
		}
		json.Unmarshal(buf.Bytes(), &doc) //nolint:errcheck
		got := doc.Runs[0].Results[0].Level
		if got != tc.level {
			t.Errorf("severity %q → level %q, want %q", tc.sev, got, tc.level)
		}
	}
}

func TestSARIF_EmptyFindings(t *testing.T) {
	rep := &report.Report{ScannerVersion: "v0.5.0"}
	var buf bytes.Buffer
	if err := sarif.New().Render(rep, &buf); err != nil {
		t.Fatalf("Render empty: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Errorf("output is not valid JSON: %s", buf.String())
	}
}
