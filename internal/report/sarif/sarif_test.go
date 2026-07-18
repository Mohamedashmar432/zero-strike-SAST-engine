package sarif_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report/sarif"
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

func TestSARIF_Render_EnrichedFields(t *testing.T) {
	rep := &report.Report{
		ScannerVersion: "v0.5.0",
		RootPath:       "/project",
		Findings: []core.Finding{
			{
				RuleID:      "ZS-PY-001",
				RuleName:    "eval-injection",
				Message:     "Use of eval",
				Severity:    core.SeverityHigh,
				Location:    core.Location{File: "/project/src/main.py", StartLine: 10},
				Rationale:   "eval() with untrusted input allows arbitrary code execution.",
				Remediation: "Use ast.literal_eval() instead of eval() when parsing user data.",
				References:  []string{"https://owasp.org/Top10/2025/A05_2025-Injection/", "https://example.com/other"},
				CWE:         []string{"CWE-95"},
				OWASP:       []string{"A05:2025"},
				Fingerprint: "abc123fingerprint",
			},
			{
				RuleID:   "ZS-PY-002",
				RuleName: "pickle-loads",
				Message:  "Unsafe deserialization",
				Severity: core.SeverityMedium,
				Location: core.Location{File: "/project/src/utils.py", StartLine: 5},
				// All enrichment fields left empty/zero.
			},
		},
	}

	var buf bytes.Buffer
	if err := sarif.New().Render(rep, &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	raw := buf.String()

	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID              string `json:"id"`
						FullDescription *struct {
							Text string `json:"text"`
						} `json:"fullDescription"`
						Help *struct {
							Text string `json:"text"`
						} `json:"help"`
						HelpURI    string `json:"helpUri"`
						Properties *struct {
							Tags []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID              string            `json:"ruleId"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, raw)
	}

	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules len = %d, want 2", len(run.Tool.Driver.Rules))
	}

	enriched := run.Tool.Driver.Rules[0]
	if enriched.ID != "ZS-PY-001" {
		t.Fatalf("rules[0].id = %q, want ZS-PY-001", enriched.ID)
	}
	if enriched.FullDescription == nil || enriched.FullDescription.Text != "eval() with untrusted input allows arbitrary code execution." {
		t.Errorf("fullDescription.text = %+v, want rationale text", enriched.FullDescription)
	}
	wantHelp := "eval() with untrusted input allows arbitrary code execution.\n\nRemediation: Use ast.literal_eval() instead of eval() when parsing user data." +
		"\n\nReferences:\n- https://owasp.org/Top10/2025/A05_2025-Injection/\n- https://example.com/other"
	if enriched.Help == nil || enriched.Help.Text != wantHelp {
		t.Errorf("help.text = %+v, want %q", enriched.Help, wantHelp)
	}
	if enriched.HelpURI != "https://owasp.org/Top10/2025/A05_2025-Injection/" {
		t.Errorf("helpUri = %q, want first reference", enriched.HelpURI)
	}
	if enriched.Properties == nil {
		t.Fatal("properties is nil, want tags")
	}
	wantTags := []string{"external/cwe/cwe-95", "owasp:a05-2025"}
	if len(enriched.Properties.Tags) != len(wantTags) {
		t.Fatalf("tags = %v, want %v", enriched.Properties.Tags, wantTags)
	}
	for i, tag := range wantTags {
		if enriched.Properties.Tags[i] != tag {
			t.Errorf("tags[%d] = %q, want %q", i, enriched.Properties.Tags[i], tag)
		}
	}

	// The empty-fields finding's rule must have all enrichment fields omitted.
	plain := run.Tool.Driver.Rules[1]
	if plain.ID != "ZS-PY-002" {
		t.Fatalf("rules[1].id = %q, want ZS-PY-002", plain.ID)
	}
	if plain.FullDescription != nil {
		t.Errorf("rules[1].fullDescription = %+v, want nil", plain.FullDescription)
	}
	if plain.Help != nil {
		t.Errorf("rules[1].help = %+v, want nil", plain.Help)
	}
	if plain.HelpURI != "" {
		t.Errorf("rules[1].helpUri = %q, want empty", plain.HelpURI)
	}
	if plain.Properties != nil {
		t.Errorf("rules[1].properties = %+v, want nil", plain.Properties)
	}

	if run.Results[0].RuleID != "ZS-PY-001" {
		t.Fatalf("results[0].ruleId = %q, want ZS-PY-001", run.Results[0].RuleID)
	}
	if got := run.Results[0].PartialFingerprints["zerostrikeFingerprint/v1"]; got != "abc123fingerprint" {
		t.Errorf("partialFingerprints[zerostrikeFingerprint/v1] = %q, want abc123fingerprint", got)
	}
	if run.Results[1].PartialFingerprints != nil {
		t.Errorf("results[1].partialFingerprints = %v, want nil (no fingerprint set)", run.Results[1].PartialFingerprints)
	}

	// Raw-string checks that the omitted keys are truly absent, not present-but-null/empty.
	for _, key := range []string{`"partialFingerprints"`} {
		// Only the enriched result (index 0) should carry this key; ensure it
		// doesn't leak into the second result's object. We check by counting
		// occurrences: exactly one, for the enriched finding.
		count := strings.Count(raw, key)
		if count != 1 {
			t.Errorf("raw JSON contains %q %d times, want exactly 1 (only on enriched result)", key, count)
		}
	}
	for _, key := range []string{`"fullDescription"`, `"help"`, `"helpUri"`, `"properties"`} {
		count := strings.Count(raw, key)
		if count != 1 {
			t.Errorf("raw JSON contains %q %d times, want exactly 1 (only on enriched rule)", key, count)
		}
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
				Results []struct {
					Level string `json:"level"`
				} `json:"results"`
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
