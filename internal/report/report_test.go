package report_test

import (
	"testing"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/report"
)

func sampleFindings() []core.Finding {
	return []core.Finding{
		{
			RuleID:   "ZS-PY-001",
			Severity: core.SeverityHigh,
			Language: core.Language("python"),
			Location: core.Location{File: "a.py"},
		},
		{
			RuleID:   "ZS-PY-002",
			Severity: core.SeverityCritical,
			Language: core.Language("python"),
			Location: core.Location{File: "b.py"},
		},
		{
			RuleID:   "ZS-PY-001",
			Severity: core.SeverityLow,
			Language: core.Language("go"),
			Location: core.Location{File: "a.py"},
		},
	}
}

func TestGroupFindings_None(t *testing.T) {
	findings := sampleFindings()
	groups := report.GroupFindings(findings, report.GroupByNone)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].Key != "" || groups[0].Label != "" {
		t.Errorf("expected empty key/label for GroupByNone, got %q/%q", groups[0].Key, groups[0].Label)
	}
	if len(groups[0].Findings) != len(findings) {
		t.Errorf("expected all %d findings in single group, got %d", len(findings), len(groups[0].Findings))
	}
}

func TestGroupFindings_UnknownValue(t *testing.T) {
	findings := sampleFindings()
	groups := report.GroupFindings(findings, report.GroupBy("bogus"))
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for unknown GroupBy, got %d", len(groups))
	}
	if len(groups[0].Findings) != len(findings) {
		t.Errorf("expected all findings in single group, got %d", len(groups[0].Findings))
	}
}

func TestGroupFindings_File(t *testing.T) {
	findings := sampleFindings()
	groups := report.GroupFindings(findings, report.GroupByFile)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Key != "a.py" || groups[0].Label != "a.py" {
		t.Errorf("expected first group a.py, got %q", groups[0].Key)
	}
	if len(groups[0].Findings) != 2 {
		t.Errorf("expected 2 findings in a.py group, got %d", len(groups[0].Findings))
	}
	if groups[1].Key != "b.py" {
		t.Errorf("expected second group b.py, got %q", groups[1].Key)
	}
	// preserve original relative order within group
	if groups[0].Findings[0].RuleID != "ZS-PY-001" || groups[0].Findings[1].Severity != core.SeverityLow {
		t.Errorf("findings within group not in original order: %+v", groups[0].Findings)
	}
}

func TestGroupFindings_Rule(t *testing.T) {
	findings := sampleFindings()
	groups := report.GroupFindings(findings, report.GroupByRule)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Key != "ZS-PY-001" {
		t.Errorf("expected first group ZS-PY-001 (first-seen order), got %q", groups[0].Key)
	}
	if len(groups[0].Findings) != 2 {
		t.Errorf("expected 2 findings for ZS-PY-001, got %d", len(groups[0].Findings))
	}
	if groups[1].Key != "ZS-PY-002" {
		t.Errorf("expected second group ZS-PY-002, got %q", groups[1].Key)
	}
}

func TestGroupFindings_Severity(t *testing.T) {
	findings := sampleFindings()
	groups := report.GroupFindings(findings, report.GroupBySeverity)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}
	// must be ordered critical, high, low (highest to lowest), not input order
	wantOrder := []string{"critical", "high", "low"}
	for i, g := range groups {
		if g.Key != wantOrder[i] {
			t.Errorf("group %d: expected key %q, got %q", i, wantOrder[i], g.Key)
		}
		if g.Label != wantOrder[i] {
			t.Errorf("group %d: expected label %q, got %q", i, wantOrder[i], g.Label)
		}
	}
}

func TestGroupFindings_Language(t *testing.T) {
	findings := sampleFindings()
	groups := report.GroupFindings(findings, report.GroupByLanguage)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].Key != "python" || groups[1].Key != "go" {
		t.Errorf("expected first-seen order [python, go], got [%q, %q]", groups[0].Key, groups[1].Key)
	}
}

func TestGroupFindings_EmptyInput(t *testing.T) {
	for _, by := range []report.GroupBy{report.GroupByNone, report.GroupByFile, report.GroupByRule, report.GroupBySeverity, report.GroupByLanguage} {
		groups := report.GroupFindings(nil, by)
		if by == report.GroupByNone {
			if len(groups) != 1 {
				t.Errorf("GroupByNone with empty input: expected 1 group, got %d", len(groups))
			}
			continue
		}
		if len(groups) != 0 {
			t.Errorf("GroupBy %q with empty input: expected 0 groups, got %d", by, len(groups))
		}
	}
}
