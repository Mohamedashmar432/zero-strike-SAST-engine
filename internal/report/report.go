package report

import (
	"io"
	"time"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/core"
)

// ScanStats summarizes a completed scan.
type ScanStats struct {
	FilesScanned  int
	FilesSkipped  int
	FilesCached   int
	TotalFindings int
	BySeverity    map[core.Severity]int
	ByLanguage    map[core.Language]int
	ByCategory    map[string]int
	ByScanner     map[string]int           // "sast" | "secret" | "sca" → count
	ByKind        map[core.FindingKind]int // FindingKindSAST | FindingKindSecret | FindingKindSCA → count
	Suppressed    int                      // findings filtered by allowlist
}

// Report is the full output of a completed scan.
type Report struct {
	ScanID         string
	ScannerVersion string
	StartedAt      time.Time
	Duration       time.Duration
	RootPath       string
	GitCommit      string
	Branch         string
	Hostname       string
	Findings       []core.Finding
	Stats          ScanStats
	Diagnostics    []analyzer.Diagnostic
	GroupBy        GroupBy
}

// Reporter renders a Report to an io.Writer in a specific format.
type Reporter interface {
	Render(report *Report, dest io.Writer) error
	Format() string // "json" | "sarif" | "html"
}

// GroupBy selects how GroupFindings partitions a slice of findings.
type GroupBy string

const (
	GroupByNone     GroupBy = ""
	GroupByFile     GroupBy = "file"
	GroupByRule     GroupBy = "rule"
	GroupBySeverity GroupBy = "severity"
	GroupByLanguage GroupBy = "language"
)

// Group is one partition of findings sharing a common key under some GroupBy.
type Group struct {
	Key      string
	Label    string
	Findings []core.Finding
}

var severityGroupOrder = []core.Severity{
	core.SeverityCritical,
	core.SeverityHigh,
	core.SeverityMedium,
	core.SeverityLow,
	core.SeverityInfo,
}

// GroupFindings partitions findings according to by. It always returns at
// least one group (even for empty input or an unrecognized GroupBy), so
// callers can treat "no grouping" uniformly as a single group containing
// everything. Findings retain their original relative order within a group;
// groups are ordered by first appearance in findings, except for
// GroupBySeverity which is ordered from highest to lowest severity.
func GroupFindings(findings []core.Finding, by GroupBy) []Group {
	switch by {
	case GroupByFile:
		return groupByKey(findings, func(f core.Finding) string { return f.Location.File })
	case GroupByRule:
		return groupByKey(findings, func(f core.Finding) string { return f.RuleID })
	case GroupByLanguage:
		return groupByKey(findings, func(f core.Finding) string { return string(f.Language) })
	case GroupBySeverity:
		return groupBySeverity(findings)
	default:
		return []Group{{Key: "", Label: "", Findings: findings}}
	}
}

func groupByKey(findings []core.Finding, keyFn func(core.Finding) string) []Group {
	index := make(map[string]int)
	var groups []Group
	for _, f := range findings {
		key := keyFn(f)
		if i, ok := index[key]; ok {
			groups[i].Findings = append(groups[i].Findings, f)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, Group{Key: key, Label: key, Findings: []core.Finding{f}})
	}
	return groups
}

func groupBySeverity(findings []core.Finding) []Group {
	by := make(map[core.Severity][]core.Finding)
	for _, f := range findings {
		by[f.Severity] = append(by[f.Severity], f)
	}
	var groups []Group
	for _, sev := range severityGroupOrder {
		if fs, ok := by[sev]; ok {
			s := string(sev)
			groups = append(groups, Group{Key: s, Label: s, Findings: fs})
		}
	}
	return groups
}
