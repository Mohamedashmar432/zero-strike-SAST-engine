package report

import (
	"io"
	"time"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
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
	// AcceptedExemptions counts findings moved out of Findings because a portal admin accepted
	// them (see Report.AcceptedExemptions). Not included in TotalFindings or BySeverity.
	AcceptedExemptions int
	// TierExcluded is the number of hardening/quality-tier findings left out
	// of this report (see core.Tier); TierExcludedByRule lists them per rule
	// ID. Both are zero/empty when the scan ran with --include-hardening.
	TierExcluded       int
	TierExcludedByRule map[string]int `json:",omitempty"`
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
	// AcceptedExemptions holds findings the scanner still detected but a portal admin has accepted
	// as a false positive (or, for a dependency, an accepted risk). They are reported, never
	// counted: not in Findings, Stats.TotalFindings, BySeverity or the exit code.
	//
	// The finding sits one level deeper ("Finding": {...}) on purpose. The CI gates customers
	// already have in their pipeline YAML count `^      "Severity": "critical"` -- exactly six
	// spaces, i.e. a field of a Findings element. Nested here, a Severity line is indented eight
	// and those unchanged gates do not count it. TestReportLayoutContract locks this in.
	AcceptedExemptions []ExemptedFinding
	// Dependencies is the full inventory the SCA scanner parsed from the manifests, vulnerable or
	// not, so the portal can match advisories published after this scan. Sorted by ecosystem,
	// package, version, manifest. omitzero (not omitempty) is deliberate: nil means SCA did not
	// run and the key is absent, while an empty non-nil slice means SCA ran over no manifests and
	// serialises as []. The element has no Severity field, so the CI-gate grep cannot match it.
	Dependencies []DependencyRef `json:"Dependencies,omitzero"`
	Stats              ScanStats
	Diagnostics        []analyzer.Diagnostic
	GroupBy            GroupBy
}

// DependencyRef is one parsed dependency. Manifest is repo-relative with forward slashes.
// Direct is whatever the manifest parser said; the yarn and pnpm parsers set it true for every
// entry, so consumers must not trust it for those ecosystems' lockfiles.
type DependencyRef struct {
	Ecosystem string
	Package   string
	Version   string
	Manifest  string
	Direct    bool
}

// ExemptedFinding is one finding matched by an admin-accepted exemption.
type ExemptedFinding struct {
	Fingerprint string
	File        string // repo-relative, as the exemption names it
	Kind        string // "false_positive" | "accepted_risk"
	Finding     core.Finding
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

// SeverityOrder is the canonical highest-to-lowest severity ordering used
// wherever findings are grouped or displayed by severity.
var SeverityOrder = []core.Severity{
	core.SeverityCritical,
	core.SeverityHigh,
	core.SeverityMedium,
	core.SeverityLow,
	core.SeverityInfo,
}

// IsGrouped reports whether by should produce grouped output. GroupByNone
// and any unrecognized value are treated as "not grouped" — this must stay
// consistent with GroupFindings' own default case, so reporters that branch
// on "should I emit Groups or a flat Findings list" get the same answer
// GroupFindings would give for the same value, rather than each reporter
// re-deriving (and risking drifting from) that equivalence independently.
func IsGrouped(by GroupBy) bool {
	switch by {
	case GroupByFile, GroupByRule, GroupBySeverity, GroupByLanguage:
		return true
	default:
		return false
	}
}

// GroupFindings partitions findings according to by. For GroupByNone (or any
// unrecognized value), it returns a single group containing all findings,
// even when findings is empty. The other four modes return one group per
// distinct key and zero groups for empty input. Findings retain their
// original relative order within a group; groups are ordered by first
// appearance in findings, except for GroupBySeverity which is ordered from
// highest to lowest severity.
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
	for _, sev := range SeverityOrder {
		if fs, ok := by[sev]; ok {
			s := string(sev)
			groups = append(groups, Group{Key: s, Label: s, Findings: fs})
		}
	}
	return groups
}
