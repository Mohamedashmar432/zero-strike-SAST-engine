package jsonreport

import (
	"encoding/json"
	"io"
	"time"

	"github.com/zerostrike/scanner/internal/analyzer"
	"github.com/zerostrike/scanner/internal/report"
)

type jsonReporter struct{}

// New returns a Reporter that writes indented JSON.
func New() report.Reporter { return &jsonReporter{} }

func (r *jsonReporter) Format() string { return "json" }

// groupedDoc mirrors report.Report but replaces the flat Findings slice
// with pre-partitioned Groups. It is used only when rep.GroupBy requests
// grouping; field names are left untagged to match the un-tagged
// convention used by report.Report/core.Finding/report.Group.
type groupedDoc struct {
	ScanID         string
	ScannerVersion string
	StartedAt      time.Time
	Duration       time.Duration
	RootPath       string
	GitCommit      string
	Branch         string
	Hostname       string
	Stats          report.ScanStats
	Diagnostics    []analyzer.Diagnostic
	GroupBy        report.GroupBy
	Groups         []report.Group
}

func (r *jsonReporter) Render(rep *report.Report, dest io.Writer) error {
	enc := json.NewEncoder(dest)
	enc.SetIndent("", "  ")

	if !report.IsGrouped(rep.GroupBy) {
		return enc.Encode(rep)
	}

	doc := groupedDoc{
		ScanID:         rep.ScanID,
		ScannerVersion: rep.ScannerVersion,
		StartedAt:      rep.StartedAt,
		Duration:       rep.Duration,
		RootPath:       rep.RootPath,
		GitCommit:      rep.GitCommit,
		Branch:         rep.Branch,
		Hostname:       rep.Hostname,
		Stats:          rep.Stats,
		Diagnostics:    rep.Diagnostics,
		GroupBy:        rep.GroupBy,
		Groups:         report.GroupFindings(rep.Findings, rep.GroupBy),
	}
	return enc.Encode(doc)
}
