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
}

// Reporter renders a Report to an io.Writer in a specific format.
type Reporter interface {
	Render(report *Report, dest io.Writer) error
	Format() string // "json" | "sarif" | "html"
}
