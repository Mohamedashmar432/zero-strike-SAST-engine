package sarif

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/report"
)

type sarifReporter struct{}

// New returns a Reporter that writes SARIF 2.1.0.
func New() report.Reporter { return &sarifReporter{} }

func (r *sarifReporter) Format() string { return "sarif" }

// SARIF 2.1.0 wire types (minimal for GitHub Code Scanning).
type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name,omitempty"`
	ShortDescription sarifMsg    `json:"shortDescription"`
}

type sarifMsg struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifMsg        `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysLoc `json:"physicalLocation"`
}

type sarifPhysLoc struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func (r *sarifReporter) Render(rep *report.Report, dest io.Writer) error {
	// Build de-duplicated rule list preserving first-seen order.
	ruleIndex := make(map[string]int)
	var rules []sarifRule
	for _, f := range rep.Findings {
		if _, ok := ruleIndex[f.RuleID]; !ok {
			ruleIndex[f.RuleID] = len(rules)
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleName,
				ShortDescription: sarifMsg{Text: f.RuleName},
			})
		}
	}
	if rules == nil {
		rules = []sarifRule{}
	}

	results := make([]sarifResult, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		line := f.Location.StartLine
		if line < 1 {
			line = 1
		}
		col := f.Location.StartCol // omitted from JSON when 0 via omitempty
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex[f.RuleID],
			Level:     severityLevel(f.Severity),
			Message:   sarifMsg{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysLoc{
					ArtifactLocation: sarifArtifact{
						URI:       relURI(rep.RootPath, f.Location.File),
						URIBaseID: "%SRCROOT%",
					},
					Region: sarifRegion{StartLine: line, StartColumn: col},
				},
			}},
		})
	}

	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ZeroStrike",
				Version:        rep.ScannerVersion,
				InformationURI: "https://github.com/zerostrike/scanner",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(dest)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func severityLevel(s core.Severity) string {
	switch s {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// relURI returns a forward-slash relative path from root to file, suitable for a SARIF URI.
func relURI(root, file string) string {
	if root == "" || file == "" {
		return filepath.ToSlash(file)
	}
	rel, err := filepath.Rel(root, file)
	if err != nil {
		return filepath.ToSlash(file)
	}
	return filepath.ToSlash(rel)
}
