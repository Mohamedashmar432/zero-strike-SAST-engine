package sarif

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/report"
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
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription sarifMsg         `json:"shortDescription"`
	FullDescription  *sarifMsg        `json:"fullDescription,omitempty"`
	Help             *sarifMsg        `json:"help,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       *sarifProperties `json:"properties,omitempty"`
}

// sarifProperties carries GitHub code-scanning convention properties, e.g.
// CWE/OWASP tags surfaced from a rule's first-seen finding.
type sarifProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifMsg struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMsg          `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
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
	StartLine   int                   `json:"startLine"`
	StartColumn int                   `json:"startColumn,omitempty"`
	EndLine     int                   `json:"endLine,omitempty"`
	Snippet     *sarifArtifactContent `json:"snippet,omitempty"`
}

// sarifArtifactContent is the SARIF artifactContent object (spec §3.3),
// used for region.snippet.
type sarifArtifactContent struct {
	Text string `json:"text"`
}

func (r *sarifReporter) Render(rep *report.Report, dest io.Writer) error {
	// Build de-duplicated rule list preserving first-seen order.
	ruleIndex := make(map[string]int)
	var rules []sarifRule
	for _, f := range rep.Findings {
		if _, ok := ruleIndex[f.RuleID]; !ok {
			ruleIndex[f.RuleID] = len(rules)

			rule := sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleName,
				ShortDescription: sarifMsg{Text: f.RuleName},
			}

			if f.Rationale != "" {
				rule.FullDescription = &sarifMsg{Text: f.Rationale}
			}

			helpText := ""
			switch {
			case f.Rationale != "" && f.Remediation != "":
				helpText = f.Rationale + "\n\nRemediation: " + f.Remediation
			case f.Rationale != "":
				helpText = f.Rationale
			case f.Remediation != "":
				helpText = f.Remediation
			}
			// helpUri holds only one URL, so the rest of the rule's
			// references would be silently dropped without this.
			if len(f.References) > 1 {
				helpText += "\n\nReferences:"
				for _, ref := range f.References {
					helpText += "\n- " + ref
				}
			}
			if helpText != "" {
				rule.Help = &sarifMsg{Text: helpText}
			}

			if len(f.References) > 0 {
				rule.HelpURI = f.References[0]
			}

			var tags []string
			for _, c := range f.CWE {
				tags = append(tags, cweTag(c))
			}
			for _, o := range f.OWASP {
				tags = append(tags, owaspTag(o))
			}
			if len(tags) > 0 {
				rule.Properties = &sarifProperties{Tags: tags}
			}

			rules = append(rules, rule)
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

		var fingerprints map[string]string
		if f.Fingerprint != "" {
			fingerprints = map[string]string{"zerostrikeFingerprint/v1": f.Fingerprint}
		}

		region := sarifRegion{StartLine: line, StartColumn: col}
		if f.Location.EndLine > line {
			region.EndLine = f.Location.EndLine
		}
		if len(f.Evidence) > 0 && f.Evidence[0].Snippet != "" {
			region.Snippet = &sarifArtifactContent{Text: f.Evidence[0].Snippet}
		}

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
					Region: region,
				},
			}},
			PartialFingerprints: fingerprints,
		})
	}

	doc := sarifDoc{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ZeroStrike",
				Version:        rep.ScannerVersion,
				InformationURI: "https://github.com/Mohamedashmar432/zero-strike-SAST-engine",
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

// cweTag formats a rule YAML CWE entry (e.g. "CWE-611") as a GitHub
// code-scanning tag (e.g. "external/cwe/cwe-611").
func cweTag(id string) string {
	return "external/cwe/" + strings.ToLower(id)
}

// owaspTag formats a rule YAML OWASP entry (e.g. "A05:2025") as a GitHub
// code-scanning tag (e.g. "owasp:a05-2025").
func owaspTag(id string) string {
	return "owasp:" + strings.ReplaceAll(strings.ToLower(id), ":", "-")
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
