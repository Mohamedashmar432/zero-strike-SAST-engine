package secrets

import (
	"bytes"
	"context"
	"math"
	"os"
	"regexp"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/analyzer"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/findings"
	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/walker"
)

type detector struct {
	ruleID     string
	detectorID string
	pattern    *regexp.Regexp
	severity   core.Severity
	minEntropy float64 // 0 = no entropy filter
}

var detectors = []detector{
	{
		ruleID:     "ZS-SEC-001",
		detectorID: "aws-access-key",
		pattern:    regexp.MustCompile(`(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-002",
		detectorID: "github-token",
		pattern:    regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-003",
		detectorID: "generic-api-key",
		pattern:    regexp.MustCompile(`(?i)api[_\-]?key\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,64})["']?`),
		severity:   core.SeverityHigh,
		minEntropy: 3.0,
	},
	{
		ruleID:     "ZS-SEC-004",
		detectorID: "hardcoded-password",
		pattern:    regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']`),
		severity:   core.SeverityHigh,
		minEntropy: 3.0,
	},
	{
		ruleID:     "ZS-SEC-005",
		detectorID: "private-key-pem",
		pattern:    regexp.MustCompile(`-----BEGIN (?:\w+ )?PRIVATE KEY-----`),
		severity:   core.SeverityCritical,
	},
}

// SecretsScanner detects hardcoded secrets via regex patterns.
// Pure Go — no CGo, testable on Windows without gcc.
type SecretsScanner struct{}

// New returns a SecretsScanner.
func New() *SecretsScanner { return &SecretsScanner{} }

func (s *SecretsScanner) Name() string { return "secrets" }

func (s *SecretsScanner) Accepts(entry walker.FileEntry) bool {
	return !entry.IsBinary
}

func (s *SecretsScanner) Scan(_ context.Context, files []walker.FileEntry) ([]core.Finding, []analyzer.Diagnostic, error) {
	var out []core.Finding
	for _, entry := range files {
		data, err := os.ReadFile(entry.Path)
		if err != nil {
			continue
		}
		out = append(out, scanContent(entry.Path, data)...)
	}
	return out, nil, nil
}

func scanContent(path string, data []byte) []core.Finding {
	var out []core.Finding
	lines := bytes.Split(data, []byte("\n"))
	for lineNum, line := range lines {
		for _, d := range detectors {
			match := d.pattern.FindSubmatch(line)
			if match == nil {
				continue
			}
			// Use captured group (index 1) if present, else full match.
			captured := match[0]
			if len(match) > 1 {
				captured = match[1]
			}
			if d.minEntropy > 0 && shannonEntropy(string(captured)) < d.minEntropy {
				continue
			}
			name := d.detectorID
			f := findings.BuildSecretFinding(
				d.detectorID,
				d.ruleID,
				name,
				"Potential "+name+" detected",
				path,
				lineNum+1,
				captured,
				shannonEntropy(string(captured)),
				d.severity,
			)
			out = append(out, f)
		}
	}
	return out
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
