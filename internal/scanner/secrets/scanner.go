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
		pattern:    regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})`),
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
		pattern:    regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-006",
		detectorID: "sendgrid-api-key",
		pattern:    regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-007",
		detectorID: "slack-token",
		pattern:    regexp.MustCompile(`(xox[baprs]-[0-9a-zA-Z]{10,48})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-008",
		detectorID: "stripe-api-key",
		pattern:    regexp.MustCompile(`((?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-009",
		detectorID: "google-cloud-api-key",
		pattern:    regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-010",
		detectorID: "azure-secret",
		pattern:    regexp.MustCompile(`(?i)(?:azure[_\-]?secret|azure[_\-]?key)\s*[:=]\s*["']?([a-zA-Z0-9~_.-]{34})["']?`),
		severity:   core.SeverityHigh,
		minEntropy: 3.0,
	},
	{
		ruleID:     "ZS-SEC-011",
		detectorID: "jwt-token",
		pattern:    regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
		severity:   core.SeverityMedium,
	},
	{
		ruleID:     "ZS-SEC-012",
		detectorID: "mongodb-uri",
		pattern:    regexp.MustCompile(`(mongodb(?:\+srv)?:\/\/[^:\s"']+:[^@\s"']+@[^\s"']+)`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-013",
		detectorID: "postgresql-uri",
		pattern:    regexp.MustCompile(`(postgres(?:ql)?:\/\/[^:\s"']+:[^@\s"']+@[^\s"']+)`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-014",
		detectorID: "mysql-uri",
		pattern:    regexp.MustCompile(`(mysql:\/\/[^:\s"']+:[^@\s"']+@[^\s"']+)`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-015",
		detectorID: "redis-uri",
		pattern:    regexp.MustCompile(`(redis:\/\/(?:[^:\s"']*:[^@\s"']+@)[^\s"']+)`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-016",
		detectorID: "json-yaml-secret",
		// Deliberately excludes api_key and password/passwd/pwd: ZS-SEC-003 and
		// ZS-SEC-004 already match those keywords on every file type, so keeping
		// them here reported the same line twice. Only the keywords no other
		// detector covers belong in this alternation.
		pattern:    regexp.MustCompile(`(?i)"?(?:secret|access_key|token)"?\s*[:=]\s*"([^"]{6,})"`),
		severity:   core.SeverityMedium,
		minEntropy: 3.0,
	},
	{
		ruleID:     "ZS-SEC-017",
		detectorID: "twilio-api-key",
		pattern:    regexp.MustCompile(`(SK[0-9a-fA-F]{32})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-018",
		detectorID: "mailgun-api-key",
		pattern:    regexp.MustCompile(`(key-[0-9a-zA-Z]{32})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-019",
		detectorID: "square-access-token",
		pattern:    regexp.MustCompile(`(sq0atp-[0-9A-Za-z\-_]{22})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-020",
		detectorID: "pypi-token",
		pattern:    regexp.MustCompile(`(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-021",
		detectorID: "npm-token",
		pattern:    regexp.MustCompile(`(npm_[A-Za-z0-9]{32,36})`),
		severity:   core.SeverityCritical,
	},
	{
		ruleID:     "ZS-SEC-022",
		detectorID: "heroku-api-key",
		pattern:    regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-023",
		detectorID: "vault-token",
		pattern:    regexp.MustCompile(`(?:^|[^a-zA-Z0-9])(hvs\.[a-zA-Z0-9_-]{90,}|s\.[a-zA-Z0-9]{24})(?:[^a-zA-Z0-9]|$)`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-024",
		detectorID: "discord-bot-token",
		pattern:    regexp.MustCompile(`([MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-025",
		detectorID: "shopify-token",
		pattern:    regexp.MustCompile(`(shpat_[a-fA-F0-9]{32}|shpca_[a-fA-F0-9]{32})`),
		severity:   core.SeverityHigh,
	},
	{
		ruleID:     "ZS-SEC-026",
		detectorID: "openai-api-key",
		pattern:    regexp.MustCompile(`(sk-(?:proj-)?[a-zA-Z0-9\-_]{32,})`),
		severity:   core.SeverityHigh,
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
