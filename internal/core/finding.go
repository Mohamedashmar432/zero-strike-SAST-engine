package core

// Severity describes how critical a security finding is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence describes how certain the engine is about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Evidence is a code snippet associated with a finding.
type Evidence struct {
	Snippet   string
	StartLine int
	EndLine   int
}

// Finding represents a single security issue detected in source code.
type Finding struct {
	ID          string
	RuleID      string
	RuleName    string
	Category    string
	Severity    Severity
	Confidence  Confidence
	Message     string
	Location    Location
	Language    Language
	Evidence    []Evidence
	CWE         []string
	OWASP       []string
	References  []string
	Metadata    map[string]string
	Fingerprint string // stable cross-run identity: hash(ruleID + enclosingSymbol + normalizedSnippet)
}
