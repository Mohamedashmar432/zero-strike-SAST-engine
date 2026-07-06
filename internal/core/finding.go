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

// FindingKind discriminates between the three scanner modalities.
type FindingKind string

const (
	FindingKindSAST   FindingKind = "sast"
	FindingKindSecret FindingKind = "secret"
	FindingKindSCA    FindingKind = "sca"
	FindingKindConfig FindingKind = "config"
)

// SecretFinding carries metadata for a detected secret.
type SecretFinding struct {
	DetectorID string
	Entropy    float64
	Redacted   string // first 4 chars + "****" — display only, never fingerprinted
}

// DependencyFinding carries metadata for a vulnerable dependency.
type DependencyFinding struct {
	Ecosystem        string
	Package          string
	InstalledVersion string
	VulnerableRange  string
	FixedVersion     string   // "" if no fix published
	AdvisoryIDs      []string // CVE-…, GHSA-…, PYSEC-…, OSV-…
	Manifest         string   // path to the lock file
	Direct           bool
}

// ConfigFinding carries metadata for a detected framework misconfiguration.
type ConfigFinding struct {
	Framework  string // "django" | "express" | "cors" | "laravel"
	ConfigFile string
	Key        string
}

// Evidence is a code snippet associated with a finding.
type Evidence struct {
	Snippet   string
	StartLine int
	EndLine   int
}

// TaintContext describes the tainted-data flow that produced a finding,
// when the finding depended on taint tracking (see internal/analyzer/taint).
type TaintContext struct {
	SourceVar  string // tainted identifier referenced at the sink, e.g. "q"
	SourceExpr string // the RHS/expression snippet that introduced the taint, e.g. "request.args.get('q')"
	Sink       string // sink callee or LHS attribute, e.g. "os.system" or "innerHTML"
}

// Finding represents a single security issue detected in source code.
type Finding struct {
	ID           string
	RuleID       string
	RuleName     string
	Category     string
	Severity     Severity
	Confidence   Confidence
	Message      string
	Location     Location
	Language     Language
	Evidence     []Evidence
	CWE          []string
	OWASP        []string
	References   []string
	Metadata     map[string]string
	Fingerprint  string // stable cross-run identity: hash(ruleID + enclosingSymbol + normalizedSnippet)
	Kind         FindingKind
	Secret       *SecretFinding     // non-nil iff Kind == FindingKindSecret
	Dependency   *DependencyFinding // non-nil iff Kind == FindingKindSCA
	Config       *ConfigFinding     // non-nil iff Kind == FindingKindConfig
	Rationale    string             // reviewer-facing "why this is risky" explanation, from rule YAML
	Remediation  string             // concrete fix guidance, from the rule's FixSuggestion (populated by internal/findings.BuildFinding)
	TaintContext *TaintContext      // non-nil iff the finding depended on tainted-data tracking
}
