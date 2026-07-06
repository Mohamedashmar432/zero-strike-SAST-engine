package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/engine"
	"github.com/zerostrike/scanner/internal/symboltable"
)

// DependencyInput carries the fields needed to build a DependencyFinding.
type DependencyInput struct {
	Ecosystem        string
	Package          string
	InstalledVersion string
	VulnerableRange  string
	FixedVersion     string
	Manifest         string
	Direct           bool
}

// BuildFinding converts a MatchResult into a core.Finding with a stable cross-run Fingerprint.
func BuildFinding(result engine.MatchResult, mc *engine.MatchContext) core.Finding {
	node := result.Node
	loc := node.Location
	if mc.File != nil && mc.File.IR != nil {
		loc.File = mc.File.IR.Path
	}

	enclosingSym := ""
	if mc.File != nil && mc.File.Symbols != nil {
		enclosingSym = enclosingSymbolName(loc, mc.File.Symbols)
	}

	fp := computeFingerprint(result.Rule.ID, enclosingSym, node.Text)

	var evidence []core.Evidence
	if node.Text != "" {
		evidence = []core.Evidence{{Snippet: node.Text, StartLine: loc.StartLine, EndLine: loc.EndLine}}
	}

	lang := core.LangUnknown
	if mc.File != nil && mc.File.IR != nil {
		lang = mc.File.IR.Language
	}

	var taintCtx *core.TaintContext
	if result.TaintedVar != "" {
		sink := result.Rule.Match.Callee
		if sink == "" {
			if lhs, ok := node.Attrs["lhs"].(string); ok {
				sink = lhs
			}
		}
		sourceExpr := ""
		if mc.File != nil {
			sourceExpr = mc.File.TaintReasons[result.TaintedVar]
		}
		taintCtx = &core.TaintContext{
			SourceVar:  result.TaintedVar,
			SourceExpr: sourceExpr,
			Sink:       sink,
		}
	}

	return core.Finding{
		ID:           uuid.New().String(),
		RuleID:       result.Rule.ID,
		RuleName:     result.Rule.Name,
		Category:     result.Rule.Category,
		Severity:     result.Rule.Severity,
		Confidence:   result.Rule.Confidence,
		Message:      result.Rule.Message,
		Location:     loc,
		Language:     lang,
		Fingerprint:  fp,
		Evidence:     evidence,
		CWE:          result.Rule.CWE,
		OWASP:        result.Rule.OWASP,
		References:   result.Rule.References,
		Rationale:    result.Rule.Rationale,
		Remediation:  result.Rule.FixSuggestion,
		Kind:         core.FindingKindSAST,
		TaintContext: taintCtx,
	}
}

// BuildSecretFinding constructs a core.Finding for a detected secret.
// rawSecret is hashed immediately and never stored in the returned Finding.
func BuildSecretFinding(
	detectorID, ruleID, ruleName, message, filePath string,
	line int,
	rawSecret []byte,
	entropy float64,
	severity core.Severity,
) core.Finding {
	// Fingerprint: sha256(detectorID + "|" + hex(sha256(rawSecret[:32])))[:16]
	cap := len(rawSecret)
	if cap > 32 {
		cap = 32
	}
	secretHash := sha256.Sum256(rawSecret[:cap])
	fp := sha256.Sum256([]byte(detectorID + "|" + hex.EncodeToString(secretHash[:])))
	fingerprint := hex.EncodeToString(fp[:])[:16]

	redacted := "****"
	if len(rawSecret) >= 4 {
		redacted = string(rawSecret[:4]) + "****"
	}

	return core.Finding{
		ID:          uuid.New().String(),
		RuleID:      ruleID,
		RuleName:    ruleName,
		Category:    "secret",
		Severity:    severity,
		Confidence:  core.ConfidenceHigh,
		Message:     message,
		Location:    core.Location{File: filePath, StartLine: line, EndLine: line},
		Language:    core.LangUnknown,
		Fingerprint: fingerprint,
		Kind:        core.FindingKindSecret,
		Secret: &core.SecretFinding{
			DetectorID: detectorID,
			Entropy:    entropy,
			Redacted:   redacted,
		},
	}
}

// BuildDependencyFinding constructs a core.Finding for a vulnerable dependency.
func BuildDependencyFinding(
	ruleID, ruleName, message string,
	dep DependencyInput,
	advisoryIDs []string,
	severity core.Severity,
	confidence core.Confidence,
) core.Finding {
	primary := "none"
	if len(advisoryIDs) > 0 {
		primary = advisoryIDs[0]
	}
	fp := sha256.Sum256([]byte(dep.Ecosystem + "|" + dep.Package + "|" + primary))
	fingerprint := hex.EncodeToString(fp[:])[:16]

	return core.Finding{
		ID:          uuid.New().String(),
		RuleID:      ruleID,
		RuleName:    ruleName,
		Category:    "dependency",
		Severity:    severity,
		Confidence:  confidence,
		Message:     message,
		Location:    core.Location{File: dep.Manifest},
		Language:    core.LangUnknown,
		Fingerprint: fingerprint,
		Kind:        core.FindingKindSCA,
		Dependency: &core.DependencyFinding{
			Ecosystem:        dep.Ecosystem,
			Package:          dep.Package,
			InstalledVersion: dep.InstalledVersion,
			VulnerableRange:  dep.VulnerableRange,
			FixedVersion:     dep.FixedVersion,
			AdvisoryIDs:      advisoryIDs,
			Manifest:         dep.Manifest,
			Direct:           dep.Direct,
		},
	}
}

// ConfigInput carries the fields needed to build a ConfigFinding.
type ConfigInput struct {
	Framework  string
	ConfigFile string
	Key        string
	Value      string // matched text, for message/evidence only — never a credential, no redaction needed
}

// BuildConfigFinding constructs a core.Finding for a detected framework misconfiguration.
func BuildConfigFinding(
	ruleID, ruleName, message, category string,
	input ConfigInput,
	loc core.Location,
	severity core.Severity,
	confidence core.Confidence,
	cwe, owasp []string,
) core.Finding {
	fp := sha256.Sum256([]byte(ruleID + "|" + input.ConfigFile + "|" + input.Key))
	fingerprint := hex.EncodeToString(fp[:])[:16]

	var evidence []core.Evidence
	if input.Value != "" {
		evidence = []core.Evidence{{Snippet: input.Value, StartLine: loc.StartLine, EndLine: loc.EndLine}}
	}

	return core.Finding{
		ID:          uuid.New().String(),
		RuleID:      ruleID,
		RuleName:    ruleName,
		Category:    category,
		Severity:    severity,
		Confidence:  confidence,
		Message:     message,
		Location:    loc,
		Language:    core.LangUnknown,
		Evidence:    evidence,
		CWE:         cwe,
		OWASP:       owasp,
		Fingerprint: fingerprint,
		Kind:        core.FindingKindConfig,
		Config: &core.ConfigFinding{
			Framework:  input.Framework,
			ConfigFile: input.ConfigFile,
			Key:        input.Key,
		},
	}
}

// computeFingerprint returns a 16-char hex fingerprint stable across line-number changes.
// Hash input: ruleID + "|" + enclosingSymbol + "|" + normalizedSnippet.
func computeFingerprint(ruleID, enclosingSym, snippet string) string {
	normalized := strings.Join(strings.Fields(strings.TrimSpace(snippet)), " ")
	h := sha256.Sum256([]byte(ruleID + "|" + enclosingSym + "|" + normalized))
	return hex.EncodeToString(h[:])[:16]
}

func enclosingSymbolName(loc core.Location, syms symboltable.SymbolTable) string {
	for _, sym := range syms.AllSymbols() {
		if (sym.Kind == symboltable.SymbolFunction || sym.Kind == symboltable.SymbolClass) &&
			sym.Location.StartLine <= loc.StartLine && sym.Location.EndLine >= loc.StartLine {
			return sym.Name
		}
	}
	return ""
}
