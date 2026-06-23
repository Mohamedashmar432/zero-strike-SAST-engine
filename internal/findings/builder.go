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

	return core.Finding{
		ID:          uuid.New().String(),
		RuleID:      result.Rule.ID,
		RuleName:    result.Rule.Name,
		Category:    result.Rule.Category,
		Severity:    result.Rule.Severity,
		Confidence:  result.Rule.Confidence,
		Message:     result.Rule.Message,
		Location:    loc,
		Language:    lang,
		Fingerprint: fp,
		Evidence:    evidence,
		CWE:         result.Rule.CWE,
		OWASP:       result.Rule.OWASP,
		References:  result.Rule.References,
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
