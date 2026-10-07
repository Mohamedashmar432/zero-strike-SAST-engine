package findings

import (
	"fmt"
	"strings"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// intraRunKey is the dedup key for eliminating exact duplicates within a single scan.
// Intentionally includes line/column — only catches identical locations in one run.
// Cross-run identity uses Finding.Fingerprint instead.
func intraRunKey(f core.Finding) string {
	return fmt.Sprintf("%s|%s|%d|%d", f.RuleID, f.Location.File, f.Location.StartLine, f.Location.StartCol)
}

// credentialRuleIDs are the rules across both engines that report the same
// underlying fact: a credential written as a literal in source.
//
// The SAST "Hardcoded Credential" rules and the secrets detectors run
// independently and neither knows about the other, so one line produced two
// findings and one config.py:9 became four rows across two severities. The
// duplication is not a false positive, but it inflates the count and makes a
// reviewer triage the same decision twice.
var credentialRuleIDs = map[string]bool{
	// Secrets engine — generic credential shapes.
	"ZS-SEC-003": true, // generic-api-key
	"ZS-SEC-004": true, // hardcoded-password
	"ZS-SEC-012": true, // mongodb-uri
	"ZS-SEC-013": true, // postgresql-uri
	"ZS-SEC-014": true, // mysql-uri
	"ZS-SEC-015": true, // redis-uri
	"ZS-SEC-016": true, // json-yaml-secret
	// SAST — "Hardcoded Credential", one rule per language.
	"ZS-PY-020":   true,
	"ZS-JS-007":   true,
	"ZS-TS-012":   true,
	"ZS-GO-005":   true,
	"ZS-JAVA-005": true,
	"ZS-PHP-005":  true,
	"ZS-CS-006":   true,
	// v0.37.0 credential detectors (CWE-798). The comparison, pair and
	// keyword forms routinely land on the same line as ZS-SEC-004/027, and
	// one hardcoded credential is one finding. Key-material rules (CWE-321)
	// are deliberately absent: merging one into a CWE-798 finding would
	// drop the more specific weakness.
	"ZS-SEC-027": true, // hardcoded-password-comparison
	"ZS-SEC-028": true, // xml-credential
	"ZS-SEC-031": true, // dotenv-secret
	"ZS-SEC-032": true, // compose-env-secret
	"ZS-PY-140":  true,
	"ZS-PY-141":  true,
	"ZS-PY-144":  true,
	"ZS-PY-145":  true,
	"ZS-JS-140":  true,
	"ZS-JS-141":  true,
	"ZS-JS-143":  true,
	"ZS-JS-146":  true,
	"ZS-TS-140":  true,
	"ZS-TS-141":  true,
	"ZS-TS-143":  true,
	"ZS-TS-146":  true,
}

// normalizedClass returns the cross-engine finding class for f, or "" when f
// belongs to no shared class and should dedup on its rule ID alone.
//
// Only the credential family is classified. Rule-ID namespaces are otherwise
// disjoint (ZS-SEC-* / ZS-PY-* / ZS-CFG-*), so the default key shape is left
// exactly as it was rather than broadened speculatively.
func normalizedClass(f core.Finding) string {
	if credentialRuleIDs[f.RuleID] {
		return "credential"
	}
	return ""
}

// classKey drops the column deliberately: the two engines locate the same
// literal at different columns — one at the assignment, one at the matched
// value — so a column-sensitive key would never collapse them.
func classKey(class string, f core.Finding) string {
	return fmt.Sprintf("%s|%s|%d", class, f.Location.File, f.Location.StartLine)
}

type defaultDeduplicator struct{}

// NewDeduplicator returns a Deduplicator that removes intra-run duplicates.
func NewDeduplicator() Deduplicator { return &defaultDeduplicator{} }

func (d *defaultDeduplicator) Deduplicate(findings []core.Finding) []core.Finding {
	// Maps to the index in out rather than to a presence bit, so a duplicate
	// can merge its evidence into the finding that was kept instead of being
	// silently discarded.
	seen := make(map[string]int, len(findings))
	out := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		k := intraRunKey(f)
		if class := normalizedClass(f); class != "" {
			k = classKey(class, f)
		}
		if i, dup := seen[k]; dup {
			if preferred(f, out[i]) {
				// Keep the AST-backed finding as the representative and
				// record the line-regex one under also_reported_by. Scanners
				// run concurrently, so "first one in" was a coin toss over
				// which rule ID (and message) the user saw for one credential.
				prev := out[i]
				out[i] = f
				mergeDuplicate(&out[i], prev)
				continue
			}
			mergeDuplicate(&out[i], f)
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	return out
}

// mergeDuplicate records that a second rule reported the same fact, so the
// dropped finding's provenance survives in the kept one. Without this the
// second engine's contribution disappears without trace, which is worse than
// double-counting: a reviewer cannot tell the finding was corroborated.
func mergeDuplicate(kept *core.Finding, dropped core.Finding) {
	if kept.RuleID == dropped.RuleID {
		return // an exact duplicate of the same rule adds nothing
	}
	if kept.Metadata == nil {
		kept.Metadata = make(map[string]string, 1)
	}
	const key = "also_reported_by"
	for _, existing := range strings.Split(kept.Metadata[key], ",") {
		if existing == dropped.RuleID {
			return
		}
	}
	if prev := kept.Metadata[key]; prev != "" {
		kept.Metadata[key] = prev + "," + dropped.RuleID
	} else {
		kept.Metadata[key] = dropped.RuleID
	}
}

// preferred reports whether candidate should replace kept as the
// representative of a merged credential class: a SAST finding (it carries
// the AST node, enclosing symbol and rule-specific remediation) wins over a
// secret-scanner line match. Otherwise the first finding stays.
func preferred(candidate, kept core.Finding) bool {
	return candidate.Kind == core.FindingKindSAST && kept.Kind != core.FindingKindSAST
}
