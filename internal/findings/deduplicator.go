package findings

import (
	"fmt"

	"github.com/zerostrike/scanner/internal/core"
)

// intraRunKey is the dedup key for eliminating exact duplicates within a single scan.
// Intentionally includes line/column — only catches identical locations in one run.
// Cross-run identity uses Finding.Fingerprint instead.
func intraRunKey(f core.Finding) string {
	return fmt.Sprintf("%s|%s|%d|%d", f.RuleID, f.Location.File, f.Location.StartLine, f.Location.StartCol)
}

type defaultDeduplicator struct{}

// NewDeduplicator returns a Deduplicator that removes intra-run duplicates.
func NewDeduplicator() Deduplicator { return &defaultDeduplicator{} }

func (d *defaultDeduplicator) Deduplicate(findings []core.Finding) []core.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		k := intraRunKey(f)
		if _, dup := seen[k]; !dup {
			seen[k] = struct{}{}
			out = append(out, f)
		}
	}
	return out
}
