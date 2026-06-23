package findings

import (
	"github.com/zerostrike/scanner/internal/core"
	"github.com/zerostrike/scanner/internal/engine"
)

// Collector aggregates MatchResults from multiple files into Findings.
type Collector interface {
	Add(results []engine.MatchResult)
	All() []core.Finding
}

// Deduplicator removes duplicate findings by location hash.
type Deduplicator interface {
	Deduplicate(findings []core.Finding) []core.Finding
}
