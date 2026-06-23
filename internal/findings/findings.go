package findings

import "github.com/zerostrike/scanner/internal/core"

// Collector aggregates Findings from multiple files into a single slice.
// Implementations must be safe for concurrent Add calls.
type Collector interface {
	Add(findings []core.Finding)
	All() []core.Finding
}

// Deduplicator removes duplicate findings by location hash.
type Deduplicator interface {
	Deduplicate(findings []core.Finding) []core.Finding
}
