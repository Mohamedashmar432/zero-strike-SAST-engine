package cache

import "github.com/zerostrike/scanner/internal/core"

// FindingStore persists the findings produced for a file, keyed by file
// path, so a Cache hit can return the same findings without re-scanning.
//
// This is additive to Cache rather than folded into it: Entry.FindingIDs
// alone cannot reconstitute a core.Finding, since Finding.ID is a fresh
// uuid.New().String() minted per run (see internal/findings/builder.go) and
// therefore has no stable meaning across runs. A companion store keyed by
// file path (not by the ephemeral finding ID) is what actually lets a cache
// hit skip re-scanning a file.
type FindingStore interface {
	PutFindings(filePath string, findings []core.Finding) error
	GetFindings(filePath string) ([]core.Finding, error)
}
