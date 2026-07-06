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

// FindingCache is a Cache and FindingStore combined, plus PutRecord — the
// shape a caller wiring finding caching into the scan path actually needs.
// An Entry and the Findings it produced are always available together at
// the point a file finishes scanning, so PutRecord is the primary write
// path: it stores both as a single atomic write, with no read-modify-write
// step, so it can never leave a record pairing a fresh Entry with stale or
// absent Findings the way calling Set and PutFindings independently can
// (see DiskCache's doc comment for that failure mode). Set/PutFindings
// remain on Cache/FindingStore for interface compliance and for the rare
// case where only one half of a record is being updated on its own; new
// callers that have both an Entry and its Findings at once should prefer
// PutRecord.
type FindingCache interface {
	Cache
	FindingStore
	PutRecord(entry Entry, findings []core.Finding) error
}
