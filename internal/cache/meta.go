package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// FormatVersion is this package's on-disk cache layout version - bump by
// hand whenever DiskCache/DiskASTCache's file format changes.
const FormatVersion = 1

const (
	findingsDirName = "findings"
	irDirName       = "ir"
	metaFileName    = "meta.json"
)

// Meta records the versioning inputs that must match between a cache write
// and a cache read for that data to still be considered valid.
type Meta struct {
	FormatVersion   int
	EngineVersion   string
	RuleSetHash     string
	IRSchemaVersion int
}

// Manager bundles a finding cache and an AST cache under one cache root,
// opened together so their shared invalidation logic (see Open) applies
// consistently to both.
type Manager struct {
	Findings interface {
		Cache
		FindingStore
	}
	AST ASTCache
}

// Open opens (or initializes) the cache rooted at rootPath (typically
// "<scanRootPath>/.zerostrike/cache"), comparing the stored Meta (from a
// prior run, if any) against current. A mismatch triggers a whole-bucket
// wipe - never a partial/selective invalidation - per this severity table:
//
//   - FormatVersion mismatch: wipe the entire cache root
//   - EngineVersion mismatch: wipe both findings/ and ir/
//   - RuleSetHash mismatch:   wipe findings/ only (ir/ stays valid - parsing
//     doesn't depend on rules)
//   - IRSchemaVersion mismatch: wipe ir/ only
//
// Checks are performed in the order above and stop at the first mismatch,
// since a broader wipe (e.g. FormatVersion) makes narrower ones moot.
//
// After any wipe, current is written as the new meta.json before Open
// returns, so the next Open call compares against it. This is deliberately
// conservative - a whole-bucket wipe on ANY mismatch, never an attempt to
// invalidate "just the affected entries" - per this cache's stated design
// principle that under-invalidating (serving stale results) is worse than
// over-invalidating (an unnecessary cache miss).
//
// A meta.json that does not exist yet (first run) is not a mismatch: Open
// skips comparison entirely, writes current, and proceeds with fresh
// findings/ and ir/ subdirectories.
//
// A meta.json that DOES exist but can't be read or parsed (e.g. truncated
// by a crash during an out-of-band edit, or simply corrupted) is a genuine
// judgment call: this implementation treats it the same as a FormatVersion
// mismatch (wipe everything), rather than as "no prior meta" or as a hard
// error. Rationale: we have no way to know what the corrupt file was
// asserting compatibility with, and per this package's stated principle
// (over-invalidate rather than risk serving stale/unverifiable data), the
// safe choice is to treat "can't verify" the same as "known incompatible".
// Note meta.json itself is written via the same atomic temp-file+rename
// path as everything else in this package (see atomicWriteFile), so this
// should only be reachable via an out-of-band edit to the cache directory,
// not a torn write from this package's own code.
func Open(rootPath string, current Meta) (*Manager, error) {
	if err := os.MkdirAll(rootPath, 0o755); err != nil {
		return nil, err
	}

	findingsDir := filepath.Join(rootPath, findingsDirName)
	irDir := filepath.Join(rootPath, irDirName)
	metaPath := filepath.Join(rootPath, metaFileName)

	prev, exists, corrupt := readPriorMeta(metaPath)

	wipeAll := corrupt
	wipeFindings := false
	wipeIR := false

	if exists && !corrupt {
		switch {
		case prev.FormatVersion != current.FormatVersion:
			wipeAll = true
		case prev.EngineVersion != current.EngineVersion:
			wipeFindings = true
			wipeIR = true
		case prev.RuleSetHash != current.RuleSetHash:
			wipeFindings = true
		case prev.IRSchemaVersion != current.IRSchemaVersion:
			wipeIR = true
		}
	}

	if wipeAll {
		if err := os.RemoveAll(rootPath); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(rootPath, 0o755); err != nil {
			return nil, err
		}
	} else {
		if wipeFindings {
			if err := os.RemoveAll(findingsDir); err != nil {
				return nil, err
			}
		}
		if wipeIR {
			if err := os.RemoveAll(irDir); err != nil {
				return nil, err
			}
		}
	}

	metaData, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	if err := atomicWriteFile(metaPath, metaData); err != nil {
		return nil, err
	}

	findingsCache, err := NewDiskCache(findingsDir)
	if err != nil {
		return nil, err
	}
	astCache, err := NewDiskASTCache(irDir)
	if err != nil {
		return nil, err
	}

	return &Manager{Findings: findingsCache, AST: astCache}, nil
}

// readPriorMeta reads rootPath's meta.json, if any. It returns:
//   - (meta, true, false) if a valid prior Meta was read.
//   - (Meta{}, false, false) if no meta.json exists yet (first run).
//   - (Meta{}, false, true) if meta.json exists but could not be read or
//     parsed - see Open's doc comment for how this is handled.
func readPriorMeta(metaPath string) (prev Meta, exists bool, corrupt bool) {
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Meta{}, false, false
		}
		return Meta{}, false, true
	}
	if err := json.Unmarshal(data, &prev); err != nil {
		return Meta{}, false, true
	}
	return prev, true, false
}
