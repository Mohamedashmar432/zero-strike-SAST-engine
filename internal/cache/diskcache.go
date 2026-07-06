package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/zerostrike/scanner/internal/core"
)

// diskCacheRecord is the on-disk JSON shape holding both the Cache Entry
// and the FindingStore findings for one file path, stored together in a
// single file (see DiskCache's doc comment for why).
type diskCacheRecord struct {
	Entry    Entry
	Findings []core.Finding
}

// DiskCache is a Cache and FindingStore backed by one JSON file per file
// path under root, named by the sha256 hex digest of the file path. File
// paths are not themselves safe/portable filesystem names (arbitrary
// length, path separators, characters reserved on Windows, etc.), so the
// path is hashed to produce the on-disk file name.
//
// Design choice - Set and PutFindings share one file: Cache.Set and
// FindingStore.PutFindings both describe the outcome of scanning the same
// file path (an Entry recording "this file was scanned, here is its content
// hash" and the Findings that scan produced belong together), and a caller
// wiring caching into the real scan path will naturally call both for the
// same file. Storing them in one diskCacheRecord per path - rather than two
// independent files/stores - means a cache lookup is one read, and rules
// out the two-files-disagreeing failure mode (e.g. an Entry says a file is
// cached but its findings file is missing, stale, or was never written).
//
// Set and PutFindings each still perform their own independent
// read-modify-write against that shared record, going through
// atomicWriteFile (temp file + rename) for the actual write. That keeps
// each individual call atomic - a concurrent reader always observes one
// complete diskCacheRecord, never a torn write mixing an old Entry with new
// Findings or vice versa - without needing a mutex. It does NOT make the
// pair of calls (Set then PutFindings) atomic as a unit: a crash between
// the two leaves a record with a fresh Entry (whose SHA256 matches the
// file's current content) but stale Findings from whatever the file
// produced last time it was successfully cached - a "hit" that looks valid
// by content hash but returns wrong findings, which is worse than a miss.
// This does NOT reliably self-heal on an unchanged file: once such a record
// exists, a later Get sees a hash match and there is no reason for anything
// to call PutFindings again for that file until its content next changes.
//
// PutRecord exists specifically to avoid this: it writes the Entry and
// Findings together as one atomic write, with no read first, so the
// inconsistent-pairing window described above cannot occur. Callers that
// have both an Entry and its Findings available at once (the normal case
// right after scanning a file) should use PutRecord, not Set+PutFindings.
// Set and PutFindings remain for Cache/FindingStore interface compliance
// and for updating only one half of a record on its own.
type DiskCache struct {
	root string
}

var (
	_ Cache        = (*DiskCache)(nil)
	_ FindingStore = (*DiskCache)(nil)
	_ FindingCache = (*DiskCache)(nil)
)

// NewDiskCache creates root (if needed) and returns a DiskCache rooted there.
func NewDiskCache(root string) (*DiskCache, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &DiskCache{root: root}, nil
}

// pathFor returns the on-disk path for filePath's cache record.
func (c *DiskCache) pathFor(filePath string) string {
	sum := sha256.Sum256([]byte(filePath))
	return filepath.Join(c.root, hex.EncodeToString(sum[:])+".json")
}

// readRecord reads and unmarshals filePath's record. The second return
// value is false for any read/parse failure (missing file, permission
// error, corrupt JSON) - all treated uniformly as a cache miss so a bad
// cache file can never block a scan, only cost it a re-scan/re-compute.
func (c *DiskCache) readRecord(filePath string) (diskCacheRecord, bool) {
	data, err := os.ReadFile(c.pathFor(filePath))
	if err != nil {
		return diskCacheRecord{}, false
	}
	var rec diskCacheRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return diskCacheRecord{}, false
	}
	return rec, true
}

// writeRecord marshals rec and writes it atomically to filePath's cache file.
func (c *DiskCache) writeRecord(filePath string, rec diskCacheRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return atomicWriteFile(c.pathFor(filePath), data)
}

// Get returns the cached Entry for filePath, or (Entry{}, false) on a miss.
func (c *DiskCache) Get(filePath string) (Entry, bool) {
	rec, ok := c.readRecord(filePath)
	if !ok {
		return Entry{}, false
	}
	return rec.Entry, true
}

// Set stores entry, preserving any Findings already recorded for the same
// file path (read-modify-write against the shared record - see DiskCache's
// doc comment).
func (c *DiskCache) Set(entry Entry) error {
	rec, _ := c.readRecord(entry.FilePath)
	rec.Entry = entry
	return c.writeRecord(entry.FilePath, rec)
}

// Remove deletes filePath's cache record entirely (Entry and Findings
// together). Removing an already-absent entry is not an error.
func (c *DiskCache) Remove(filePath string) error {
	err := os.Remove(c.pathFor(filePath))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Close is a no-op: DiskCache holds no open file handles between calls.
func (c *DiskCache) Close() error { return nil }

// PutFindings stores findings, preserving any Entry already recorded for
// the same file path (read-modify-write against the shared record - see
// DiskCache's doc comment).
func (c *DiskCache) PutFindings(filePath string, findings []core.Finding) error {
	rec, _ := c.readRecord(filePath)
	rec.Findings = findings
	return c.writeRecord(filePath, rec)
}

// GetFindings returns the cached findings for filePath, or (nil, nil) on a
// miss.
func (c *DiskCache) GetFindings(filePath string) ([]core.Finding, error) {
	rec, ok := c.readRecord(filePath)
	if !ok {
		return nil, nil
	}
	return rec.Findings, nil
}

// PutRecord stores entry and findings together as a single atomic write,
// with no preceding read — unlike Set and PutFindings, which each do a
// read-modify-write against whatever record (if any) already exists for
// entry.FilePath. This is the primary write path for a caller that always
// has both an Entry and its Findings at once (the normal case at the end of
// scanning one file): it cannot leave a record pairing a fresh Entry with
// stale or absent Findings, because the two are never written separately.
func (c *DiskCache) PutRecord(entry Entry, findings []core.Finding) error {
	return c.writeRecord(entry.FilePath, diskCacheRecord{Entry: entry, Findings: findings})
}

// atomicWriteFile writes data to finalPath by first writing to a temp file
// in the same directory, then renaming it into place. os.Rename is atomic
// on both POSIX and Windows for same-volume renames (the temp file is
// deliberately created in finalPath's own directory to guarantee same-
// volume), so a concurrent reader of finalPath always observes either the
// previous complete file or the new complete file - never a partial write.
// That single guarantee is the entire concurrency mechanism this package
// relies on for safety under multiple concurrent scan workers; no mutex is
// needed because there is never a window where finalPath holds partial
// data.
func atomicWriteFile(finalPath string, data []byte) error {
	dir := filepath.Dir(finalPath)
	tmp, err := os.CreateTemp(dir, "*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
