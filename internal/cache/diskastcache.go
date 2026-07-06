package cache

import (
	"os"
	"path/filepath"
)

// DiskASTCache is an ASTCache backed by one raw-bytes file per content hash
// under root, named "<contentHash>.bin".
//
// The cache key is contentHash alone. filePath is part of ASTCache's
// interface signature - a convenience for callers that already have it
// handy - but is deliberately never consulted here for the lookup key:
// content-addressing is the entire point of this cache, since it means the
// IR for a file survives that file being renamed or moved (as long as its
// content hash is unchanged) and is unaffected by rule-set changes (parsing
// doesn't depend on rules). Keying on filePath, or on filePath+contentHash,
// would defeat that design.
type DiskASTCache struct {
	root string
}

var _ ASTCache = (*DiskASTCache)(nil)

// NewDiskASTCache creates root (if needed) and returns a DiskASTCache
// rooted there.
func NewDiskASTCache(root string) (*DiskASTCache, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &DiskASTCache{root: root}, nil
}

// pathFor returns the on-disk path for contentHash's cached blob.
func (c *DiskASTCache) pathFor(contentHash string) string {
	return filepath.Join(c.root, contentHash+".bin")
}

// GetIR returns the cached IR blob for contentHash, or (nil, false) on a
// miss. filePath is ignored - see DiskASTCache's doc comment.
func (c *DiskASTCache) GetIR(filePath, contentHash string) ([]byte, bool) {
	data, err := os.ReadFile(c.pathFor(contentHash))
	if err != nil {
		return nil, false
	}
	return data, true
}

// SetIR stores data under contentHash, via the same atomic
// temp-file-then-rename pattern as DiskCache (see atomicWriteFile in
// diskcache.go). filePath is ignored - see DiskASTCache's doc comment.
func (c *DiskASTCache) SetIR(filePath, contentHash string, data []byte) error {
	return atomicWriteFile(c.pathFor(contentHash), data)
}
