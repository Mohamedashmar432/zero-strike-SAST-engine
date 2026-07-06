package cache

// Entry holds cached data for a single file.
type Entry struct {
	FilePath string
	SHA256   string
	// FindingIDs is unused by DiskCache: Finding.ID is a fresh
	// uuid.New().String() per run, so an ID alone can't reconstitute a
	// finding on a later run. Findings are persisted separately via
	// FindingStore/FindingCache, keyed by FilePath, not by this field.
	FindingIDs []string
}

// Cache stores and retrieves file scan results keyed by file path.
type Cache interface {
	Get(filePath string) (Entry, bool)
	Set(entry Entry) error
	Remove(filePath string) error
	Close() error
}
