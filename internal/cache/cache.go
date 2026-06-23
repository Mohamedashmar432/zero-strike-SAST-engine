package cache

// Entry holds cached data for a single file.
type Entry struct {
	FilePath   string
	SHA256     string
	FindingIDs []string
}

// Cache stores and retrieves file scan results keyed by file path.
type Cache interface {
	Get(filePath string) (Entry, bool)
	Set(entry Entry) error
	Remove(filePath string) error
	Close() error
}
