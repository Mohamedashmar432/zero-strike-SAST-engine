package cache

import "github.com/zerostrike/scanner/internal/core"

// NoopCache is a Cache and FindingStore that never stores anything and
// always reports a miss - the implementation used to satisfy --no-cache
// without special-casing "caching is disabled" throughout the scan path.
// It implements both interfaces (like DiskCache does) so a caller wiring
// --no-cache can use a single value wherever a Cache, a FindingStore, or
// both (e.g. cache.Manager.Findings, which requires both) are expected.
type NoopCache struct{}

var (
	_ Cache        = NoopCache{}
	_ FindingStore = NoopCache{}
)

func (NoopCache) Get(filePath string) (Entry, bool) { return Entry{}, false }
func (NoopCache) Set(entry Entry) error             { return nil }
func (NoopCache) Remove(filePath string) error      { return nil }
func (NoopCache) Close() error                      { return nil }

func (NoopCache) PutFindings(filePath string, findings []core.Finding) error {
	return nil
}

func (NoopCache) GetFindings(filePath string) ([]core.Finding, error) {
	return nil, nil
}

// NoopASTCache is an ASTCache that never stores anything and always reports
// a miss.
type NoopASTCache struct{}

var _ ASTCache = NoopASTCache{}

func (NoopASTCache) GetIR(filePath, contentHash string) ([]byte, bool) { return nil, false }
func (NoopASTCache) SetIR(filePath, contentHash string, data []byte) error {
	return nil
}
