package ir

// Builder converts a language-specific parse result into an IRFile.
// Each language parser implements this interface.
type Builder interface {
	Build(path string, source []byte) (*IRFile, error)
}
