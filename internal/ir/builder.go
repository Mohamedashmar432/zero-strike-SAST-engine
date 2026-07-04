package ir

// BuildWarning is a lightweight diagnostic emitted when a Builder encounters a
// recoverable problem (e.g. a tree-sitter ERROR node). It does not stop
// analysis of the surrounding file.
type BuildWarning struct {
	File    string
	Message string
	Line    int
}

// Builder is a self-contained parse+IR entrypoint for one language: it parses
// source and converts the resulting CST into an IRFile. Each language package
// implements this interface and registers a constructor with
// internal/langreg, which is the single dispatch table used by the SAST
// scanner.
type Builder interface {
	Build(path string, source []byte) (*IRFile, []BuildWarning, error)
}
