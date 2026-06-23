// Package walker provides recursive filesystem traversal for ZeroStrike.
// It respects .gitignore and .zsignore files found during traversal, skips
// well-known non-source directories, and filters binary files.
package walker

import "github.com/zerostrike/scanner/internal/core"

// FileEntry represents a single source file discovered during a walk.
type FileEntry struct {
	Path     string
	Language core.Language
	Size     int64
}

// Options controls the behaviour of a Walker.
// Zero-value fields use package-level defaults.
type Options struct {
	// MaxFileSizeBytes is the upper size limit for files that are emitted.
	// Files larger than this are silently skipped.
	// Default: 1 MB (1 << 20 bytes).
	MaxFileSizeBytes int64

	// ExcludeDirs contains additional directory names to skip.
	// Merged with the hardcoded defaults at construction time.
	ExcludeDirs []string

	// ExcludeExts contains additional file extensions (with leading dot) to skip.
	// Merged with the hardcoded defaults at construction time.
	ExcludeExts []string
}

// Walker walks a directory tree and streams discovered FileEntry values.
type Walker interface {
	// Walk starts a recursive traversal rooted at rootPath.
	// It returns two channels: one for file entries and one for non-fatal
	// errors encountered during traversal.  Both channels are closed once
	// the walk has finished.  Walk itself does not block — traversal runs
	// in a background goroutine.
	Walk(rootPath string) (<-chan FileEntry, <-chan error)
}

// NewWalker constructs a Walker that applies the supplied Options.
// A nil Options pointer is accepted and causes all defaults to be used.
func NewWalker(opts *Options) Walker {
	const defaultMaxSize int64 = 1 << 20 // 1 MB

	effective := Options{MaxFileSizeBytes: defaultMaxSize}
	if opts != nil {
		if opts.MaxFileSizeBytes > 0 {
			effective.MaxFileSizeBytes = opts.MaxFileSizeBytes
		}
		effective.ExcludeDirs = opts.ExcludeDirs
		effective.ExcludeExts = opts.ExcludeExts
	}

	return &fsWalker{opts: effective}
}
