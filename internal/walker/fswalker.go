package walker

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

// fsWalker is the concrete Walker implementation backed by the real filesystem.
type fsWalker struct {
	opts Options
}

// Walk starts a recursive traversal rooted at rootPath and returns channels
// through which FileEntry values and errors are delivered.
// The goroutine closes both channels when traversal completes.
func (w *fsWalker) Walk(rootPath string) (<-chan FileEntry, <-chan error) {
	entries := make(chan FileEntry, 64)
	errs := make(chan error, 16)

	go func() {
		defer close(entries)
		defer close(errs)
		w.walk(rootPath, rootPath, nil, entries, errs)
	}()

	return entries, errs
}

// walk performs the actual recursive descent.
// ignorePatterns accumulates patterns from ignore files found in parent dirs.
func (w *fsWalker) walk(
	rootPath, dirPath string,
	ignorePatterns []string,
	entries chan<- FileEntry,
	errs chan<- error,
) {
	// Load ignore patterns from this directory.
	patterns := w.loadIgnorePatterns(dirPath, ignorePatterns)

	dirEntries, err := os.ReadDir(dirPath)
	if err != nil {
		errs <- err
		return
	}

	for _, de := range dirEntries {
		fullPath := filepath.Join(dirPath, de.Name())

		if de.IsDir() {
			if isSkippedDir(de.Name(), w.opts.ExcludeDirs) {
				continue
			}
			// Recurse into sub-directory.
			w.walk(rootPath, fullPath, patterns, entries, errs)
			continue
		}

		// Regular file — apply filters.
		if !de.Type().IsRegular() {
			continue
		}
		if isSkippedExt(de.Name(), w.opts.ExcludeExts) {
			continue
		}

		info, err := de.Info()
		if err != nil {
			errs <- err
			continue
		}
		if isBinaryBySize(info.Size(), w.opts.MaxFileSizeBytes) {
			continue
		}

		// Check ignore patterns relative to root.
		rel, err := filepath.Rel(rootPath, fullPath)
		if err != nil {
			errs <- err
			continue
		}
		if isIgnored(rel, patterns) {
			continue
		}

		entry := FileEntry{
			Path:     fullPath,
			Language: core.LangUnknown,
			Size:     info.Size(),
		}
		if f, err := os.Open(fullPath); err == nil {
			buf := make([]byte, 512)
			n, _ := f.Read(buf)
			f.Close()
			entry.IsBinary = bytes.IndexByte(buf[:n], 0) >= 0
		}
		entries <- entry
	}
}

// loadIgnorePatterns merges existing patterns with any .gitignore / .zsignore
// files found directly inside dir.
func (w *fsWalker) loadIgnorePatterns(dir string, existing []string) []string {
	result := make([]string, len(existing))
	copy(result, existing)

	for _, name := range []string{".gitignore", ".zsignore"} {
		p, err := parseIgnoreFile(filepath.Join(dir, name))
		if err != nil {
			// File absent or unreadable — silently skip.
			continue
		}
		result = append(result, p...)
	}
	return result
}

// isIgnored reports whether relPath (relative to walk root) matches any pattern.
func isIgnored(relPath string, patterns []string) bool {
	for _, pat := range patterns {
		if matchesIgnorePattern(pat, relPath) {
			return true
		}
	}
	return false
}

// Ensure fsWalker satisfies the Walker interface at compile time.
var _ Walker = (*fsWalker)(nil)

