package walker

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// hardcodedSkipDirs lists directory names that are always excluded.
var hardcodedSkipDirs = []string{
	// VCS / tooling
	".git", ".zerostrike",
	// Dependencies / vendored code
	"vendor", "node_modules",
	// Python runtime artifacts and virtual envs
	"__pycache__", ".venv", "venv",
	// Static / generated / build output (common source of false positives)
	"static", "assets", "public", "media",
	"dist", "build", "bin", "obj",
	// Test coverage and linter caches
	"htmlcov", "coverage", ".tox", ".pytest_cache",
	".mypy_cache", ".ruff_cache",
	// Framework migration dirs
	"migrations",
}

// hardcodedBinaryExts lists file extensions that are always treated as binary.
var hardcodedBinaryExts = []string{
	".exe", ".dll", ".so", ".dylib",
	".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
	".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
	".pdf", ".class", ".pyc", ".pyd", ".wasm",
}

// isSkippedDir reports whether dirName should be excluded from traversal.
// caller passes just the base name of the directory, not a full path.
func isSkippedDir(dirName string, extra []string) bool {
	for _, d := range hardcodedSkipDirs {
		if dirName == d {
			return true
		}
	}
	for _, d := range extra {
		if dirName == d {
			return true
		}
	}
	return false
}

// isSkippedExt reports whether the file identified by name should be excluded
// based on its extension.
func isSkippedExt(name string, extra []string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		return false
	}
	for _, e := range hardcodedBinaryExts {
		if ext == e {
			return true
		}
	}
	for _, e := range extra {
		if ext == e {
			return true
		}
	}
	return false
}

// isBinaryBySize reports whether a file whose size is known exceeds the limit.
func isBinaryBySize(size, maxBytes int64) bool {
	return size > maxBytes
}

// parseIgnoreFile reads a .gitignore / .zsignore file and returns the list
// of non-comment, non-empty pattern lines.
func parseIgnoreFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, scanner.Err()
}

// matchesIgnorePattern reports whether relPath (relative to the directory
// that contained the ignore file) is matched by pattern.
// Supports:
//   - exact file-name match  ("secrets.py")
//   - prefix-directory match ("build/")
//   - simple glob via filepath.Match
func matchesIgnorePattern(pattern, relPath string) bool {
	// Normalise path separators to forward slashes for matching.
	rel := filepath.ToSlash(relPath)

	// Directory pattern: "dir/" → match anything inside that dir.
	if strings.HasSuffix(pattern, "/") {
		prefix := strings.TrimSuffix(pattern, "/")
		return strings.HasPrefix(rel, prefix+"/") || rel == prefix
	}

	// Try exact base-name match first.
	base := filepath.Base(rel)
	if matched, _ := filepath.Match(pattern, base); matched {
		return true
	}

	// Try full relative-path match (handles "subdir/file.py" patterns).
	if matched, _ := filepath.Match(pattern, rel); matched {
		return true
	}

	// Try matching each path component prefix ("subdir/secret.py" style).
	parts := strings.Split(rel, "/")
	for i := range parts {
		sub := strings.Join(parts[i:], "/")
		if matched, _ := filepath.Match(pattern, sub); matched {
			return true
		}
	}

	return false
}
