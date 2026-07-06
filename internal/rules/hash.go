// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// HashRuleSet returns a deterministic SHA256 hex digest over the content of
// every *.yaml file directly within the given directories in fsys. It reads
// each directory non-recursively (matching defaultLoader.LoadDir's own
// behavior in loader.go), so the result reflects exactly the files the rule
// loader would actually load.
//
// Two rule sets with identical file content hash identically regardless of
// the order of dirs or of directory-listing order on disk; any content or
// file-set change (a rule edited, added, or removed) produces a different
// hash. This is achieved by hashing each file individually (after
// normalizing CRLF line endings to LF, so the digest is stable across a
// Windows dev checkout and a Linux CI runner of the same embedded content —
// this repo has no .gitattributes pinning line endings, and its Windows
// checkouts do produce CRLF where CI's do not), then sorting the (path,
// per-file-hash) pairs by path before combining them into the final digest.
//
// Edge-case contract, since callers (cache invalidation logic) should be
// able to rely on this without re-reading the implementation:
//   - dirs entries are expected to be disjoint (no two entries covering the
//     same file). Passing overlapping entries hashes the shared file once
//     per entry that reaches it, changing the digest — today's two real call
//     shapes (RuleDirs' disjoint data/<lang> dirs, or a single "." dir) never
//     overlap, but a caller composing dirs some other way must keep them
//     disjoint.
//   - an empty dirs slice is not an error: it returns the fixed digest of an
//     empty input (sha256 of an empty string), not a sentinel or error.
//   - a directory in dirs that does not exist is skipped, contributing
//     nothing to the hash — this is what lets rules.RuleDirs be hashed even
//     if a future language directory is momentarily absent. Any OTHER read
//     error (permission denied, a genuinely unreadable directory) is
//     propagated as an error rather than silently treated as "no rules
//     here," since silently under-counting a rule directory is exactly the
//     kind of mistake that would make the cache serve stale findings after
//     a real rule change.
//
// Callers pass rules.RuleDirs for the built-in embedded rule set:
//
//	rules.HashRuleSet(rules.EmbeddedFS, rules.RuleDirs)
//
// For an external --rules directory, note that internal/pipeline/scanner.go
// (loadAllRules/rulesFS) does NOT expect a data/<lang> subdirectory layout —
// it loads *.yaml files directly from the root of that directory via
// loader.LoadDir("."). The matching call is therefore:
//
//	rules.HashRuleSet(os.DirFS(cfg.RulesDir), []string{"."})
func HashRuleSet(fsys fs.FS, dirs []string) (string, error) {
	type fileHash struct {
		path string
		sum  [sha256.Size]byte
	}

	var files []fileHash
	for _, dir := range dirs {
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return "", fmt.Errorf("hash rule set: read dir %s: %w", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			p := path.Join(dir, e.Name())
			data, err := fs.ReadFile(fsys, p)
			if err != nil {
				return "", fmt.Errorf("hash rule set: read %s: %w", p, err)
			}
			normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
			files = append(files, fileHash{path: p, sum: sha256.Sum256([]byte(normalized))})
		}
	}

	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	var combined strings.Builder
	for _, f := range files {
		combined.WriteString(f.path)
		combined.WriteByte('|')
		combined.WriteString(hex.EncodeToString(f.sum[:]))
		combined.WriteByte('\n')
	}

	final := sha256.Sum256([]byte(combined.String()))
	return hex.EncodeToString(final[:]), nil
}
