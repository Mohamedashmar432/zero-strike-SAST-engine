// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"crypto/sha256"
	"encoding/hex"
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
// Two rule sets with identical file content (byte-for-byte) hash identically
// regardless of the order of dirs or of directory-listing order on disk; any
// content or file-set change (a rule edited, added, or removed) produces a
// different hash. This is achieved by hashing each file individually, then
// sorting the (path, per-file-hash) pairs by path before combining them into
// the final digest.
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
//
// A directory in dirs that does not exist (or is unreadable) is silently
// skipped rather than treated as an error — this relies on fs.Glob's
// documented behavior of ignoring filesystem errors when listing a pattern's
// directory, which lets an external rules override that only supplies a
// subset of languages (or has no language subdirectories at all) hash
// successfully instead of failing on missing dirs.
func HashRuleSet(fsys fs.FS, dirs []string) (string, error) {
	type fileHash struct {
		path string
		sum  [sha256.Size]byte
	}

	var files []fileHash
	for _, dir := range dirs {
		matches, err := fs.Glob(fsys, path.Join(dir, "*.yaml"))
		if err != nil {
			return "", fmt.Errorf("hash rule set: glob %s: %w", dir, err)
		}
		for _, m := range matches {
			data, err := fs.ReadFile(fsys, m)
			if err != nil {
				return "", fmt.Errorf("hash rule set: read %s: %w", m, err)
			}
			files = append(files, fileHash{path: m, sum: sha256.Sum256(data)})
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
