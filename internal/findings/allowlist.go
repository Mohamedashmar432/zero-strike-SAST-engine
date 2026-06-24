package findings

import (
	"os"
	"path/filepath"

	"github.com/zerostrike/scanner/internal/core"
	"gopkg.in/yaml.v3"
)

// Suppression is a single allowlist entry.
type Suppression struct {
	ID          string `yaml:"id"`          // rule ID (e.g. ZS-SEC-003); mutually exclusive with Fingerprint
	Fingerprint string `yaml:"fingerprint"` // stable fingerprint of a specific finding instance
	Path        string `yaml:"path"`        // optional glob; only valid when ID is set
	Reason      string `yaml:"reason"`      // documentation only
}

// AllowList holds parsed suppression entries from a .zs-allow.yaml file.
type AllowList struct {
	Version      string       `yaml:"version"`
	Suppressions []Suppression `yaml:"suppressions"`
}

// LoadAllowList parses a YAML allowlist file. Returns an error only on read or
// parse failure; an empty file is valid.
func LoadAllowList(path string) (*AllowList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var al AllowList
	return &al, yaml.Unmarshal(data, &al)
}

// Suppressed reports whether f should be filtered from scan results.
//
// Matching precedence:
//  1. Fingerprint set → exact fingerprint match (ID/Path ignored).
//  2. ID + Path set   → rule ID match AND filepath.Match(path, file).
//  3. ID only         → all findings with that rule ID.
//
// ponytail: filepath.Match only — ** glob not supported; add doublestar lib if needed.
func (al *AllowList) Suppressed(f core.Finding) bool {
	for _, s := range al.Suppressions {
		if s.Fingerprint != "" {
			if s.Fingerprint == f.Fingerprint {
				return true
			}
			continue
		}
		if s.ID != "" && s.ID == f.RuleID {
			if s.Path == "" {
				return true
			}
			rel := filepath.ToSlash(f.Location.File)
			pat := filepath.ToSlash(s.Path)
			if ok, _ := filepath.Match(pat, filepath.Base(rel)); ok {
				return true
			}
			if ok, _ := filepath.Match(pat, rel); ok {
				return true
			}
		}
	}
	return false
}
